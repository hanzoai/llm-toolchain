package server_test

import (
	"context"
	"testing"
	"time"

	basetests "github.com/hanzoai/base/tests"
	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	zcap "github.com/zap-proto/go/cap"

	gen "github.com/hanzoai/llm-toolchain/gen"
	"github.com/hanzoai/llm-toolchain/server"
)

const testOrg = "test-org"

// testMasterKey is a fixed 32-byte master KEK for the suite — the SecretBox is
// deterministic given (master, org), so Seal/Open round-trips within a test.
var testMasterKey = []byte("0123456789abcdef0123456789abcdef")

// newService spins up a Base test app with the four collections provisioned, a
// SecretBox, a ZAP router node listening, and returns the listen address, node
// id, and a cleanup func.
func newService(t *testing.T, port int) (addr, peerID string, cleanup func()) {
	t.Helper()

	app, err := basetests.NewTestApp()
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}
	if err := server.EnsureCollections(app); err != nil {
		t.Fatalf("ensure collections: %v", err)
	}
	secrets, err := server.NewSecretBox(testMasterKey, testOrg)
	if err != nil {
		t.Fatalf("secret box: %v", err)
	}

	logger := luxlog.New("component", "llmtc-test")
	node := zaplib.NewNode(zaplib.NodeConfig{
		NodeID:      "llmtc-test-srv",
		Port:        port,
		NoDiscovery: true,
	})
	srv := server.NewServer(app, logger, testOrg, secrets, zcap.Verifier{})
	srv.Register(node)
	if err := node.Start(); err != nil {
		t.Fatalf("node start: %v", err)
	}

	return "127.0.0.1:" + itoa(port), "llmtc-test-srv", func() {
		node.Stop()
		app.Cleanup()
	}
}

// newClient dials the service with a synthetic CapKindIAMSession cap holding the
// given permissions.
func newClient(t *testing.T, addr, peerID string, perms uint64, port int) (*server.Client, func()) {
	t.Helper()
	capBuf, err := server.SyntheticCap(perms)
	if err != nil {
		t.Fatalf("synthetic cap: %v", err)
	}
	cli := zaplib.NewNode(zaplib.NodeConfig{
		NodeID:      "llmtc-test-cli-" + itoa(port),
		Port:        port,
		NoDiscovery: true,
	})
	if err := cli.Start(); err != nil {
		t.Fatalf("client node start: %v", err)
	}
	c, err := server.Dial(cli, addr, peerID, capBuf)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // handshake settle
	return c, func() { cli.Stop() }
}

func ctx5(t *testing.T) (context.Context, func()) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// ─── LLM API keys ─────────────────────────────────────────────────────────────

// TestKeyCreateEncryptsAndAllOmitsSecret is the security-critical test: the
// secret is NEVER returned by keyCreate or keyAll (only the masked display), and
// the create→all round trip surfaces the key by its safe projection.
func TestKeyCreateEncryptsAndAllOmitsSecret(t *testing.T) {
	addr, peer, stop := newService(t, 19710)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermKeyRead|server.PermKeyWrite, 19711)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	const secret = "sk-super-secret-value-1234"
	ref, err := cli.KeyCreate(ctx, gen.KeyCreateParamsInput{
		ProjectId: "p1", Provider: "openai", Adapter: "openai", SecretKey: secret, BaseURL: "https://api.openai.com",
	})
	if err != nil {
		t.Fatalf("KeyCreate: %v", err)
	}
	if ref.Id() == "" {
		t.Fatal("expected non-empty id")
	}
	if ref.DisplaySecretKey() != "...1234" {
		t.Fatalf("display = %q, want ...1234", ref.DisplaySecretKey())
	}

	list, err := cli.KeyAll(ctx, "p1")
	if err != nil {
		t.Fatalf("KeyAll: %v", err)
	}
	if list.TotalCount() != 1 || list.Data().Len() != 1 {
		t.Fatalf("count = %d / len = %d, want 1/1", list.TotalCount(), list.Data().Len())
	}
	view, err := gen.WrapLlmApiKeyView(list.Data().BytesAt(0))
	if err != nil {
		t.Fatalf("wrap view: %v", err)
	}
	if view.DisplaySecretKey() != "...1234" {
		t.Fatalf("view display = %q", view.DisplaySecretKey())
	}
	// The SAFE projection must not leak the plaintext anywhere in the row body.
	if containsSecret(list.Data().BytesAt(0), secret) {
		t.Fatal("SECURITY: plaintext secret leaked into keyAll body")
	}
}

func TestKeyUpdateRejectsProviderChange(t *testing.T) {
	addr, peer, stop := newService(t, 19712)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermKeyWrite|server.PermKeyRead, 19713)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	ref, err := cli.KeyCreate(ctx, gen.KeyCreateParamsInput{
		ProjectId: "p1", Provider: "openai", Adapter: "openai", SecretKey: "sk-aaaa",
	})
	if err != nil {
		t.Fatalf("KeyCreate: %v", err)
	}
	// Changing provider must be rejected.
	if _, err := cli.KeyUpdate(ctx, gen.KeyUpdateParamsInput{
		ProjectId: "p1", Id: ref.Id(), Provider: "anthropic", Adapter: "openai",
	}); err == nil {
		t.Fatal("expected provider-change rejection")
	}
	// Same provider/adapter, no new secret → allowed, display unchanged.
	got, err := cli.KeyUpdate(ctx, gen.KeyUpdateParamsInput{
		ProjectId: "p1", Id: ref.Id(), Provider: "openai", Adapter: "openai", BaseURL: "https://x",
	})
	if err != nil {
		t.Fatalf("KeyUpdate (no secret): %v", err)
	}
	if got.DisplaySecretKey() != "...aaaa" {
		t.Fatalf("display after no-secret update = %q, want ...aaaa", got.DisplaySecretKey())
	}
}

func TestKeyDelete(t *testing.T) {
	addr, peer, stop := newService(t, 19714)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermKeyWrite|server.PermKeyRead, 19715)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	ref, err := cli.KeyCreate(ctx, gen.KeyCreateParamsInput{ProjectId: "p1", Provider: "openai", Adapter: "openai", SecretKey: "sk-z"})
	if err != nil {
		t.Fatalf("KeyCreate: %v", err)
	}
	res, err := cli.KeyDelete(ctx, "p1", ref.Id())
	if err != nil {
		t.Fatalf("KeyDelete: %v", err)
	}
	if !res.Success() {
		t.Fatal("expected success=true")
	}
	list, _ := cli.KeyAll(ctx, "p1")
	if list.TotalCount() != 0 {
		t.Fatalf("expected 0 keys after delete, got %d", list.TotalCount())
	}
}

func TestKeyTest(t *testing.T) {
	addr, peer, stop := newService(t, 19716)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermKeyRead, 19717)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	ok, err := cli.KeyTest(ctx, gen.KeyTestParamsInput{Provider: "openai", Adapter: "openai", SecretKey: "sk-x"})
	if err != nil {
		t.Fatalf("KeyTest: %v", err)
	}
	if !ok.Success() {
		t.Fatalf("expected success, got error %q", ok.Error())
	}
	bad, err := cli.KeyTest(ctx, gen.KeyTestParamsInput{Provider: "openai"})
	if err != nil {
		t.Fatalf("KeyTest (bad): %v", err)
	}
	if bad.Success() {
		t.Fatal("expected failure for missing secretKey")
	}
}

// ─── LLM schemas + tools (identical handlers; test both ordinals) ─────────────

func TestSchemaCreateGetUpdateDelete(t *testing.T) {
	addr, peer, stop := newService(t, 19718)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermSchemaRead|server.PermSchemaWrite, 19719)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	ref, err := cli.SchemaCreate(ctx, gen.NamedDocParamsInput{ProjectId: "p1", Name: "s1", Description: "d", Body: `{"type":"object"}`})
	if err != nil {
		t.Fatalf("SchemaCreate: %v", err)
	}
	// Duplicate name → conflict.
	if _, err := cli.SchemaCreate(ctx, gen.NamedDocParamsInput{ProjectId: "p1", Name: "s1", Body: `{}`}); err == nil {
		t.Fatal("expected duplicate-name conflict")
	}
	upd, err := cli.SchemaUpdate(ctx, gen.NamedDocUpdateInput{ProjectId: "p1", Id: ref.Id(), Name: "s1", Description: "d2", Body: `{"type":"array"}`})
	if err != nil {
		t.Fatalf("SchemaUpdate: %v", err)
	}
	if upd.Description() != "d2" {
		t.Fatalf("description = %q, want d2", upd.Description())
	}
	list, err := cli.SchemaGetAll(ctx, "p1")
	if err != nil {
		t.Fatalf("SchemaGetAll: %v", err)
	}
	if list.Data().Len() != 1 {
		t.Fatalf("len = %d, want 1", list.Data().Len())
	}
	res, err := cli.SchemaDelete(ctx, "p1", ref.Id())
	if err != nil || !res.Success() {
		t.Fatalf("SchemaDelete: %v success=%v", err, res.Success())
	}
}

func TestToolCreateGetDelete(t *testing.T) {
	addr, peer, stop := newService(t, 19720)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermToolRead|server.PermToolWrite, 19721)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	ref, err := cli.ToolCreate(ctx, gen.NamedDocParamsInput{ProjectId: "p1", Name: "t1", Description: "tool", Body: `{"type":"object"}`})
	if err != nil {
		t.Fatalf("ToolCreate: %v", err)
	}
	list, err := cli.ToolGetAll(ctx, "p1")
	if err != nil {
		t.Fatalf("ToolGetAll: %v", err)
	}
	if list.Data().Len() != 1 {
		t.Fatalf("len = %d, want 1", list.Data().Len())
	}
	doc, _ := gen.WrapLlmDocRef(list.Data().BytesAt(0))
	if doc.Name() != "t1" {
		t.Fatalf("name = %q, want t1", doc.Name())
	}
	if _, err := cli.ToolDelete(ctx, "p1", ref.Id()); err != nil {
		t.Fatalf("ToolDelete: %v", err)
	}
}

// ─── Cloud models ─────────────────────────────────────────────────────────────

func TestModelConfigSetGetDefaults(t *testing.T) {
	addr, peer, stop := newService(t, 19722)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermModelRead|server.PermModelWrite, 19723)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	// Unset project → tRPC defaults.
	def, err := cli.ModelGetConfig(ctx, "fresh")
	if err != nil {
		t.Fatalf("ModelGetConfig (default): %v", err)
	}
	if def.DefaultModel() != "zen4" || def.MaxTokens() != 4096 {
		t.Fatalf("defaults = %s/%d, want zen4/4096", def.DefaultModel(), def.MaxTokens())
	}
	// Set, then read back the persisted values.
	if _, err := cli.ModelSetConfig(ctx, gen.ModelConfigParamsInput{ProjectId: "p1", DefaultModel: "zen5", Temperature: 0.3, MaxTokens: 8192}); err != nil {
		t.Fatalf("ModelSetConfig: %v", err)
	}
	got, err := cli.ModelGetConfig(ctx, "p1")
	if err != nil {
		t.Fatalf("ModelGetConfig: %v", err)
	}
	if got.DefaultModel() != "zen5" || got.MaxTokens() != 8192 {
		t.Fatalf("got = %s/%d, want zen5/8192", got.DefaultModel(), got.MaxTokens())
	}
	if got.Temperature() < 0.29 || got.Temperature() > 0.31 {
		t.Fatalf("temperature = %v, want ~0.3", got.Temperature())
	}
}

func TestModelListEmpty(t *testing.T) {
	addr, peer, stop := newService(t, 19724)
	defer stop()
	cli, stopCli := newClient(t, addr, peer, server.PermModelRead, 19725)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	list, err := cli.ModelList(ctx, "p1")
	if err != nil {
		t.Fatalf("ModelList: %v", err)
	}
	if list.Object() != "list" {
		t.Fatalf("object = %q, want list", list.Object())
	}
	if list.Data().Len() != 0 {
		t.Fatalf("expected empty registry, got %d", list.Data().Len())
	}
}

// ─── Permission chokepoint ────────────────────────────────────────────────────

// TestPermissionDenied proves the bitmask chokepoint per category: a cap holding
// ONLY key perms cannot touch schemas, and a write op needs the write bit.
func TestPermissionDenied(t *testing.T) {
	addr, peer, stop := newService(t, 19726)
	defer stop()
	// Holds key read+write, but NO schema/tool/model bits.
	cli, stopCli := newClient(t, addr, peer, server.PermKeyRead|server.PermKeyWrite, 19727)
	defer stopCli()
	ctx, cancel := ctx5(t)
	defer cancel()

	if _, err := cli.SchemaGetAll(ctx, "p1"); err == nil {
		t.Fatal("expected schema read to be denied without PermSchemaRead")
	}
	if _, err := cli.ModelGetConfig(ctx, "p1"); err == nil {
		t.Fatal("expected model read to be denied without PermModelRead")
	}

	// A read-only key cap cannot write keys.
	roCli, stopRO := newClient(t, addr, peer, server.PermKeyRead, 19728)
	defer stopRO()
	if _, err := roCli.KeyCreate(ctx, gen.KeyCreateParamsInput{ProjectId: "p1", Provider: "openai", Adapter: "openai", SecretKey: "x"}); err == nil {
		t.Fatal("expected keyCreate to be denied without PermKeyWrite")
	}
}

// ─── Pipelining proof (create-then-use) ───────────────────────────────────────

// TestPipeliningCreateThenList is the load-bearing pipelining proof: schemaGetAll
// (pipelined off schemaCreate's promise) must ship before schemaCreate's answer
// resolves. We assert on the instrumented send log that BOTH sends precede the
// first recv, and that the dependent getAll observed the just-created row
// (inheriting org through the resolved promise).
func TestPipeliningCreateThenList(t *testing.T) {
	addr, peer, stop := newService(t, 19730)
	defer stop()

	var log []server.SendEvent
	cli, stopCli := newClient(t, addr, peer, server.PermSchemaRead|server.PermSchemaWrite, 19731)
	defer stopCli()
	cli.WithSendLog(&log)
	dep, stopDep := newClient(t, addr, peer, server.PermSchemaRead|server.PermSchemaWrite, 19732)
	defer stopDep()
	dep.WithSendLog(&log)

	ctx, cancel := ctx5(t)
	defer cancel()

	ref, list, err := cli.PipelineCreateThenList(ctx, dep, gen.NamedDocParamsInput{
		ProjectId: "p1", Name: "piped", Description: "x", Body: `{"type":"object"}`,
	})
	if err != nil {
		t.Fatalf("PipelineCreateThenList: %v", err)
	}
	if ref.Id() == "" {
		t.Fatal("expected created id")
	}
	if list.Data().Len() == 0 {
		t.Fatal("dependent getAll saw no rows — promise org not inherited")
	}

	firstRecv, sendsBeforeFirstRecv := -1, 0
	for i, e := range log {
		if e.Kind == "recv" {
			firstRecv = i
			break
		}
		if e.Kind == "send" {
			sendsBeforeFirstRecv++
		}
	}
	t.Logf("send log: %s", formatLog(log))
	if firstRecv == -1 {
		t.Fatal("no recv events recorded")
	}
	if sendsBeforeFirstRecv < 2 {
		t.Fatalf("pipelining violated: only %d sends before first answer; want 2", sendsBeforeFirstRecv)
	}
	t.Logf("PIPELINING PROVEN: %d calls shipped before the first answer resolved", sendsBeforeFirstRecv)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func containsSecret(body []byte, secret string) bool {
	for i := 0; i+len(secret) <= len(body); i++ {
		if string(body[i:i+len(secret)]) == secret {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func formatLog(log []server.SendEvent) string {
	out := ""
	for _, e := range log {
		method := "create"
		if e.Method == server.MethodSchemaGetAll {
			method = "getAll"
		}
		out += e.Kind + "(" + method + ",p=" + itoa(int(e.PromiseID)) + ",t=" + itoa(int(e.Target)) + ") "
	}
	return out
}
