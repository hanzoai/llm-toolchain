package server_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/base/core"
	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	zcap "github.com/zap-proto/go/cap"

	gen "github.com/hanzoai/llm-toolchain/gen"
	"github.com/hanzoai/llm-toolchain/server"
)

// TestSecretEncryptedAtRest is the durable security proof: after a key is
// created, the PLAINTEXT secret must not appear anywhere in the on-disk SQLite
// files — only AES-256-GCM ciphertext. We boot a Base app against a real data
// dir, create a key over the live ZAP path, then scan every *.db byte for the
// plaintext. This is the CLAUDE.md "never store secrets in plaintext" invariant,
// verified on disk rather than asserted in prose.
func TestSecretEncryptedAtRest(t *testing.T) {
	dataDir := t.TempDir()

	app := core.NewBaseApp(core.BaseAppConfig{
		DataDir: dataDir,
		IsDev:   true,
	})
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer app.ResetBootstrapState()
	if err := app.RunAllMigrations(); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	if err := server.EnsureCollections(app); err != nil {
		t.Fatalf("ensure collections: %v", err)
	}
	secrets, err := server.NewSecretBox(testMasterKey, testOrg)
	if err != nil {
		t.Fatalf("secret box: %v", err)
	}

	const port = 19740
	node := zaplib.NewNode(zaplib.NodeConfig{NodeID: "llmtc-atrest-srv", Port: port, NoDiscovery: true})
	srv := server.NewServer(app, luxlog.New("component", "llmtc-atrest"), testOrg, secrets, zcap.Verifier{})
	srv.Register(node)
	if err := node.Start(); err != nil {
		t.Fatalf("node start: %v", err)
	}
	defer node.Stop()

	cli, stopCli := newClient(t, "127.0.0.1:"+itoa(port), "llmtc-atrest-srv", server.PermKeyWrite|server.PermKeyRead, 19741)
	defer stopCli()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const plaintext = "sk-PLAINTEXT-MUST-NOT-PERSIST-9f8e7d6c"
	const headerVal = "HEADER-SECRET-SHOULD-ALSO-BE-ENCRYPTED"
	if _, err := cli.KeyCreate(ctx, gen.KeyCreateParamsInput{
		ProjectId:    "p1",
		Provider:     "openai",
		Adapter:      "openai",
		SecretKey:    plaintext,
		ExtraHeaders: `{"X-Secret":"` + headerVal + `"}`,
	}); err != nil {
		t.Fatalf("KeyCreate: %v", err)
	}

	// Force a checkpoint so the WAL is flushed into the main db file, then scan
	// every db artifact (db, -wal, -shm) for the plaintext.
	if _, err := app.DB().NewQuery("PRAGMA wal_checkpoint(TRUNCATE)").Execute(); err != nil {
		t.Logf("wal_checkpoint: %v (continuing — scanning all db artifacts anyway)", err)
	}
	node.Stop() // release file handles / flush

	needles := [][]byte{[]byte(plaintext), []byte(headerVal)}
	scanned := 0
	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		scanned++
		for _, n := range needles {
			if bytes.Contains(data, n) {
				t.Fatalf("SECURITY: plaintext %q found at rest in %s", n, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk data dir: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned no files — data dir empty, test would be vacuous")
	}
	t.Logf("at-rest OK: scanned %d files under %s, no plaintext secret present", scanned, dataDir)

	// Sanity: the SecretBox round-trips (so we know encryption, not omission,
	// is what kept the plaintext off disk).
	sealed, _ := secrets.Seal(plaintext)
	if got, _ := secrets.Open(sealed); got != plaintext {
		t.Fatalf("secretbox round-trip failed: got %q", got)
	}
}
