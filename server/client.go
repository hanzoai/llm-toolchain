package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	zaplib "github.com/luxfi/zap"
	zcap "github.com/zap-proto/go/cap"

	gen "github.com/hanzoai/llm-toolchain/gen"
)

// Client is a LlmToolchain ZAP capability-RPC client — what console's bridge
// substitutes for the four in-process tRPC routers: a thin typed wrapper over a
// luxfi/zap connection that ships the verified capability with every call.
type Client struct {
	node   *zaplib.Node
	peerID string
	capBuf []byte

	promiseSeq atomic.Uint32 // monotonic PromiseID allocator

	logMu   sync.Mutex
	sendLog *[]SendEvent
}

// SendEvent is one entry in the instrumentation log: a call left the client
// (send) or its answer arrived (recv), with a monotonic sequence number. Used by
// the pipelining proof.
type SendEvent struct {
	Seq       uint64
	Kind      string // "send" or "recv"
	Method    uint32
	PromiseID uint32
	Target    uint32
	At        time.Time
}

var sendEventSeq atomic.Uint64

// pipelineIDSeq hands out process-unique promise ids for pipelined call groups,
// starting high so they never collide with a per-client PromiseID.
var pipelineIDSeq uint32 = 1 << 20

func nextPipelineID() uint32 { return atomic.AddUint32(&pipelineIDSeq, 1) }

// Dial constructs a Client over an already-started local node, connecting to the
// service at addr. capBuf is the caller's opaque capability buffer.
func Dial(node *zaplib.Node, addr, peerID string, capBuf []byte) (*Client, error) {
	if err := node.ConnectDirect(addr); err != nil {
		return nil, fmt.Errorf("llmtc client: connect %s: %w", addr, err)
	}
	return &Client{node: node, peerID: peerID, capBuf: capBuf}, nil
}

// WithSendLog attaches an instrumentation slice the client appends send/recv
// events to. Returns the client for chaining.
func (c *Client) WithSendLog(log *[]SendEvent) *Client {
	c.sendLog = log
	return c
}

func (c *Client) record(kind string, method, promiseID, target uint32) {
	if c.sendLog == nil {
		return
	}
	c.logMu.Lock()
	*c.sendLog = append(*c.sendLog, SendEvent{
		Seq:       sendEventSeq.Add(1),
		Kind:      kind,
		Method:    method,
		PromiseID: promiseID,
		Target:    target,
		At:        time.Now(),
	})
	c.logMu.Unlock()
}

func (c *Client) nextPromise() uint32 { return c.promiseSeq.Add(1) }

// call ships one request (with the given payload) and blocks for its correlated
// response.
func (c *Client) call(ctx context.Context, method, promiseID, target uint32, payload []byte) (Response, error) {
	msg, err := buildRequest(Call{
		Method:    method,
		PromiseID: promiseID,
		Target:    target,
		Cap:       c.capBuf,
		Payload:   payload,
	})
	if err != nil {
		return Response{}, err
	}
	c.record("send", method, promiseID, target)
	resp, err := c.node.Call(ctx, c.peerID, msg)
	if err != nil {
		return Response{}, err
	}
	c.record("recv", method, promiseID, target)
	return parseResponse(resp), nil
}

// do is the common request path for a non-pipelined call: ship payload, check
// status, return the raw body bytes for the caller to Wrap.
func (c *Client) do(ctx context.Context, method uint32, payload []byte, what string) ([]byte, error) {
	resp, err := c.call(ctx, method, c.nextPromise(), NoTarget, payload)
	if err != nil {
		return nil, err
	}
	if resp.Status != StatusOK {
		return nil, fmt.Errorf("%s: status %d: %s", what, resp.Status, resp.Body)
	}
	return resp.Body, nil
}

// ─── LLM API keys ─────────────────────────────────────────────────────────────

func (c *Client) KeyCreate(ctx context.Context, in gen.KeyCreateParamsInput) (gen.LlmApiKeyRef, error) {
	b, err := c.do(ctx, MethodKeyCreate, gen.NewKeyCreateParams(in), "keyCreate")
	if err != nil {
		return gen.LlmApiKeyRef{}, err
	}
	return gen.WrapLlmApiKeyRef(b)
}

func (c *Client) KeyAll(ctx context.Context, projectId string) (gen.LlmApiKeyList, error) {
	b, err := c.do(ctx, MethodKeyAll, gen.NewProjectScope(gen.ProjectScopeInput{ProjectId: projectId}), "keyAll")
	if err != nil {
		return gen.LlmApiKeyList{}, err
	}
	return gen.WrapLlmApiKeyList(b)
}

func (c *Client) KeyUpdate(ctx context.Context, in gen.KeyUpdateParamsInput) (gen.LlmApiKeyRef, error) {
	b, err := c.do(ctx, MethodKeyUpdate, gen.NewKeyUpdateParams(in), "keyUpdate")
	if err != nil {
		return gen.LlmApiKeyRef{}, err
	}
	return gen.WrapLlmApiKeyRef(b)
}

func (c *Client) KeyDelete(ctx context.Context, projectId, id string) (gen.MutationResult, error) {
	b, err := c.do(ctx, MethodKeyDelete, gen.NewIdScope(gen.IdScopeInput{ProjectId: projectId, Id: id}), "keyDelete")
	if err != nil {
		return gen.MutationResult{}, err
	}
	return gen.WrapMutationResult(b)
}

func (c *Client) KeyTest(ctx context.Context, in gen.KeyTestParamsInput) (gen.TestResult, error) {
	b, err := c.do(ctx, MethodKeyTest, gen.NewKeyTestParams(in), "keyTest")
	if err != nil {
		return gen.TestResult{}, err
	}
	return gen.WrapTestResult(b)
}

// ─── LLM schemas ──────────────────────────────────────────────────────────────

func (c *Client) SchemaCreate(ctx context.Context, in gen.NamedDocParamsInput) (gen.LlmDocRef, error) {
	return c.docCreate(ctx, MethodSchemaCreate, in, "schemaCreate")
}
func (c *Client) SchemaGetAll(ctx context.Context, projectId string) (gen.LlmDocList, error) {
	return c.docGetAll(ctx, MethodSchemaGetAll, projectId, "schemaGetAll")
}
func (c *Client) SchemaUpdate(ctx context.Context, in gen.NamedDocUpdateInput) (gen.LlmDocRef, error) {
	return c.docUpdate(ctx, MethodSchemaUpdate, in, "schemaUpdate")
}
func (c *Client) SchemaDelete(ctx context.Context, projectId, id string) (gen.MutationResult, error) {
	return c.docDelete(ctx, MethodSchemaDelete, projectId, id, "schemaDelete")
}

// ─── LLM tools ────────────────────────────────────────────────────────────────

func (c *Client) ToolCreate(ctx context.Context, in gen.NamedDocParamsInput) (gen.LlmDocRef, error) {
	return c.docCreate(ctx, MethodToolCreate, in, "toolCreate")
}
func (c *Client) ToolGetAll(ctx context.Context, projectId string) (gen.LlmDocList, error) {
	return c.docGetAll(ctx, MethodToolGetAll, projectId, "toolGetAll")
}
func (c *Client) ToolUpdate(ctx context.Context, in gen.NamedDocUpdateInput) (gen.LlmDocRef, error) {
	return c.docUpdate(ctx, MethodToolUpdate, in, "toolUpdate")
}
func (c *Client) ToolDelete(ctx context.Context, projectId, id string) (gen.MutationResult, error) {
	return c.docDelete(ctx, MethodToolDelete, projectId, id, "toolDelete")
}

// docCreate/docGetAll/docUpdate/docDelete are the shared schema+tool client
// paths (the two router groups are structurally identical — one impl, two
// method ordinals).
func (c *Client) docCreate(ctx context.Context, method uint32, in gen.NamedDocParamsInput, what string) (gen.LlmDocRef, error) {
	b, err := c.do(ctx, method, gen.NewNamedDocParams(in), what)
	if err != nil {
		return gen.LlmDocRef{}, err
	}
	return gen.WrapLlmDocRef(b)
}
func (c *Client) docGetAll(ctx context.Context, method uint32, projectId, what string) (gen.LlmDocList, error) {
	b, err := c.do(ctx, method, gen.NewProjectScope(gen.ProjectScopeInput{ProjectId: projectId}), what)
	if err != nil {
		return gen.LlmDocList{}, err
	}
	return gen.WrapLlmDocList(b)
}
func (c *Client) docUpdate(ctx context.Context, method uint32, in gen.NamedDocUpdateInput, what string) (gen.LlmDocRef, error) {
	b, err := c.do(ctx, method, gen.NewNamedDocUpdate(in), what)
	if err != nil {
		return gen.LlmDocRef{}, err
	}
	return gen.WrapLlmDocRef(b)
}
func (c *Client) docDelete(ctx context.Context, method uint32, projectId, id, what string) (gen.MutationResult, error) {
	b, err := c.do(ctx, method, gen.NewIdScope(gen.IdScopeInput{ProjectId: projectId, Id: id}), what)
	if err != nil {
		return gen.MutationResult{}, err
	}
	return gen.WrapMutationResult(b)
}

// ─── Cloud models ─────────────────────────────────────────────────────────────

func (c *Client) ModelList(ctx context.Context, projectId string) (gen.CloudModelList, error) {
	b, err := c.do(ctx, MethodModelList, gen.NewProjectScope(gen.ProjectScopeInput{ProjectId: projectId}), "modelList")
	if err != nil {
		return gen.CloudModelList{}, err
	}
	return gen.WrapCloudModelList(b)
}
func (c *Client) ModelGetConfig(ctx context.Context, projectId string) (gen.ModelConfig, error) {
	b, err := c.do(ctx, MethodModelGetConfig, gen.NewProjectScope(gen.ProjectScopeInput{ProjectId: projectId}), "modelGetConfig")
	if err != nil {
		return gen.ModelConfig{}, err
	}
	return gen.WrapModelConfig(b)
}
func (c *Client) ModelSetConfig(ctx context.Context, in gen.ModelConfigParamsInput) (gen.ModelConfig, error) {
	b, err := c.do(ctx, MethodModelSetConfig, gen.NewModelConfigParams(in), "modelSetConfig")
	if err != nil {
		return gen.ModelConfig{}, err
	}
	return gen.WrapModelConfig(b)
}

// ─── Pipelining: create-then-use ──────────────────────────────────────────────

// PipelineCreateThenList issues schemaCreate @5 and a dependent schemaGetAll @6
// such that getAll is in flight at the server BEFORE create's answer resolves —
// Cap'n Proto promise pipelining. getAll Targets create's PromiseID; the server
// resolves create's answer (the authenticated org + new id) and only then
// dispatches the promised getAll against the inherited org — no intermediate
// round trip back to the client.
//
// Transport note (load-bearing): luxfi/zap processes a single connection's
// frames strictly FIFO — one handler runs to completion before the next frame
// is read. So genuine concurrent in-flight calls require the two calls on
// SEPARATE connections, where the server runs two dispatch loops and its promise
// table (await/resolve) coordinates them. `dep` is therefore a SECOND client
// connection over which the dependent getAll is shipped.
//
// Proof (on the shared send log both clients append to): getAll's send precedes
// create's recv — the dependent call was on the wire before the call it depends
// on had answered. The server's await() blocks getAll until create resolves the
// promise, which is the pipelining join.
func (c *Client) PipelineCreateThenList(ctx context.Context, dep *Client, in gen.NamedDocParamsInput) (gen.LlmDocRef, gen.LlmDocList, error) {
	createPromise := nextPipelineID()
	listPromise := nextPipelineID()

	var (
		ref       gen.LlmDocRef
		list      gen.LlmDocList
		createErr error
		listErr   error
		wg        sync.WaitGroup
	)
	barrier := make(chan struct{})
	wg.Add(2)

	// Call #1: schemaCreate @5 on connection c — the promise the dependent call
	// targets.
	go func() {
		defer wg.Done()
		close(barrier)
		resp, err := c.call(ctx, MethodSchemaCreate, createPromise, NoTarget, gen.NewNamedDocParams(in))
		if err != nil {
			createErr = err
			return
		}
		if resp.Status != StatusOK {
			createErr = fmt.Errorf("schemaCreate: status %d: %s", resp.Status, resp.Body)
			return
		}
		ref, createErr = gen.WrapLlmDocRef(resp.Body)
	}()

	// Call #2: schemaGetAll @6 on connection dep, pipelined off create's promise.
	// Shipped without awaiting create's answer; the server holds it until create
	// resolves the promise, then dispatches against the inherited org.
	go func() {
		defer wg.Done()
		<-barrier
		resp, err := dep.call(ctx, MethodSchemaGetAll, listPromise, createPromise,
			gen.NewProjectScope(gen.ProjectScopeInput{ProjectId: in.ProjectId}))
		if err != nil {
			listErr = err
			return
		}
		if resp.Status != StatusOK {
			listErr = fmt.Errorf("schemaGetAll: status %d: %s", resp.Status, resp.Body)
			return
		}
		list, listErr = gen.WrapLlmDocList(resp.Body)
	}()

	wg.Wait()
	if createErr != nil {
		return gen.LlmDocRef{}, gen.LlmDocList{}, createErr
	}
	if listErr != nil {
		return gen.LlmDocRef{}, gen.LlmDocList{}, listErr
	}
	return ref, list, nil
}

// SyntheticCap mints an in-memory CapKindIAMSession capability for tests and
// bootstrap: ed25519-signed (the SPEC bootstrap scheme), holding the given
// permission bits. The signature is real (ed25519); production wires an
// IAM-issued cap instead. Returns the opaque buffer to pass to Dial.
func SyntheticCap(perms uint64) ([]byte, error) {
	signer, err := zcap.NewEd25519Signer()
	if err != nil {
		return nil, err
	}
	c, err := zcap.Issue(zcap.Issuance{
		Kind:        uint32(zcap.KindIAMSession),
		Holder:      signer.Public(),
		Permissions: perms,
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}, signer)
	if err != nil {
		return nil, err
	}
	return c.Bytes(), nil
}
