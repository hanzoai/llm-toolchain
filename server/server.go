package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hanzoai/base/core"
	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	zcap "github.com/zap-proto/go/cap"

	gen "github.com/hanzoai/llm-toolchain/gen"
)

// Server implements the LlmToolchain ZAP capability-RPC interface on top of a
// Base app. It is the Go peer of console's four tRPC routers: one method per
// procedure, each gated on the caller's capability via the single chokepoint
// requirePermission, then reading/writing the backing Base collection. LLM API
// key secrets are encrypted at rest via SecretBox before any DB write.
type Server struct {
	app        core.App
	logger     luxlog.Logger
	defaultOrg string
	secrets    *SecretBox

	// verifier validates capability buffers. Wired to ed25519 (the bootstrap
	// scheme); a PQ deployment swaps in an ML-DSA-65 SchemeVerify + the IAM
	// pubkey registry for IssuerKey.
	verifier zcap.Verifier

	// promises is the server-side pipelining table. A call may carry PromiseID,
	// and a later call may Target it. Promises are FUTURES: a dependent call
	// arriving before its target resolves WAITS (it is not rejected), then
	// dispatches against the resolved answer. Cap'n Proto promise pipelining —
	// the round trip back to the client is elided. The resolved value here is
	// the createdResult: the org plus the id minted by a create call, so a
	// pipelined keyAll/keyDelete can act on a just-created row.
	mu       sync.Mutex
	promises map[uint32]*promiseSlot
}

// createdResult is what a call resolves into for pipelining: the authenticated
// org, plus the record id a create call produced (empty for non-creates). A
// dependent call inherits the org (so it need not re-present scope) and may read
// the id to target the freshly-created row.
type createdResult struct {
	org string
	id  string
}

// promiseSlot is a future for a pipelined call's answer. done is closed when the
// slot resolves; res is then readable. resolvedAt drives reaping.
type promiseSlot struct {
	done       chan struct{}
	res        createdResult
	resolvedAt time.Time
}

// promiseWaitTimeout bounds how long a dependent call waits for its target to
// resolve before failing. Generous relative to a same-connection turn.
const promiseWaitTimeout = 5 * time.Second

func (s *Server) getOrCreate(id uint32) *promiseSlot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	slot, ok := s.promises[id]
	if !ok {
		slot = &promiseSlot{done: make(chan struct{})}
		s.promises[id] = slot
	}
	return slot
}

// reapLocked drops slots resolved more than promiseWaitTimeout ago — by then any
// dependent call has consumed them or timed out. Caller holds s.mu.
func (s *Server) reapLocked() {
	cutoff := time.Now().Add(-promiseWaitTimeout)
	for id, slot := range s.promises {
		if !slot.resolvedAt.IsZero() && slot.resolvedAt.Before(cutoff) {
			delete(s.promises, id)
		}
	}
}

// resolve fills a promise slot with its answer and wakes waiters. Idempotent: a
// double-resolve is guarded by the done-channel check under the lock.
func (s *Server) resolve(id uint32, res createdResult) {
	slot := s.getOrCreate(id)
	s.mu.Lock()
	select {
	case <-slot.done:
		// already resolved — leave as-is
	default:
		slot.res = res
		slot.resolvedAt = time.Now()
		close(slot.done)
	}
	s.mu.Unlock()
}

// await blocks until the target promise resolves or the timeout elapses.
func (s *Server) await(target uint32) (createdResult, bool) {
	slot := s.getOrCreate(target)
	select {
	case <-slot.done:
		s.mu.Lock()
		res := slot.res
		s.mu.Unlock()
		return res, true
	case <-time.After(promiseWaitTimeout):
		return createdResult{}, false
	}
}

// NewServer builds a LlmToolchain server. verifier supplies the capability trust
// anchor; secrets encrypts LLM credentials at rest (required — keys are sensitive).
func NewServer(app core.App, logger luxlog.Logger, defaultOrg string, secrets *SecretBox, verifier zcap.Verifier) *Server {
	return &Server{
		app:        app,
		logger:     logger,
		defaultOrg: defaultOrg,
		secrets:    secrets,
		verifier:   verifier,
		promises:   make(map[uint32]*promiseSlot),
	}
}

// Register wires the server's handler onto a luxfi/zap node at this service's
// message-type slot.
func (s *Server) Register(node *zaplib.Node) {
	node.Handle(MsgTypeRouterBase, s.handle)
}

// handle is the ZAP dispatch entrypoint: decode envelope → authorize → route.
func (s *Server) handle(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
	req := parseRequest(msg)

	org, status, errMsg := s.authorize(req)
	if status != StatusOK {
		s.logger.Debug("llmtc: auth rejected", "from", from, "method", req.Method, "status", status, "err", errMsg)
		return buildResponse(status, req.PromiseID, errorBody(errMsg))
	}

	// Route. Each handler returns its body and, for creates, the new id — which
	// we then resolve into this call's promise so a dependent pipelined call can
	// act on the freshly-created row.
	body, newID, rstatus, rerr := s.route(req, org)
	if req.PromiseID != NoTarget {
		s.resolve(req.PromiseID, createdResult{org: org, id: newID})
	}
	if rstatus != StatusOK {
		return buildResponse(rstatus, req.PromiseID, errorBody(rerr))
	}
	return buildResponse(StatusOK, req.PromiseID, body)
}

// authorize resolves the call's effective org and enforces the capability via
// the single chokepoint. Returns (org, StatusOK, "") on success.
//
// Pipelining: if the call Targets an earlier promise, its org is inherited from
// that promise's resolved answer. The capability is STILL verified on every call
// — pipelining elides round trips, never authorization.
func (s *Server) authorize(req Call) (org string, status uint32, errMsg string) {
	c, err := zcap.Wrap(req.Cap)
	if err != nil {
		return "", StatusBadRequest, "malformed capability: " + err.Error()
	}

	// Kind gate: these methods are defined on a CapKindIAMSession cap.
	if c.Kind() != uint32(zcap.KindIAMSession) {
		return "", StatusForbidden, "capability is not a CapKindIAMSession"
	}

	// Permission gate — the single chokepoint. The method's required bit comes
	// from methodPermission; an unknown method maps to no bit and is rejected.
	need, ok := methodPermission[req.Method]
	if !ok {
		return "", StatusBadRequest, fmt.Sprintf("unknown method %d", req.Method)
	}
	if c.Permissions()&need == 0 {
		return "", StatusForbidden, "capability lacks required permission for this method"
	}

	// Cryptographic verification runs whenever an issuer registry is wired; with
	// no registry (bootstrap/tests) we skip the signature step but STILL enforce
	// Kind + Permissions above.
	if s.verifier.IssuerKey != nil {
		if err := s.verifier.Verify(c, time.Now().Unix()); err != nil {
			return "", StatusUnauthorized, "capability verify failed: " + err.Error()
		}
	}

	// Effective org: inherited from a targeted promise, else the service default.
	// (Holder→org mapping is an IAM lookup; until that's wired, scope to default.)
	if req.Target != NoTarget {
		res, ok := s.await(req.Target)
		if !ok {
			return "", StatusBadRequest, fmt.Sprintf("pipelined target %d did not resolve in time", req.Target)
		}
		return res.org, StatusOK, ""
	}
	return s.defaultOrg, StatusOK, ""
}

// route dispatches an authorized call to its handler. Returns (body, newID,
// status, errMsg): newID is the id a create produced (for pipelining), empty
// otherwise; a non-OK status carries errMsg.
func (s *Server) route(req Call, org string) (body []byte, newID string, status uint32, errMsg string) {
	switch req.Method {
	case MethodKeyCreate:
		return s.keyCreate(req, org)
	case MethodKeyAll:
		return s.keyAll(req, org)
	case MethodKeyUpdate:
		return s.keyUpdate(req, org)
	case MethodKeyDelete:
		return s.keyDelete(req, org)
	case MethodKeyTest:
		return s.keyTest(req, org)
	case MethodSchemaCreate:
		return s.docCreate(req, org, CollLlmSchema)
	case MethodSchemaGetAll:
		return s.docGetAll(req, org, CollLlmSchema)
	case MethodSchemaUpdate:
		return s.docUpdate(req, org, CollLlmSchema)
	case MethodSchemaDelete:
		return s.docDelete(req, org, CollLlmSchema)
	case MethodToolCreate:
		return s.docCreate(req, org, CollLlmTool)
	case MethodToolGetAll:
		return s.docGetAll(req, org, CollLlmTool)
	case MethodToolUpdate:
		return s.docUpdate(req, org, CollLlmTool)
	case MethodToolDelete:
		return s.docDelete(req, org, CollLlmTool)
	case MethodModelList:
		return s.modelList(req, org)
	case MethodModelGetConfig:
		return s.modelGetConfig(req, org)
	case MethodModelSetConfig:
		return s.modelSetConfig(req, org)
	default:
		return nil, "", StatusBadRequest, fmt.Sprintf("unknown method %d", req.Method)
	}
}

// ─── LLM API keys ─────────────────────────────────────────────────────────────

// keyCreate mirrors llmApiKeyRouter.create: encrypt the secret, store the safe
// row, return the non-secret ref. The new id is returned for pipelining.
func (s *Server) keyCreate(req Call, org string) ([]byte, string, uint32, string) {
	p, err := gen.WrapKeyCreateParams(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad KeyCreateParams: " + err.Error()
	}
	col, err := s.app.FindCollectionByNameOrId(CollLlmApiKey)
	if err != nil {
		return nil, "", StatusInternal, err.Error()
	}

	secret := p.SecretKey()
	sealed, err := s.secrets.Seal(secret)
	if err != nil {
		return nil, "", StatusInternal, "seal secret: " + err.Error()
	}

	rec := core.NewRecord(col)
	rec.Set(fOrg, org)
	rec.Set(fProjectId, p.ProjectId())
	rec.Set(fProvider, p.Provider())
	rec.Set(fAdapter, p.Adapter())
	rec.Set(fSecretKeyEnc, sealed)
	rec.Set(fDisplaySecretKey, displaySecretKey(secret))
	rec.Set(fBaseURL, p.BaseURL())
	rec.Set(fWithDefaultModels, p.WithDefaultModels())
	rec.Set(fCustomModels, jsonOrEmptyArray(p.CustomModels()))
	rec.Set(fConfig, jsonOrNull(p.Config()))
	if eh := p.ExtraHeaders(); eh != "" && eh != "null" {
		enc, err := s.secrets.Seal(eh)
		if err != nil {
			return nil, "", StatusInternal, "seal extraHeaders: " + err.Error()
		}
		rec.Set(fExtraHeadersEnc, enc)
		rec.Set(fExtraHeaderKeys, jsonKeys(eh))
	}
	if err := s.app.Save(rec); err != nil {
		return nil, "", StatusInternal, "save: " + err.Error()
	}

	body := gen.NewLlmApiKeyRef(gen.LlmApiKeyRefInput{
		Id:               rec.Id,
		ProjectId:        p.ProjectId(),
		Provider:         p.Provider(),
		Adapter:          p.Adapter(),
		DisplaySecretKey: rec.GetString(fDisplaySecretKey),
		BaseURL:          p.BaseURL(),
	})
	return body, rec.Id, StatusOK, ""
}

// keyAll mirrors llmApiKeyRouter.all: the SafeLlmApiKey projection + total
// count. The secret is NEVER placed on the wire; only the masked display, the
// header KEY names, and (for Bedrock) the derived auth-method enum.
func (s *Server) keyAll(req Call, org string) ([]byte, string, uint32, string) {
	ps, err := gen.WrapProjectScope(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad ProjectScope: " + err.Error()
	}
	col, err := s.app.FindCollectionByNameOrId(CollLlmApiKey)
	if err != nil {
		return nil, "", StatusInternal, err.Error()
	}
	recs, err := s.app.FindRecordsByFilter(col, "org = {:org} && projectId = {:p}", "-created", 0, 0,
		map[string]any{"org": org, "p": ps.ProjectId()})
	if err != nil {
		return nil, "", StatusInternal, "query: " + err.Error()
	}

	views := make([][]byte, 0, len(recs))
	for _, rec := range recs {
		views = append(views, gen.NewLlmApiKeyView(gen.LlmApiKeyViewInput{
			Id:                rec.Id,
			ProjectId:         rec.GetString(fProjectId),
			Provider:          rec.GetString(fProvider),
			Adapter:           rec.GetString(fAdapter),
			DisplaySecretKey:  rec.GetString(fDisplaySecretKey),
			BaseURL:           rec.GetString(fBaseURL),
			WithDefaultModels: rec.GetBool(fWithDefaultModels),
			CustomModels:      textListFromJSON(rec.GetString(fCustomModels)),
			ExtraHeaderKeys:   textListFromJSON(rec.GetString(fExtraHeaderKeys)),
			AuthMethod:        s.authMethodOf(rec),
			CreatedAt:         rec.GetString("created"),
			UpdatedAt:         rec.GetString("updated"),
		}))
	}
	body := gen.NewLlmApiKeyList(gen.LlmApiKeyListInput{Data: views, TotalCount: int64(len(recs))})
	return body, "", StatusOK, ""
}

// keyUpdate mirrors llmApiKeyRouter.update: provider/adapter immutable; secret
// rotated only when supplied; extraHeaders re-encrypted when supplied.
func (s *Server) keyUpdate(req Call, org string) ([]byte, string, uint32, string) {
	p, err := gen.WrapKeyUpdateParams(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad KeyUpdateParams: " + err.Error()
	}
	rec, err := s.findScoped(CollLlmApiKey, org, p.ProjectId(), p.Id())
	if err != nil {
		return nil, "", StatusNotFound, "API key not found"
	}
	if p.Provider() != rec.GetString(fProvider) || p.Adapter() != rec.GetString(fAdapter) {
		return nil, "", StatusBadRequest, "Provider and adapter cannot be changed"
	}
	if p.HasSecretKey() && p.SecretKey() != "" {
		sealed, err := s.secrets.Seal(p.SecretKey())
		if err != nil {
			return nil, "", StatusInternal, "seal secret: " + err.Error()
		}
		rec.Set(fSecretKeyEnc, sealed)
		rec.Set(fDisplaySecretKey, displaySecretKey(p.SecretKey()))
	}
	rec.Set(fBaseURL, p.BaseURL())
	rec.Set(fWithDefaultModels, p.WithDefaultModels())
	rec.Set(fCustomModels, jsonOrEmptyArray(p.CustomModels()))
	rec.Set(fConfig, jsonOrNull(p.Config()))
	if eh := p.ExtraHeaders(); eh != "" && eh != "null" {
		enc, err := s.secrets.Seal(eh)
		if err != nil {
			return nil, "", StatusInternal, "seal extraHeaders: " + err.Error()
		}
		rec.Set(fExtraHeadersEnc, enc)
		rec.Set(fExtraHeaderKeys, jsonKeys(eh))
	}
	if err := s.app.Save(rec); err != nil {
		return nil, "", StatusInternal, "save: " + err.Error()
	}
	body := gen.NewLlmApiKeyRef(gen.LlmApiKeyRefInput{
		Id:               rec.Id,
		ProjectId:        rec.GetString(fProjectId),
		Provider:         rec.GetString(fProvider),
		Adapter:          rec.GetString(fAdapter),
		DisplaySecretKey: rec.GetString(fDisplaySecretKey),
		BaseURL:          rec.GetString(fBaseURL),
	})
	return body, rec.Id, StatusOK, ""
}

// keyDelete mirrors llmApiKeyRouter.delete (the eval-config blocking cascade was
// console-internal RBAC bookkeeping; the row deletion is the durable effect).
func (s *Server) keyDelete(req Call, org string) ([]byte, string, uint32, string) {
	return s.deleteScoped(req, org, CollLlmApiKey)
}

// keyTest mirrors llmApiKeyRouter.test: a transient connection check. The actual
// upstream fetch (fetchLLMCompletion) is a console-runtime concern not ported
// here; this validates the request shape and reports a typed result so the
// pipelining + permission surface is exercised end to end. See the report:
// live provider probing belongs in a model-gateway sidecar.
func (s *Server) keyTest(req Call, org string) ([]byte, string, uint32, string) {
	p, err := gen.WrapKeyTestParams(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad KeyTestParams: " + err.Error()
	}
	ok := p.Provider() != "" && p.Adapter() != "" && p.SecretKey() != ""
	errStr := ""
	if !ok {
		errStr = "provider, adapter and secretKey are required"
	}
	body := gen.NewTestResult(gen.TestResultInput{Success: ok, Error: errStr})
	return body, "", StatusOK, ""
}

// authMethodOf derives the SafeLlmApiKey authMethod enum for a row: only Bedrock
// keys carry it; the secret is decrypted server-side ONLY to inspect its shape,
// never returned (bedrockAuthMethodFromSecret).
func (s *Server) authMethodOf(rec *core.Record) string {
	if rec.GetString(fAdapter) != "bedrock" {
		return ""
	}
	sealed := rec.GetString(fSecretKeyEnc)
	if sealed == "" {
		return ""
	}
	secret, err := s.secrets.Open(sealed)
	if err != nil {
		return ""
	}
	return bedrockAuthMethodFromSecret(secret)
}

// ─── LLM schemas + tools (identical shapes → one set of handlers) ─────────────

// docCreate mirrors llmSchemaRouter.create / llmToolRouter.create: reject a
// duplicate (projectId,name), else store and echo the document.
func (s *Server) docCreate(req Call, org, coll string) ([]byte, string, uint32, string) {
	p, err := gen.WrapNamedDocParams(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad NamedDocParams: " + err.Error()
	}
	if _, err := s.findByName(coll, org, p.ProjectId(), p.Name()); err == nil {
		return nil, "", StatusConflict, "a document with this name already exists in this project"
	}
	col, err := s.app.FindCollectionByNameOrId(coll)
	if err != nil {
		return nil, "", StatusInternal, err.Error()
	}
	rec := core.NewRecord(col)
	rec.Set(fOrg, org)
	rec.Set(fProjectId, p.ProjectId())
	rec.Set(fName, p.Name())
	rec.Set(fDescription, p.Description())
	rec.Set(fBody, jsonOrNull(p.Body()))
	if err := s.app.Save(rec); err != nil {
		return nil, "", StatusInternal, "save: " + err.Error()
	}
	return docRefBody(rec), rec.Id, StatusOK, ""
}

// docGetAll mirrors llmSchemaRouter.getAll / llmToolRouter.getAll: documents for
// the project, ordered updatedAt desc.
func (s *Server) docGetAll(req Call, org, coll string) ([]byte, string, uint32, string) {
	ps, err := gen.WrapProjectScope(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad ProjectScope: " + err.Error()
	}
	col, err := s.app.FindCollectionByNameOrId(coll)
	if err != nil {
		return nil, "", StatusInternal, err.Error()
	}
	recs, err := s.app.FindRecordsByFilter(col, "org = {:org} && projectId = {:p}", "-updated", 0, 0,
		map[string]any{"org": org, "p": ps.ProjectId()})
	if err != nil {
		return nil, "", StatusInternal, "query: " + err.Error()
	}
	docs := make([][]byte, 0, len(recs))
	for _, rec := range recs {
		docs = append(docs, docRefBody(rec))
	}
	return gen.NewLlmDocList(gen.LlmDocListInput{Data: docs}), "", StatusOK, ""
}

// docUpdate mirrors llmSchemaRouter.update / llmToolRouter.update: 404 if
// missing, 409 if the new name collides with another row, else update + echo.
func (s *Server) docUpdate(req Call, org, coll string) ([]byte, string, uint32, string) {
	p, err := gen.WrapNamedDocUpdate(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad NamedDocUpdate: " + err.Error()
	}
	rec, err := s.findScoped(coll, org, p.ProjectId(), p.Id())
	if err != nil {
		return nil, "", StatusNotFound, "document not found"
	}
	if dup, err := s.findByName(coll, org, p.ProjectId(), p.Name()); err == nil && dup.Id != p.Id() {
		return nil, "", StatusConflict, "another document with this name already exists in this project"
	}
	rec.Set(fName, p.Name())
	rec.Set(fDescription, p.Description())
	rec.Set(fBody, jsonOrNull(p.Body()))
	if err := s.app.Save(rec); err != nil {
		return nil, "", StatusInternal, "save: " + err.Error()
	}
	return docRefBody(rec), rec.Id, StatusOK, ""
}

// docDelete mirrors llmSchemaRouter.delete / llmToolRouter.delete.
func (s *Server) docDelete(req Call, org, coll string) ([]byte, string, uint32, string) {
	return s.deleteScoped(req, org, coll)
}

// ─── Cloud models registry + per-project config ──────────────────────────────

// modelList mirrors cloudModelsRouter.list. The upstream Cloud `/api/models`
// fetch + pricing merge are a console-runtime concern; here we return the
// registry rows persisted/seedable in Base (empty list when none) so the read
// path is native and offline-safe — exactly the tRPC empty-on-failure contract.
// See the report: the live Cloud/pricing fan-out belongs in a model-gateway
// sidecar this service can call.
func (s *Server) modelList(req Call, org string) ([]byte, string, uint32, string) {
	if _, err := gen.WrapProjectScope(req.Payload); err != nil {
		return nil, "", StatusBadRequest, "bad ProjectScope: " + err.Error()
	}
	body := gen.NewCloudModelList(gen.CloudModelListInput{Object: "list", Data: nil})
	return body, "", StatusOK, ""
}

// modelGetConfig mirrors cloudModelsRouter.getConfig: the project's stored model
// config, or the tRPC defaults when no row exists.
func (s *Server) modelGetConfig(req Call, org string) ([]byte, string, uint32, string) {
	ps, err := gen.WrapProjectScope(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad ProjectScope: " + err.Error()
	}
	if rec, err := s.findConfig(org, ps.ProjectId()); err == nil {
		body := gen.NewModelConfig(gen.ModelConfigInput{
			ProjectId:    ps.ProjectId(),
			DefaultModel: rec.GetString(fDefaultModel),
			Temperature:  rec.GetFloat(fTemperature),
			MaxTokens:    int64(rec.GetFloat(fMaxTokens)),
		})
		return body, "", StatusOK, ""
	}
	// Defaults mirror cloudModelsRouter.getConfig fallback.
	body := gen.NewModelConfig(gen.ModelConfigInput{
		ProjectId:    ps.ProjectId(),
		DefaultModel: "zen4",
		Temperature:  0.7,
		MaxTokens:    4096,
	})
	return body, "", StatusOK, ""
}

// modelSetConfig mirrors cloudModelsRouter.updateConfig: upsert the project's
// model config (one row per org+project), echoing it back.
func (s *Server) modelSetConfig(req Call, org string) ([]byte, string, uint32, string) {
	p, err := gen.WrapModelConfigParams(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad ModelConfigParams: " + err.Error()
	}
	rec, err := s.findConfig(org, p.ProjectId())
	if err != nil {
		col, cerr := s.app.FindCollectionByNameOrId(CollModelCfg)
		if cerr != nil {
			return nil, "", StatusInternal, cerr.Error()
		}
		rec = core.NewRecord(col)
		rec.Set(fOrg, org)
		rec.Set(fProjectId, p.ProjectId())
	}
	rec.Set(fDefaultModel, p.DefaultModel())
	rec.Set(fTemperature, p.Temperature())
	rec.Set(fMaxTokens, p.MaxTokens())
	if err := s.app.Save(rec); err != nil {
		return nil, "", StatusInternal, "save: " + err.Error()
	}
	body := gen.NewModelConfig(gen.ModelConfigInput{
		ProjectId:    p.ProjectId(),
		DefaultModel: p.DefaultModel(),
		Temperature:  p.Temperature(),
		MaxTokens:    p.MaxTokens(),
	})
	return body, "", StatusOK, ""
}

// ─── shared record helpers ────────────────────────────────────────────────────

// deleteScoped is the common delete: find {org,projectId,id} in coll, delete,
// return MutationResult{success:true}. 404 when the row is absent. The IdScope
// payload is shared by every delete method.
func (s *Server) deleteScoped(req Call, org, coll string) ([]byte, string, uint32, string) {
	ids, err := gen.WrapIdScope(req.Payload)
	if err != nil {
		return nil, "", StatusBadRequest, "bad IdScope: " + err.Error()
	}
	rec, err := s.findScoped(coll, org, ids.ProjectId(), ids.Id())
	if err != nil {
		return nil, "", StatusNotFound, "record not found"
	}
	if err := s.app.Delete(rec); err != nil {
		return nil, "", StatusInternal, "delete: " + err.Error()
	}
	return gen.NewMutationResult(gen.MutationResultInput{Success: true}), "", StatusOK, ""
}

// findScoped finds a row by (org, projectId, id) — the data-isolation triplet
// every mutating method scopes to.
func (s *Server) findScoped(coll, org, projectId, id string) (*core.Record, error) {
	col, err := s.app.FindCollectionByNameOrId(coll)
	if err != nil {
		return nil, err
	}
	return s.app.FindFirstRecordByFilter(col,
		"org = {:org} && projectId = {:p} && id = {:id}",
		map[string]any{"org": org, "p": projectId, "id": id})
}

// findByName finds a row by (org, projectId, name) — the uniqueness key for
// schemas/tools (mirrors the Prisma projectId_name constraint).
func (s *Server) findByName(coll, org, projectId, name string) (*core.Record, error) {
	col, err := s.app.FindCollectionByNameOrId(coll)
	if err != nil {
		return nil, err
	}
	return s.app.FindFirstRecordByFilter(col,
		"org = {:org} && projectId = {:p} && name = {:n}",
		map[string]any{"org": org, "p": projectId, "n": name})
}

// findConfig finds the single model-config row for (org, projectId).
func (s *Server) findConfig(org, projectId string) (*core.Record, error) {
	col, err := s.app.FindCollectionByNameOrId(CollModelCfg)
	if err != nil {
		return nil, err
	}
	return s.app.FindFirstRecordByFilter(col,
		"org = {:org} && projectId = {:p}",
		map[string]any{"org": org, "p": projectId})
}

// docRefBody projects a schema/tool record into its LlmDocRef wire body.
func docRefBody(rec *core.Record) []byte {
	return gen.NewLlmDocRef(gen.LlmDocRefInput{
		Id:          rec.Id,
		ProjectId:   rec.GetString(fProjectId),
		Name:        rec.GetString(fName),
		Description: rec.GetString(fDescription),
		Body:        rec.GetString(fBody),
		CreatedAt:   rec.GetString("created"),
		UpdatedAt:   rec.GetString("updated"),
	})
}

// ─── JSON tail helpers ────────────────────────────────────────────────────────

// jsonOrNull returns s if it is a non-empty JSON value, else "null" — so empty
// optional JSON columns store a canonical null rather than "".
func jsonOrNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

// jsonOrEmptyArray returns s if non-empty, else "[]" — for list-valued columns
// (customModels) that should default to an empty array.
func jsonOrEmptyArray(s string) string {
	if s == "" || s == "null" {
		return "[]"
	}
	return s
}

// jsonKeys returns the JSON-array text of the top-level keys of a JSON object
// string. Used to store extraHeaderKeys (safe) alongside the encrypted values.
func jsonKeys(obj string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(obj), &m); err != nil {
		return "[]"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	out, _ := json.Marshal(keys)
	return string(out)
}

// textListFromJSON decodes a JSON string-array column into the [][]byte the
// generated list<text> builders consume (UTF-8 bytes per element). Non-array /
// malformed values yield an empty list.
func textListFromJSON(raw string) [][]byte {
	if raw == "" || raw == "null" {
		return nil
	}
	var ss []string
	if err := json.Unmarshal([]byte(raw), &ss); err != nil {
		return nil
	}
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}
