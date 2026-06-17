# llm-toolchain.zap — canonical wire schema for the LlmToolchain service.
#
# Dialect: zap-spec (the `package … / Field Type @off` grammar that
# github.com/zap-proto/go/cmd/zapgen consumes). SAME dialect as the capability
# schema (zap-spec/capabilities.zap). ONE schema, two code targets: this Go
# service binary compiles it via `make zap-gen` into Go views; the console
# copies it verbatim and compiles with `zapgen --target=ts` into TS View/Builder
# classes over @hanzo/zap. No capnp on either side — the field set below is the
# single byte-for-byte contract both speak.
#
# This service replaces FOUR console tRPC routers with native ZAP capability RPC:
#   llmApiKeyRouter   — LLM provider credentials (secretKey ENCRYPTED at rest)
#   llmSchemaRouter   — structured-output JSON schemas
#   llmToolRouter     — tool/function-call definitions
#   cloudModelsRouter — Cloud model registry + per-project model config
#
# RPC surface (hand-dispatched in server/, exactly as cap/ hand-writes Verify on
# top of zapgen'd views — zapgen emits DATA views, never method stubs):
#
#   interface LlmToolchain @ MsgTypeRouterBase (205) {
#     # ── LLM API keys (secretKey encrypted) ──────────────────────────────
#     keyCreate  @0  (KeyCreateParams)  -> (LlmApiKeyRef)     # PermKeyWrite
#     keyAll     @1  (ProjectScope)     -> (LlmApiKeyList)    # PermKeyRead  (never returns secretKey)
#     keyUpdate  @2  (KeyUpdateParams)  -> (LlmApiKeyRef)     # PermKeyWrite
#     keyDelete  @3  (IdScope)          -> (MutationResult)   # PermKeyWrite
#     keyTest    @4  (KeyTestParams)    -> (TestResult)       # PermKeyRead
#     # ── LLM schemas ─────────────────────────────────────────────────────
#     schemaCreate @5  (NamedDocParams) -> (LlmDocRef)        # PermSchemaWrite
#     schemaGetAll @6  (ProjectScope)   -> (LlmDocList)       # PermSchemaRead
#     schemaUpdate @7  (NamedDocUpdate) -> (LlmDocRef)        # PermSchemaWrite
#     schemaDelete @8  (IdScope)        -> (MutationResult)   # PermSchemaWrite
#     # ── LLM tools ───────────────────────────────────────────────────────
#     toolCreate   @9  (NamedDocParams) -> (LlmDocRef)        # PermToolWrite
#     toolGetAll   @10 (ProjectScope)   -> (LlmDocList)       # PermToolRead
#     toolUpdate   @11 (NamedDocUpdate) -> (LlmDocRef)        # PermToolWrite
#     toolDelete   @12 (IdScope)        -> (MutationResult)   # PermToolWrite
#     # ── Cloud models registry + per-project config ──────────────────────
#     modelList      @13 (ProjectScope)        -> (CloudModelList)  # PermModelRead
#     modelGetConfig @14 (ProjectScope)        -> (ModelConfig)     # PermModelRead
#     modelSetConfig @15 (ModelConfigParams)   -> (ModelConfig)     # PermModelWrite
#   }
#
# Permission model: the caller's verified Capability (CapKindIAMSession = 0x01)
# carries a u64 Permissions bitmask. Each method gates on its category bit
# (LLMTCPermissions below) through the single chokepoint
# server.requirePermission(cap, bit). See zap-spec/capabilities_kinds.md.
#
#   PermKeyRead     1<<0   PermKeyWrite     1<<1
#   PermSchemaRead  1<<2   PermSchemaWrite  1<<3
#   PermToolRead    1<<4   PermToolWrite    1<<5
#   PermModelRead   1<<6   PermModelWrite   1<<7

package llmtc

# ─── Request params (one struct per method that takes input) ──────────────────

# ProjectScope is the bare {projectId} input shared by every list/read method
# (keyAll, schemaGetAll, toolGetAll, modelList, modelGetConfig). Project scope
# is the data-isolation key — the service scopes all reads to it under the org.
struct ProjectScope {
    ProjectId text @0
}

# IdScope is the {projectId,id} input shared by every delete method.
struct IdScope {
    ProjectId text @0
    Id        text @8
}

# KeyCreateParams mirrors CreateLlmApiKey. SecretKey is the PLAINTEXT provider
# credential on the wire (the channel is the ZAP transport; the secret is
# encrypted with AES-256-GCM the instant it lands, before any DB write).
# ExtraHeaders / CustomModels / Config are JSON-encoded text blobs (the tRPC
# model stored opaque JSON columns for these).
struct KeyCreateParams {
    ProjectId         text @0
    Provider          text @8
    Adapter           text @16
    SecretKey         text @24   # plaintext in; encrypted at rest
    BaseURL           text @32
    WithDefaultModels bool @40
    CustomModels      text @44   # JSON array
    Config            text @52   # JSON object
    ExtraHeaders      text @60   # JSON object
}

# KeyUpdateParams mirrors UpdateLlmApiKey: id + same shape, secretKey OPTIONAL
# (empty = keep existing). Provider/adapter are immutable; the server rejects a
# change. HasSecretKey distinguishes "rotate to empty" from "leave unchanged".
struct KeyUpdateParams {
    ProjectId         text @0
    Id                text @8
    Provider          text @16
    Adapter           text @24
    HasSecretKey      bool @32   # false => keep existing secret
    SecretKey         text @36
    BaseURL           text @44
    WithDefaultModels bool @52
    CustomModels      text @56   # JSON array
    Config            text @64   # JSON object
    ExtraHeaders      text @72   # JSON object
}

# KeyTestParams mirrors the `test` procedure input (a transient connection
# check; no persistence). Same provider shape as create, minus DB-only fields.
struct KeyTestParams {
    ProjectId    text @0
    Provider     text @8
    Adapter      text @16
    SecretKey    text @24
    BaseURL      text @32
    CustomModels text @40   # JSON array
    Config       text @48   # JSON object
    ExtraHeaders text @56   # JSON object
}

# NamedDocParams mirrors CreateLlmSchemaInput / CreateLlmToolInput — a
# name+description+JSON-body document scoped to a project. `Body` carries the
# `schema` (schemas) or `parameters` (tools) JSON verbatim; the two routers are
# structurally identical, so they share one params struct (DRY).
struct NamedDocParams {
    ProjectId   text @0
    Name        text @8
    Description text @16
    Body        text @24   # JSON: schema | parameters
}

# NamedDocUpdate mirrors UpdateLlmSchemaInput / UpdateLlmToolInput: NamedDoc + id.
struct NamedDocUpdate {
    ProjectId   text @0
    Id          text @8
    Name        text @16
    Description text @24
    Body        text @32   # JSON: schema | parameters
}

# ModelConfigParams mirrors UpdateModelConfigInput: per-project model defaults.
struct ModelConfigParams {
    ProjectId    text @0
    DefaultModel text @8
    Temperature  f64  @16
    MaxTokens    i64  @24
}

# ─── Response bodies ──────────────────────────────────────────────────────────

# MutationResult is the {success:true} every delete returns. A distinct, tiny
# body so callers (and the pipeline join) have a typed ack.
struct MutationResult {
    Success bool @0
}

# LlmApiKeyRef is the safe handle returned by keyCreate/keyUpdate: identifying
# fields only — NEVER the secret. DisplaySecretKey is the masked "...abcd" tail,
# exactly as the tRPC model exposed.
struct LlmApiKeyRef {
    Id               text @0
    ProjectId        text @8
    Provider         text @16
    Adapter          text @24
    DisplaySecretKey text @32
    BaseURL          text @40
}

# LlmApiKeyView is one row in keyAll's list — the SafeLlmApiKey projection
# (no secretKey, no extraHeaders values; only the masked display + metadata).
# AuthMethod is the Bedrock-derived enum string (empty for non-Bedrock).
struct LlmApiKeyView {
    Id               text       @0
    ProjectId        text       @8
    Provider         text       @16
    Adapter          text       @24
    DisplaySecretKey text       @32
    BaseURL          text       @40
    WithDefaultModels bool      @48
    CustomModels     list<text> @52   # plaintext list of model ids
    ExtraHeaderKeys  list<text> @60   # KEYS only — values stay encrypted
    AuthMethod       text       @68
    CreatedAt        text       @76
    UpdatedAt        text       @84
}

# LlmApiKeyList is keyAll's body: the safe rows + a total count (the tRPC
# `{data, totalCount}` shape).
struct LlmApiKeyList {
    Data       list<LlmApiKeyView> @0
    TotalCount i64                 @8
}

# TestResult mirrors the {success, error} testLLMConnection return.
struct TestResult {
    Success bool @0
    Error   text @4
}

# LlmDocRef is the handle returned by schema/tool create+update: the stored
# document echoed back (id + name + description + body + timestamps). Shared by
# both routers since the row shapes are identical.
struct LlmDocRef {
    Id          text @0
    ProjectId   text @8
    Name        text @16
    Description text @24
    Body        text @32   # JSON: schema | parameters
    CreatedAt   text @40
    UpdatedAt   text @48
}

# LlmDocList is schema/tool getAll's body: the documents, ordered updatedAt desc.
struct LlmDocList {
    Data list<LlmDocRef> @0
}

# CloudModelView is one entry from the Cloud model registry (GET /api/models).
struct CloudModelView {
    Id      text @0
    Object  text @8
    Created i64  @16
    OwnedBy text @24
    Premium bool @32
}

# CloudModelList is modelList's body — the registry rows.
struct CloudModelList {
    Object text                 @0
    Data   list<CloudModelView> @8
}

# ModelConfig mirrors the per-project ModelConfig (get/set both return it).
struct ModelConfig {
    ProjectId    text @0
    DefaultModel text @8
    Temperature  f64  @16
    MaxTokens    i64  @24
}
