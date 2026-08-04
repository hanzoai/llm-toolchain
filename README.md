# llm-toolchain

A Hanzo Base-native Go service binary that replaces **four** console tRPC routers
with native ZAP capability RPC:

| tRPC router | → ZAP methods |
|---|---|
| `llmApiKeyRouter` | `keyCreate @0`, `keyAll @1`, `keyUpdate @2`, `keyDelete @3`, `keyTest @4` |
| `llmSchemaRouter` | `schemaCreate @5`, `schemaGetAll @6`, `schemaUpdate @7`, `schemaDelete @8` |
| `llmToolRouter` | `toolCreate @9`, `toolGetAll @10`, `toolUpdate @11`, `toolDelete @12` |
| `cloudModelsRouter` | `modelList @13`, `modelGetConfig @14`, `modelSetConfig @15` |

One of the parallel service-binary builds in the console tRPC→ZAP migration.
Cloned from the `ui-customization` reference template.

## Wire contract

`proto/llm-toolchain.zap` (zap-spec dialect, **not** capnp) is the single
byte-for-byte contract. `make zap-gen` compiles it to Go views in `gen/`; the
console copies the same file and compiles it with `zapgen --target=ts`. The
transport carries typed views as opaque bytes — data fully separate from place.

- **Transport**: `github.com/luxfi/zap` node, `msgType 205`, port **9994**.
- **Envelope**: `(Method, PromiseID, Target, Cap, Payload)` → `(Status, PromiseID, Body)`.
- **Capability**: opaque `zap-proto/go` `CapKindIAMSession` buffer, re-`Wrap`ped
  and verified server-side on every call.

## Capability permissions (`LLMTCPermissions`)

One read + one write bit per category; the single chokepoint
`Server.authorize` gates each method on `methodPermission[method]`:

| bit | grants |
|---|---|
| `PermKeyRead 1<<0` / `PermKeyWrite 1<<1` | LLM API keys |
| `PermSchemaRead 1<<2` / `PermSchemaWrite 1<<3` | LLM schemas |
| `PermToolRead 1<<4` / `PermToolWrite 1<<5` | LLM tools |
| `PermModelRead 1<<6` / `PermModelWrite 1<<7` | cloud models |

## Secrets at rest

LLM provider credentials (`secretKey`, `extraHeaders`) are **encrypted at rest**
with `SecretBox` — AES-256-GCM under an org-derived DEK (the same HMAC key ladder
as the Base vault plugin). Plaintext is never stored and never returned: `keyAll`
exposes only the masked `displaySecretKey`, the header KEY names, and the
Bedrock-derived auth-method enum. `TestSecretEncryptedAtRest` proves this by
scanning the on-disk SQLite files for the plaintext.

## Pipelining

Cap'n Proto-style promise pipelining (`PromiseID` + `Target`): a `create` call
resolves the new row's id + org, and a dependent call shipped on a second
connection (`Target` = create's `PromiseID`) is held server-side until the
promise resolves, then dispatched against the inherited org — no intermediate
round trip. `Client.PipelineCreateThenList` + `TestPipeliningCreateThenList`
demonstrate and prove the create-then-use chain.

## Build & test

```sh
make zap-gen   # regenerate gen/ from the .zap schema (idempotent)
make build     # CGO_ENABLED=0 GOWORK=off, pure-Go reproducible binary
make test      # in-process ZAP RPC + pipelining + at-rest suite
make run       # serve HTTP :8090 + ZAP :9994
make probe     # build the out-of-process smoke probe
```

The binary is **CI-built** (multi-arch, hanzoai self-hosted runners →
`ghcr.io/hanzoai/llm-toolchain`). Do not build images locally.

## Configuration

| flag / env | default | purpose |
|---|---|---|
| `--zap` / `ZAP_ADDR` | `127.0.0.1:9994` | typed ZAP listener |
| `--org` / `LLM_TOOLCHAIN_ORG` | `default` | default org scope |
| `--vaultDir` / `VAULT_DIR` | (unset) | enables per-org encrypted SQLite shards |
| `VAULT_MASTER_KEY` | (ephemeral) | 32-byte master KEK (from KMS in prod) |

MIT OR Apache-2.0, at your option — see [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
