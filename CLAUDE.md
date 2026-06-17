# CLAUDE.md — contract for AI helpers

A Hanzo Base-native Go service binary: the LLM toolchain. Replaces four console
tRPC routers (LLM api-keys / schemas / tools / cloud-models) with native ZAP
capability RPC. Cloned from the `ui-customization` reference template; keep it
lean and consistent with that pattern.

## The one rule

**The `.zap` schema is the source of truth.** `proto/llm-toolchain.zap` defines
the data structs; `gen/` is its Go projection via `make zap-gen`. Never
hand-edit `gen/`. Change the schema, regenerate, then update `server/`.

## Two schema dialects (do not conflate)

- `proto/llm-toolchain.zap` is the **zap-spec dialect** (`package … /
  Field Type @off`) that `github.com/zap-proto/go/cmd/zapgen` compiles to Go.
  This is what THIS repo (a Go service) consumes.
- The console keeps a copy compiled with `zapgen --target=ts` to TS View/Builder
  classes. Same file, two code targets; the field set is the shared contract.
  No capnp on either side.

## Build / test

- Pure-Go always: `CGO_ENABLED=0`. CGO pulls blst/accel C deps that need a full
  toolchain and break reproducibility. `make` sets this + `GOWORK=off`.
- `GOWORK=off`: this repo is self-contained via go.mod `replace`s; a parent
  `go.work` must not capture it.
- `make zap-gen` and `make build` are **idempotent** (byte-identical regen,
  reproducible binary). Keep them so — no timestamps/paths in generated output.
- `make test` runs the in-process ZAP RPC + permission + pipelining + at-rest
  suite. Show it passing; don't claim "done" without it.

## Architecture invariants (DRY, orthogonal, decomplected)

- **Three wire layers, separated:** transport (`luxfi/zap` Node, msgType 205) /
  envelope (`server/wire.go`) / payload (`gen/` typed views). The capability is
  carried as OPAQUE bytes through all three — auth is a value, not a place.
- **One auth chokepoint:** `Server.authorize`. Kind + the per-method permission
  bit (`methodPermission`) always enforced; signature verify gated on a wired
  issuer registry. Do not scatter permission checks into the method handlers.
- **Secrets encrypted at rest:** LLM credentials go through `SecretBox`
  (AES-256-GCM, org-derived DEK — the Base vault key ladder lifted as a value).
  Plaintext is never stored and never returned. `keyAll` is the SafeLlmApiKey
  projection only. `TestSecretEncryptedAtRest` scans the on-disk db to prove it.
- **One backend:** Hanzo Base. No Prisma, Postgres-as-source-of-truth, Mongo,
  Redis, tRPC, nginx, capnp. Data lives in four Base collections
  (`llm_api_key`, `llm_schema`, `llm_tool`, `model_config`).
- **Schema/tool handlers are shared:** the two routers are structurally
  identical, so `docCreate/docGetAll/docUpdate/docDelete` serve both ordinals.
- **Pipelining is real:** a dependent call can target a `create`'s promise; the
  server's promise table (`await`/`resolve`) joins them, the dependent call
  inheriting the resolved org + id. Genuine in-flight pipelining needs the two
  calls on SEPARATE connections (the transport is FIFO per connection) — see
  `Client.PipelineCreateThenList` and the pipelining test.

## Known follow-ups (not blockers)

- `keyTest` validates request shape only; the live `fetchLLMCompletion` probe and
  `cloudModelsRouter.list` Cloud/pricing fan-out are console-runtime concerns
  that belong in a model-gateway sidecar this service calls. Both honor the
  original tRPC empty/typed-result contract.

## Do not

- Build Docker images locally (CI does, multi-arch → ghcr.io/hanzoai).
- Push to GitHub from here unless asked.
- Add plugins this one service doesn't need. Lean binary.
- Touch the console — wiring is documented in README, not done here.
