package server

import (
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/hook"
)

// Collection names — the four Base collections backing this service, one per
// migrated tRPC router's persisted model. All rows carry `org` (scoped from the
// verified capability) and `projectId` (the data-isolation key the routers used).
const (
	CollLlmApiKey = "llm_api_key"  // llmApiKeyRouter  — secretKey ENCRYPTED at rest
	CollLlmSchema = "llm_schema"   // llmSchemaRouter
	CollLlmTool   = "llm_tool"     // llmToolRouter
	CollModelCfg  = "model_config" // cloudModelsRouter (per-project config only)
)

// LlmApiKey field names. `secretKeyEnc` holds AES-256-GCM ciphertext (base64) —
// NEVER plaintext (CLAUDE.md: never store secrets in plaintext). `extraHeaders`
// is likewise encrypted; `extraHeaderKeys` stores only the KEY names (safe to
// return). `displaySecretKey` is the masked tail the UI shows.
const (
	fOrg               = "org"
	fProjectId         = "projectId"
	fProvider          = "provider"
	fAdapter           = "adapter"
	fSecretKeyEnc      = "secretKeyEnc" // base64(AES-256-GCM)
	fDisplaySecretKey  = "displaySecretKey"
	fBaseURL           = "baseURL"
	fWithDefaultModels = "withDefaultModels"
	fCustomModels      = "customModels"    // JSON array
	fConfig            = "config"          // JSON object
	fExtraHeadersEnc   = "extraHeadersEnc" // base64(AES-256-GCM) of JSON object
	fExtraHeaderKeys   = "extraHeaderKeys" // JSON array of key names (safe)
)

// Shared document field names (schemas + tools have identical shapes).
const (
	fName        = "name"
	fDescription = "description"
	fBody        = "body" // JSON: schema (schemas) | parameters (tools)
)

// Model-config field names (per-project model defaults).
const (
	fDefaultModel = "defaultModel"
	fTemperature  = "temperature"
	fMaxTokens    = "maxTokens"
)

// RegisterCollections ensures all four collections exist before the ZAP
// listener accepts calls. Idempotent: re-running finds existing collections and
// no-ops. Wired via OnBootstrap so it runs once at startup.
func RegisterCollections(app core.App) {
	app.OnBootstrap().Bind(&hook.Handler[*core.BootstrapEvent]{
		Id: "llmToolchainCollections",
		Func: func(e *core.BootstrapEvent) error {
			if err := e.Next(); err != nil {
				return err
			}
			return EnsureCollections(app)
		},
	})
}

// EnsureCollections creates any missing collection. Exported so tests and
// one-shot migrations can provision directly rather than via OnBootstrap.
// Idempotent.
func EnsureCollections(app core.App) error {
	if err := ensureLlmApiKey(app); err != nil {
		return err
	}
	if err := ensureNamedDoc(app, CollLlmSchema, "idx_llm_schema"); err != nil {
		return err
	}
	if err := ensureNamedDoc(app, CollLlmTool, "idx_llm_tool"); err != nil {
		return err
	}
	return ensureModelConfig(app)
}

func ensureLlmApiKey(app core.App) error {
	if _, err := app.FindCollectionByNameOrId(CollLlmApiKey); err == nil {
		return nil
	}
	col := core.NewBaseCollection(CollLlmApiKey)
	col.Fields.Add(&core.TextField{Name: fOrg, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fProjectId, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fProvider, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fAdapter, Required: true, Max: 64})
	// secretKeyEnc / extraHeadersEnc are base64 AES-256-GCM ciphertext — large
	// enough for a JSON-credential blob's ciphertext.
	col.Fields.Add(&core.TextField{Name: fSecretKeyEnc, Max: 65536})
	col.Fields.Add(&core.TextField{Name: fDisplaySecretKey, Max: 255})
	col.Fields.Add(&core.TextField{Name: fBaseURL, Max: 2048})
	col.Fields.Add(&core.BoolField{Name: fWithDefaultModels})
	col.Fields.Add(&core.JSONField{Name: fCustomModels, MaxSize: 65536})
	col.Fields.Add(&core.JSONField{Name: fConfig, MaxSize: 65536})
	col.Fields.Add(&core.TextField{Name: fExtraHeadersEnc, Max: 65536})
	col.Fields.Add(&core.JSONField{Name: fExtraHeaderKeys, MaxSize: 65536})
	col.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	col.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	col.AddIndex("idx_llm_api_key_project", false, fProjectId, "")
	return app.Save(col)
}

// ensureNamedDoc provisions a schema/tool collection. Both are
// {org,projectId,name,description,body}; the tRPC unique constraint was
// (projectId,name), so we mirror it as a unique composite index.
func ensureNamedDoc(app core.App, name, idxPrefix string) error {
	if _, err := app.FindCollectionByNameOrId(name); err == nil {
		return nil
	}
	col := core.NewBaseCollection(name)
	col.Fields.Add(&core.TextField{Name: fOrg, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fProjectId, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fName, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fDescription, Max: 4096})
	col.Fields.Add(&core.JSONField{Name: fBody, MaxSize: 1 << 20})
	col.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	col.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	// Unique per (projectId, name) — mirrors the Prisma projectId_name constraint.
	col.AddIndex(idxPrefix+"_proj_name", true, fProjectId+", "+fName, "")
	return app.Save(col)
}

func ensureModelConfig(app core.App) error {
	if _, err := app.FindCollectionByNameOrId(CollModelCfg); err == nil {
		return nil
	}
	col := core.NewBaseCollection(CollModelCfg)
	col.Fields.Add(&core.TextField{Name: fOrg, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fProjectId, Required: true, Max: 255})
	col.Fields.Add(&core.TextField{Name: fDefaultModel, Max: 255})
	col.Fields.Add(&core.NumberField{Name: fTemperature})
	col.Fields.Add(&core.NumberField{Name: fMaxTokens})
	col.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	col.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	// One config row per (org, projectId).
	col.AddIndex("idx_model_config_proj", true, fOrg+", "+fProjectId, "")
	return app.Save(col)
}
