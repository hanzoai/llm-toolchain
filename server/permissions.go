package server

// LLMTCPermissions — the u64 Permissions bitmask a CapKindIAMSession capability
// carries for THIS service. One read bit + one write bit per category, so an
// IAM-issued session cap can grant, say, schema+tool read without key write.
// This is the policy surface the single chokepoint requirePermission gates on;
// the console mints caps whose bits mirror the old per-procedure RBAC scopes
// (llmApiKeys:read → PermKeyRead, llmSchemas:CUD → PermSchemaWrite, …).
const (
	PermKeyRead     uint64 = 1 << 0 // read LLM API keys (safe projection; never the secret)
	PermKeyWrite    uint64 = 1 << 1 // create/update/delete LLM API keys
	PermSchemaRead  uint64 = 1 << 2 // read LLM schemas
	PermSchemaWrite uint64 = 1 << 3 // create/update/delete LLM schemas
	PermToolRead    uint64 = 1 << 4 // read LLM tools
	PermToolWrite   uint64 = 1 << 5 // create/update/delete LLM tools
	PermModelRead   uint64 = 1 << 6 // read cloud model registry + per-project config
	PermModelWrite  uint64 = 1 << 7 // write per-project model config
)

// PermAll is every bit — the bootstrap/admin grant a synthetic cap holds in
// tests and the out-of-process probe.
const PermAll uint64 = PermKeyRead | PermKeyWrite |
	PermSchemaRead | PermSchemaWrite |
	PermToolRead | PermToolWrite |
	PermModelRead | PermModelWrite

// methodPermission maps each method ordinal to the single permission bit it
// requires. The dispatch path consults this once (requirePermission) before any
// collection access — verification of policy is one function in one place,
// disjoint from the methods, which stay in their lane (decomplected).
var methodPermission = map[uint32]uint64{
	MethodKeyCreate: PermKeyWrite,
	MethodKeyAll:    PermKeyRead,
	MethodKeyUpdate: PermKeyWrite,
	MethodKeyDelete: PermKeyWrite,
	MethodKeyTest:   PermKeyRead,

	MethodSchemaCreate: PermSchemaWrite,
	MethodSchemaGetAll: PermSchemaRead,
	MethodSchemaUpdate: PermSchemaWrite,
	MethodSchemaDelete: PermSchemaWrite,

	MethodToolCreate: PermToolWrite,
	MethodToolGetAll: PermToolRead,
	MethodToolUpdate: PermToolWrite,
	MethodToolDelete: PermToolWrite,

	MethodModelList:      PermModelRead,
	MethodModelGetConfig: PermModelRead,
	MethodModelSetConfig: PermModelWrite,
}
