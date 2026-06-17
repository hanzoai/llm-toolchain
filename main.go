// Command llm-toolchain is a Hanzo Base-native Go service binary: a typed ZAP
// capability-RPC backend for the LLM toolchain, built on Hanzo Base (embedded
// SQLite + plugins). It replaces FOUR console in-process tRPC routers —
// llmApiKeyRouter, llmSchemaRouter, llmToolRouter, cloudModelsRouter — with
// native capability RPC.
//
// Architecture (the reference pattern the parallel service-binary builds share):
//
//	base.New()                    → Base app: embedded SQLite, hooks, migrations
//	  ├── vault (optional)        → per-org encrypted SQLite shard (KEK)
//	  ├── server.RegisterColls    → the four backing collections
//	  └── server.Register(node)   → THIS service's typed router (msgType 205)
//	apis.NewRouter(app)           → sidecar HTTP (health/metrics), NOT app data
//	app.Start()                   → serves HTTP :8090 + ZAP :9994
//
// LLM API key secrets are encrypted at rest (SecretBox, AES-256-GCM under an
// org-derived DEK) before any DB write — CLAUDE.md: never store secrets in
// plaintext. The master KEK comes from KMS in production.
//
// The .zap schema (proto/) is the source of truth; gen/ is its Go projection.
package main

import (
	"crypto/rand"
	"log"
	"os"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/plugins/vault"
	"github.com/hanzoai/base/tools/hook"
	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	zcap "github.com/zap-proto/go/cap"

	"github.com/hanzoai/llm-toolchain/server"
)

func main() {
	app := base.New()

	var zapAddr string
	app.RootCmd.PersistentFlags().StringVar(&zapAddr, "zap", envOr("ZAP_ADDR", "127.0.0.1:9994"),
		"address for the typed ZAP capability-RPC listener")

	var defaultOrg string
	app.RootCmd.PersistentFlags().StringVar(&defaultOrg, "org", envOr("LLM_TOOLCHAIN_ORG", "default"),
		"default organization scope when a capability carries no org binding")

	var vaultDir string
	app.RootCmd.PersistentFlags().StringVar(&vaultDir, "vaultDir", os.Getenv("VAULT_DIR"),
		"directory for per-org encrypted SQLite shards (enables the vault plugin)")

	app.RootCmd.ParseFlags(os.Args[1:])

	master := masterKey()

	// Optional: per-org encrypted SQLite backing via the vault plugin. The
	// SecretBox (LLM-key encryption below) uses the SAME master KEK + key ladder,
	// so the vault plugin and this service's at-rest encryption share one trust
	// anchor. Enabled only when --vaultDir is set so local dev stays single-file.
	if vaultDir != "" {
		vault.MustRegister(app, vault.Config{
			Enabled:   true,
			DataDir:   vaultDir,
			OrgID:     defaultOrg,
			MasterKey: master,
		})
	}

	// SecretBox: at-rest encryption for LLM provider credentials. Fail loudly at
	// boot if the master key is the wrong length — sensitive data must not be
	// stored unencrypted.
	secrets, err := server.NewSecretBox(master, defaultOrg)
	if err != nil {
		log.Fatal("llm-toolchain: secret box: ", err)
	}

	// Ensure the four backing collections exist.
	server.RegisterCollections(app)

	// Stand up the typed ZAP router alongside Base's serve lifecycle. A dedicated
	// luxfi/zap node (NoDiscovery: direct dial only — discovery is the gateway's
	// job, not mDNS here).
	logger := luxlog.New("component", "llm-toolchain")
	node := zaplib.NewNode(zaplib.NodeConfig{
		NodeID:      "llm-toolchain",
		Port:        portOf(zapAddr),
		NoDiscovery: true,
	})

	// Verifier: bootstrap (ed25519, no issuer registry → Kind+Permissions
	// enforced, signature step skipped). Wire IssuerKey to the IAM pubkey
	// registry to enable full cryptographic verification.
	srv := server.NewServer(app, logger, defaultOrg, secrets, zcap.Verifier{})
	srv.Register(node)

	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Id: "llmToolchainZapNode",
		Func: func(e *core.ServeEvent) error {
			if err := e.Next(); err != nil {
				return err
			}
			if err := node.Start(); err != nil {
				return err
			}
			logger.Info("llm-toolchain ZAP router listening", "addr", zapAddr, "msgType", server.MsgTypeRouterBase)
			return nil
		},
	})
	app.OnTerminate().Bind(&hook.Handler[*core.TerminateEvent]{
		Id: "llmToolchainZapNodeStop",
		Func: func(e *core.TerminateEvent) error {
			node.Stop()
			return e.Next()
		},
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// masterKey returns the 32-byte master KEK: from VAULT_MASTER_KEY (raw 32 bytes)
// in production (sourced from KMS), else a process-ephemeral random key for dev
// (throwaway data — shards/secrets won't survive a restart, which is correct
// for local dev).
func masterKey() []byte {
	if v := os.Getenv("VAULT_MASTER_KEY"); len(v) >= 32 {
		return []byte(v)[:32]
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// portOf extracts the port from a host:port address, defaulting to 9994.
func portOf(addr string) int {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p := 0
			for _, c := range addr[i+1:] {
				if c < '0' || c > '9' {
					return 9994
				}
				p = p*10 + int(c-'0')
			}
			if p == 0 {
				return 9994
			}
			return p
		}
	}
	return 9994
}
