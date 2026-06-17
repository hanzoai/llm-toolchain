package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// SecretBox encrypts LLM provider credentials at rest. It is the SAME
// AES-256-GCM + HMAC key-ladder the Base vault plugin uses (UserShard.Encrypt /
// deriveOrgKEK / deriveUserDEK), lifted here as a VALUE rather than coupled to
// the vault plugin's unexported *plugin type: the secret-at-rest primitive is
// "AES-256-GCM under an org-derived DEK", and that primitive lives wherever it
// is needed. One construction, one place.
//
//	Master KEK (from KMS in prod; env/ephemeral in dev)
//	  └── Org KEK = HMAC-SHA256(master, "vault:org:"  + orgID)
//	        └── DEK = HMAC-SHA256(orgKEK, "vault:llmtc:secret")
//	              └── per-secret AES-256-GCM, random 12-byte nonce (prepended)
//
// The DEK label is service-scoped ("vault:llmtc:secret") so the same master KEK
// yields a key distinct from any other Base vault consumer for the same org —
// compromise containment without a separate master.
type SecretBox struct {
	dek []byte // 32-byte data encryption key (AES-256)
}

// NewSecretBox derives the LlmToolchain secret DEK from the master KEK and org.
// masterKey MUST be 32 bytes — the same invariant the vault plugin enforces
// (vault.Config.validate). Returns an error rather than panicking so the caller
// (main) fails loudly at boot with a clear message.
func NewSecretBox(masterKey []byte, orgID string) (*SecretBox, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("secretbox: masterKey must be 32 bytes, got %d", len(masterKey))
	}
	if orgID == "" {
		return nil, fmt.Errorf("secretbox: orgID is required")
	}
	orgKEK := hmacSum(masterKey, "vault:org:"+orgID)
	dek := hmacSum(orgKEK, "vault:llmtc:secret")
	return &SecretBox{dek: dek}, nil
}

// Seal encrypts plaintext and returns a base64-std string suitable for storage
// in a SQLite text column. Output = base64(nonce || AES-256-GCM ciphertext),
// byte-identical in scheme to vault UserShard.Encrypt.
func (s *SecretBox) Seal(plaintext string) (string, error) {
	gcm, err := s.gcm()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal: base64-decode, split nonce, AES-256-GCM open. Used only
// server-side (e.g. deriving the Bedrock auth-method enum) — the plaintext
// secret is never written back onto the wire.
func (s *SecretBox) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("secretbox: bad base64: %w", err)
	}
	gcm, err := s.gcm()
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("secretbox: ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("secretbox: open: %w", err)
	}
	return string(pt), nil
}

func (s *SecretBox) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func hmacSum(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// displaySecretKey returns the masked tail the tRPC model stored alongside the
// encrypted secret (getDisplaySecretKey in the console router): "...abcd", or a
// "...ab" trailing-quote variant for JSON-credential providers (Bedrock/Vertex
// stored a `{...}` blob). Sentinels for default cloud credentials map to a
// human label exactly as the console did.
func displaySecretKey(secretKey string) string {
	switch secretKey {
	case bedrockUseDefaultCredentials:
		return "Default AWS credentials"
	case vertexUseDefaultCredentials:
		return "Default GCP credentials (ADC)"
	}
	n := len(secretKey)
	if n >= 2 && secretKey[n-2:] == `"}` {
		if n >= 6 {
			return "..." + secretKey[n-6:n-2]
		}
		return "..." + secretKey
	}
	if n >= 4 {
		return "..." + secretKey[n-4:]
	}
	return "..." + secretKey
}

// bedrockAuthMethodFromSecret derives the SafeLlmApiKey authMethod enum exactly
// as the console did (getBedrockAuthMethod): only Bedrock keys carry it; the
// decrypted secret is inspected for shape, never returned. Empty string means
// "no auth method" (non-Bedrock, or unparseable).
func bedrockAuthMethodFromSecret(secret string) string {
	switch secret {
	case bedrockUseDefaultCredentials:
		return "default-credentials"
	}
	var m map[string]any
	if json.Unmarshal([]byte(secret), &m) == nil {
		if _, hasAPIKey := m["apiKey"]; hasAPIKey {
			return "api-key"
		}
		return "access-keys"
	}
	return ""
}

// Credential sentinels (mirrors @hanzo/shared BEDROCK_USE_DEFAULT_CREDENTIALS /
// VERTEXAI_USE_DEFAULT_CREDENTIALS): a stored secret equal to one of these
// means "use the platform's default cloud credentials" rather than a literal key.
const (
	bedrockUseDefaultCredentials = "__BEDROCK_USE_DEFAULT_CREDENTIALS__"
	vertexUseDefaultCredentials  = "__VERTEXAI_USE_DEFAULT_CREDENTIALS__"
)
