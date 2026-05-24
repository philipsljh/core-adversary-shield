// oracle_signer.go
// Ed25519 Oracle Signer - Stateless Signing Component
// Used for signing heartbeat verification, rebind tickets, and other core business signatures
// Private key is read from environment variable, never hardcoded

package middleware

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// ============================================================================
// Global Key State (loaded once at startup, read-only thereafter)
// ============================================================================

var (
	// oraclePrivateKey in-memory private key, locked at runtime, never distributed
	oraclePrivateKey ed25519.PrivateKey
	oraclePublicKey  ed25519.PublicKey
	oracleInitOnce   sync.Once
	oracleInitErr    error
)

// ============================================================================
// Signing Payload Structure
// ============================================================================

// OraclePayload defines the concatenation order for signing payloads
type OraclePayload struct {
	Username   string
	Nonce      string
	ExpireTime int64
	ScriptHash string
}

// String concatenates the payload into a standard compact byte stream
// Format: "username|nonce|expire_timestamp|script_hash"
func (p *OraclePayload) String() string {
	return fmt.Sprintf("%s|%s|%d|%s", p.Username, p.Nonce, p.ExpireTime, p.ScriptHash)
}

// ============================================================================
// Initialization and Key Loading
// ============================================================================

// initOracleKeys loads Ed25519 key pair from environment variable
// Production requires RXXL_ED25519_PRIVATE_KEY, dev mode generates temp keys
func initOracleKeys() {
	privStr := os.Getenv("RXXL_ED25519_PRIVATE_KEY")

	if privStr == "" {
		isDevMode := os.Getenv("RXXL_DEV_MODE") == "1"

		if isDevMode {
			slog.Warn("[Oracle] DEVELOPMENT MODE - Using temporary Ed25519 key pair",
				"warning", "DO NOT deploy to production",
				"risk", "Keys regenerated on each restart")
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				slog.Error("[Oracle] FATAL: temp key generation failed", "error", err)
				oracleInitErr = fmt.Errorf("temp key generation failed: %v", err)
				return
			}
			oraclePrivateKey = priv
			oraclePublicKey = pub
			slog.Info("[Oracle] Ed25519 signer ready (temp key, dev mode)",
				"public_key", base64.StdEncoding.EncodeToString(oraclePublicKey))
			return
		}

		slog.Error("[Oracle] FATAL: RXXL_ED25519_PRIVATE_KEY required in production. " +
			"Set RXXL_DEV_MODE=1 for development.")
		oracleInitErr = fmt.Errorf("RXXL_ED25519_PRIVATE_KEY required in production")
		return
	}

	privBytes, err := base64.StdEncoding.DecodeString(privStr)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		slog.Error("[Oracle] FATAL: private key decode failed",
			"error", err,
			"key_len", len(privBytes),
			"expected_len", ed25519.PrivateKeySize)
		oracleInitErr = fmt.Errorf("private key load failed: %v", err)
		return
	}

	oraclePrivateKey = ed25519.PrivateKey(privBytes)
	oraclePublicKey = oraclePrivateKey.Public().(ed25519.PublicKey)
	slog.Info("[Oracle] Ed25519 signer ready (key from env)",
		"public_key", base64.StdEncoding.EncodeToString(oraclePublicKey))
}

// GetOraclePublicKey returns the current public key as Base64 encoded string
func GetOraclePublicKey() string {
	oracleInitOnce.Do(initOracleKeys)
	if oraclePublicKey == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(oraclePublicKey)
}

// ============================================================================
// Core Signing Functions
// ============================================================================

// SignOracle signs a specified payload using Ed25519
// Returns Base64 encoded signature
func SignOracle(username, nonce string, expireTime int64, scriptHash string) (string, error) {
	oracleInitOnce.Do(initOracleKeys)
	if oracleInitErr != nil {
		return "", fmt.Errorf("oracle signer not ready: %v", oracleInitErr)
	}

	if username == "" || nonce == "" || scriptHash == "" {
		return "", fmt.Errorf("signing parameters cannot be empty")
	}

	if expireTime <= 0 {
		return "", fmt.Errorf("invalid expiration timestamp: %d", expireTime)
	}

	payload := &OraclePayload{
		Username:   username,
		Nonce:      nonce,
		ExpireTime: expireTime,
		ScriptHash: scriptHash,
	}
	payloadBytes := []byte(payload.String())

	signature := ed25519.Sign(oraclePrivateKey, payloadBytes)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyOracle verifies an Ed25519 signature
func VerifyOracle(username, nonce string, expireTime int64, scriptHash, signatureBase64 string) bool {
	oracleInitOnce.Do(initOracleKeys)
	if oraclePublicKey == nil {
		slog.Error("[Oracle] Verify failed: public key not initialized")
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		slog.Warn("[Oracle] Verify failed: invalid signature format",
			"error", err,
			"sig_len", len(signature),
			"expected_len", ed25519.SignatureSize)
		return false
	}

	payload := &OraclePayload{
		Username:   username,
		Nonce:      nonce,
		ExpireTime: expireTime,
		ScriptHash: scriptHash,
	}
	payloadBytes := []byte(payload.String())

	return ed25519.Verify(oraclePublicKey, payloadBytes, signature)
}

// ============================================================================
// Log Sanitization Helpers
// ============================================================================

// maskString sanitizes a string, keeping only the first n characters
func maskString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ============================================================================
// Startup Initialization
// ============================================================================

func init() {
	oracleInitOnce.Do(initOracleKeys)
}
