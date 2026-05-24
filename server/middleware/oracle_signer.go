// oracle_signer.go
// Ed25519 Oracle Signer - Stateless Signing Component
//
// This module implements the blind oracle digital signature mechanism
// for policy verification and session attestation.
//
// Private key is read from environment variable, never hardcoded.
// All sensitive material is subject to garbage collection after use.

package middleware

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"runtime"
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
// Format: "identifier|nonce|expire_timestamp|resource_hash"
type OraclePayload struct {
	Identifier   string
	Nonce        string
	ExpireTime   int64
	ResourceHash string
}

// String concatenates the payload into a standard compact byte stream
// Format: "identifier|nonce|expire_timestamp|resource_hash"
func (p *OraclePayload) String() string {
	return fmt.Sprintf("%s|%s|%d|%s", p.Identifier, p.Nonce, p.ExpireTime, p.ResourceHash)
}

// ============================================================================
// Initialization and Key Loading
// ============================================================================

// initOracleKeys loads Ed25519 key pair from environment variable
// Production requires POLICY_SERVER_ED25519_PRIVATE_KEY, dev mode generates temp keys
func initOracleKeys() {
	privStr := os.Getenv("POLICY_SERVER_ED25519_PRIVATE_KEY")

	if privStr == "" {
		isDevMode := os.Getenv("POLICY_SERVER_DEV_MODE") == "1"

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

		slog.Error("[Oracle] FATAL: POLICY_SERVER_ED25519_PRIVATE_KEY required in production. " +
			"Set POLICY_SERVER_DEV_MODE=1 for development.")
		oracleInitErr = fmt.Errorf("POLICY_SERVER_ED25519_PRIVATE_KEY required in production")
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
//
// Memory Ephemeral Principle:
// All intermediate byte slices are subject to garbage collection after use.
// Production deployments should consider using explicit memory wiping for
// compliance with high-security requirements.
func SignOracle(identifier, nonce string, expireTime int64, resourceHash string) (string, error) {
	oracleInitOnce.Do(initOracleKeys)
	if oracleInitErr != nil {
		return "", fmt.Errorf("oracle signer not ready: %v", oracleInitErr)
	}

	if identifier == "" || nonce == "" || resourceHash == "" {
		return "", fmt.Errorf("signing parameters cannot be empty")
	}

	if expireTime <= 0 {
		return "", fmt.Errorf("invalid expiration timestamp: %d", expireTime)
	}

	payload := &OraclePayload{
		Identifier:   identifier,
		Nonce:        nonce,
		ExpireTime:   expireTime,
		ResourceHash: resourceHash,
	}
	payloadBytes := []byte(payload.String())

	signature := ed25519.Sign(oraclePrivateKey, payloadBytes)

	// Memory Ephemeral: clear payload bytes after signing
	for i := range payloadBytes {
		payloadBytes[i] = 0
	}
	runtime.GC() // Trigger garbage collection for sensitive material

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyOracle verifies an Ed25519 signature
func VerifyOracle(identifier, nonce string, expireTime int64, resourceHash, signatureBase64 string) bool {
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
		Identifier:   identifier,
		Nonce:        nonce,
		ExpireTime:   expireTime,
		ResourceHash: resourceHash,
	}
	payloadBytes := []byte(payload.String())

	result := ed25519.Verify(oraclePublicKey, payloadBytes, signature)

	// Memory Ephemeral: clear payload bytes after verification
	for i := range payloadBytes {
		payloadBytes[i] = 0
	}

	return result
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
