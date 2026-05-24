// oracle_signer.go
// CN: Ed25519 预言机签名器 - 无状态签名组件 | EN: Ed25519 Oracle Signer - Stateless Signing Component
//
// CN: 本模块实现了盲预言机数字签名机制，用于策略验证和会话证明。
// EN: This module implements the blind oracle digital signature mechanism for policy verification and session attestation.
//
// CN: 私钥从环境变量读取，绝不硬编码。
// EN: Private key is read from environment variable, never hardcoded.
// CN: 所有敏感材料在使用后都会进行垃圾回收。
// EN: All sensitive material is subject to garbage collection after use.

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
// CN: 全局密钥状态（启动时加载一次，此后只读）| EN: Global Key State (loaded once at startup, read-only thereafter)
// ============================================================================

var (
	// CN: oraclePrivateKey 内存私钥，运行时锁定，永不分发 | EN: oraclePrivateKey in-memory private key, locked at runtime, never distributed
	oraclePrivateKey ed25519.PrivateKey
	oraclePublicKey  ed25519.PublicKey
	oracleInitOnce   sync.Once
	oracleInitErr    error
)

// ============================================================================
// CN: 签名载荷结构体 | EN: Signing Payload Structure
// ============================================================================

// CN: OraclePayload 定义了签名载荷的拼接顺序
// EN: OraclePayload defines the concatenation order for signing payloads
// CN: 格式："identifier|nonce|expire_timestamp|resource_hash"
// EN: Format: "identifier|nonce|expire_timestamp|resource_hash"
type OraclePayload struct {
	Identifier   string
	Nonce        string
	ExpireTime   int64
	ResourceHash string
}

// CN: String 将载荷拼接为标准的紧凑字节流
// EN: String concatenates the payload into a standard compact byte stream
// CN: 格式："identifier|nonce|expire_timestamp|resource_hash"
// EN: Format: "identifier|nonce|expire_timestamp|resource_hash"
func (p *OraclePayload) String() string {
	return fmt.Sprintf("%s|%s|%d|%s", p.Identifier, p.Nonce, p.ExpireTime, p.ResourceHash)
}

// ============================================================================
// CN: 初始化和密钥加载 | EN: Initialization and Key Loading
// ============================================================================

// CN: initOracleKeys 从环境变量加载 Ed25519 密钥对
// EN: initOracleKeys loads Ed25519 key pair from environment variable
// CN: 生产环境需要 POLICY_SERVER_ED25519_PRIVATE_KEY，开发模式生成临时密钥
// EN: Production requires POLICY_SERVER_ED25519_PRIVATE_KEY, dev mode generates temp keys
func initOracleKeys() {
	privStr := os.Getenv("POLICY_SERVER_ED25519_PRIVATE_KEY")

	if privStr == "" {
		isDevMode := os.Getenv("POLICY_SERVER_DEV_MODE") == "1"

		if isDevMode {
			slog.Warn("[Oracle] CN: 开发模式 - 使用临时 Ed25519 密钥对 | EN: DEVELOPMENT MODE - Using temporary Ed25519 key pair",
				"warning", "CN: 请勿部署到生产环境 | EN: DO NOT deploy to production",
				"risk", "CN: 密钥在每次重启时重新生成 | EN: Keys regenerated on each restart")
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				slog.Error("[Oracle] FATAL: CN: 临时密钥生成失败 | EN: temp key generation failed", "error", err)
				oracleInitErr = fmt.Errorf("temp key generation failed: %v", err)
				return
			}
			oraclePrivateKey = priv
			oraclePublicKey = pub
			slog.Info("[Oracle] CN: Ed25519 签名器已就绪（临时密钥，开发模式）| EN: Ed25519 signer ready (temp key, dev mode)",
				"public_key", base64.StdEncoding.EncodeToString(oraclePublicKey))
			return
		}

		slog.Error("[Oracle] FATAL: CN: 生产环境需要 POLICY_SERVER_ED25519_PRIVATE_KEY。设置 POLICY_SERVER_DEV_MODE=1 用于开发。| EN: POLICY_SERVER_ED25519_PRIVATE_KEY required in production. Set POLICY_SERVER_DEV_MODE=1 for development.")
		oracleInitErr = fmt.Errorf("POLICY_SERVER_ED25519_PRIVATE_KEY required in production")
		return
	}

	privBytes, err := base64.StdEncoding.DecodeString(privStr)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		slog.Error("[Oracle] FATAL: CN: 私钥解码失败 | EN: private key decode failed",
			"error", err,
			"key_len", len(privBytes),
			"expected_len", ed25519.PrivateKeySize)
		oracleInitErr = fmt.Errorf("private key load failed: %v", err)
		return
	}

	oraclePrivateKey = ed25519.PrivateKey(privBytes)
	oraclePublicKey = oraclePrivateKey.Public().(ed25519.PublicKey)
	slog.Info("[Oracle] CN: Ed25519 签名器已就绪（从环境变量加载密钥）| EN: Ed25519 signer ready (key from env)",
		"public_key", base64.StdEncoding.EncodeToString(oraclePublicKey))
}

// CN: GetOraclePublicKey 返回当前公钥的 Base64 编码字符串
// EN: GetOraclePublicKey returns the current public key as Base64 encoded string
func GetOraclePublicKey() string {
	oracleInitOnce.Do(initOracleKeys)
	if oraclePublicKey == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(oraclePublicKey)
}

// ============================================================================
// CN: 核心签名函数 | EN: Core Signing Functions
// ============================================================================

// CN: SignOracle 使用 Ed25519 对指定载荷进行签名
// EN: SignOracle signs a specified payload using Ed25519
// CN: 返回 Base64 编码的签名
// EN: Returns Base64 encoded signature
//
// CN: 内存瞬态原则：
// EN: Memory Ephemeral Principle:
// CN: 所有中间字节切片在使用后都会进行垃圾回收。
// EN: All intermediate byte slices are subject to garbage collection after use.
// CN: 生产部署应考虑使用显式内存擦除以符合高安全要求。
// EN: Production deployments should consider using explicit memory wiping for compliance with high-security requirements.
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

	// CN: 内存瞬态：签名后清除载荷字节 | EN: Memory Ephemeral: clear payload bytes after signing
	for i := range payloadBytes {
		payloadBytes[i] = 0
	}
	runtime.GC() // CN: 触发垃圾回收以清理敏感材料 | EN: Trigger garbage collection for sensitive material

	return base64.StdEncoding.EncodeToString(signature), nil
}

// CN: VerifyOracle 验证 Ed25519 签名
// EN: VerifyOracle verifies an Ed25519 signature
func VerifyOracle(identifier, nonce string, expireTime int64, resourceHash, signatureBase64 string) bool {
	oracleInitOnce.Do(initOracleKeys)
	if oraclePublicKey == nil {
		slog.Error("[Oracle] CN: 验证失败：公钥未初始化 | EN: Verify failed: public key not initialized")
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		slog.Warn("[Oracle] CN: 验证失败：签名格式无效 | EN: Verify failed: invalid signature format",
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

	// CN: 内存瞬态：验证后清除载荷字节 | EN: Memory Ephemeral: clear payload bytes after verification
	for i := range payloadBytes {
		payloadBytes[i] = 0
	}

	return result
}

// ============================================================================
// CN: 日志净化辅助函数 | EN: Log Sanitization Helpers
// ============================================================================

// CN: maskString 净化字符串，仅保留前 n 个字符
// EN: maskString sanitizes a string, keeping only the first n characters
func maskString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ============================================================================
// CN: 启动初始化 | EN: Startup Initialization
// ============================================================================

func init() {
	oracleInitOnce.Do(initOracleKeys)
}
