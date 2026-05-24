/**
 * @file SecureChannel.h
 * @brief CN: 无状态安全通道 | EN: Stateless Secure Channel
 *
 * CN: 企业级应用加固组件 - 端到端混合加密协议实现
 * EN: Enterprise-grade application hardening component - End-to-end hybrid encryption protocol implementation.
 *
 * CN: 本模块实现了 RSA-2048 + AES-256-GCM 混合加密协议。
 * EN: This module implements the RSA-2048 + AES-256-GCM hybrid encryption protocol.
 *
 * CN: 核心设计哲学:
 * EN: Core design philosophy:
 * - CN: 绝对零状态设计：类成员不持有任何会话凭证 | EN: Absolute zero-state design: Class members hold no session credentials
 * - CN: 栈内存生命周期：会话密钥在栈上生成、使用和销毁 | EN: Stack memory lifecycle: Session keys are generated, used, and destroyed on the stack
 * - CN: 内存阅后即焚：函数返回前强制执行 SecureZeroMemory 擦除 | EN: Memory annihilation: SecureZeroMemory wipe enforced before function returns
 * - CN: 一次性密钥：每次请求独立生成会话密钥，永不复用 | EN: One-time pad: Each request independently generates a session key, never reused
 *
 * CN: 加密流程:
 * EN: Encryption flow:
 * 1. CN: 生成 32 字节随机会话密钥（密码学安全 RNG）| EN: Generate 32-byte random session key (cryptographically secure RNG)
 * 2. CN: AES-256-GCM 加密业务数据 -> [IV(12)] + [密文] + [Tag(16)] | EN: AES-256-GCM encrypt business data -> [IV(12)] + [Ciphertext] + [Tag(16)]
 * 3. CN: RSA-2048 加密会话密钥 -> 256 字节密文 | EN: RSA-2048 encrypt session key -> 256-byte ciphertext
 * 4. CN: 拼接：[RSA 密文(256)] + [IV(12)] + [密文] + [Tag(16)] | EN: Concatenate: [RSA ciphertext(256)] + [IV(12)] + [Ciphertext] + [Tag(16)]
 * 5. CN: Base64 编码 | EN: Base64 encode
 * 6. CN: 外层包装：{"data": "<Base64 密文>"} | EN: Outer wrapper: {"data": "<Base64 ciphertext>"}
 *
 * CN: 解密流程:
 * EN: Decryption flow:
 * 1. CN: 从外层 JSON 提取 data 字段，Base64 解码 | EN: Extract data field from outer JSON, Base64 decode
 * 2. CN: 前 256 字节 -> RSA 私钥解密 -> 还原会话密钥（栈分配）| EN: First 256 bytes -> RSA private key decrypt -> restore session key (stack allocated)
 * 3. CN: 提取 IV（12 字节）+ 密文 + Tag | EN: Extract IV (12 bytes) + Ciphertext + Tag
 * 4. CN: AES-256-GCM 解密 -> 还原业务数据 | EN: AES-256-GCM decrypt -> restore business data
 * 5. CN: 会话密钥通过 SecureZeroMemory 立即擦除 | EN: Session key immediately wiped via SecureZeroMemory
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <array>

#ifdef _WIN32
#include <windows.h>
#endif

namespace csc {

// ========== CN: 常量定义 | EN: Constant Definitions ==========

/** CN: RSA-2048 公钥加密密文长度（字节）| EN: RSA-2048 public key encrypted ciphertext length (bytes) */
constexpr size_t RSA2048_CIPHER_LEN = 256;

/** CN: AES-256-GCM IV 长度（字节）| EN: AES-256-GCM IV length (bytes) */
constexpr size_t AES_GCM_IV_LEN = 12;

/** CN: AES-256-GCM 认证标签长度（字节）| EN: AES-256-GCM authentication tag length (bytes) */
constexpr size_t AES_GCM_TAG_LEN = 16;

/** CN: AES-256 密钥长度（字节）| EN: AES-256 key length (bytes) */
constexpr size_t AES256_KEY_LEN = 32;

/**
 * @brief CN: 加密载荷结构体 | EN: Encrypted payload structure
 *
 * CN: 包含完整的混合加密数据包，可直接用于 HTTP 请求体。
 * EN: Contains the complete hybrid encryption data packet, ready for HTTP request body.
 */
struct EncryptedPayload {
    /** CN: Base64 编码的完整密文 | EN: Base64-encoded complete ciphertext */
    std::string base64Data;

    /** CN: 原始密文长度（解码后）| EN: Raw ciphertext length (after decoding) */
    size_t rawLength = 0;

    /** CN: 操作是否成功 | EN: Whether the operation succeeded */
    bool success = false;

    /** CN: 错误消息（失败时）| EN: Error message (if failed) */
    std::string error;
};

/**
 * @brief CN: 解密载荷结构体 | EN: Decrypted payload structure
 *
 * CN: 包含解密后的业务数据。
 * EN: Contains the decrypted business data.
 */
struct DecryptedPayload {
    /** CN: 解密后的业务数据（JSON 字符串）| EN: Decrypted business data (JSON string) */
    std::string plaintext;

    /** CN: 解密是否成功 | EN: Whether decryption succeeded */
    bool success = false;

    /** CN: 错误消息（失败时）| EN: Error message (if failed) */
    std::string error;
};

/**
 * @brief CN: 无状态安全通道类 | EN: Stateless secure channel class
 *
 * CN: 此类不持有成员变量；所有密码学操作在单次函数调用的栈内存中完成。
 * EN: This class holds no member variables; all cryptographic operations complete within the stack memory of a single function call.
 *
 * CN: 使用示例:
 * EN: Usage example:
 * @code
 * // CN: 加密（客户端发送请求）| EN: Encrypt (client sends request)
 * std::string jsonData = R"({"username":"test","password":"***"})";
 * auto encrypted = SecureChannel::Encrypt(jsonData, rsaPublicKeyPem);
 * if (encrypted.success) {
 *     // CN: 发送 HTTP 请求 | EN: Send HTTP request
 *     SendRequest("{\"data\": \"" + encrypted.base64Data + "\"}");
 * }
 *
 * // CN: 解密（客户端接收响应）| EN: Decrypt (client receives response)
 * std::string response = GetResponse(); // {"data": "..."}
 * auto decrypted = SecureChannel::Decrypt(response, rsaPrivateKeyPem);
 * if (decrypted.success) {
 *     // CN: 处理业务数据 | EN: Process business data
 *     ProcessJson(decrypted.plaintext);
 * }
 * @endcode
 */
class SecureChannel {
public:
    /**
     * @brief CN: 加密业务数据（请求端流程）| EN: Encrypt business data (request-side flow)
     *
     * CN: 执行完整的混合加密流程:
     * EN: Executes the complete hybrid encryption flow:
     * 1. CN: 生成随机会话密钥（栈分配）| EN: Generate random session key (stack allocated)
     * 2. CN: AES-256-GCM 加密业务数据 | EN: AES-256-GCM encrypt business data
     * 3. CN: RSA-2048 加密会话密钥 | EN: RSA-2048 encrypt session key
     * 4. CN: 拼接并 Base64 编码 | EN: Concatenate and Base64 encode
     *
     * @param plaintext CN: 明文业务数据（JSON 字符串）| EN: Plaintext business data (JSON string)
     * @param rsaPublicKeyPEM CN: RSA-2048 公钥（PEM 格式）| EN: RSA-2048 public key (PEM format)
     * @return CN: EncryptedPayload 加密数据包 | EN: EncryptedPayload Encrypted data packet
     *
     * @note CN: 会话密钥在函数返回前通过 SecureZeroMemory 擦除 | EN: Session key is wiped via SecureZeroMemory before function returns
     * @note CN: 此方法线程安全（无共享状态）| EN: This method is thread-safe (no shared state)
     */
    static EncryptedPayload Encrypt(const std::string& plaintext,
                                     const std::string& rsaPublicKeyPEM);

    /**
     * @brief CN: 解密业务数据（响应端流程）| EN: Decrypt business data (response-side flow)
     *
     * CN: 执行完整的混合解密流程:
     * EN: Executes the complete hybrid decryption flow:
     * 1. CN: 提取 data 字段，Base64 解码 | EN: Extract data field, Base64 decode
     * 2. CN: RSA 私钥解密还原会话密钥（栈分配）| EN: RSA private key decrypt to restore session key (stack allocated)
     * 3. CN: AES-256-GCM 解密还原业务数据 | EN: AES-256-GCM decrypt to restore business data
     * 4. CN: SecureZeroMemory 擦除会话密钥 | EN: SecureZeroMemory wipe session key
     *
     * @param encryptedJson CN: 加密的 JSON 字符串 {"data": "<Base64 密文>"} | EN: Encrypted JSON string {"data": "<Base64 ciphertext>"}
     * @param rsaPrivateKeyPEM CN: RSA-2048 私钥（PEM 格式）| EN: RSA-2048 private key (PEM format)
     * @return CN: DecryptedPayload 解密后的业务数据 | EN: DecryptedPayload Decrypted business data
     *
     * @note CN: 会话密钥在函数返回前通过 SecureZeroMemory 擦除 | EN: Session key is wiped via SecureZeroMemory before function returns
     * @note CN: 此方法线程安全（无共享状态）| EN: This method is thread-safe (no shared state)
     */
    static DecryptedPayload Decrypt(const std::string& encryptedJson,
                                     const std::string& rsaPrivateKeyPEM);

    /**
     * @brief CN: 生成密码学安全的随机字节 | EN: Generate cryptographically secure random bytes
     *
     * CN: 使用操作系统级别的密码学安全随机数生成器。
     * EN: Uses OS-level cryptographically secure random number generator.
     * CN: Windows: CryptGenRandom / BCryptGenRandom
     * EN: Windows: CryptGenRandom / BCryptGenRandom
     * CN: Linux: /dev/urandom
     * EN: Linux: /dev/urandom
     *
     * @param buffer CN: 输出缓冲区 | EN: Output buffer
     * @param length CN: 字节数 | EN: Number of bytes
     * @return CN: bool 是否成功 | EN: bool Whether successful
     */
    static bool GenerateRandomBytes(uint8_t* buffer, size_t length);

    /**
     * @brief CN: Base64 编码 | EN: Base64 encode
     *
     * @param data CN: 原始数据 | EN: Raw data
     * @param length CN: 数据长度 | EN: Data length
     * @return CN: std::string Base64 编码结果 | EN: std::string Base64 encoded result
     */
    static std::string Base64Encode(const uint8_t* data, size_t length);

    /**
     * @brief CN: Base64 解码 | EN: Base64 decode
     *
     * @param base64 CN: Base64 编码字符串 | EN: Base64 encoded string
     * @return CN: std::vector<uint8_t> 解码后的原始数据 | EN: std::vector<uint8_t> Decoded raw data
     */
    static std::vector<uint8_t> Base64Decode(const std::string& base64);

private:
    // ========== CN: 内部辅助方法（私有）| EN: Internal Helper Methods (Private) ==========

    /**
     * @brief CN: AES-256-GCM 加密（内部方法）| EN: AES-256-GCM encryption (internal method)
     *
     * @param key CN: AES-256 密钥（32 字节）| EN: AES-256 key (32 bytes)
     * @param iv CN: 初始化向量（12 字节）| EN: Initialization vector (12 bytes)
     * @param plaintext CN: 明文数据 | EN: Plaintext data
     * @param ciphertext CN: 输出：密文数据 | EN: Output: ciphertext data
     * @param tag CN: 输出：认证标签（16 字节）| EN: Output: authentication tag (16 bytes)
     * @return CN: bool 是否成功 | EN: bool Whether successful
     */
    static bool AesGcmEncrypt(const uint8_t* key, const uint8_t* iv,
                               const std::string& plaintext,
                               std::vector<uint8_t>& ciphertext,
                               uint8_t* tag);

    /**
     * @brief CN: AES-256-GCM 解密（内部方法）| EN: AES-256-GCM decryption (internal method)
     *
     * @param key CN: AES-256 密钥（32 字节）| EN: AES-256 key (32 bytes)
     * @param iv CN: 初始化向量（12 字节）| EN: Initialization vector (12 bytes)
     * @param ciphertext CN: 密文数据 | EN: Ciphertext data
     * @param tag CN: 认证标签（16 字节）| EN: Authentication tag (16 bytes)
     * @param plaintext CN: 输出：明文数据 | EN: Output: plaintext data
     * @return CN: bool 是否成功（MAC 校验失败时返回 false）| EN: bool Whether successful (returns false if MAC verification fails)
     */
    static bool AesGcmDecrypt(const uint8_t* key, const uint8_t* iv,
                               const std::vector<uint8_t>& ciphertext,
                               const uint8_t* tag,
                               std::string& plaintext);

    /**
     * @brief CN: RSA-2048 公钥加密（内部方法）| EN: RSA-2048 public key encryption (internal method)
     *
     * @param publicKeyPEM CN: RSA 公钥（PEM 格式）| EN: RSA public key (PEM format)
     * @param plaintext CN: 明文数据指针（最大 245 字节，支持直接传递栈内存）| EN: Plaintext data pointer (max 245 bytes, supports direct stack memory passing)
     * @param plaintextLen CN: 明文数据长度（字节）| EN: Plaintext data length (bytes)
     * @param ciphertext CN: 输出：密文数据（256 字节）| EN: Output: ciphertext data (256 bytes)
     * @return CN: bool 是否成功 | EN: bool Whether successful
     *
     * @note CN: 此函数接受原始指针而非 std::vector，以避免明文堆内存复制泄漏
     *       EN: This function accepts raw pointers instead of std::vector to avoid plaintext heap memory copy leakage
     */
    static bool RsaEncrypt(const std::string& publicKeyPEM,
                            const uint8_t* plaintext,
                            size_t plaintextLen,
                            std::vector<uint8_t>& ciphertext);

    /**
     * @brief CN: RSA-2048 私钥解密（内部方法）| EN: RSA-2048 private key decryption (internal method)
     *
     * @param privateKeyPEM CN: RSA 私钥（PEM 格式）| EN: RSA private key (PEM format)
     * @param ciphertext CN: 密文数据（256 字节）| EN: Ciphertext data (256 bytes)
     * @param plaintext CN: 输出：明文数据 | EN: Output: plaintext data
     * @return CN: bool 是否成功 | EN: bool Whether successful
     */
    static bool RsaDecrypt(const std::string& privateKeyPEM,
                            const std::vector<uint8_t>& ciphertext,
                            std::vector<uint8_t>& plaintext);

    /**
     * @brief CN: 从 JSON 提取 data 字段 | EN: Extract data field from JSON
     *
     * @param json CN: 原始 JSON 字符串 | EN: Raw JSON string
     * @param data CN: 输出：data 字段值 | EN: Output: data field value
     * @return CN: bool 提取是否成功 | EN: bool Whether extraction succeeded
     */
    static bool ExtractDataField(const std::string& json, std::string& data);

    /**
     * @brief CN: 强制内存擦除 | EN: Force memory wipe
     *
     * CN: 使用操作系统级别的强制擦除函数防止编译器优化。
     * EN: Uses OS-level forced wipe function to prevent compiler optimization.
     * CN: Windows: SecureZeroMemory
     * EN: Windows: SecureZeroMemory
     * CN: Linux: explicit_bzero / memset_s
     * EN: Linux: explicit_bzero / memset_s
     *
     * @param ptr CN: 内存指针 | EN: Memory pointer
     * @param size CN: 字节数 | EN: Number of bytes
     */
    static void SecureErase(void* ptr, size_t size);
};

} // namespace csc