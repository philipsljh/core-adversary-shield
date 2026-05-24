/**
 * @file SecureChannel.h
 * @brief 无状态加密通道 (Stateless Secure Channel)
 * 
 * 本模块实现了白皮书 3.1 节定义的 RSA-2048 + AES-256-GCM 混合加密协议。
 * 
 * 核心设计哲学:
 * - 绝对零状态设计：类成员不持有任何会话态凭证
 * - 栈内存生命周期：会话密钥在栈上生成、使用、销毁
 * - 内存阅后即焚：函数返回前强制 SecureZeroMemory 擦除
 * - 一次一密：每次请求独立生成会话密钥，绝不复用
 * 
 * 加密流程:
 * 1. 生成 32 字节随机会话密钥（密码学安全随机数）
 * 2. AES-256-GCM 加密业务数据 → [IV(12)] + [Ciphertext] + [Tag(16)]
 * 3. RSA-2048 加密会话密钥 → 256 字节密文
 * 4. 拼接: [RSA密文(256)] + [IV(12)] + [Ciphertext] + [Tag(16)]
 * 5. Base64 编码
 * 6. 外层包装: {"data": "<Base64密文>"}
 * 
 * 解密流程:
 * 1. 提取外层 JSON 的 data 字段，Base64 解码
 * 2. 前 256 字节 → RSA 私钥解密 → 还原会话密钥（栈分配）
 * 3. 提取 IV（12 字节）+ Ciphertext + Tag
 * 4. AES-256-GCM 解密 → 还原业务数据
 * 5. 会话密钥立刻 SecureZeroMemory 擦除
 */

#pragma once

#include "Result.h"

#include <string>
#include <vector>
#include <cstdint>
#include <array>

#ifdef _WIN32
#include <windows.h>
#endif

namespace csc {

// ========== 常量定义 ==========

/** RSA-2048 公钥加密后的密文长度（字节） */
constexpr size_t RSA2048_CIPHER_LEN = 256;

/** AES-256-GCM IV 长度（字节） */
constexpr size_t AES_GCM_IV_LEN = 12;

/** AES-256-GCM 认证标签长度（字节） */
constexpr size_t AES_GCM_TAG_LEN = 16;

/** AES-256 密钥长度（字节） */
constexpr size_t AES256_KEY_LEN = 32;

/**
 * @brief 加密后的数据包结构
 * 
 * 包含完整的混合加密数据包，可直接用于 HTTP 请求体。
 */
struct EncryptedPayload {
    /** Base64 编码后的完整密文 */
    std::string base64Data;
    
    /** 原始密文长度（解码后） */
    size_t rawLength = 0;
};

/**
 * @brief 解密后的明文结构
 * 
 * 包含解密后的业务数据。
 */
struct DecryptedPayload {
    /** 解密后的业务数据（JSON 字符串） */
    std::string plaintext;
    
    /** 解密是否成功 */
    bool valid = false;
};

/**
 * @brief 无状态加密通道类
 * 
 * 此类不持有任何成员变量，所有密码学操作在单次函数调用的栈内存中完成。
 * 
 * 使用示例:
 * @code
 * // 加密（客户端发送请求）
 * std::string jsonData = R"({"username":"test","password":"***"})";
 * auto encrypted = SecureChannel::Encrypt(jsonData, rsaPublicKeyPem);
 * if (!encrypted.base64Data.empty()) {
 *     // 发送 HTTP 请求
 *     SendRequest("{\"data\": \"" + encrypted.base64Data + "\"}");
 * }
 * 
 * // 解密（客户端接收响应）
 * std::string response = GetResponse(); // {"data": "..."}
 * auto decrypted = SecureChannel::Decrypt(response, rsaPrivateKeyPem);
 * if (decrypted.valid) {
 *     // 处理业务数据
 *     ProcessJson(decrypted.plaintext);
 * }
 * @endcode
 */
class SecureChannel {
public:
    /**
     * @brief 加密业务数据（请求端流程）
     * 
     * 执行完整的混合加密流程：
     * 1. 生成随机会话密钥（栈分配）
     * 2. AES-256-GCM 加密业务数据
     * 3. RSA-2048 加密会话密钥
     * 4. 拼接并 Base64 编码
     * 
     * @param plaintext 明文业务数据（JSON 字符串）
     * @param rsaPublicKeyPEM RSA-2048 公钥（PEM 格式）
     * @return EncryptedPayload 加密后的数据包
     * 
     * @note 会话密钥在函数返回前已被 SecureZeroMemory 擦除
     * @note 此方法是线程安全的（无共享状态）
     */
    static EncryptedPayload Encrypt(const std::string& plaintext, 
                                     const std::string& rsaPublicKeyPEM);
    
    /**
     * @brief 解密业务数据（响应端流程）
     * 
     * 执行完整的混合解密流程：
     * 1. 提取 data 字段，Base64 解码
     * 2. RSA 私钥解密还原会话密钥（栈分配）
     * 3. AES-256-GCM 解密还原业务数据
     * 4. SecureZeroMemory 擦除会话密钥
     * 
     * @param encryptedJson 加密的 JSON 字符串 {"data": "<Base64密文>"}
     * @param rsaPrivateKeyPEM RSA-2048 私钥（PEM 格式）
     * @return DecryptedPayload 解密后的业务数据
     * 
     * @note 会话密钥在函数返回前已被 SecureZeroMemory 擦除
     * @note 此方法是线程安全的（无共享状态）
     */
    static DecryptedPayload Decrypt(const std::string& encryptedJson,
                                     const std::string& rsaPrivateKeyPEM);
    
    /**
     * @brief 生成密码学安全的随机字节
     * 
     * 使用操作系统级别的密码学安全随机数生成器。
     * Windows: CryptGenRandom / BCryptGenRandom
     * Linux: /dev/urandom
     * 
     * @param buffer 输出缓冲区
     * @param length 字节数
     * @return bool 是否成功
     */
    static bool GenerateRandomBytes(uint8_t* buffer, size_t length);
    
    /**
     * @brief Base64 编码
     * 
     * @param data 原始数据
     * @param length 数据长度
     * @return std::string Base64 编码结果
     */
    static std::string Base64Encode(const uint8_t* data, size_t length);
    
    /**
     * @brief Base64 解码
     * 
     * @param base64 Base64 编码字符串
     * @return std::vector<uint8_t> 解码后的原始数据
     */
    static std::vector<uint8_t> Base64Decode(const std::string& base64);

private:
    // ========== 内部辅助方法（私有） ==========
    
    /**
     * @brief AES-256-GCM 加密（内部方法）
     * 
     * @param key AES-256 密钥（32 字节）
     * @param iv 初始化向量（12 字节）
     * @param plaintext 明文数据
     * @param ciphertext 输出：密文数据
     * @param tag 输出：认证标签（16 字节）
     * @return bool 是否成功
     */
    static bool AesGcmEncrypt(const uint8_t* key, const uint8_t* iv,
                               const std::string& plaintext,
                               std::vector<uint8_t>& ciphertext,
                               uint8_t* tag);
    
    /**
     * @brief AES-256-GCM 解密（内部方法）
     * 
     * @param key AES-256 密钥（32 字节）
     * @param iv 初始化向量（12 字节）
     * @param ciphertext 密文数据
     * @param tag 认证标签（16 字节）
     * @param plaintext 输出：明文数据
     * @return bool 是否成功（MAC 校验失败返回 false）
     */
    static bool AesGcmDecrypt(const uint8_t* key, const uint8_t* iv,
                               const std::vector<uint8_t>& ciphertext,
                               const uint8_t* tag,
                               std::string& plaintext);
    
    /**
     * @brief RSA-2048 公钥加密（内部方法）
     * 
     * @param publicKeyPEM RSA 公钥（PEM 格式）
     * @param plaintext 明文数据指针（最大 245 字节，支持栈内存直接传入）
     * @param plaintextLen 明文数据长度（字节）
     * @param ciphertext 输出：密文数据（256 字节）
     * @return bool 是否成功
     * 
     * @note 此函数接受原始指针而非 std::vector，避免明文堆内存拷贝泄露
     */
    static bool RsaEncrypt(const std::string& publicKeyPEM,
                            const uint8_t* plaintext,
                            size_t plaintextLen,
                            std::vector<uint8_t>& ciphertext);
    
    /**
     * @brief RSA-2048 私钥解密（内部方法）
     * 
     * @param privateKeyPEM RSA 私钥（PEM 格式）
     * @param ciphertext 密文数据（256 字节）
     * @param plaintext 输出：明文数据
     * @return bool 是否成功
     */
    static bool RsaDecrypt(const std::string& privateKeyPEM,
                            const std::vector<uint8_t>& ciphertext,
                            std::vector<uint8_t>& plaintext);
    
    /**
     * @brief 提取 JSON 中的 data 字段
     * 
     * @param json 原始 JSON 字符串
     * @param data 输出：data 字段值
     * @return bool 是否成功提取
     */
    static bool ExtractDataField(const std::string& json, std::string& data);
    
    /**
     * @brief 强制内存擦除
     * 
     * 使用操作系统级别的强制擦除函数，防止编译器优化。
     * Windows: SecureZeroMemory
     * Linux: explicit_bzero / memset_s
     * 
     * @param ptr 内存指针
     * @param size 字节数
     */
    static void SecureErase(void* ptr, size_t size);
};

} // namespace csc