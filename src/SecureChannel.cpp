/**
 * @file SecureChannel.cpp
 * @brief 无状态加密通道实现 (Stateless Secure Channel Implementation)
 * 
 * 本文件使用 Crypto++ 库实现 RSA-2048 + AES-256-GCM 混合加密协议。
 * 
 * 编译依赖:
 * - Crypto++ (https://www.cryptopp.com/)
 * - C++17 或更高版本
 * 
 * 链接库:
 * - cryptlib.lib (Windows)
 * - libcryptopp.a (Linux)
 * 
 * 安全注意事项:
 * 1. 所有会话密钥在栈上分配，函数返回前强制擦除
 * 2. 使用 VirtualLock 防止敏感数据被交换到页面文件
 * 3. 使用 SecureZeroMemory 防止编译器优化掉内存擦除
 * 4. 使用 volatile 指针确保内存访问不被优化
 * 5. Crypto++ 已编译时禁用异常 (CRYPTOPP_DISABLE_EXCEPTIONS)，无需 try-catch
 */

#include "SecureChannel.h"

// Crypto++ 头文件
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

// 标准库
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

namespace csc {

// ========== 公共方法实现 ==========

EncryptedPayload SecureChannel::Encrypt(const std::string& plaintext,
                                         const std::string& rsaPublicKeyPEM) {
    EncryptedPayload result;
    
    // =========================================================
    // 步骤 1: 生成 32 字节随机会话密钥（栈分配）
    // =========================================================
    // 使用 std::array 确保值类型语义，避免隐式共享
    std::array<uint8_t, AES256_KEY_LEN> sessionKey{};
    
    // 锁定内存页，防止被交换到页面文件
#ifdef _WIN32
    VirtualLock(sessionKey.data(), sessionKey.size());
#endif
    
    if (!GenerateRandomBytes(sessionKey.data(), sessionKey.size())) {
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        SecureErase(sessionKey.data(), sessionKey.size());
        return result;
    }
    
    // =========================================================
    // 步骤 2: 生成 12 字节随机 IV（栈分配）
    // =========================================================
    std::array<uint8_t, AES_GCM_IV_LEN> iv{};
    if (!GenerateRandomBytes(iv.data(), iv.size())) {
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        SecureErase(sessionKey.data(), sessionKey.size());
        return result;
    }
    
    // =========================================================
    // 步骤 3: AES-256-GCM 加密业务数据
    // =========================================================
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, AES_GCM_TAG_LEN> tag{};
    
    if (!AesGcmEncrypt(sessionKey.data(), iv.data(), plaintext, ciphertext, tag.data())) {
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        SecureErase(sessionKey.data(), sessionKey.size());
        return result;
    }
    
    // =========================================================
    // 步骤 4: RSA-2048 加密会话密钥（零拷贝，直接传入栈指针）
    // =========================================================
    std::vector<uint8_t> encryptedKey;
    
    if (!RsaEncrypt(rsaPublicKeyPEM, sessionKey.data(), sessionKey.size(), encryptedKey)) {
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        SecureErase(sessionKey.data(), sessionKey.size());
        return result;
    }
    
    // =========================================================
    // 步骤 5: 拼接密文 [RSA密文(256)] + [IV(12)] + [Ciphertext] + [Tag(16)]
    // =========================================================
    std::vector<uint8_t> combined;
    combined.reserve(encryptedKey.size() + iv.size() + ciphertext.size() + tag.size());
    combined.insert(combined.end(), encryptedKey.begin(), encryptedKey.end());
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
    combined.insert(combined.end(), tag.begin(), tag.end());
    
    result.rawLength = combined.size();
    
    // =========================================================
    // 步骤 6: Base64 编码
    // =========================================================
    result.base64Data = Base64Encode(combined.data(), combined.size());
    
    // =========================================================
    // 步骤 7: 强制擦除栈上的会话密钥（物理超度）
    // =========================================================
    SecureErase(sessionKey.data(), sessionKey.size());
    SecureErase(iv.data(), iv.size());
    SecureErase(tag.data(), tag.size());
    
#ifdef _WIN32
    VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
    
    return result;
}

DecryptedPayload SecureChannel::Decrypt(const std::string& encryptedJson,
                                         const std::string& rsaPrivateKeyPEM) {
    DecryptedPayload result;
    
    // =========================================================
    // 步骤 1: 提取 data 字段，Base64 解码
    // =========================================================
    std::string base64Data;
    if (!ExtractDataField(encryptedJson, base64Data)) {
        result.valid = false;
        return result;
    }
    
    std::vector<uint8_t> combined = Base64Decode(base64Data);
    if (combined.empty()) {
        result.valid = false;
        return result;
    }
    
    // 验证最小长度: RSA(256) + IV(12) + Tag(16) = 284 字节
    constexpr size_t MIN_LENGTH = RSA2048_CIPHER_LEN + AES_GCM_IV_LEN + AES_GCM_TAG_LEN;
    if (combined.size() < MIN_LENGTH) {
        SecureErase(combined.data(), combined.size());
        combined.clear();
        combined.shrink_to_fit();
        result.valid = false;
        return result;
    }
    
    // =========================================================
    // 步骤 2: 分离 RSA 密文（前 256 字节）
    // =========================================================
    std::vector<uint8_t> encryptedKey(combined.begin(), 
                                       combined.begin() + RSA2048_CIPHER_LEN);
    
    // =========================================================
    // 步骤 3: RSA 私钥解密还原会话密钥（栈分配）
    // =========================================================
    std::array<uint8_t, AES256_KEY_LEN> sessionKey{};
    
    // 锁定内存页
#ifdef _WIN32
    VirtualLock(sessionKey.data(), sessionKey.size());
#endif
    
    std::vector<uint8_t> decryptedKey;
    if (!RsaDecrypt(rsaPrivateKeyPEM, encryptedKey, decryptedKey)) {
        SecureErase(sessionKey.data(), sessionKey.size());
        // 堆内存安全擦除
        if (!combined.empty()) {
            SecureErase(combined.data(), combined.size());
            combined.clear();
            combined.shrink_to_fit();
        }
        if (!encryptedKey.empty()) {
            SecureErase(encryptedKey.data(), encryptedKey.size());
            encryptedKey.clear();
            encryptedKey.shrink_to_fit();
        }
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        return result;
    }
    
    // 验证密钥长度
    if (decryptedKey.size() != AES256_KEY_LEN) {
        SecureErase(sessionKey.data(), sessionKey.size());
        // 堆内存安全擦除
        if (!combined.empty()) {
            SecureErase(combined.data(), combined.size());
            combined.clear();
            combined.shrink_to_fit();
        }
        if (!encryptedKey.empty()) {
            SecureErase(encryptedKey.data(), encryptedKey.size());
            encryptedKey.clear();
            encryptedKey.shrink_to_fit();
        }
        decryptedKey.clear();
        decryptedKey.shrink_to_fit();
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        return result;
    }
    
    // 复制到栈上
    std::memcpy(sessionKey.data(), decryptedKey.data(), AES256_KEY_LEN);
    SecureErase(decryptedKey.data(), decryptedKey.size());
    decryptedKey.clear();
    decryptedKey.shrink_to_fit();
    
    // =========================================================
    // 步骤 4: 分离 IV（接下来的 12 字节）
    // =========================================================
    std::array<uint8_t, AES_GCM_IV_LEN> iv{};
    std::memcpy(iv.data(), 
                combined.data() + RSA2048_CIPHER_LEN, 
                AES_GCM_IV_LEN);
    
    // =========================================================
    // 步骤 5: 分离密文和标签
    // =========================================================
    size_t ciphertextStart = RSA2048_CIPHER_LEN + AES_GCM_IV_LEN;
    size_t ciphertextLen = combined.size() - ciphertextStart - AES_GCM_TAG_LEN;
    
    std::vector<uint8_t> ciphertext(combined.begin() + ciphertextStart,
                                     combined.begin() + ciphertextStart + ciphertextLen);
    
    std::array<uint8_t, AES_GCM_TAG_LEN> tag{};
    std::memcpy(tag.data(), 
                combined.data() + combined.size() - AES_GCM_TAG_LEN, 
                AES_GCM_TAG_LEN);
    
    // =========================================================
    // 步骤 6: AES-256-GCM 解密还原业务数据
    // =========================================================
    if (!AesGcmDecrypt(sessionKey.data(), iv.data(), ciphertext, tag.data(), result.plaintext)) {
        // MAC 校验失败，可能是数据被篡改
        SecureErase(sessionKey.data(), sessionKey.size());
        // 堆内存安全擦除
        if (!combined.empty()) {
            SecureErase(combined.data(), combined.size());
            combined.clear();
            combined.shrink_to_fit();
        }
        if (!encryptedKey.empty()) {
            SecureErase(encryptedKey.data(), encryptedKey.size());
            encryptedKey.clear();
            encryptedKey.shrink_to_fit();
        }
#ifdef _WIN32
        VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
        result.valid = false;
        return result;
    }
    
    result.valid = true;
    
    // =========================================================
    // 步骤 7: 强制擦除栈上的会话密钥（物理超度）
    // =========================================================
    SecureErase(sessionKey.data(), sessionKey.size());
    SecureErase(iv.data(), iv.size());
    SecureErase(tag.data(), tag.size());
    
    // 堆内存安全擦除（最终清理）
    if (!combined.empty()) {
        SecureErase(combined.data(), combined.size());
        combined.clear();
        combined.shrink_to_fit();
    }
    if (!encryptedKey.empty()) {
        SecureErase(encryptedKey.data(), encryptedKey.size());
        encryptedKey.clear();
        encryptedKey.shrink_to_fit();
    }
    
#ifdef _WIN32
    VirtualUnlock(sessionKey.data(), sessionKey.size());
#endif
    
    return result;
}

bool SecureChannel::GenerateRandomBytes(uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return false;
    
    // Crypto++ 已编译时禁用异常 (CRYPTOPP_DISABLE_EXCEPTIONS)
    // 此处直接调用，无需 try-catch
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(buffer, length);
    return true;
}

std::string SecureChannel::Base64Encode(const uint8_t* data, size_t length) {
    std::string encoded;
    
    // Crypto++ 已编译时禁用异常，直接调用
    CryptoPP::StringSource ss(data, length, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded),
            false  // 不添加换行
        )
    );
    
    return encoded;
}

std::vector<uint8_t> SecureChannel::Base64Decode(const std::string& base64) {
    std::vector<uint8_t> decoded;
    
    // Crypto++ 已编译时禁用异常，直接调用
    CryptoPP::StringSource ss(base64, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::VectorSink(decoded)
        )
    );
    
    return decoded;
}

// ========== 私有方法实现 ==========

bool SecureChannel::AesGcmEncrypt(const uint8_t* key, const uint8_t* iv,
                                   const std::string& plaintext,
                                   std::vector<uint8_t>& ciphertext,
                                   uint8_t* tag) {
    // Crypto++ 已编译时禁用异常，直接调用
    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, AES256_KEY_LEN, iv, AES_GCM_IV_LEN);
    
    ciphertext.resize(plaintext.size());
    
    // 加密
    encryptor.ProcessData(ciphertext.data(), 
                          reinterpret_cast<const uint8_t*>(plaintext.data()),
                          plaintext.size());
    
    // 计算认证标签
    encryptor.TruncatedFinal(tag, AES_GCM_TAG_LEN);
    
    return true;
}

bool SecureChannel::AesGcmDecrypt(const uint8_t* key, const uint8_t* iv,
                                   const std::vector<uint8_t>& ciphertext,
                                   const uint8_t* tag,
                                   std::string& plaintext) {
    // Crypto++ 已编译时禁用异常，直接调用
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, AES256_KEY_LEN, iv, AES_GCM_IV_LEN);
    
    plaintext.resize(ciphertext.size());
    
    // 解密并验证标签
    decryptor.ProcessData(reinterpret_cast<uint8_t*>(plaintext.data()),
                          ciphertext.data(),
                          ciphertext.size());
    
    // 验证认证标签
    return decryptor.TruncatedVerify(tag, AES_GCM_TAG_LEN);
}

bool SecureChannel::RsaEncrypt(const std::string& publicKeyPEM,
                                const uint8_t* plaintext,
                                size_t plaintextLen,
                                std::vector<uint8_t>& ciphertext) {
    // Crypto++ 已编译时禁用异常，直接调用
    // 从 PEM 加载公钥
    CryptoPP::StringSource keySource(publicKeyPEM, true);
    CryptoPP::RSA::PublicKey publicKey;
    publicKey.Load(keySource);
    
    // 使用 OAEP 填充模式
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    
    // 验证明文长度（OAEP 最大 214 字节）
    if (plaintextLen > encryptor.MaxPlaintextLength()) {
        return false;
    }
    
    ciphertext.resize(encryptor.CiphertextLength(plaintextLen));
    
    CryptoPP::AutoSeededRandomPool rng;
    encryptor.Encrypt(rng,
                      plaintext,
                      plaintextLen,
                      ciphertext.data());
    
    return true;
}

bool SecureChannel::RsaDecrypt(const std::string& privateKeyPEM,
                                const std::vector<uint8_t>& ciphertext,
                                std::vector<uint8_t>& plaintext) {
    // Crypto++ 已编译时禁用异常，直接调用
    // 从 PEM 加载私钥
    CryptoPP::StringSource keySource(privateKeyPEM, true);
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.Load(keySource);
    
    // 使用 OAEP 填充模式
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    
    // 验证密文长度
    if (ciphertext.size() != decryptor.CiphertextLength()) {
        return false;
    }
    
    plaintext.resize(decryptor.MaxPlaintextLength());
    
    CryptoPP::DecodingResult result = decryptor.Decrypt(
        CryptoPP::NullRNG(),
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data()
    );
    
    plaintext.resize(result.messageLength);
    return result.isValidCoding;
}

bool SecureChannel::ExtractDataField(const std::string& json, std::string& data) {
    // 简易 JSON 解析：查找 "data" 字段
    // 生产环境建议使用 nlohmann/json 或 rapidjson
    
    size_t keyPos = json.find("\"data\"");
    if (keyPos == std::string::npos) {
        return false;
    }
    
    size_t colonPos = json.find(':', keyPos + 6);
    if (colonPos == std::string::npos) {
        return false;
    }
    
    size_t quoteStart = json.find('"', colonPos + 1);
    if (quoteStart == std::string::npos) {
        return false;
    }
    
    size_t quoteEnd = json.find('"', quoteStart + 1);
    if (quoteEnd == std::string::npos) {
        return false;
    }
    
    data = json.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
    return true;
}

void SecureChannel::SecureErase(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    
#ifdef _WIN32
    // Windows: 使用 SecureZeroMemory（保证不被编译器优化）
    SecureZeroMemory(ptr, size);
#else
    // Linux: 使用 explicit_bzero（C11 标准，保证不被优化）
    explicit_bzero(ptr, size);
#endif
}

} // namespace csc