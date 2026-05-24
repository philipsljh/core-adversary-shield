/**
 * @file SecureChannel.cpp
 * @brief 无状态加密通道实现 - RSA + AES-GCM 混合加解密
 *
 * 企业级应用加固组件 - 端到端混合加密协议实现
 *
 * 使用 OpenSSL 实现：
 * - AES-GCM: EVP_EncryptInit_ex / EVP_DecryptInit_ex
 * - RSA: EVP_PKEY_encrypt / EVP_PKEY_decrypt
 *
 * 注意：开源版本使用 OpenSSL 3.x API 实现，
 * 生产版本可替换为硬件加速或国密算法
 */

#include "SecureChannel.h"
#include <cstring>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <openssl/evp.h>
    #include <openssl/rsa.h>
    #include <openssl/pem.h>
    #include <openssl/err.h>
    #include <openssl/rand.h>
#endif

namespace csc {

// ============================================================
// SecureErase - 强制内存擦除
// ============================================================

void SecureChannel::SecureErase(void* ptr, size_t size) {
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    // POSIX 兼容实现：使用 volatile 指针防止优化
    volatile unsigned char* p = reinterpret_cast<unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
#endif
}

// ============================================================
// GenerateRandomBytes - 密码学安全随机数生成
// ============================================================

bool SecureChannel::GenerateRandomBytes(uint8_t* buffer, size_t length) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer,
        static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return BCRYPT_SUCCESS(status);
#else
    return RAND_bytes(buffer, static_cast<int>(length)) == 1;
#endif
}

// ============================================================
// Base64Encode / Base64Decode
// ============================================================

static const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string SecureChannel::Base64Encode(const uint8_t* data, size_t len) {
    std::string result;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                result += BASE64_CHARS[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++)
            result += BASE64_CHARS[char_array_4[j]];

        while (i++ < 3)
            result += '=';
    }

    return result;
}

std::vector<uint8_t> SecureChannel::Base64Decode(const std::string& encoded_string) {
    std::vector<uint8_t> result;
    int in_len = static_cast<int>(encoded_string.size());
    int i = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') &&
           (isalnum(encoded_string[in_]) || encoded_string[in_] == '+' || encoded_string[in_] == '/')) {
        char_array_4[i++] = static_cast<unsigned char>(encoded_string[in_]); in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = static_cast<unsigned char>(strchr(BASE64_CHARS, char_array_4[i]) - BASE64_CHARS);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                result.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (int j = 0; j < 4; j++)
            char_array_4[j] = static_cast<unsigned char>(strchr(BASE64_CHARS, char_array_4[j]) - BASE64_CHARS);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (int j = 0; j < i - 1; j++)
            result.push_back(char_array_3[j]);
    }

    return result;
}

// ============================================================
// ExtractDataField - 提取 JSON 中的 data 字段
// ============================================================

bool SecureChannel::ExtractDataField(const std::string& json, std::string& data) {
    // 简单 JSON 解析：查找 "data" 字段
    // 注意：生产环境应使用完整的 JSON 解析库
    size_t pos = json.find("\"data\"");
    if (pos == std::string::npos) {
        return false;
    }

    // 查找冒号后的值
    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return false;
    }

    // 跳过空白字符
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) {
        pos++;
    }

    // 检查是否为字符串
    if (pos >= json.size() || json[pos] != '"') {
        return false;
    }

    // 提取字符串值
    pos++;  // 跳过开始的引号
    size_t endPos = pos;
    while (endPos < json.size()) {
        if (json[endPos] == '"' && (endPos == 0 || json[endPos - 1] != '\\')) {
            break;
        }
        endPos++;
    }

    if (endPos >= json.size()) {
        return false;
    }

    data = json.substr(pos, endPos - pos);
    return true;
}

// ============================================================
// AesGcmEncrypt / AesGcmDecrypt
// ============================================================

bool SecureChannel::AesGcmEncrypt(const uint8_t* key, const uint8_t* iv,
                                   const std::string& plaintext,
                                   std::vector<uint8_t>& ciphertext,
                                   uint8_t* tag) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) break;

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key), AES256_KEY_LEN, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        // 分配输出缓冲区（明文 + tag）
        ciphertext.resize(plaintext.size() + AES_GCM_TAG_LEN);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
        authInfo.pbNonce = const_cast<PUCHAR>(iv);
        authInfo.cbNonce = AES_GCM_IV_LEN;
        authInfo.pbTag = tag;
        authInfo.cbTag = AES_GCM_TAG_LEN;

        ULONG cbResult = 0;
        status = BCryptEncrypt(hKey, const_cast<PUCHAR>(reinterpret_cast<const PUCHAR>(plaintext.data())),
            static_cast<ULONG>(plaintext.size()), &authInfo, nullptr, 0,
            ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, 0);

        if (BCRYPT_SUCCESS(status)) {
            ciphertext.resize(cbResult);
        }

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;

    bool success = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1) break;
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1) break;
        ciphertext_len += len;

        // 获取 GCM tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) break;

        ciphertext.resize(ciphertext_len);
        success = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
#endif
}

bool SecureChannel::AesGcmDecrypt(const uint8_t* key, const uint8_t* iv,
                                   const std::vector<uint8_t>& ciphertext,
                                   const uint8_t* tag,
                                   std::string& plaintext) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) break;

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key), AES256_KEY_LEN, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        plaintext.resize(ciphertext.size());

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
        authInfo.pbNonce = const_cast<PUCHAR>(iv);
        authInfo.cbNonce = AES_GCM_IV_LEN;
        authInfo.pbTag = const_cast<PUCHAR>(tag);
        authInfo.cbTag = AES_GCM_TAG_LEN;

        ULONG cbResult = 0;
        status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()), &authInfo, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())),
            static_cast<ULONG>(plaintext.size()), &cbResult, 0);

        if (BCRYPT_SUCCESS(status)) {
            plaintext.resize(cbResult);
        }

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int plaintext_len = 0;

    bool success = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;

        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext.data())),
            &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) break;
        plaintext_len = len;

        // 设置 GCM tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, const_cast<uint8_t*>(tag)) != 1) break;

        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext.data())) + plaintext_len, &len) != 1) break;
        plaintext_len += len;

        plaintext.resize(plaintext_len);
        success = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
#endif
}

// ============================================================
// RsaEncrypt / RsaDecrypt
// ============================================================

bool SecureChannel::RsaEncrypt(const std::string& publicKeyPEM,
                                const uint8_t* plaintext,
                                size_t plaintextLen,
                                std::vector<uint8_t>& ciphertext) {
#ifdef _WIN32
    // Windows CNG RSA 实现
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        // 解析 PEM 公钥（简化实现，生产环境应使用完整解析）
        // 注意：此处需要完整的 PEM 解析逻辑
        // 为简化，此处假设 publicKeyPEM 已经是 BCRYPT_RSAPUBLIC_BLOB 格式

        // 导入公钥
        status = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &hKey,
            const_cast<PUCHAR>(reinterpret_cast<const PUCHAR>(publicKeyPEM.data())),
            static_cast<ULONG>(publicKeyPEM.size()), 0);
        if (!BCRYPT_SUCCESS(status)) break;

        // 准备 OAEP 填充信息
        BCRYPT_OAEP_PADDING_INFO oaepPaddingInfo;
        oaepPaddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaepPaddingInfo.pbLabel = nullptr;
        oaepPaddingInfo.cbLabel = 0;

        // 计算加密后大小
        ULONG cbResult = 0;
        status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext),
            static_cast<ULONG>(plaintextLen), &oaepPaddingInfo, nullptr, 0,
            nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
        if (!BCRYPT_SUCCESS(status)) break;

        // 分配输出缓冲区
        ciphertext.resize(cbResult);

        // 执行加密
        status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext),
            static_cast<ULONG>(plaintextLen), &oaepPaddingInfo, nullptr, 0,
            ciphertext.data(), cbResult, &cbResult, BCRYPT_PAD_OAEP);

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
#else
    // OpenSSL RSA 实现
    BIO* bio = BIO_new_mem_buf(publicKeyPEM.data(), static_cast<int>(publicKeyPEM.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);

    if (!ctx) return false;

    bool success = false;
    do {
        if (EVP_PKEY_encrypt_init(ctx) != 1) break;
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) break;
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) break;

        // 计算加密后大小
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, plaintextLen) != 1) break;

        // 分配输出缓冲区
        ciphertext.resize(outlen);

        // 执行加密
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext, plaintextLen) != 1) break;

        ciphertext.resize(outlen);
        success = true;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    return success;
#endif
}

bool SecureChannel::RsaDecrypt(const std::string& privateKeyPEM,
                                const std::vector<uint8_t>& ciphertext,
                                std::vector<uint8_t>& plaintext) {
#ifdef _WIN32
    // Windows CNG RSA 实现
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) break;

        // 解析 PEM 私钥（简化实现）
        status = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, &hKey,
            const_cast<PUCHAR>(reinterpret_cast<const PUCHAR>(privateKeyPEM.data())),
            static_cast<ULONG>(privateKeyPEM.size()), 0);
        if (!BCRYPT_SUCCESS(status)) break;

        // 准备 OAEP 填充信息
        BCRYPT_OAEP_PADDING_INFO oaepPaddingInfo;
        oaepPaddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaepPaddingInfo.pbLabel = nullptr;
        oaepPaddingInfo.cbLabel = 0;

        // 计算解密后大小
        ULONG cbResult = 0;
        status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()), &oaepPaddingInfo, nullptr, 0,
            nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
        if (!BCRYPT_SUCCESS(status)) break;

        // 分配输出缓冲区
        plaintext.resize(cbResult);

        // 执行解密
        status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()), &oaepPaddingInfo, nullptr, 0,
            plaintext.data(), cbResult, &cbResult, BCRYPT_PAD_OAEP);

    } while (false);

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
#else
    // OpenSSL RSA 实现
    BIO* bio = BIO_new_mem_buf(privateKeyPEM.data(), static_cast<int>(privateKeyPEM.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);

    if (!ctx) return false;

    bool success = false;
    do {
        if (EVP_PKEY_decrypt_init(ctx) != 1) break;
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) break;
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1) break;

        // 计算解密后大小
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) != 1) break;

        // 分配输出缓冲区
        plaintext.resize(outlen);

        // 执行解密
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1) break;

        plaintext.resize(outlen);
        success = true;
    } while (false);

    EVP_PKEY_CTX_free(ctx);
    return success;
#endif
}

// ============================================================
// Encrypt - 混合加密入口
// ============================================================

EncryptedPayload SecureChannel::Encrypt(const std::string& plaintext,
                                         const std::string& rsaPublicKeyPEM) {
    EncryptedPayload result;

    // 1. 生成随机会话密钥（栈分配）
    alignas(32) uint8_t sessionKey[AES256_KEY_LEN];
    if (!GenerateRandomBytes(sessionKey, AES256_KEY_LEN)) {
        result.error = "Failed to generate session key";
        return result;
    }

    // 2. 生成随机 IV
    alignas(16) uint8_t iv[AES_GCM_IV_LEN];
    if (!GenerateRandomBytes(iv, AES_GCM_IV_LEN)) {
        SecureErase(sessionKey, AES256_KEY_LEN);
        result.error = "Failed to generate IV";
        return result;
    }

    // 3. AES-256-GCM 加密业务数据
    std::vector<uint8_t> ciphertext;
    alignas(16) uint8_t tag[AES_GCM_TAG_LEN];

    if (!AesGcmEncrypt(sessionKey, iv, plaintext, ciphertext, tag)) {
        SecureErase(sessionKey, AES256_KEY_LEN);
        result.error = "AES-GCM encryption failed";
        return result;
    }

    // 4. RSA-2048 加密会话密钥
    std::vector<uint8_t> encryptedSessionKey;
    if (!RsaEncrypt(rsaPublicKeyPEM, sessionKey, AES256_KEY_LEN, encryptedSessionKey)) {
        SecureErase(sessionKey, AES256_KEY_LEN);
        result.error = "RSA encryption failed";
        return result;
    }

    // 5. 拼接：[RSA密文] + [IV] + [Ciphertext] + [Tag]
    std::vector<uint8_t> combined;
    combined.reserve(encryptedSessionKey.size() + AES_GCM_IV_LEN + ciphertext.size() + AES_GCM_TAG_LEN);
    combined.insert(combined.end(), encryptedSessionKey.begin(), encryptedSessionKey.end());
    combined.insert(combined.end(), iv, iv + AES_GCM_IV_LEN);
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
    combined.insert(combined.end(), tag, tag + AES_GCM_TAG_LEN);

    // 6. Base64 编码
    result.base64Data = Base64Encode(combined.data(), combined.size());
    result.rawLength = combined.size();
    result.success = true;

    // 7. 阅后即焚：擦除会话密钥
    SecureErase(sessionKey, AES256_KEY_LEN);

    return result;
}

// ============================================================
// Decrypt - 混合解密入口
// ============================================================

DecryptedPayload SecureChannel::Decrypt(const std::string& encryptedJson,
                                         const std::string& rsaPrivateKeyPEM) {
    DecryptedPayload result;

    // 1. 提取 data 字段
    std::string base64Data;
    if (!ExtractDataField(encryptedJson, base64Data)) {
        result.error = "Failed to extract data field from JSON";
        return result;
    }

    // 2. Base64 解码
    std::vector<uint8_t> decoded = Base64Decode(base64Data);
    if (decoded.empty()) {
        result.error = "Base64 decode failed";
        return result;
    }

    // 3. 提取 RSA 密文（前 256 字节）
    if (decoded.size() < RSA2048_CIPHER_LEN + AES_GCM_IV_LEN + AES_GCM_TAG_LEN) {
        result.error = "Ciphertext too short";
        return result;
    }

    std::vector<uint8_t> encryptedSessionKey(decoded.begin(), decoded.begin() + RSA2048_CIPHER_LEN);

    // 4. RSA 私钥解密还原会话密钥（栈分配）
    alignas(32) uint8_t sessionKey[AES256_KEY_LEN];
    std::vector<uint8_t> decryptedSessionKey;

    if (!RsaDecrypt(rsaPrivateKeyPEM, encryptedSessionKey, decryptedSessionKey)) {
        result.error = "RSA decryption failed";
        return result;
    }

    if (decryptedSessionKey.size() != AES256_KEY_LEN) {
        result.error = "Invalid session key size";
        return result;
    }

    std::memcpy(sessionKey, decryptedSessionKey.data(), AES256_KEY_LEN);
    SecureErase(decryptedSessionKey.data(), decryptedSessionKey.size());

    // 5. 提取 IV
    const uint8_t* iv = decoded.data() + RSA2048_CIPHER_LEN;

    // 6. 提取 Ciphertext + Tag
    const uint8_t* ciphertextStart = iv + AES_GCM_IV_LEN;
    size_t ciphertextLen = decoded.size() - RSA2048_CIPHER_LEN - AES_GCM_IV_LEN;

    if (ciphertextLen < AES_GCM_TAG_LEN) {
        SecureErase(sessionKey, AES256_KEY_LEN);
        result.error = "Invalid ciphertext length";
        return result;
    }

    std::vector<uint8_t> ciphertext(ciphertextStart, ciphertextStart + ciphertextLen - AES_GCM_TAG_LEN);
    const uint8_t* tag = ciphertextStart + ciphertextLen - AES_GCM_TAG_LEN;

    // 7. AES-256-GCM 解密还原业务数据
    if (!AesGcmDecrypt(sessionKey, iv, ciphertext, tag, result.plaintext)) {
        SecureErase(sessionKey, AES256_KEY_LEN);
        result.error = "AES-GCM decryption failed (MAC verification error)";
        return result;
    }

    result.success = true;

    // 8. 阅后即焚：擦除会话密钥
    SecureErase(sessionKey, AES256_KEY_LEN);

    return result;
}

} // namespace csc