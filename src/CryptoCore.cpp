/**
 * @file CryptoCore.cpp
 * @brief CN: 加密核心模块实现 - 密码学原语 | EN: Cryptographic core module implementation - Cryptographic primitives
 *
 * CN: 企业级应用加固组件 - 密码学原语实现
 * EN: Enterprise-grade application hardening component - Cryptographic primitives implementation.
 *
 * CN: 注意：开源版本使用 OpenSSL 或标准库实现，生产版本可替换为硬件加速或国密算法
 * EN: Note: Open-source version uses OpenSSL or standard library; production version can be replaced with hardware acceleration or national cryptographic algorithms.
 */

#include "CryptoCore.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <openssl/evp.h>
    #include <openssl/rand.h>
#endif

// ============================================================
// CN: 工具函数：Base64 编码/解码 | EN: Utility Functions: Base64 Encode/Decode
// ============================================================

static const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string Base64Encode(const uint8_t* data, size_t len) {
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

static std::vector<uint8_t> Base64Decode(const std::string& encoded_string) {
    std::vector<uint8_t> result;
    int in_len = encoded_string.size();
    int i = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') && 
           (isalnum(encoded_string[in_]) || encoded_string[in_] == '+' || encoded_string[in_] == '/')) {
        char_array_4[i++] = encoded_string[in_]; in_++;
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
// CN: CryptoCore 实现 | EN: CryptoCore Implementation
// ============================================================

std::string CryptoCore::GenerateKey() {
    std::string key(32, '\0');
    
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
        32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
#else
    if (RAND_bytes(reinterpret_cast<unsigned char*>(const_cast<char*>(key.data())), 32) != 1) {
        return std::string();
    }
#endif
    
    return key;
}

std::string CryptoCore::GenerateSalt() {
    std::string salt(16, '\0');
    
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(const_cast<char*>(salt.data())),
        16,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
#else
    if (RAND_bytes(reinterpret_cast<unsigned char*>(const_cast<char*>(salt.data())), 16) != 1) {
        return std::string();
    }
#endif
    
    return salt;
}

std::string CryptoCore::Encrypt(const std::string& plaintext, const std::string& key) {
    if (key.size() != 32) {
        return std::string();
    }

    // CN: 生成随机 IV（12 字节用于 GCM）| EN: Generate random IV (12 bytes for GCM)
    std::string iv(12, '\0');
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(const_cast<char*>(iv.data())),
        12,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
#else
    if (RAND_bytes(reinterpret_cast<unsigned char*>(const_cast<char*>(iv.data())), 12) != 1) {
        return std::string();
    }
#endif

    // CN: 加密 | EN: Encryption
    std::string ciphertext(plaintext.size() + 16, '\0');  // +16 for GCM tag
    
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    
    do {
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) break;
        
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) break;
        
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, 
            (PUCHAR)key.data(), key.size(), 0);
        if (!BCRYPT_SUCCESS(status)) break;
        
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
        authInfo.pbNonce = (PUCHAR)iv.data();
        authInfo.cbNonce = iv.size();
        authInfo.pbTag = (PUCHAR)ciphertext.data() + plaintext.size();
        authInfo.cbTag = 16;
        
        ULONG cbResult = 0;
        status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), plaintext.size(),
            &authInfo, nullptr, 0, (PUCHAR)ciphertext.data(), ciphertext.size(), &cbResult, 0);
        
    } while (false);
    
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
    
    ciphertext.resize(plaintext.size());  // CN: 只保留 ciphertext，tag 在后面 | EN: Keep only ciphertext, tag follows
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string();
    
    int len = 0;
    int ciphertext_len = 0;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
        reinterpret_cast<const unsigned char*>(key.data()),
        reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    
    if (EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    ciphertext_len += len;
    
    // CN: 获取 GCM tag | EN: Get GCM tag
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(ciphertext_len);
    // CN: 附加 tag 到 ciphertext | EN: Append tag to ciphertext
    ciphertext.append(reinterpret_cast<char*>(tag), 16);
#endif

    // CN: 组装输出：IV + Ciphertext + Tag | EN: Assemble output: IV + Ciphertext + Tag
    std::string output = iv + ciphertext;
    return Base64Encode(reinterpret_cast<const uint8_t*>(output.data()), output.size());
}

std::string CryptoCore::Decrypt(const std::string& base64Cipher, const std::string& key) {
    if (key.size() != 32) {
        return std::string();
    }

    // CN: Base64 解码 | EN: Base64 decode
    auto decoded = Base64Decode(base64Cipher);
    if (decoded.size() < 12 + 16) {  // CN: 至少 IV(12) + Tag(16) | EN: At least IV(12) + Tag(16)
        return std::string();
    }

    // CN: 提取 IV | EN: Extract IV
    std::string iv(decoded.begin(), decoded.begin() + 12);
    
    // CN: 提取 Ciphertext + Tag | EN: Extract Ciphertext + Tag
    std::string cipherWithTag(decoded.begin() + 12, decoded.end());
    std::string ciphertext(cipherWithTag.begin(), cipherWithTag.end() - 16);
    std::string tag(cipherWithTag.end() - 16, cipherWithTag.end());

    std::string plaintext(cipherWithTag.size() - 16, '\0');

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
            (PUCHAR)key.data(), key.size(), 0);
        if (!BCRYPT_SUCCESS(status)) break;
        
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
        authInfo.pbNonce = (PUCHAR)iv.data();
        authInfo.cbNonce = iv.size();
        authInfo.pbTag = (PUCHAR)tag.data();
        authInfo.cbTag = tag.size();
        
        ULONG cbResult = 0;
        status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), ciphertext.size(),
            &authInfo, nullptr, 0, (PUCHAR)plaintext.data(), plaintext.size(), &cbResult, 0);
        
    } while (false);
    
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
    
    plaintext.resize(cbResult);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string();
    
    int len = 0;
    int plaintext_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()),
        reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    
    if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len,
        reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    plaintext_len = len;
    
    // CN: 设置 GCM tag | EN: Set GCM tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    
    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + plaintext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
#endif

    return plaintext;
}

std::string CryptoCore::DeriveKeyFromPassword(const std::string& password, const std::string& salt, int iterations) {
    std::string key(32, '\0');
    
#ifdef _WIN32
    // CN: 使用 BCrypt 的 PBKDF2 实现 | EN: Use BCrypt's PBKDF2 implementation
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_PBKDF2_ALGORITHM, nullptr, 0);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptDeriveKeyPBKDF2(hAlg,
            (PUCHAR)password.data(), password.size(),
            (PUCHAR)salt.data(), salt.size(),
            iterations,
            (PUCHAR)key.data(), key.size(),
            0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
#else
    if (PKCS5_PBKDF2_HMAC(password.data(), password.size(),
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
        iterations, EVP_sha256(),
        32, reinterpret_cast<unsigned char*>(key.data())) != 1) {
        return std::string();
    }
#endif
    
    return key;
}