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
    // CN: 显式定义 NTSTATUS 失败码，防止某些 Windows SDK 版本中 STATUS_UNSUCCESSFUL 未声明导致编译阻断
    // EN: Explicitly define NTSTATUS failure code to prevent compilation blocker when STATUS_UNSUCCESSFUL is undeclared in some Windows SDK versions
    #ifndef STATUS_UNSUCCESSFUL
    #define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
    #endif
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
    NTSTATUS ivStatus = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(const_cast<char*>(iv.data())),
        12,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(ivStatus)) {
        return std::string();
    }
#else
    if (RAND_bytes(reinterpret_cast<unsigned char*>(const_cast<char*>(iv.data())), 12) != 1) {
        return std::string();
    }
#endif

    // CN: 计算并分配完整的全额缓冲区：12字节 IV + 明文长度 + 16字节 GCM Tag
    // EN: Calculate and allocate the full final payload buffer: 12-byte IV + plaintext length + 16-byte GCM Tag
    size_t cipherLen = plaintext.size();
    std::string finalPayload;
    finalPayload.resize(12 + cipherLen + 16);
    
#ifdef _WIN32
    // CN: 拷贝 IV 到 finalPayload 起始位置
    // EN: Copy IV to the start of finalPayload
    memcpy(&finalPayload[0], iv.data(), 12);
    
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG cbResult = 0;
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
        authInfo.pbNonce = reinterpret_cast<PUCHAR>(&finalPayload[0]);
        authInfo.cbNonce = 12;
        authInfo.pbTag = reinterpret_cast<PUCHAR>(&finalPayload[12 + cipherLen]);
        authInfo.cbTag = 16;
        
        status = BCryptEncrypt(hKey, 
            reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())), 
            static_cast<ULONG>(cipherLen),
            &authInfo, nullptr, 0, 
            reinterpret_cast<PUCHAR>(&finalPayload[12]), 
            static_cast<ULONG>(cipherLen), 
            &cbResult, 0);
        
    } while (false);
    
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
    
    return Base64Encode(reinterpret_cast<const uint8_t*>(finalPayload.data()), finalPayload.size());
#else
    // CN: OpenSSL 分支：使用绝对坐标布局
    // EN: OpenSSL branch: Use absolute coordinate layout
    std::string opensslPayload;
    opensslPayload.resize(12 + cipherLen + 16);
    memcpy(&opensslPayload[0], iv.data(), 12);
    
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
    
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&opensslPayload[12]), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(cipherLen)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&opensslPayload[12]) + ciphertext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    ciphertext_len += len;
    
    // CN: 获取 GCM tag | EN: Get GCM tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, reinterpret_cast<unsigned char*>(&opensslPayload[12 + ciphertext_len]));
    
    EVP_CIPHER_CTX_free(ctx);
    
    return Base64Encode(reinterpret_cast<const uint8_t*>(opensslPayload.data()), opensslPayload.size());
#endif
}

std::string CryptoCore::Decrypt(const std::string& base64Cipher, const std::string& key) {
    if (key.size() != 32) {
        return std::string();
    }

    // CN: Base64 解码 | EN: Base64 decode
    auto decoded = Base64Decode(base64Cipher);

    // CN: 基础长度合法性边界检查，负载必须大于 IV(12) + Tag(16)
    // EN: Fundamental length validity boundary check; payload must be larger than IV(12) + Tag(16)
    if (decoded.size() < 28) {
        return std::string();
    }

    // CN: 计算纯密文长度：总长度 - 12字节 IV - 16字节 Tag
    // EN: Calculate pure ciphertext length: total length - 12-byte IV - 16-byte Tag
    size_t cipherLen = decoded.size() - 12 - 16;

    // CN: 分配明文输出缓冲区
    // EN: Allocate plaintext output buffer
    std::string plaintext(cipherLen, '\0');

#ifdef _WIN32
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG cbResult = 0;
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
        // CN: 精准锚定 IV 坐标：从 decodedPayload[0] 读取 12 字节
        // EN: Precisely anchor IV coordinate: read 12 bytes from decodedPayload[0]
        authInfo.pbNonce = reinterpret_cast<PUCHAR>(decoded.data());
        authInfo.cbNonce = 12;
        // CN: 精准锚定 Tag 坐标：从 decodedPayload[12 + cipherLen] 读取 16 字节
        // EN: Precisely anchor Tag coordinate: read 16 bytes from decodedPayload[12 + cipherLen]
        authInfo.pbTag = reinterpret_cast<PUCHAR>(&decoded[12 + cipherLen]);
        authInfo.cbTag = 16;
        
        // CN: 精准锚定密文解密区：从 decodedPayload[12] 读取 cipherLen 字节
        // EN: Precisely anchor ciphertext decryption area: read cipherLen bytes from decodedPayload[12]
        status = BCryptDecrypt(hKey,
            reinterpret_cast<PUCHAR>(&decoded[12]),
            static_cast<ULONG>(cipherLen),
            &authInfo, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())),
            static_cast<ULONG>(cipherLen),
            &cbResult, 0);
        
    } while (false);
    
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        return std::string();
    }
    
    // CN: 解密成功后，根据返回的 cbResult 对明文传出缓冲区进行裁剪
    // EN: After successful decryption, resize the plaintext output buffer according to the returned cbResult
    plaintext.resize(static_cast<size_t>(cbResult));
#else
    // CN: OpenSSL 分支：使用绝对坐标拆解
    // EN: OpenSSL branch: Use absolute coordinate decomposition
    std::string ivStr(decoded.begin(), decoded.begin() + 12);
    std::string ciphertextStr(decoded.begin() + 12, decoded.begin() + 12 + cipherLen);
    std::string tagStr(decoded.begin() + 12 + cipherLen, decoded.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string();
    
    int len = 0;
    int plaintext_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()),
        reinterpret_cast<const unsigned char*>(ivStr.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    
    if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len,
        reinterpret_cast<const unsigned char*>(ciphertextStr.data()), ciphertextStr.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    }
    plaintext_len = len;
    
    // CN: 设置 GCM tag | EN: Set GCM tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tagStr.data()));
    
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