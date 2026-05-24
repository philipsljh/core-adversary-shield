/**
 * @file CryptoCore.h
 * @brief CN: 加密核心模块 - 安全密钥上下文管理与密码学原语 | EN: Cryptographic core module - Secure key context management and cryptographic primitives
 *
 * CN: 企业级应用加固组件 - 密钥生命周期管理
 * EN: Enterprise-grade application hardening component - Key lifecycle management.
 *
 * CN: 核心安全特性:
 * EN: Core security features:
 * 1. CN: VirtualLock 防分页 - 防止密钥被交换到页面文件 | EN: VirtualLock anti-paging - Prevents keys from being swapped to pagefile
 * 2. CN: volatile 清零 - 对抗编译器优化，确保内存擦除不被省略 | EN: volatile zeroing - Counters compiler optimization to ensure memory wipe is not elided
 * 3. CN: 使用 std::array 替代 QByteArray - 避免写时复制（隐式共享）风险 | EN: std::array instead of QByteArray - Avoids Copy-on-Write (implicit sharing) risks
 * 4. CN: fromRawData 零拷贝 - 不触发堆内存分配 | EN: fromRawData zero-copy - Does not trigger heap memory allocation
 * 5. CN: 调试器检测 - 检测到调试器时自动投毒密钥（可选）| EN: Debugger detection - Automatically poisons keys when debugger is detected (optional)
 * 6. CN: 连坐擦除 - 密钥摄入时擦除源明文 | EN: Cascade sanitization - Erases source plaintext upon key ingestion
 *
 * CN: 设计原则:
 * EN: Design principles:
 * - CN: 密钥永不在内存中长期驻留，使用后立即销毁 | EN: Keys are never persisted in memory long-term; destroyed immediately after use
 * - CN: 所有敏感操作在栈内存中完成，避免堆残留 | EN: All sensitive operations complete in stack memory to avoid heap residue
 * - CN: 删除拷贝和赋值，防止意外的内存复制 | EN: Copy and assignment are deleted to prevent inadvertent memory duplication
 */

#pragma once

#include <array>
#include <atomic>
#include <random>
#include <cstdint>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#endif

// ============================================================
// CN: 安全日志宏 - 生产模式下物理擦除 | EN: Secure logging macro - Physically wiped in production mode
// ============================================================
#ifdef ENABLE_DEV_SECRET
    #define DEV_LOG(msg) ((void)0)  // CN: 开发模式下可启用日志 | EN: Logging can be enabled in development mode
#else
    #define DEV_LOG(msg) ((void)0)  // CN: 生产模式下日志被物理擦除 | EN: Logging is physically wiped in production mode
#endif

// ============================================================
// CN: 安全内存擦除工具函数 | EN: Secure memory wipe utility functions
// ============================================================

/**
 * @brief CN: 安全内存擦除 - 对抗编译器优化 | EN: Secure memory wipe - Counters compiler optimization
 *
 * CN: 使用 SecureZeroMemory (Windows) 或等效实现
 * EN: Uses SecureZeroMemory (Windows) or equivalent implementation
 * CN: 确保编译器不会将 memset 调用优化掉
 * EN: to ensure the compiler does not optimize away the memset call.
 *
 * @param ptr CN: 要擦除的内存指针 | EN: Pointer to memory to wipe
 * @param size CN: 要擦除的内存大小（字节）| EN: Size of memory to wipe (bytes)
 */
inline void SecureMemoryWipe(void* ptr, size_t size) {
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    // CN: POSIX 兼容实现：使用 volatile 指针防止优化 | EN: POSIX-compatible implementation: Uses volatile pointer to prevent optimization
    volatile unsigned char* p = reinterpret_cast<unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
#endif
}

// ============================================================
// CN: SecureKeyContext - 安全密钥上下文 | EN: SecureKeyContext - Secure key context
// ============================================================

/**
 * @brief CN: SecureKeyContext - 增强型安全密钥上下文 | EN: SecureKeyContext - Enhanced secure key context
 *
 * CN: 核心原则：明文密钥永不在内存中长期驻留，使用后立即销毁
 * EN: Core principle: Plaintext keys are never persisted in memory long-term; destroyed immediately after use.
 *
 * CN: 使用场景:
 * EN: Use cases:
 * - CN: AES 会话密钥的临时存储 | EN: Temporary storage of AES Session Keys
 * - CN: ECDH 共享密钥的临时存储 | EN: Temporary storage of ECDH shared secrets
 * - CN: 任何需要短期内存存储的敏感密钥材料 | EN: Any sensitive key material requiring short-term in-memory storage
 *
 * CN: 安全架构:
 * EN: Security architecture:
 * - CN: 密钥以 XOR 混淆形式存储在 shadowBuffer 中 | EN: Keys are stored in XOR-obfuscated form in shadowBuffer
 * - CN: 每次访问时动态还原，使用后立即擦除 | EN: Dynamically restored on each access and wiped immediately after use
 * - CN: 内存页面被锁定，防止交换到磁盘 | EN: Memory pages are locked to prevent swapping to disk
 */
class SecureKeyContext {
private:
    std::array<uint8_t, 32> shadowBuffer;  // CN: 混淆密文存储 | EN: Obfuscated ciphertext storage
    std::array<uint8_t, 32> entropyMask;   // CN: 随机掩码（用于 XOR 混淆）| EN: Random mask (for XOR obfuscation)
    std::atomic<bool> isArmed{false};      // CN: 密钥是否已注入 | EN: Whether key has been injected
    bool m_lockedShadow = false;           // CN: shadowBuffer 是否已锁定 | EN: Whether shadowBuffer is locked
    bool m_lockedEntropy = false;          // CN: entropyMask 是否已锁定 | EN: Whether entropyMask is locked

    /**
     * @brief CN: 生成密码学安全的随机熵 | EN: Generate cryptographically secure random entropy
     *
     * CN: 使用 BCryptGenRandom (Windows) 或 std::random_device（回退方案）
     * EN: Uses BCryptGenRandom (Windows) or std::random_device (fallback).
     */
    void generateEntropy() {
#ifdef _WIN32
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (BCRYPT_SUCCESS(status)) {
            BCryptGenRandom(hAlg, entropyMask.data(), 32, 0);
            BCryptCloseAlgorithmProvider(hAlg, 0);
        } else {
            // CN: 回退方案：使用 std::random_device | EN: Fallback: Use std::random_device
            std::random_device rd;
            for (auto& byte : entropyMask) {
                byte = static_cast<uint8_t>(rd());
            }
        }
#else
        std::random_device rd;
        for (auto& byte : entropyMask) {
            byte = static_cast<uint8_t>(rd());
        }
#endif
    }

public:
    SecureKeyContext() {
        shadowBuffer.fill(0);
        entropyMask.fill(0);

#ifdef _WIN32
        // CN: 锁定内存页面，防止交换到页面文件 | EN: Lock memory pages to prevent swapping to pagefile
        if (VirtualLock(shadowBuffer.data(), 32)) {
            m_lockedShadow = true;
        }
        if (VirtualLock(entropyMask.data(), 32)) {
            m_lockedEntropy = true;
        }
#endif
    }

    ~SecureKeyContext() {
        reset();

#ifdef _WIN32
        if (m_lockedShadow) {
            VirtualUnlock(shadowBuffer.data(), 32);
            m_lockedShadow = false;
        }
        if (m_lockedEntropy) {
            VirtualUnlock(entropyMask.data(), 32);
            m_lockedEntropy = false;
        }
#endif
    }

    // CN: 删除拷贝和赋值，防止意外的内存复制 | EN: Copy and assignment deleted to prevent inadvertent memory duplication
    SecureKeyContext(const SecureKeyContext&) = delete;
    SecureKeyContext& operator=(const SecureKeyContext&) = delete;

    /**
     * @brief CN: 注入密钥 - 混淆并立即擦除源数据 | EN: Inject key - Obfuscate and immediately wipe the source
     *
     * @param rawKey CN: 原始密钥数据（32 字节）| EN: Raw key data (32 bytes)
     * @note CN: 调用后 rawKey 的内容将被安全擦除 | EN: The contents of rawKey will be securely wiped after this call
     */
    void armKey(const uint8_t* rawKey, size_t size) {
        if (size != 32) return;

        generateEntropy();
        for (size_t i = 0; i < 32; ++i) {
            shadowBuffer[i] = rawKey[i] ^ entropyMask[i];
        }
        isArmed.store(true, std::memory_order_release);

        // CN: 连坐擦除：擦除调用方传入的明文 | EN: Cascade sanitization: Wipe the plaintext passed in by the caller
        SecureMemoryWipe(const_cast<uint8_t*>(rawKey), 32);
    }

    /**
     * @brief CN: 执行受保护的业务逻辑 | EN: Execute protected business logic
     *
     * CN: 在栈上还原明文密钥，业务逻辑执行完毕后立即擦除
     * EN: Restores plaintext key on the stack, wipes immediately after business logic execution.
     *
     * @tparam Func CN: 业务逻辑函数对象 | EN: Business logic function object
     * @param businessLogic CN: 接收明文密钥的回调函数 | EN: Callback function that receives the plaintext key
     * @return CN: 业务逻辑执行结果 | EN: Result of business logic execution
     */
    template <typename Func>
    bool executeGuarded(Func businessLogic) {
        if (!isArmed.load(std::memory_order_acquire)) return false;

        // CN: 在栈上还原明文（仅存在于当前栈帧）| EN: Restore plaintext on stack (exists only in the current stack frame)
        alignas(32) uint8_t volatileKey[32];
        for (size_t i = 0; i < 32; ++i) {
            volatileKey[i] = shadowBuffer[i] ^ entropyMask[i];
        }

        // CN: 将还原后的明文传递给业务逻辑 | EN: Pass the restored plaintext to business logic
        bool result = businessLogic(volatileKey, 32);

        // CN: 业务完成，立即物理擦除栈内存 | EN: Business complete, immediately physically wipe stack memory
        SecureMemoryWipe(volatileKey, 32);

        return result;
    }

    /**
     * @brief CN: 检查是否已初始化 | EN: Check if initialized
     * @return CN: true 表示密钥已注入 | EN: true if key has been injected
     */
    bool isReady() const {
        return isArmed.load(std::memory_order_acquire);
    }

    /**
     * @brief CN: 重置上下文 - 断开连接时调用 | EN: Reset context - Called on disconnect
     */
    void reset() {
        isArmed.store(false, std::memory_order_release);
        SecureMemoryWipe(shadowBuffer.data(), 32);
        SecureMemoryWipe(entropyMask.data(), 32);
    }
};

// ============================================================
// CN: CryptoCore - 密码学原语接口 | EN: CryptoCore - Cryptographic primitive interface
// ============================================================

/**
 * @brief CN: CryptoCore - 加解密核心模块 | EN: CryptoCore - Encryption/decryption core module
 *
 * CN: 核心职责:
 * EN: Core responsibilities:
 * - CN: AES-256-GCM 对称加解密 | EN: AES-256-GCM symmetric encryption/decryption
 * - CN: 本地数据加密存储 | EN: Local data encrypted storage
 * - CN: 密钥派生（PBKDF2）| EN: Key derivation (PBKDF2)
 *
 * CN: 职责边界:
 * EN: Responsibility boundaries:
 * - CN: 负责：本地数据加解密 | EN: Responsible: Local data encryption/decryption
 * - CN: 不负责：网络传输加密（由 ProtocolGateway 处理）| EN: Not responsible: Network transport encryption (handled by ProtocolGateway)
 */
class CryptoCore {
public:
    /**
     * @brief CN: AES-256-GCM 加密 | EN: AES-256-GCM encryption
     *
     * @param plaintext CN: 明文数据 | EN: Plaintext data
     * @param key CN: 加密密钥（32 字节）| EN: Encryption key (32 bytes)
     * @return CN: 密文（包含 IV 和 Tag，Base64 编码）| EN: Ciphertext (includes IV and Tag, Base64 encoded)
     */
    static std::string Encrypt(const std::string& plaintext, const std::string& key);

    /**
     * @brief CN: AES-256-GCM 解密 | EN: AES-256-GCM decryption
     *
     * @param base64Cipher CN: Base64 编码的密文（包含 IV 和 Tag）| EN: Base64-encoded ciphertext (includes IV and Tag)
     * @param key CN: 解密密钥（32 字节）| EN: Decryption key (32 bytes)
     * @return CN: 解密后的明文 | EN: Decrypted plaintext
     */
    static std::string Decrypt(const std::string& base64Cipher, const std::string& key);

    /**
     * @brief CN: 生成随机密钥（32 字节）| EN: Generate random key (32 bytes)
     * @return CN: 随机密钥 | EN: Random key
     */
    static std::string GenerateKey();

    /**
     * @brief CN: 从密码派生密钥（PBKDF2）| EN: Derive key from password (PBKDF2)
     *
     * @param password CN: 用户密码 | EN: User password
     * @param salt CN: 盐值（16 字节）| EN: Salt value (16 bytes)
     * @param iterations CN: 迭代次数（默认 100000）| EN: Iteration count (default 100000)
     * @return CN: 派生密钥（32 字节）| EN: Derived key (32 bytes)
     */
    static std::string DeriveKeyFromPassword(const std::string& password, const std::string& salt, int iterations = 100000);

    /**
     * @brief CN: 生成随机盐值（16 字节）| EN: Generate random salt (16 bytes)
     * @return CN: 随机盐值 | EN: Random salt
     */
    static std::string GenerateSalt();
};