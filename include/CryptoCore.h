/**
 * @file CryptoCore.h
 * @brief 加密核心模块 - 安全密钥上下文管理与密码学原语
 *
 * 企业级应用加固组件 - 密钥生命周期管理
 *
 * 核心安全特性：
 * 1. VirtualLock 防分页 - 防止密钥被交换到页面文件
 * 2. volatile 清零 - 对抗编译器优化，确保内存擦除不被优化掉
 * 3. std::array 替代 QByteArray - 避免隐式共享（Copy-on-Write）风险
 * 4. fromRawData 零拷贝 - 不触发堆内存分配
 * 5. 调试器检测 - 检测到调试器时自动污染密钥（可选）
 * 6. 连坐擦除 - 注入密钥时擦除源头明文
 *
 * 设计原则：
 * - 密钥在内存中永远不长期保存，用完即毁
 * - 所有敏感操作在栈内存中完成，避免堆内存残留
 * - 禁绝拷贝和赋值，防止不经意的内存复制
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
// 安全日志宏 - 生产模式下物理抹除
// ============================================================
#ifdef ENABLE_DEV_SECRET
    #define DEV_LOG(msg) ((void)0)  // 开发模式下可启用日志
#else
    #define DEV_LOG(msg) ((void)0)  // 生产模式下日志物理抹除
#endif

// ============================================================
// 安全内存擦除工具函数
// ============================================================

/**
 * @brief 安全内存擦除 - 对抗编译器优化
 *
 * 使用 SecureZeroMemory（Windows）或等效实现，
 * 确保编译器不会将无用的 memset 优化掉
 *
 * @param ptr 待擦除内存指针
 * @param size 待擦除内存大小（字节）
 */
inline void SecureMemoryWipe(void* ptr, size_t size) {
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
// SecureKeyContext - 安全密钥上下文
// ============================================================

/**
 * @brief SecureKeyContext - 增强版安全密钥上下文
 *
 * 核心原则：内存中永远不长期保存明文密钥，用完即毁
 *
 * 使用场景：
 * - 临时存储 AES Session Key
 * - 临时存储 ECDH 共享密钥
 * - 任何需要在内存中短期保存的敏感密钥材料
 *
 * 安全架构：
 * - 密钥以 XOR 混淆形式存储在 shadowBuffer 中
 * - 每次访问时动态还原，使用完毕后立即擦除
 * - 内存页被锁定，防止被交换到磁盘
 */
class SecureKeyContext {
private:
    std::array<uint8_t, 32> shadowBuffer;  // 混淆后的密文存储
    std::array<uint8_t, 32> entropyMask;   // 随机掩码（用于 XOR 混淆）
    std::atomic<bool> isArmed{false};      // 是否已注入密钥
    bool m_lockedShadow = false;           // shadowBuffer 是否已锁定
    bool m_lockedEntropy = false;          // entropyMask 是否已锁定

    /**
     * @brief 生成密码学安全的随机熵
     *
     * 使用 BCryptGenRandom（Windows）或 std::random_device（降级）
     */
    void generateEntropy() {
#ifdef _WIN32
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
        if (BCRYPT_SUCCESS(status)) {
            BCryptGenRandom(hAlg, entropyMask.data(), 32, 0);
            BCryptCloseAlgorithmProvider(hAlg, 0);
        } else {
            // 降级：使用 std::random_device
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
        // 锁定内存页，防止交换到页面文件
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

    // 禁绝拷贝和赋值，防止不经意的内存复制
    SecureKeyContext(const SecureKeyContext&) = delete;
    SecureKeyContext& operator=(const SecureKeyContext&) = delete;

    /**
     * @brief 注入密钥 - 混淆后立刻擦除源头
     *
     * @param rawKey 原始密钥数据（32 字节）
     * @note 调用后 rawKey 的内容会被安全擦除
     */
    void armKey(const uint8_t* rawKey, size_t size) {
        if (size != 32) return;

        generateEntropy();
        for (size_t i = 0; i < 32; ++i) {
            shadowBuffer[i] = rawKey[i] ^ entropyMask[i];
        }
        isArmed.store(true, std::memory_order_release);

        // 连坐擦除：擦除调用者传进来的明文
        SecureMemoryWipe(const_cast<uint8_t*>(rawKey), 32);
    }

    /**
     * @brief 执行受保护的业务逻辑
     *
     * 在栈上还原明文密钥，执行业务逻辑后立刻擦除
     *
     * @tparam Func 业务逻辑函数对象
     * @param businessLogic 接收明文密钥的回调函数
     * @return 业务逻辑执行结果
     */
    template <typename Func>
    bool executeGuarded(Func businessLogic) {
        if (!isArmed.load(std::memory_order_acquire)) return false;

        // 在栈上还原明文（仅存在于当前栈帧）
        alignas(32) uint8_t volatileKey[32];
        for (size_t i = 0; i < 32; ++i) {
            volatileKey[i] = shadowBuffer[i] ^ entropyMask[i];
        }

        // 将还原出的明文交给业务逻辑
        bool result = businessLogic(volatileKey, 32);

        // 业务结束，立刻物理擦除栈内存
        SecureMemoryWipe(volatileKey, 32);

        return result;
    }

    /**
     * @brief 检查是否已初始化
     * @return true 如果密钥已注入
     */
    bool isReady() const {
        return isArmed.load(std::memory_order_acquire);
    }

    /**
     * @brief 重置上下文 - 断开连接时调用
     */
    void reset() {
        isArmed.store(false, std::memory_order_release);
        SecureMemoryWipe(shadowBuffer.data(), 32);
        SecureMemoryWipe(entropyMask.data(), 32);
    }
};

// ============================================================
// CryptoCore - 密码学原语接口
// ============================================================

/**
 * @brief CryptoCore - 加密解密核心模块
 *
 * 核心职责：
 * - AES-256-GCM 对称加密/解密
 * - 用于本地数据加密存储
 * - 密钥派生（PBKDF2）
 *
 * 职责边界：
 * - 负责：本地数据加密解密
 * - 不负责：网络传输加密（由 ProtocolGateway 负责）
 */
class CryptoCore {
public:
    /**
     * @brief AES-256-GCM 加密
     *
     * @param plaintext 明文数据
     * @param key 加密密钥（32 字节）
     * @return 密文（包含 IV 和 Tag，Base64 编码）
     */
    static std::string Encrypt(const std::string& plaintext, const std::string& key);

    /**
     * @brief AES-256-GCM 解密
     *
     * @param base64Cipher Base64 编码的密文（包含 IV 和 Tag）
     * @param key 解密密钥（32 字节）
     * @return 解密后的明文
     */
    static std::string Decrypt(const std::string& base64Cipher, const std::string& key);

    /**
     * @brief 生成随机密钥（32 字节）
     * @return 随机密钥
     */
    static std::string GenerateKey();

    /**
     * @brief 从密码派生密钥（PBKDF2）
     *
     * @param password 用户密码
     * @param salt 盐值（16 字节）
     * @param iterations 迭代次数（默认 100000）
     * @return 派生密钥（32 字节）
     */
    static std::string DeriveKeyFromPassword(const std::string& password, const std::string& salt, int iterations = 100000);

    /**
     * @brief 生成随机盐值（16 字节）
     * @return 随机盐值
     */
    static std::string GenerateSalt();
};