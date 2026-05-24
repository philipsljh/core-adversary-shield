/**
 * @file RuntimeEnvironmentValidator.h
 * @brief CN: 运行环境验证层 | EN: Runtime Environment Validator
 *
 * CN: 本模块实现了白皮书中定义的反调试、内存投毒与环境检测逻辑。
 * EN: This module implements anti-debugging, memory poisoning, and environment detection logic defined in the white paper.
 *
 * CN: 核心设计哲学:
 * EN: Core design philosophy:
 * - CN: XOR 混淆密钥存储：shadowBuffer[32] + entropyMask[32]，栈帧内还原，阅后即焚 | EN: XOR obfuscated key storage: shadowBuffer[32] + entropyMask[32], restored within stack frame, annihilated after use
 * - CN: 延迟随机投毒：检测到调试器后延迟 3~8 次心跳触发内存投毒 | EN: Delayed random poisoning: Triggers memory poisoning 3-8 heartbeats after debugger detection
 * - CN: API 动态符号解析：通过预计算哈希值动态解析系统 API 地址（骨架实现）| EN: Dynamic API symbol resolution: Dynamically resolves system API addresses via precomputed hashes (skeleton implementation)
 *
 * CN: 使用示例:
 * EN: Usage example:
 * @code
 * RuntimeEnvironmentValidator validator;
 * if (validator.validate() == EnvironmentState::COMPROMISED) {
 *     // CN: 环境已被污染，停止敏感操作 | EN: Environment compromised, stop sensitive operations
 *     return;
 * }
 * @endcode
 */

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef _WIN32
#include <windows.h>
#endif

namespace csc {

// ============================================================================
// CN: 枚举定义 | EN: Enum Definitions
// ============================================================================

/**
 * @brief CN: 环境状态枚举 | EN: Environment state enum
 */
enum class EnvironmentState {
    CLEAN,       ///< CN: 环境安全 | EN: Environment secure
    SUSPICIOUS,  ///< CN: 可疑（检测到调试器但未投毒）| EN: Suspicious (debugger detected but not poisoned)
    COMPROMISED  ///< CN: 已污染（已投毒，通信密钥已损坏）| EN: Compromised (poisoned, communication key corrupted)
};

/**
 * @brief CN: 投毒状态枚举 | EN: Poison state enum
 */
enum class PoisonState {
    CLEAN,     ///< CN: 未检测到威胁 | EN: No threat detected
    DETECTED,  ///< CN: 检测到调试器（计数累加中）| EN: Debugger detected (count accumulating)
    POISONED   ///< CN: 已执行投毒 | EN: Poisoning executed
};

// ============================================================================
// CN: XorKeyStorage - XOR 混淆密钥存储 | EN: XorKeyStorage - XOR Obfuscated Key Storage
// ============================================================================

/**
 * @brief CN: XOR 混淆密钥存储上下文 | EN: XOR obfuscated key storage context
 *
 * CN: 核心机制:
 * EN: Core mechanism:
 * - CN: shadowBuffer[32]: 存储 key[i] ^ entropyMask[i] 的混淆结果 | EN: shadowBuffer[32]: Stores obfuscated result of key[i] ^ entropyMask[i]
 * - CN: entropyMask[32]: 随机生成的掩码，用于混淆/还原密钥 | EN: entropyMask[32]: Randomly generated mask for key obfuscation/restoration
 * - CN: recoverKey(): 在栈帧内执行 XOR 还原，使用后立即 SecureZeroMemory | EN: recoverKey(): Performs XOR restoration within stack frame, SecureZeroMemory after use
 * - CN: poison(): 比特位翻转投毒，使后续 recoverKey() 返回脏数据 | EN: poison(): Bit-flip poisoning causes subsequent recoverKey() to return corrupted data
 *
 * CN: 内存安全:
 * EN: Memory safety:
 * - CN: 所有敏感数据在析构时强制擦除 | EN: All sensitive data forcibly erased on destruction
 * - CN: 使用 SecureZeroMemory 防止编译器优化 | EN: Uses SecureZeroMemory to prevent compiler optimization
 */
class XorKeyStorage {
public:
    XorKeyStorage();
    ~XorKeyStorage();

    /**
     * @brief CN: 存储密钥（XOR 混淆）| EN: Store key (XOR obfuscation)
     * @param key CN: 原始密钥指针 | EN: Raw key pointer
     * @param length CN: 密钥长度（最大 32 字节）| EN: Key length (max 32 bytes)
     */
    void storeKey(const uint8_t* key, size_t length);

    /**
     * @brief CN: 还原密钥（XOR 逆运算）| EN: Restore key (XOR inverse operation)
     * @param outBuffer CN: 输出缓冲区（调用方负责在使用后擦除）| EN: Output buffer (caller responsible for erasure after use)
     * @param outLength CN: 输出缓冲区长度 | EN: Output buffer length
     * @return CN: bool 是否成功还原 | EN: bool Whether restoration succeeded
     */
    bool recoverKey(uint8_t* outBuffer, size_t outLength);

    /**
     * @brief CN: 执行比特位翻转投毒 | EN: Execute bit-flip poisoning
     *
     * CN: 投毒后，后续调用 recoverKey() 将返回损坏的密钥，使后续加密/解密操作自然失败，不直接崩溃暴露检测逻辑。
     * EN: After poisoning, subsequent recoverKey() calls return corrupted keys, causing subsequent encryption/decryption operations to fail naturally without directly crashing and exposing detection logic.
     */
    void poison();

    /**
     * @brief CN: 安全擦除所有敏感数据 | EN: Securely erase all sensitive data
     */
    void secureErase();

    /**
     * @brief CN: 获取已存储密钥长度 | EN: Get stored key length
     */
    size_t getStoredLength() const { return storedLength; }

private:
    uint8_t shadowBuffer[32];  ///< CN: XOR 混淆存储缓冲区 | EN: XOR obfuscated storage buffer
    uint8_t entropyMask[32];   ///< CN: 随机掩码 | EN: Random mask
    size_t storedLength;       ///< CN: 已存储密钥长度 | EN: Stored key length
};

// ============================================================================
// CN: MemoryPoisoning - 延迟随机投毒计数器 | EN: MemoryPoisoning - Delayed Random Poisoning Counter
// ============================================================================

/**
 * @brief CN: 内存投毒计数器 | EN: Memory poisoning counter
 *
 * CN: 核心机制:
 * EN: Core mechanism:
 * - CN: 每次心跳调用 onHeartbeatTick() 检测调试器 | EN: Calls onHeartbeatTick() each heartbeat to detect debugger
 * - CN: 检测到调试器时累加计数器 | EN: Increments counter when debugger detected
 * - CN: 计数器达到随机阈值（3~8 次）时执行投毒 | EN: Executes poisoning when counter reaches random threshold (3-8)
 * - CN: 投毒后 isCompromised() 返回 true | EN: Returns true from isCompromised() after poisoning
 *
 * CN: 设计目的:
 * EN: Design purpose:
 * - CN: 延迟投毒防止逆向工程师通过断点定位检测逻辑 | EN: Delayed poisoning prevents reverse engineers from locating detection logic via breakpoints
 * - CN: 随机阈值防止通过固定次数绕过 | EN: Random threshold prevents bypassing via fixed counts
 */
class MemoryPoisoning {
public:
    MemoryPoisoning();
    ~MemoryPoisoning();

    /**
     * @brief CN: 心跳 tick 调用 | EN: Heartbeat tick call
     * @return CN: PoisonState 当前投毒状态 | EN: PoisonState Current poisoning state
     */
    PoisonState onHeartbeatTick();

    /**
     * @brief CN: 检查环境是否已被污染 | EN: Check if environment has been compromised
     * @return CN: bool true = 已投毒，环境不可信 | EN: bool true = poisoned, environment untrusted
     */
    bool isCompromised() const;

    /**
     * @brief CN: 获取当前检测计数 | EN: Get current detection count
     */
    uint8_t getDetectionCount() const;

    /**
     * @brief CN: 获取投毒阈值 | EN: Get poisoning threshold
     */
    uint8_t getThreshold() const;

private:
    bool checkDebugger();

    volatile uint8_t detectionCount;   ///< CN: 检测计数（volatile 防优化）| EN: Detection count (volatile prevents optimization)
    volatile uint8_t poisonThreshold;  ///< CN: 随机投毒阈值（3~8）| EN: Random poisoning threshold (3-8)
    volatile bool isPoisoned;          ///< CN: 是否已投毒 | EN: Whether poisoned
};

// ============================================================================
// CN: RuntimeEnvironmentValidator - 主验证器 | EN: RuntimeEnvironmentValidator - Main Validator
// ============================================================================

/**
 * @brief CN: 运行环境验证器 | EN: Runtime environment validator
 *
 * CN: 整合 SecureKeyContext 和 MemoryPoisoning，提供统一的环境验证接口。
 * EN: Integrates SecureKeyContext and MemoryPoisoning to provide a unified environment validation interface.
 *
 * CN: 使用方式:
 * EN: Usage:
 * @code
 * RuntimeEnvironmentValidator validator;
 *
 * // CN: 每次心跳调用 | EN: Call each heartbeat
 * EnvironmentState state = validator.validate();
 * if (state == EnvironmentState::COMPROMISED) {
 *     // CN: 环境已污染，停止敏感操作 | EN: Environment compromised, stop sensitive operations
 *     return;
 * }
 *
 * // CN: 程序退出时 | EN: On program exit
 * validator.secureErase();
 * @endcode
 */
class RuntimeEnvironmentValidator {
public:
    RuntimeEnvironmentValidator();
    ~RuntimeEnvironmentValidator();

    /**
     * @brief CN: 执行环境验证 | EN: Execute environment validation
     * @return CN: EnvironmentState 环境状态 | EN: EnvironmentState Environment state
     */
    EnvironmentState validate();

    /**
     * @brief CN: 检查环境是否安全 | EN: Check if environment is secure
     * @return CN: bool true = 安全 | EN: bool true = secure
     */
    bool isSafe() const;

    /**
     * @brief CN: 安全擦除所有敏感数据 | EN: Securely erase all sensitive data
     */
    void secureErase();

private:
    MemoryPoisoning* m_poisoning;
};

// ============================================================================
// CN: 辅助函数 | EN: Helper Functions
// ============================================================================

/**
 * @brief CN: 强制内存擦除 | EN: Force memory erasure
 * @param ptr CN: 内存指针 | EN: Memory pointer
 * @param size CN: 字节数 | EN: Number of bytes
 */
void SecureErase(void* ptr, size_t size);

} // namespace csc