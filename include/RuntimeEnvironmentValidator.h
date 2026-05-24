/**
 * @file RuntimeEnvironmentValidator.h
 * @brief 运行环境验证层 (Runtime Environment Validator)
 * 
 * 本模块实现了白皮书中定义的反调试、内存投毒与环境检测逻辑。
 * 
 * 核心设计哲学:
 * - XOR 混淆密钥存储：shadowBuffer[32] + entropyMask[32]，栈帧内还原，阅后即焚
 * - 延迟随机投毒：检测到调试器后延迟 3~8 次心跳触发内存投毒
 * - API 动态符号解析：通过预计算哈希值动态解析系统 API 地址（骨架实现）
 * 
 * 使用示例:
 * @code
 * RuntimeEnvironmentValidator validator;
 * if (validator.validate() == EnvironmentState::COMPROMISED) {
 *     // 环境已被污染，停止敏感操作
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
// 枚举定义
// ============================================================================

/**
 * @brief 环境状态枚举
 */
enum class EnvironmentState {
    CLEAN,       ///< 环境安全
    SUSPICIOUS,  ///< 可疑（检测到调试器但未投毒）
    COMPROMISED  ///< 已污染（已投毒，通信密钥已损坏）
};

/**
 * @brief 投毒状态枚举
 */
enum class PoisonState {
    CLEAN,     ///< 未检测到威胁
    DETECTED,  ///< 检测到调试器（计数累加中）
    POISONED   ///< 已执行投毒
};

// ============================================================================
// XorKeyStorage - XOR 混淆密钥存储
// ============================================================================

/**
 * @brief XOR 混淆密钥存储上下文
 * 
 * 核心机制:
 * - shadowBuffer[32]: 存储 key[i] ^ entropyMask[i] 的混淆结果
 * - entropyMask[32]: 随机生成的掩码，用于混淆/还原密钥
 * - recoverKey(): 在栈帧内执行 XOR 还原，使用后立即 SecureZeroMemory
 * - poison(): 比特位翻转投毒，使后续 recoverKey() 返回脏数据
 * 
 * 内存安全:
 * - 所有敏感数据在析构时强制擦除
 * - 使用 SecureZeroMemory 防止编译器优化
 */
class XorKeyStorage {
public:
    XorKeyStorage();
    ~XorKeyStorage();

    /**
     * @brief 存储密钥（XOR 混淆）
     * @param key 原始密钥指针
     * @param length 密钥长度（最大 32 字节）
     */
    void storeKey(const uint8_t* key, size_t length);

    /**
     * @brief 还原密钥（XOR 逆运算）
     * @param outBuffer 输出缓冲区（调用方负责在使用后擦除）
     * @param outLength 输出缓冲区长度
     * @return bool 是否成功还原
     */
    bool recoverKey(uint8_t* outBuffer, size_t outLength);

    /**
     * @brief 执行比特位翻转投毒
     * 
     * 投毒后，后续调用 recoverKey() 将返回损坏的密钥，
     * 使后续加密/解密操作自然失败，不直接崩溃暴露检测逻辑。
     */
    void poison();

    /**
     * @brief 安全擦除所有敏感数据
     */
    void secureErase();

    /**
     * @brief 获取已存储密钥长度
     */
    size_t getStoredLength() const { return storedLength; }

private:
    uint8_t shadowBuffer[32];  ///< XOR 混淆存储缓冲区
    uint8_t entropyMask[32];   ///< 随机掩码
    size_t storedLength;       ///< 已存储密钥长度
};

// ============================================================================
// MemoryPoisoning - 延迟随机投毒计数器
// ============================================================================

/**
 * @brief 内存投毒计数器
 * 
 * 核心机制:
 * - 每次心跳调用 onHeartbeatTick() 检测调试器
 * - 检测到调试器时累加计数器
 * - 计数器达到随机阈值（3~8 次）时执行投毒
 * - 投毒后 isCompromised() 返回 true
 * 
 * 设计目的:
 * - 延迟投毒防止逆向工程师通过断点定位检测逻辑
 * - 随机阈值防止通过固定次数绕过
 */
class MemoryPoisoning {
public:
    MemoryPoisoning();
    ~MemoryPoisoning();

    /**
     * @brief 心跳 tick 调用
     * @return PoisonState 当前投毒状态
     */
    PoisonState onHeartbeatTick();

    /**
     * @brief 检查环境是否已被污染
     * @return bool true = 已投毒，环境不可信
     */
    bool isCompromised() const;

    /**
     * @brief 获取当前检测计数
     */
    uint8_t getDetectionCount() const;

    /**
     * @brief 获取投毒阈值
     */
    uint8_t getThreshold() const;

private:
    bool checkDebugger();

    volatile uint8_t detectionCount;   ///< 检测计数（volatile 防优化）
    volatile uint8_t poisonThreshold;  ///< 随机投毒阈值（3~8）
    volatile bool isPoisoned;          ///< 是否已投毒
};

// ============================================================================
// RuntimeEnvironmentValidator - 主验证器
// ============================================================================

/**
 * @brief 运行环境验证器
 * 
 * 整合 SecureKeyContext 和 MemoryPoisoning，提供统一的环境验证接口。
 * 
 * 使用方式:
 * @code
 * RuntimeEnvironmentValidator validator;
 * 
 * // 每次心跳调用
 * EnvironmentState state = validator.validate();
 * if (state == EnvironmentState::COMPROMISED) {
 *     // 环境已污染，停止敏感操作
 *     return;
 * }
 * 
 * // 程序退出时
 * validator.secureErase();
 * @endcode
 */
class RuntimeEnvironmentValidator {
public:
    RuntimeEnvironmentValidator();
    ~RuntimeEnvironmentValidator();

    /**
     * @brief 执行环境验证
     * @return EnvironmentState 环境状态
     */
    EnvironmentState validate();

    /**
     * @brief 检查环境是否安全
     * @return bool true = 安全
     */
    bool isSafe() const;

    /**
     * @brief 安全擦除所有敏感数据
     */
    void secureErase();

private:
    MemoryPoisoning* m_poisoning;
};

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * @brief 强制内存擦除
 * @param ptr 内存指针
 * @param size 字节数
 */
void SecureErase(void* ptr, size_t size);

} // namespace csc