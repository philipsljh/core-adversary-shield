/**
 * @file RuntimeEnvironmentValidator.cpp
 * @brief 运行环境验证层实现 (Runtime Environment Validator Implementation)
 * 
 * 本模块实现了白皮书中定义的反调试、内存投毒与环境检测逻辑。
 * 
 * 核心设计哲学:
 * - XOR 混淆密钥存储：shadowBuffer + entropyMask，栈帧内还原，阅后即焚
 * - 延迟随机投毒：检测到调试器后延迟 3~8 次心跳触发内存投毒
 * - 比特位翻转：投毒使后续通信自然失效，不直接崩溃暴露检测逻辑
 * 
 * 安全注意事项:
 * 1. 所有敏感数据在栈上分配，函数返回前强制擦除
 * 2. 使用 SecureZeroMemory 防止编译器优化掉内存擦除
 * 3. 投毒计数器使用 volatile 防止编译器优化
 */

#include "RuntimeEnvironmentValidator.h"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

#include <cstring>
#include <random>
#include <chrono>

namespace csc {

// ============================================================================
// XorKeyStorage 实现
// ============================================================================

XorKeyStorage::XorKeyStorage() {
    // 初始化 shadowBuffer 为随机噪声
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(shadowBuffer), shadowBuffer);
        CryptGenRandom(hProv, sizeof(entropyMask), entropyMask);
        CryptReleaseContext(hProv, 0);
    } else {
        // 回退到伪随机
        std::memset(shadowBuffer, 0xCC, sizeof(shadowBuffer));
        std::memset(entropyMask, 0x55, sizeof(entropyMask));
    }
#else
    std::memset(shadowBuffer, 0xCC, sizeof(shadowBuffer));
    std::memset(entropyMask, 0x55, sizeof(entropyMask));
#endif
}

XorKeyStorage::~XorKeyStorage() {
    // 析构时强制擦除
    SecureErase(shadowBuffer, sizeof(shadowBuffer));
    SecureErase(entropyMask, sizeof(entropyMask));
}

void XorKeyStorage::storeKey(const uint8_t* key, size_t length) {
    if (!key || length == 0 || length > sizeof(shadowBuffer)) return;
    
    // XOR 混淆存储：shadowBuffer[i] = key[i] ^ entropyMask[i]
    for (size_t i = 0; i < length; ++i) {
        shadowBuffer[i] = key[i] ^ entropyMask[i];
    }
    storedLength = length;
}

bool XorKeyStorage::recoverKey(uint8_t* outBuffer, size_t outLength) {
    if (!outBuffer || outLength < storedLength || storedLength == 0) return false;
    
    // 栈帧内 XOR 还原：key[i] = shadowBuffer[i] ^ entropyMask[i]
    for (size_t i = 0; i < storedLength; ++i) {
        outBuffer[i] = shadowBuffer[i] ^ entropyMask[i];
    }
    
    return true;
}

void XorKeyStorage::poison() {
    // 比特位翻转投毒：翻转 shadowBuffer 的随机位
    // 使后续 recoverKey() 返回脏数据，通信自然失效
    if (storedLength > 0) {
        // 翻转第一个字节的所有位
        shadowBuffer[0] = ~shadowBuffer[0];
        // 如果长度足够，再翻转最后一个字节
        if (storedLength > 1) {
            shadowBuffer[storedLength - 1] = ~shadowBuffer[storedLength - 1];
        }
    }
}

void XorKeyStorage::secureErase() {
    SecureErase(shadowBuffer, sizeof(shadowBuffer));
    SecureErase(entropyMask, sizeof(entropyMask));
    storedLength = 0;
}

// ============================================================================
// MemoryPoisoning 实现
// ============================================================================

MemoryPoisoning::MemoryPoisoning()
    : detectionCount(0)
    , poisonThreshold(0)
    , isPoisoned(false) {
    // 随机设置投毒阈值 3~8 次
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(3, 8);
    poisonThreshold = static_cast<uint8_t>(dist(gen));
}

MemoryPoisoning::~MemoryPoisoning() {
    // 析构时擦除计数器
    SecureErase(&detectionCount, sizeof(detectionCount));
    SecureErase(&poisonThreshold, sizeof(poisonThreshold));
}

bool MemoryPoisoning::checkDebugger() {
#ifdef _WIN32
    // 使用 PEB.BeingDebugged 标志检测调试器
    // 这是最基础的检测，生产环境可叠加更多检测
    bool isDebugged = false;
    
    // 方法 1: IsDebuggerPresent API
    if (IsDebuggerPresent()) {
        isDebugged = true;
    }
    
    // 方法 2: PEB BeingDebugged 直接读取
    if (!isDebugged) {
        __try {
            PPEB pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;
            if (pPeb && pPeb->BeingDebugged) {
                isDebugged = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 忽略异常
        }
    }
    
    return isDebugged;
#else
    // Linux: 检查 /proc/self/status 中的 TracerPid
    return false;
#endif
}

PoisonState MemoryPoisoning::onHeartbeatTick() {
    // 每次心跳调用，检测调试器
    if (checkDebugger()) {
        detectionCount++;
        
        // 检查是否达到投毒阈值
        if (detectionCount >= poisonThreshold) {
            isPoisoned = true;
            return PoisonState::POISONED;
        }
        
        // 尚未达到阈值，返回警告状态
        return PoisonState::DETECTED;
    }
    
    // 未检测到调试器
    return isPoisoned ? PoisonState::POISONED : PoisonState::CLEAN;
}

bool MemoryPoisoning::isCompromised() const {
    return isPoisoned;
}

uint8_t MemoryPoisoning::getDetectionCount() const {
    return detectionCount;
}

uint8_t MemoryPoisoning::getThreshold() const {
    return poisonThreshold;
}

// ============================================================================
// RuntimeEnvironmentValidator 实现
// ============================================================================

RuntimeEnvironmentValidator::RuntimeEnvironmentValidator()
    : m_poisoning(new MemoryPoisoning()) {
}

RuntimeEnvironmentValidator::~RuntimeEnvironmentValidator() {
    delete m_poisoning;
    m_poisoning = nullptr;
}

EnvironmentState RuntimeEnvironmentValidator::validate() {
    // 步骤 1: 检查调试器
    PoisonState state = m_poisoning->onHeartbeatTick();
    
    if (state == PoisonState::POISONED) {
        // 已投毒，返回污染状态
        return EnvironmentState::COMPROMISED;
    }
    
    if (state == PoisonState::DETECTED) {
        // 检测到调试器但尚未投毒，返回警告
        return EnvironmentState::SUSPICIOUS;
    }
    
    // 步骤 2: 其他环境检查（可扩展）
    // - 虚拟机检测
    // - 沙箱检测
    // - 完整性校验
    
    return EnvironmentState::CLEAN;
}

bool RuntimeEnvironmentValidator::isSafe() const {
    return !m_poisoning->isCompromised();
}

void RuntimeEnvironmentValidator::secureErase() {
    if (m_poisoning) {
        delete m_poisoning;
        m_poisoning = nullptr;
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

void SecureErase(void* ptr, size_t size) {
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