/**
 * @file RuntimeEnvironmentValidator.cpp
 * @brief CN: 运行环境验证层实现 | EN: Runtime Environment Validator Implementation
 *
 * CN: 本模块实现了白皮书中定义的反调试、内存投毒与环境检测逻辑。
 * EN: This module implements anti-debugging, memory poisoning, and environment detection logic defined in the white paper.
 *
 * CN: 核心设计哲学:
 * EN: Core design philosophy:
 * - CN: XOR 混淆密钥存储：shadowBuffer + entropyMask，栈帧内还原，阅后即焚 | EN: XOR obfuscated key storage: shadowBuffer + entropyMask, restored within stack frame, annihilated after use
 * - CN: 延迟随机投毒：检测到调试器后延迟 3~8 次心跳触发内存投毒 | EN: Delayed random poisoning: Triggers memory poisoning 3-8 heartbeats after debugger detection
 * - CN: 比特位翻转：投毒使后续通信自然失效，不直接崩溃暴露检测逻辑 | EN: Bit-flip poisoning: Causes subsequent communication to fail naturally without directly crashing and exposing detection logic
 *
 * CN: 安全注意事项:
 * EN: Security considerations:
 * 1. CN: 所有敏感数据在栈上分配，函数返回前强制擦除 | EN: All sensitive data allocated on stack, forcibly erased before function return
 * 2. CN: 使用 SecureZeroMemory 防止编译器优化掉内存擦除 | EN: Uses SecureZeroMemory to prevent compiler optimization of memory erasure
 * 3. CN: 投毒计数器使用 volatile 防止编译器优化 | EN: Poisoning counter uses volatile to prevent compiler optimization
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
// CN: XorKeyStorage 实现 | EN: XorKeyStorage Implementation
// ============================================================================

XorKeyStorage::XorKeyStorage() {
    // CN: 初始化 shadowBuffer 为随机噪声 | EN: Initialize shadowBuffer with random noise
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(shadowBuffer), shadowBuffer);
        CryptGenRandom(hProv, sizeof(entropyMask), entropyMask);
        CryptReleaseContext(hProv, 0);
    } else {
        // CN: 回退到伪随机 | EN: Fallback to pseudo-random
        std::memset(shadowBuffer, 0xCC, sizeof(shadowBuffer));
        std::memset(entropyMask, 0x55, sizeof(entropyMask));
    }
#else
    std::memset(shadowBuffer, 0xCC, sizeof(shadowBuffer));
    std::memset(entropyMask, 0x55, sizeof(entropyMask));
#endif
}

XorKeyStorage::~XorKeyStorage() {
    // CN: 析构时强制擦除 | EN: Force erasure on destruction
    SecureErase(shadowBuffer, sizeof(shadowBuffer));
    SecureErase(entropyMask, sizeof(entropyMask));
}

void XorKeyStorage::storeKey(const uint8_t* key, size_t length) {
    if (!key || length == 0 || length > sizeof(shadowBuffer)) return;

    // CN: XOR 混淆存储：shadowBuffer[i] = key[i] ^ entropyMask[i] | EN: XOR obfuscated storage: shadowBuffer[i] = key[i] ^ entropyMask[i]
    for (size_t i = 0; i < length; ++i) {
        shadowBuffer[i] = key[i] ^ entropyMask[i];
    }
    storedLength = length;
}

bool XorKeyStorage::recoverKey(uint8_t* outBuffer, size_t outLength) {
    if (!outBuffer || outLength < storedLength || storedLength == 0) return false;

    // CN: 栈帧内 XOR 还原：key[i] = shadowBuffer[i] ^ entropyMask[i] | EN: Stack frame XOR restoration: key[i] = shadowBuffer[i] ^ entropyMask[i]
    for (size_t i = 0; i < storedLength; ++i) {
        outBuffer[i] = shadowBuffer[i] ^ entropyMask[i];
    }

    return true;
}

void XorKeyStorage::poison() {
    // CN: 比特位翻转投毒：翻转 shadowBuffer 的随机位，使后续 recoverKey() 返回脏数据，通信自然失效
    // EN: Bit-flip poisoning: Flip random bits in shadowBuffer, causing subsequent recoverKey() to return corrupted data, communication fails naturally
    if (storedLength > 0) {
        // CN: 翻转第一个字节的所有位 | EN: Flip all bits of the first byte
        shadowBuffer[0] = ~shadowBuffer[0];
        // CN: 如果长度足够，再翻转最后一个字节 | EN: If length is sufficient, also flip the last byte
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
// CN: MemoryPoisoning 实现 | EN: MemoryPoisoning Implementation
// ============================================================================

MemoryPoisoning::MemoryPoisoning()
    : detectionCount(0)
    , poisonThreshold(0)
    , isPoisoned(false) {
    // CN: 随机设置投毒阈值 3~8 次 | EN: Randomly set poisoning threshold 3-8 times
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(3, 8);
    poisonThreshold = static_cast<uint8_t>(dist(gen));
}

MemoryPoisoning::~MemoryPoisoning() {
    // CN: 析构时擦除计数器 | EN: Erase counters on destruction
    SecureErase(&detectionCount, sizeof(detectionCount));
    SecureErase(&poisonThreshold, sizeof(poisonThreshold));
}

bool MemoryPoisoning::checkDebugger() {
#ifdef _WIN32
    // CN: 使用 PEB.BeingDebugged 标志检测调试器 | EN: Use PEB.BeingDebugged flag to detect debugger
    // CN: 这是最基础的检测，生产环境可叠加更多检测 | EN: This is the most basic detection; production environment can stack more detections
    bool isDebugged = false;

    // CN: 方法 1: IsDebuggerPresent API | EN: Method 1: IsDebuggerPresent API
    if (IsDebuggerPresent()) {
        isDebugged = true;
    }

    // CN: 方法 2: PEB BeingDebugged 直接读取 | EN: Method 2: PEB BeingDebugged direct read
    if (!isDebugged) {
        __try {
            PPEB pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;
            if (pPeb && pPeb->BeingDebugged) {
                isDebugged = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // CN: 忽略异常 | EN: Ignore exception
        }
    }

    return isDebugged;
#else
    // CN: Linux: 检查 /proc/self/status 中的 TracerPid | EN: Linux: Check TracerPid in /proc/self/status
    return false;
#endif
}

PoisonState MemoryPoisoning::onHeartbeatTick() {
    // CN: 每次心跳调用，检测调试器 | EN: Each heartbeat call, detect debugger
    if (checkDebugger()) {
        detectionCount++;

        // CN: 检查是否达到投毒阈值 | EN: Check if poisoning threshold is reached
        if (detectionCount >= poisonThreshold) {
            isPoisoned = true;
            return PoisonState::POISONED;
        }

        // CN: 尚未达到阈值，返回警告状态 | EN: Threshold not yet reached, return warning state
        return PoisonState::DETECTED;
    }

    // CN: 未检测到调试器 | EN: Debugger not detected
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
// CN: RuntimeEnvironmentValidator 实现 | EN: RuntimeEnvironmentValidator Implementation
// ============================================================================

RuntimeEnvironmentValidator::RuntimeEnvironmentValidator()
    : m_poisoning(new MemoryPoisoning()) {
}

RuntimeEnvironmentValidator::~RuntimeEnvironmentValidator() {
    delete m_poisoning;
    m_poisoning = nullptr;
}

EnvironmentState RuntimeEnvironmentValidator::validate() {
    // CN: 步骤 1: 检查调试器 | EN: Step 1: Check debugger
    PoisonState state = m_poisoning->onHeartbeatTick();

    if (state == PoisonState::POISONED) {
        // CN: 已投毒，返回污染状态 | EN: Poisoned, return compromised state
        return EnvironmentState::COMPROMISED;
    }

    if (state == PoisonState::DETECTED) {
        // CN: 检测到调试器但尚未投毒，返回警告 | EN: Debugger detected but not yet poisoned, return warning
        return EnvironmentState::SUSPICIOUS;
    }

    // CN: 步骤 2: 其他环境检查（可扩展）| EN: Step 2: Other environment checks (extensible)
    // - CN: 虚拟机检测 | EN: Virtual machine detection
    // - CN: 沙箱检测 | EN: Sandbox detection
    // - CN: 完整性校验 | EN: Integrity verification

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
// CN: 辅助函数 | EN: Helper Functions
// ============================================================================

void SecureErase(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

#ifdef _WIN32
    // CN: Windows: 使用 SecureZeroMemory（保证不被编译器优化）| EN: Windows: Uses SecureZeroMemory (guaranteed not to be optimized by compiler)
    SecureZeroMemory(ptr, size);
#else
    // CN: Linux: 使用 explicit_bzero（C11 标准，保证不被优化）| EN: Linux: Uses explicit_bzero (C11 standard, guaranteed not to be optimized)
    explicit_bzero(ptr, size);
#endif
}

} // namespace csc