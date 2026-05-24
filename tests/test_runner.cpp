/**
 * @file test_runner.cpp
 * @brief CN: CAS 项目 GoogleTest 风格自动化测试入口 | EN: CAS project GoogleTest-style automated test entry point
 *
 * CN: 本文件包含 8 个核心测试用例，验证安全模块是否彻底闭环。
 * EN: This file contains 8 core test cases to verify that security modules are fully closed-loop.
 */

#pragma execution_character_set("utf-8")

#include <windows.h>
#include <bcrypt.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <chrono>
#include <iomanip>
#include <sstream>

// CN: 引入核心头文件 | EN: Include core headers
#include "CryptoCore.h"
#include "SecureChannel.h"
#include "AuthGateway.h"
#include "RuntimeEnvironmentValidator.h"
#include "SecurityDef.h"

// ============================================================================
// CN: 测试基础设施 - GoogleTest 风格 | EN: Test Infrastructure - GoogleTest Style
// ============================================================================

// CN: 测试统计计数器 | EN: Test statistics counters
static int g_testsPassed = 0;
static int g_testsFailed = 0;
static int g_testsTotal = 0;
static long long g_totalTimeMs = 0;

// CN: 高精度计时器辅助类 | EN: High-precision timer helper class
class TestTimer {
public:
    // CN: 构造函数：记录开始时间 | EN: Constructor: record start time
    TestTimer() : m_start(std::chrono::high_resolution_clock::now()) {}

    // CN: 返回已流逝的毫秒数 | EN: Return elapsed milliseconds
    long long elapsedMs() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - m_start).count();
    }

private:
    std::chrono::high_resolution_clock::time_point m_start;
};

// CN: GoogleTest 风格测试运行宏 | EN: GoogleTest-style test run macro
#define RUN_TEST(name, func) do { \
    ++g_testsTotal; \
    std::cout << "[ RUN      ] " << name << std::endl; \
    TestTimer timer; \
    try { \
        func(); \
        long long ms = timer.elapsedMs(); \
        g_totalTimeMs += ms; \
        std::cout << "[       OK ] " << name << " (" << ms << " ms)" << std::endl; \
        ++g_testsPassed; \
    } catch (const std::exception& e) { \
        long long ms = timer.elapsedMs(); \
        g_totalTimeMs += ms; \
        std::cout << "[  FAILED  ] " << name << " (" << ms << " ms): " << e.what() << std::endl; \
        ++g_testsFailed; \
    } catch (...) { \
        long long ms = timer.elapsedMs(); \
        g_totalTimeMs += ms; \
        std::cout << "[  FAILED  ] " << name << " (" << ms << " ms): Unknown exception" << std::endl; \
        ++g_testsFailed; \
    } \
} while(0)

// CN: 断言宏 - 带详细错误信息 | EN: Assertion macro - with detailed error messages
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        throw std::runtime_error(std::string("Assertion failed: ") + (msg)); \
    } \
} while(0)

// ============================================================================
// CN: T01 - 内存阅后即焚验证 | EN: T01 - Memory Annihilation Verification
// ============================================================================

// CN: 测试 SecureMemoryWipe 和 SecureErase 是否正确清零缓冲区
// EN: Test whether SecureMemoryWipe and SecureErase correctly zero out buffers
void Test01_MemoryAnnihilation() {
    // CN: 测试 1a: SecureMemoryWipe 基础功能
    // EN: Test 1a: SecureMemoryWipe basic functionality
    {
        alignas(32) uint8_t sensitiveBuffer[64];

        // CN: 填充敏感数据 | EN: Fill with sensitive data
        for (size_t i = 0; i < sizeof(sensitiveBuffer); ++i) {
            sensitiveBuffer[i] = static_cast<uint8_t>(0xAB);
        }

        // CN: 执行安全擦除 | EN: Execute secure wipe
        SecureMemoryWipe(sensitiveBuffer, sizeof(sensitiveBuffer));

        // CN: 使用 volatile 指针进行阅后即焚断言，防止断言本身干扰优化器
        // EN: Use volatile pointers for secure erase assertions to prevent interference with the optimizer
        const volatile uint8_t* verifyPtr = reinterpret_cast<const volatile uint8_t*>(sensitiveBuffer);
        for (size_t i = 0; i < sizeof(sensitiveBuffer); ++i) {
            TEST_ASSERT(verifyPtr[i] == 0, "SecureMemoryWipe failed - buffer not zeroed");
        }
    }

    // CN: 测试 1b: csc::SecureErase(volatile void*) 基础功能
    // EN: Test 1b: csc::SecureErase(volatile void*) basic functionality
    {
        alignas(32) uint8_t volatileBuffer[32];

        // CN: 填充敏感数据 | EN: Fill with sensitive data
        for (size_t i = 0; i < sizeof(volatileBuffer); ++i) {
            volatileBuffer[i] = static_cast<uint8_t>(0xCD);
        }

        // CN: 执行安全擦除 | EN: Execute secure wipe
        csc::SecureErase(volatileBuffer, sizeof(volatileBuffer));

        // CN: 验证擦除结果 | EN: Verify wipe result
        const volatile uint8_t* verifyPtr = reinterpret_cast<const volatile uint8_t*>(volatileBuffer);
        for (size_t i = 0; i < sizeof(volatileBuffer); ++i) {
            TEST_ASSERT(verifyPtr[i] == 0, "csc::SecureErase failed - buffer not zeroed");
        }
    }

    // CN: 测试 1c: SecureKeyContext 的 armKey 连坐擦除
    // EN: Test 1c: SecureKeyContext armKey cascade sanitization
    {
        alignas(32) uint8_t rawKey[32];

        // CN: 填充原始密钥 | EN: Fill original key
        for (size_t i = 0; i < 32; ++i) {
            rawKey[i] = static_cast<uint8_t>(0xEF);
        }

        // CN: 注入密钥（应连坐擦除 rawKey）| EN: Inject key (should cascade wipe rawKey)
        SecureKeyContext ctx;
        ctx.armKey(rawKey, 32);

        // CN: 验证 rawKey 已被擦除 | EN: Verify rawKey has been wiped
        const volatile uint8_t* verifyPtr = reinterpret_cast<const volatile uint8_t*>(rawKey);
        for (size_t i = 0; i < 32; ++i) {
            TEST_ASSERT(verifyPtr[i] == 0, "SecureKeyContext armKey cascade wipe failed");
        }

        TEST_ASSERT(ctx.isReady(), "SecureKeyContext should be armed after armKey");
    }
}

// ============================================================================
// CN: T02 - volatile 指针擦除验证 | EN: T02 - Volatile Pointer Erase Verification
// ============================================================================

void Test02_VolatilePointerErase() {
    // CN: 测试 volatile 指针擦除的正确性
    // EN: Test correctness of volatile pointer erasure
    std::vector<uint8_t> buffer(128, 0x55);

    // CN: 使用 volatile 指针擦除 | EN: Wipe using volatile pointer
    csc::SecureErase(buffer.data(), buffer.size());

    // CN: 验证擦除结果 | EN: Verify wipe result
    for (size_t i = 0; i < buffer.size(); ++i) {
        TEST_ASSERT(buffer[i] == 0, "Volatile pointer erase failed");
    }
}

// ============================================================================
// CN: T03 - 密钥上下文生命周期验证 | EN: T03 - Key Context Lifecycle Verification
// ============================================================================

void Test03_KeyContextLifecycle() {
    // CN: 测试 SecureKeyContext 的完整生命周期
    // EN: Test complete lifecycle of SecureKeyContext

    // CN: 创建上下文 | EN: Create context
    SecureKeyContext ctx;
    TEST_ASSERT(!ctx.isReady(), "SecureKeyContext should not be ready initially");

    // CN: 准备密钥 | EN: Prepare key
    alignas(32) uint8_t testKey[32];
    for (size_t i = 0; i < 32; ++i) {
        testKey[i] = static_cast<uint8_t>(i + 1);
    }

    // CN: 注入密钥 | EN: Inject key
    ctx.armKey(testKey, 32);
    TEST_ASSERT(ctx.isReady(), "SecureKeyContext should be ready after armKey");

    // CN: 执行受保护的业务逻辑 | EN: Execute guarded business logic
    bool businessResult = ctx.executeGuarded([](const uint8_t* key, size_t len) -> bool {
        // CN: 验证密钥在回调中正确还原 | EN: Verify key is correctly restored in callback
        TEST_ASSERT(key != nullptr, "Key pointer should not be null");
        TEST_ASSERT(len == 32, "Key length should be 32");

        // CN: 验证密钥内容 | EN: Verify key content
        for (size_t i = 0; i < 32; ++i) {
            if (key[i] != static_cast<uint8_t>(i + 1)) {
                return false;
            }
        }
        return true;
    });

    TEST_ASSERT(businessResult, "executeGuarded business logic should succeed");

    // CN: 重置上下文 | EN: Reset context
    ctx.reset();
    TEST_ASSERT(!ctx.isReady(), "SecureKeyContext should not be ready after reset");
}

// ============================================================================
// CN: T04 - XOR 密钥存储投毒验证 | EN: T04 - XOR Key Storage Poisoning Verification
// ============================================================================

void Test04_XorKeyStoragePoisoning() {
    // CN: 测试 XorKeyStorage 的存储、还原和投毒机制
    // EN: Test XorKeyStorage store, recover, and poison mechanisms

    // CN: 创建 XOR 密钥存储 | EN: Create XOR key storage
    csc::XorKeyStorage storage;

    // CN: 准备原始密钥 | EN: Prepare original key
    const uint8_t originalKey[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    // CN: 存储密钥 | EN: Store key
    storage.storeKey(originalKey, 32);
    TEST_ASSERT(storage.getStoredLength() == 32, "Stored length should be 32");

    // CN: 还原密钥并验证 | EN: Recover key and verify
    {
        uint8_t recoveredKey[32] = {0};
        bool recoverResult = storage.recoverKey(recoveredKey, 32);
        TEST_ASSERT(recoverResult, "recoverKey should succeed before poisoning");

        // CN: 验证还原的密钥与原始密钥一致 | EN: Verify recovered key matches original
        for (size_t i = 0; i < 32; ++i) {
            TEST_ASSERT(recoveredKey[i] == originalKey[i],
                       "Recovered key should match original key before poisoning");
        }
    }

    // CN: 执行投毒 | EN: Execute poisoning
    storage.poison();

    // CN: 投毒后还原密钥，应返回脏数据 | EN: Recover key after poisoning, should return corrupted data
    {
        uint8_t recoveredKey[32] = {0};
        bool recoverResult = storage.recoverKey(recoveredKey, 32);
        (void)recoverResult; // CN: 显式抑制未使用变量警告 | EN: Explicitly suppress unused variable warning

        // CN: 投毒后 recoverKey 可能返回 true 但数据已损坏
        // EN: recoverKey may return true after poisoning but data is corrupted
        bool dataCorrupted = false;
        for (size_t i = 0; i < 32; ++i) {
            if (recoveredKey[i] != originalKey[i]) {
                dataCorrupted = true;
                break;
            }
        }
        TEST_ASSERT(dataCorrupted, "Recovered key should be corrupted after poisoning");
    }

    // CN: 安全擦除 | EN: Secure erase
    storage.secureErase();
}

// ============================================================================
// CN: T05 - AES 加解密冒烟测试 | EN: T05 - AES Encryption/Decryption Smoke Test
// ============================================================================

void Test05_AesSmokeTest() {
    // CN: 测试 CryptoCore 的 AES 加解密基本功能
    // EN: Test CryptoCore AES encryption/decryption basic functionality

    // CN: 生成随机密钥 | EN: Generate random key
    std::string key = CryptoCore::GenerateKey();
    TEST_ASSERT(key.length() == 32, "Generated key should be 32 bytes");

    // CN: 准备明文 | EN: Prepare plaintext
    std::string plaintext = "Hello, CAS Security Test!";

    // CN: 加密 | EN: Encrypt
    std::string ciphertext = CryptoCore::Encrypt(plaintext, key);
    TEST_ASSERT(!ciphertext.empty(), "Ciphertext should not be empty");

    // CN: 解密 | EN: Decrypt
    std::string decrypted = CryptoCore::Decrypt(ciphertext, key);
    TEST_ASSERT(decrypted == plaintext, "Decrypted text should match original plaintext");
}

// ============================================================================
// CN: T06 - Base64 编解码双向一致性验证 | EN: T06 - Base64 Encode/Decode Bidirectional Consistency
// ============================================================================

void Test06_Base64Consistency() {
    // CN: 测试 SecureChannel 的 Base64 编解码一致性
    // EN: Test SecureChannel Base64 encode/decode consistency

    // CN: 准备测试数据 | EN: Prepare test data
    std::vector<uint8_t> testData = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8
    };

    // CN: 确保测试桩内部不会因为隐式转换触发 /W4 警告
    // EN: Ensure test harness avoids triggering /W4 warnings due to implicit conversions
    size_t inputLen = testData.size();
    ULONG safeLen = static_cast<ULONG>(inputLen);
    TEST_ASSERT(safeLen == inputLen, "Length conversion should be lossless");

    // CN: 编码 | EN: Encode
    std::string encoded = csc::SecureChannel::Base64Encode(testData.data(), testData.size());
    TEST_ASSERT(!encoded.empty(), "Encoded string should not be empty");

    // CN: 解码 | EN: Decode
    std::vector<uint8_t> decoded = csc::SecureChannel::Base64Decode(encoded);
    TEST_ASSERT(decoded.size() == testData.size(), "Decoded size should match original size");

    // CN: 验证数据一致性 | EN: Verify data consistency
    for (size_t i = 0; i < testData.size(); ++i) {
        TEST_ASSERT(decoded[i] == testData[i], "Decoded data should match original data");
    }
}

// ============================================================================
// CN: T07 - AuthGateway 桩点空转验证 | EN: T07 - AuthGateway Stub Idle Verification
// ============================================================================

void Test07_AuthGatewayStub() {
    // CN: 测试 AuthGateway 的构造/析构无警告、无死锁
    // EN: Test AuthGateway construction/destruction without warnings or deadlocks

    // CN: 使用占位 RSA 公钥（仅测试构造/析构）
    // EN: Use placeholder RSA public key (construction/destruction test only)
    std::string placeholderPublicKey = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaU8xKwwKU9dHDxIvul0\n-----END RSA PUBLIC KEY-----";

    // CN: 构造网关 | EN: Construct gateway
    {
        csc::AuthGateway gateway("https://example.com/api", placeholderPublicKey);
        // CN: 网关对象在作用域内正常存在 | EN: Gateway object exists normally within scope
    }
    // CN: 网关对象在作用域结束时正常析构 | EN: Gateway object destructs normally at scope end

    // CN: 测试 EnforcementContext 的安全重置
    // EN: Test EnforcementContext secure reset
    {
        csc::EnforcementContext ctx;
        ctx.accessToken = "test_token_12345";
        ctx.hardwareFingerprint = "hwid_abcdef";
        ctx.serverTimestamp = 1234567890;

        ctx.secureReset();

        TEST_ASSERT(ctx.accessToken.empty(), "accessToken should be empty after secure_reset");
        TEST_ASSERT(ctx.hardwareFingerprint.empty(), "hardwareFingerprint should be empty after secure_reset");
        TEST_ASSERT(ctx.serverTimestamp == 0, "serverTimestamp should be 0 after secure_reset");
    }
}

// ============================================================================
// CN: T08 - 运行环境验证器测试 | EN: T08 - Runtime Environment Validator Test
// ============================================================================

void Test08_RuntimeEnvironmentValidator() {
    // CN: 测试 RuntimeEnvironmentValidator 的基本功能
    // EN: Test RuntimeEnvironmentValidator basic functionality

    csc::RuntimeEnvironmentValidator validator;

    // CN: 执行环境验证 | EN: Execute environment validation
    csc::EnvironmentState state = validator.validate();

    // CN: 在无调试器环境下应返回 CLEAN 或 SUSPICIOUS
    // EN: Should return CLEAN or SUSPICIOUS in debugger-free environment
    TEST_ASSERT(state == csc::EnvironmentState::CLEAN ||
                state == csc::EnvironmentState::SUSPICIOUS,
                "Environment state should be CLEAN or SUSPICIOUS without debugger");

    // CN: 检查安全状态 | EN: Check safety status
    bool isSafe = validator.isSafe();
    TEST_ASSERT(isSafe, "Environment should be safe initially");

    // CN: 安全擦除 | EN: Secure erase
    validator.secureErase();
}

// ============================================================================
// CN: 打印测试汇总仪表盘 | EN: Print Test Summary Dashboard
// ============================================================================

static void PrintTestSummary() {
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "TEST EXECUTION SUMMARY" << std::endl;
    std::cout << "========================================" << std::endl;

    // CN: 计算通过率 | EN: Calculate pass rate
    int passRate = (g_testsTotal > 0) ? (g_testsPassed * 100 / g_testsTotal) : 0;

    std::cout << "TOTAL TASKS:    " << g_testsTotal << std::endl;

    // CN: 格式化 PASSED 行 | EN: Format PASSED line
    std::cout << "PASSED:         " << g_testsPassed;
    std::cout << " [ " << std::setw(3) << passRate << "% ]" << std::endl;

    std::cout << "FAILED:         " << g_testsFailed << std::endl;
    std::cout << "TOTAL TIME:     " << g_totalTimeMs << " ms" << std::endl;
    std::cout << "========================================" << std::endl;

    if (g_testsFailed > 0) {
        std::cout << "[  FAILED  ] " << g_testsFailed << " TEST(S) FAILED" << std::endl;
    } else {
        std::cout << "[  PASSED  ] ALL TESTS PASSED" << std::endl;
    }
    std::cout << "========================================" << std::endl;
}

// ============================================================================
// CN: 主函数 | EN: Main Function
// ============================================================================

int main() {
    // CN: 设置控制台输出编码为 UTF-8
    // EN: Set console output encoding to UTF-8
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "========================================" << std::endl;
    std::cout << "  CAS Core Security Test Suite v1.0" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // CN: 执行所有测试用例 | EN: Execute all test cases
    RUN_TEST("T01_MemoryAnnihilation", Test01_MemoryAnnihilation);
    RUN_TEST("T02_VolatilePointerErase", Test02_VolatilePointerErase);
    RUN_TEST("T03_KeyContextLifecycle", Test03_KeyContextLifecycle);
    RUN_TEST("T04_XorKeyStoragePoisoning", Test04_XorKeyStoragePoisoning);
    RUN_TEST("T05_AesSmokeTest", Test05_AesSmokeTest);
    RUN_TEST("T06_Base64Consistency", Test06_Base64Consistency);
    RUN_TEST("T07_AuthGatewayStub", Test07_AuthGatewayStub);
    RUN_TEST("T08_RuntimeEnvironmentValidator", Test08_RuntimeEnvironmentValidator);

    // CN: 输出测试汇总仪表盘 | EN: Output test summary dashboard
    PrintTestSummary();

    // CN: 返回退出码 | EN: Return exit code
    if (g_testsFailed > 0) {
        return 1;
    } else {
        return 0;
    }
}