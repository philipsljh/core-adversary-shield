/**
 * @file SecurityDef.h
 * @brief CN: 编译期字符串混淆开关 | EN: Compile-time string obfuscation toggle
 *
 * CN: 企业级应用加固组件 - 编译期静态字符串保护
 * EN: Enterprise-grade application hardening component - compile-time static string protection.
 *
 * CN: 功能特性:
 * EN: Features:
 * - CN: Release 模式：启用多轮混合加密混淆，防止静态分析工具提取敏感字符串
 *   EN: Release mode: Enables multi-round hybrid encryption obfuscation to prevent static analysis tools from extracting sensitive strings
 * - CN: Internal-Release / Debug 模式：使用 IdentitySecureString 包装器（提供 .unlock() 兼容接口）
 *   EN: Internal-Release / Debug mode: Uses IdentitySecureString wrapper (provides .unlock() compatible interface)
 *
 * CN: 设计原则:
 * EN: Design principles:
 * - CN: 零运行时开销：混淆在编译期完成
 *   EN: Zero runtime overhead: Obfuscation is completed at compile time
 * - CN: 接口一致性：无论混淆状态如何，业务代码调用方式保持一致
 *   EN: Interface consistency: Business code invocation remains identical regardless of obfuscation state
 * - CN: 可审计性：开源版本保留完整的混淆/解混淆逻辑供安全审查
 *   EN: Auditability: Open-source version retains complete obfuscation/deobfuscation logic for security review
 */

#pragma once
#pragma execution_character_set("utf-8")

#include <string>

// ============================================================
// CN: 编译期字符串混淆开关 | EN: Compile-time string obfuscation toggle
// ============================================================
// CN: 混淆仅在正式 Release 模式（非 Internal）下启用
// EN: Obfuscation is enabled only in official Release mode (non-Internal)
// CN: 内部版本预处理器定义包含 "CONFIG_BUILD_INTERNAL"
// EN: Internal version preprocessor definitions include "CONFIG_BUILD_INTERNAL"
// ============================================================

#if defined(NDEBUG) && !defined(CONFIG_BUILD_INTERNAL)
    // CN: 生产模式：启用字符串混淆加密
    // EN: Production mode: Enable string obfuscation encryption
    // CN: 注意：开源版本中，_S 宏实现由第三方混淆库提供
    // EN: Note: In the open-source version, the _S macro implementation is provided by a third-party obfuscation library
    // CN: 此处保留接口定义，实际使用需链接对应混淆库
    // EN: Interface definitions are retained here; actual usage requires linking the corresponding obfuscation library
    #ifdef HAVE_SYSX_OBFUSCATOR
        #include "sysx_obfuscator.h"
        #define _SC(str) _S(str)
    #else
        // CN: 开源版本默认使用明文（便于审计和调试）
        // EN: Open-source version defaults to plaintext by default (for auditing and debugging)
        #define _SC(str) IdentitySecureString(str)
    #endif
#else
    /**
     * @brief CN: IdentitySecureString - 开发/测试模式字符串包装器 | EN: IdentitySecureString - String wrapper for development/testing mode
     *
     * CN: 提供与混淆版本完全一致的接口:
     * EN: Provides an interface identical to the obfuscated version:
     * - CN: unlock(): 返回原始字符串指针 | EN: unlock(): Returns the original string pointer
     * - CN: wipe(): 安全擦除（开发模式下为空操作）| EN: wipe(): Secure erasure (no-op in development mode)
     * - CN: 隐式类型转换：支持 const char* 和 std::string | EN: Implicit type conversion: Supports const char* and std::string
     */
    struct IdentitySecureString {
        const char* ptr;

        explicit IdentitySecureString(const char* s) : ptr(s) {}

        /**
         * @brief CN: 解锁并返回原始字符串 | EN: Unlock and return the original string
         * @return CN: 原始字符串指针 | EN: Original string pointer
         */
        const char* unlock() const { return ptr; }

        /**
         * @brief CN: 安全擦除原始字符串 | EN: Securely erase the original string
         * @note CN: 开发模式下为空操作；生产模式下调用 SecureZeroMemory
         *       EN: No-op in development mode; calls SecureZeroMemory in production mode
         */
        void wipe() const {}

        /**
         * @brief CN: 隐式转换为 const char* | EN: Implicit conversion to const char*
         */
        operator const char*() const { return ptr; }

        /**
         * @brief CN: 隐式转换为 std::string | EN: Implicit conversion to std::string
         */
        operator std::string() const { return std::string(ptr); }
    };

    #define _SC(str) IdentitySecureString(str)
#endif

// ============================================================
// CN: _SC_Q() 宏 - 将 _SC() 解密结果转换为 QString（用于 Qt JSON 操作）
// EN: _SC_Q() macro - Converts _SC() decryption result to QString (for Qt JSON operations)
// ============================================================
#if defined(NDEBUG) && !defined(CONFIG_BUILD_INTERNAL) && defined(HAVE_SYSX_OBFUSCATOR)
    #define _SC_Q(s) QString::fromUtf8(_SC(s).unlock())
#else
    // CN: Internal/Debug 模式：_SC 返回 IdentitySecureString，直接隐式转换
    // EN: Internal/Debug mode: _SC returns IdentitySecureString, direct implicit conversion
    #define _SC_Q(s) QString::fromUtf8(_SC(s))
#endif