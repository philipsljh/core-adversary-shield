/**
 * @file SecurityDef.h
 * @brief 安全编译期字符串混淆开关
 *
 * 企业级应用加固组件 - 编译期静态字符串保护
 *
 * 功能说明：
 * - Release 模式：启用多轮混合加密混淆，防止静态分析工具提取敏感字符串
 * - Internal-Release / Debug 模式：使用 IdentitySecureString 包装器（提供 .unlock() 兼容接口）
 *
 * 设计原则：
 * - 零运行时开销：混淆在编译期完成
 * - 接口一致性：无论是否启用混淆，业务代码调用方式完全一致
 * - 可审计性：开源版本保留完整的混淆/解混淆逻辑供安全审查
 */

#pragma once
#pragma execution_character_set("utf-8")

#include <string>

// ============================================================
// 编译期字符串混淆开关
// ============================================================
// 仅在正式 Release 且非 Internal 模式下启用混淆
// Internal 版本的预处理器定义包含 "CONFIG_BUILD_INTERNAL"
// ============================================================

#if defined(NDEBUG) && !defined(CONFIG_BUILD_INTERNAL)
    // 生产模式：启用字符串混淆加密
    // 注意：开源版本中，_S 宏的具体实现由第三方混淆库提供
    // 此处保留接口定义，实际使用时需链接对应的混淆库
    #ifdef HAVE_SYSX_OBFUSCATOR
        #include "sysx_obfuscator.h"
        #define _SC(str) _S(str)
    #else
        // 开源版本默认降级为明文（便于审计和调试）
        #define _SC(str) IdentitySecureString(str)
    #endif
#else
    /**
     * @brief IdentitySecureString - 开发/测试模式下的字符串包装器
     *
     * 提供与混淆版本完全一致的接口：
     * - unlock(): 返回原始字符串指针
     * - wipe(): 安全擦除（开发模式下为空操作）
     * - 隐式类型转换：支持 const char* 和 std::string
     */
    struct IdentitySecureString {
        const char* ptr;

        explicit IdentitySecureString(const char* s) : ptr(s) {}

        /**
         * @brief 解锁并返回原始字符串
         * @return 原始字符串指针
         */
        const char* unlock() const { return ptr; }

        /**
         * @brief 安全擦除原始字符串
         * @note 开发模式下为空操作，生产模式下调用 SecureZeroMemory
         */
        void wipe() const {}

        /**
         * @brief 隐式转换为 const char*
         */
        operator const char*() const { return ptr; }

        /**
         * @brief 隐式转换为 std::string
         */
        operator std::string() const { return std::string(ptr); }
    };

    #define _SC(str) IdentitySecureString(str)
#endif

// ============================================================
// _SC_Q() 宏 - 将 _SC() 解密结果转为 QString（用于 Qt JSON 操作）
// ============================================================
#if defined(NDEBUG) && !defined(CONFIG_BUILD_INTERNAL) && defined(HAVE_SYSX_OBFUSCATOR)
    #define _SC_Q(s) QString::fromUtf8(_SC(s).unlock())
#else
    // Internal/Debug 模式：_SC 返回 IdentitySecureString，直接隐式转换
    #define _SC_Q(s) QString::fromUtf8(_SC(s))
#endif