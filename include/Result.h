/**
 * @file Result.h
 * @brief CN: 无异常错误处理模板（No Exceptions Pattern）| EN: No-exceptions error handling template (No Exceptions Pattern)
 *
 * CN: 企业级应用加固组件 - 统一错误处理框架
 * EN: Enterprise-grade application hardening component - Unified error handling framework.
 *
 * CN: 本模块实现了零信任架构下定义的 ResultT<T> 模板结构体，
 * EN: This module implements the ResultT<T> template struct defined under zero-trust architecture,
 * CN: 完全废弃 throw/std::runtime_error。所有业务和网络返回值
 * EN: completely deprecating throw/std::runtime_error. All business and network return values
 * CN: 被强制包装在统一的模板结构体中向下传递。
 * EN: are forcibly wrapped in a unified template struct for downward propagation.
 *
 * CN: 设计哲学:
 * EN: Design philosophy:
 * - CN: 标准化错误分类（A/B/C/D 四类）| EN: Standardized error classification (A/B/C/D four categories)
 * - CN: 编译期类型安全 | EN: Compile-time type safety
 * - CN: 零运行时异常开销 | EN: Zero runtime exception overhead
 * - CN: 显式错误恢复策略 | EN: Explicit error recovery strategies
 */

#pragma once

#include <string>
#include <cstdint>

namespace csc {

/**
 * @brief CN: 网关错误分类枚举 | EN: Gateway error classification enum
 *
 * CN: 用于上层决策的错误分类系统；每个类别对应不同的用户交互策略。
 * EN: Error classification system for upper-layer decision making; each category corresponds to a different user interaction strategy.
 *
 * | CN: 类别 | EN: Category | CN: 枚举值 | EN: Enum Value | CN: 含义 | EN: Meaning | CN: 上层决策 | EN: Upper-layer Decision |
 * |----------|------------|------|---------|------|---------|----------|---------------------|
 * | SUCCESS | 0 | CN: 操作成功 | EN: Operation successful | CN: 正常流程 | EN: Normal flow |
 * | CLASS_A_AUTH_FATAL | 1 | CN: 显式授权失败 | EN: Explicit authorization failure | CN: 弹窗提示，引导重新认证 | EN: Dialog prompt, guide re-authentication |
 * | CLASS_B_RATE_LIMIT | 2 | CN: 显式限流 | EN: Explicit rate limit | CN: 显示冷却时间，禁用按钮 | EN: Display cooldown time, disable button |
 * | CLASS_C_NETWORK_RETRY | 3 | CN: 瞬态环境异常 | EN: Transient environment anomaly | CN: 允许用户手动重试 | EN: Allow manual user retry |
 * | CLASS_D_TAMPERED_ENV | 4 | CN: 高风险协议异常 | EN: High-risk protocol anomaly | CN: 断开连接，记录事件 | EN: Disconnect, log event |
 */
enum class GatewayErrorClass : uint8_t {
    /** CN: 操作成功 | EN: Operation successful */
    SUCCESS = 0,

    /**
     * CN: A 类错误：显式授权失败 | EN: Class A Error: Explicit authorization failure
     *
     * CN: 触发条件：HTTP 401/403、账户冻结、凭证过期、设备指纹不匹配
     * EN: Trigger conditions: HTTP 401/403, account frozen, credential expired, device fingerprint mismatch
     * CN: 用户策略：弹窗提示，引导重新认证
     * EN: User strategy: Dialog prompt, guide re-authentication
     */
    CLASS_A_AUTH_FATAL = 1,

    /**
     * CN: B 类错误：显式限流 | EN: Class B Error: Explicit rate limit
     *
     * CN: 触发条件：HTTP 429、频繁请求、临时黑名单、冷却中
     * EN: Trigger conditions: HTTP 429, frequent requests, temporary blacklist, cooldown active
     * CN: 用户策略：显示冷却时间，禁用按钮
     * EN: User strategy: Display cooldown time, disable button
     */
    CLASS_B_RATE_LIMIT = 2,

    /**
     * CN: C 类错误：瞬态环境异常 | EN: Class C Error: Transient environment anomaly
     *
     * CN: 触发条件：超时、DNS 解析失败、HTTP 5xx、网络断开
     * EN: Trigger conditions: Timeout, DNS resolution failure, HTTP 5xx, network disconnect
     * CN: 用户策略：允许用户手动重试
     * EN: User strategy: Allow manual user retry
     */
    CLASS_C_NETWORK_RETRY = 3,

    /**
     * CN: D 类错误：高风险协议异常 | EN: Class D Error: High-risk protocol anomaly
     *
     * CN: 触发条件：解密失败、MAC 校验错误、JSON 结构缺失、Nonce 不匹配
     * EN: Trigger conditions: Decryption failure, MAC verification error, JSON structure missing, Nonce mismatch
     * CN: 用户策略：断开连接，记录事件，禁止重试
     * EN: User strategy: Disconnect, log event, prohibit retry
     */
    CLASS_D_TAMPERED_ENV = 4
};

/**
 * @brief CN: 泛型结果模板结构体 | EN: Generic result template struct
 *
 * CN: 所有业务函数和网络请求返回值必须使用此模板包装。
 * EN: All business function and network request return values must be wrapped using this template.
 * CN: 禁止使用 throw 抛出异常；所有错误通过 success + errorClass 传递。
 * EN: Throwing exceptions via throw is prohibited; all errors are propagated via success + errorClass.
 *
 * @tparam T CN: 成功时携带的数据类型 | EN: Data type carried on success
 *
 * CN: 使用示例:
 * EN: Usage example:
 * @code
 * ResultT<UserInfo> result = Authenticate(username, password);
 * if (!result.success) {
 *     switch (result.errorClass) {
 *         case GatewayErrorClass::CLASS_A_AUTH_FATAL:
 *             ShowAuthFailedDialog(result.message);
 *             break;
 *         case GatewayErrorClass::CLASS_C_NETWORK_RETRY:
 *             EnableRetryButton(result.message);
 *             break;
 *         // ...
 *     }
 *     return;
 * }
 * // CN: 成功，使用 result.data | EN: Success, use result.data
 * @endcode
 */
template<typename T>
struct ResultT {
    /**
     * @brief CN: 操作是否成功 | EN: Whether the operation succeeded
     *
     * CN: 这是一级检查标志。当 success == false 时，必须检查 errorClass
     * EN: This is the first-level check flag. When success == false, errorClass must be checked
     * CN: 以确定错误类型和恢复策略。
     * EN: to determine the error type and recovery strategy.
     */
    bool success = false;

    /**
     * @brief CN: 错误分类 | EN: Error classification
     *
     * CN: 仅在 success == false 时有效。用于上层决策用户交互策略。
     * EN: Only valid when success == false. Used for upper-layer decision making on user interaction strategy.
     * CN: 当 success == true 时，此值固定为 GatewayErrorClass::SUCCESS。
     * EN: When success == true, this value is fixed to GatewayErrorClass::SUCCESS.
     */
    GatewayErrorClass errorClass = GatewayErrorClass::SUCCESS;

    /**
     * @brief CN: 底层错误码（仅用于净化日志）| EN: Low-level error code (for sanitized logs only)
     *
     * CN: 用于内部日志和调试的原始错误码。
     * EN: Raw error code for internal logging and debugging.
     * CN: 具体错误码不暴露给用户，仅显示模糊提示。
     * EN: Specific error codes are not exposed to users; only a vague message is displayed.
     */
    int originalCode = 0;

    /**
     * @brief CN: 用户显示消息 | EN: User display message
     *
     * CN: 用于 UI 显示的净化后错误描述。
     * EN: Sanitized error description for UI display.
     * CN: 成功时为空字符串。
     * EN: Empty string on success.
     */
    std::string message;

    /**
     * @brief CN: 成功时的数据载荷 | EN: Data payload on success
     *
     * CN: 仅在 success == true 时有效。
     * EN: Only valid when success == true.
     * CN: 当 success == false 时，此值为默认构造的空对象。
     * EN: When success == false, this value is a default-constructed empty object.
     */
    T data{};

    /**
     * @brief CN: 特殊场景令牌 | EN: Special scenario token
     *
     * CN: 用于改密或配置更新等特殊业务流程中的二次验证令牌。
     * EN: Used for secondary verification tokens in special business flows such as credential changes or configuration updates.
     * CN: 正常请求时为空字符串。
     * EN: Empty string for normal requests.
     */
    std::string rebindToken;

    // ========== CN: 便捷工厂方法 | EN: Convenience Factory Methods ==========

    /**
     * @brief CN: 构造成功结果 | EN: Construct a success result
     *
     * @param data CN: 成功时携带的数据 | EN: Data carried on success
     * @return CN: ResultT<T> 成功结果 | EN: ResultT<T> Success result
     */
    static ResultT<T> Ok(const T& data) {
        ResultT<T> result;
        result.success = true;
        result.errorClass = GatewayErrorClass::SUCCESS;
        result.data = data;
        return result;
    }

    /**
     * @brief CN: 构造 A 类错误（授权失败）| EN: Construct a Class A error (authorization failure)
     *
     * @param code CN: 底层错误码 | EN: Low-level error code
     * @param msg CN: 用户显示消息 | EN: User display message
     * @return CN: ResultT<T> 错误结果 | EN: ResultT<T> Error result
     */
    static ResultT<T> AuthFatal(int code, const std::string& msg) {
        ResultT<T> result;
        result.success = false;
        result.errorClass = GatewayErrorClass::CLASS_A_AUTH_FATAL;
        result.originalCode = code;
        result.message = msg;
        return result;
    }

    /**
     * @brief CN: 构造 B 类错误（限流）| EN: Construct a Class B error (rate limit)
     *
     * @param code CN: 底层错误码 | EN: Low-level error code
     * @param msg CN: 用户显示消息 | EN: User display message
     * @return CN: ResultT<T> 错误结果 | EN: ResultT<T> Error result
     */
    static ResultT<T> RateLimit(int code, const std::string& msg) {
        ResultT<T> result;
        result.success = false;
        result.errorClass = GatewayErrorClass::CLASS_B_RATE_LIMIT;
        result.originalCode = code;
        result.message = msg;
        return result;
    }

    /**
     * @brief CN: 构造 C 类错误（网络异常）| EN: Construct a Class C error (network anomaly)
     *
     * @param code CN: 底层错误码 | EN: Low-level error code
     * @param msg CN: 用户显示消息 | EN: User display message
     * @return CN: ResultT<T> 错误结果 | EN: ResultT<T> Error result
     */
    static ResultT<T> NetworkRetry(int code, const std::string& msg) {
        ResultT<T> result;
        result.success = false;
        result.errorClass = GatewayErrorClass::CLASS_C_NETWORK_RETRY;
        result.originalCode = code;
        result.message = msg;
        return result;
    }

    /**
     * @brief CN: 构造 D 类错误（协议异常）| EN: Construct a Class D error (protocol anomaly)
     *
     * @param code CN: 底层错误码 | EN: Low-level error code
     * @param msg CN: 用户显示消息 | EN: User display message
     * @return CN: ResultT<T> 错误结果 | EN: ResultT<T> Error result
     */
    static ResultT<T> TamperedEnv(int code, const std::string& msg) {
        ResultT<T> result;
        result.success = false;
        result.errorClass = GatewayErrorClass::CLASS_D_TAMPERED_ENV;
        result.originalCode = code;
        result.message = msg;
        return result;
    }

    /**
     * @brief CN: 构造带令牌的特殊错误结果 | EN: Construct a special error result with token
     *
     * CN: 用于改密或配置更新等需要二次验证的场景。
     * EN: Used for scenarios requiring secondary verification such as credential changes or configuration updates.
     *
     * @param errorClass CN: 错误分类 | EN: Error classification
     * @param code CN: 底层错误码 | EN: Low-level error code
     * @param msg CN: 用户显示消息 | EN: User display message
     * @param token CN: 二次验证令牌 | EN: Secondary verification token
     * @return CN: ResultT<T> 错误结果 | EN: ResultT<T> Error result
     */
    static ResultT<T> WithToken(GatewayErrorClass errorClass, int code,
                                  const std::string& msg, const std::string& token) {
        ResultT<T> result;
        result.success = false;
        result.errorClass = errorClass;
        result.originalCode = code;
        result.message = msg;
        result.rebindToken = token;
        return result;
    }
};

/**
 * @brief CN: 空结果类型 | EN: Empty result type
 *
 * CN: 用于不需要携带数据载荷的操作（如登出、心跳）。
 * EN: Used for operations that do not need to carry a data payload (e.g., logout, heartbeat).
 */
struct EmptyResult {};

/**
 * @brief CN: 空结果模板别名 | EN: Empty result template alias
 */
using Result = ResultT<EmptyResult>;

} // namespace csc