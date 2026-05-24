/**
 * @file Result.h
 * @brief 无异常模式错误处理模板 (No Exceptions Pattern)
 * 
 * 本模块实现了白皮书 4.7 节定义的 ResultT<T> 模板结构体，
 * 全面废弃 throw/std::runtime_error，所有业务和网络返回值
 * 强制包装在统一的模板结构体中向下传递。
 * 
 * 设计哲学:
 * - 错误分类标准化 (A/B/C/D 四类)
 * - 编译期类型安全
 * - 零运行时异常开销
 * - 明确的错误恢复策略
 */

#pragma once

#include <string>
#include <cstdint>

namespace csc {

/**
 * @brief 网关错误分类枚举
 * 
 * 错误分类体系用于上层决策，每个分类对应不同的用户交互策略。
 * 
 * | 分类 | 枚举值 | 含义 | 上层决策 |
 * |------|--------|------|----------|
 * | SUCCESS | 0 | 操作成功 | 正常流程 |
 * | CLASS_A_AUTH_FATAL | 1 | 明确授权失败 | 弹窗提示，引导重新登录 |
 * | CLASS_B_RATE_LIMIT | 2 | 明确风控限制 | 显示冷却时间，禁用按钮 |
 * | CLASS_C_NETWORK_RETRY | 3 | 瞬时环境异常 | 允许用户手动重试 |
 * | CLASS_D_TAMPERED_ENV | 4 | 高危协议异常 | 断开连接，记录日志 |
 */
enum class GatewayErrorClass : uint8_t {
    /** 操作成功 */
    SUCCESS = 0,
    
    /** 
     * A 类错误：明确授权失败
     * 
     * 触发条件: HTTP 401/403、账户冻结、凭证过期、设备指纹不匹配
     * 用户策略: 弹窗提示，引导重新登录
     */
    CLASS_A_AUTH_FATAL = 1,
    
    /** 
     * B 类错误：明确风控限制
     * 
     * 触发条件: HTTP 429、频繁请求、临时拉黑、冷却中
     * 用户策略: 显示冷却时间，禁用按钮
     */
    CLASS_B_RATE_LIMIT = 2,
    
    /** 
     * C 类错误：瞬时环境异常
     * 
     * 触发条件: 超时、DNS 解析失败、HTTP 5xx、网络断开
     * 用户策略: 允许用户手动重试
     */
    CLASS_C_NETWORK_RETRY = 3,
    
    /** 
     * D 类错误：高危协议异常
     * 
     * 触发条件: 解密失败、MAC 校验错误、JSON 结构缺失、Nonce 不匹配
     * 用户策略: 断开连接，记录日志，禁止重试
     */
    CLASS_D_TAMPERED_ENV = 4
};

/**
 * @brief 通用结果模板结构体
 * 
 * 所有业务函数和网络请求的返回值必须使用此模板包装。
 * 禁止使用 throw 抛出异常，所有错误通过 success + errorClass 传递。
 * 
 * @tparam T 成功时携带的数据类型
 * 
 * 使用示例:
 * @code
 * ResultT<UserInfo> result = Login(username, password);
 * if (!result.success) {
 *     switch (result.errorClass) {
 *         case GatewayErrorClass::CLASS_A_AUTH_FATAL:
 *             ShowLoginFailedDialog(result.message);
 *             break;
 *         case GatewayErrorClass::CLASS_C_NETWORK_RETRY:
 *             EnableRetryButton(result.message);
 *             break;
 *         // ...
 *     }
 *     return;
 * }
 * // 成功，使用 result.data
 * @endcode
 */
template<typename T>
struct ResultT {
    /** 
     * @brief 操作是否成功
     * 
     * 这是第一级判断标志。success == false 时必须检查 errorClass
     * 以确定错误类型和恢复策略。
     */
    bool success = false;
    
    /** 
     * @brief 错误分类
     * 
     * 仅在 success == false 时有效。用于上层决策用户交互策略。
     * success == true 时此值固定为 GatewayErrorClass::SUCCESS。
     */
    GatewayErrorClass errorClass = GatewayErrorClass::SUCCESS;
    
    /** 
     * @brief 底层错误码（仅供脱敏日志）
     * 
     * 原始错误码，用于内部日志记录和调试。
     * 不向用户暴露具体错误码，仅显示模糊文案 message。
     */
    int originalCode = 0;
    
    /** 
     * @brief 用户显示文案
     * 
     * 模糊化的错误描述，用于 UI 展示。
     * 成功时为空字符串。
     */
    std::string message;
    
    /** 
     * @brief 成功时的数据体
     * 
     * 仅在 success == true 时有效。
     * success == false 时此值为默认构造的空对象。
     */
    T data{};
    
    /** 
     * @brief 特殊场景票据
     * 
     * 用于改绑、改密等特殊业务流程的二次验证票据。
     * 普通请求为空字符串。
     */
    std::string rebindToken;
    
    // ========== 便捷构造方法 ==========
    
    /**
     * @brief 构造成功结果
     * 
     * @param data 成功时携带的数据
     * @return ResultT<T> 成功结果
     */
    static ResultT<T> Ok(const T& data) {
        ResultT<T> result;
        result.success = true;
        result.errorClass = GatewayErrorClass::SUCCESS;
        result.data = data;
        return result;
    }
    
    /**
     * @brief 构造 A 类错误（授权失败）
     * 
     * @param code 底层错误码
     * @param msg 用户显示文案
     * @return ResultT<T> 错误结果
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
     * @brief 构造 B 类错误（风控限制）
     * 
     * @param code 底层错误码
     * @param msg 用户显示文案
     * @return ResultT<T> 错误结果
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
     * @brief 构造 C 类错误（网络异常）
     * 
     * @param code 底层错误码
     * @param msg 用户显示文案
     * @return ResultT<T> 错误结果
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
     * @brief 构造 D 类错误（协议异常）
     * 
     * @param code 底层错误码
     * @param msg 用户显示文案
     * @return ResultT<T> 错误结果
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
     * @brief 构造带票据的特殊错误结果
     * 
     * 用于改绑、改密等需要二次验证的场景。
     * 
     * @param errorClass 错误分类
     * @param code 底层错误码
     * @param msg 用户显示文案
     * @param token 二次验证票据
     * @return ResultT<T> 错误结果
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
 * @brief 空结果类型
 * 
 * 用于不需要携带数据体的操作（如登出、心跳等）。
 */
struct EmptyResult {};

/**
 * @brief 空结果模板别名
 */
using Result = ResultT<EmptyResult>;

} // namespace csc