/**
 * @file AuthGateway.h
 * @brief 认证网关 (Authentication Gateway)
 *
 * 企业级应用加固组件 - 零信任认证网关
 *
 * 核心设计哲学:
 * - 网关绝对无状态：类成员变量不持有任何会话态凭证
 * - 所有密钥流转在单次函数调用的栈内存中完成
 * - 凭证阅后即焚：鉴权失败后立刻 SecureZeroMemory 擦除
 * - 业务上下文彻底撕裂：执法上下文与显示快照物理隔离
 *
 * 职责边界:
 * - 负责：网络请求编排、加密通道调用、凭证生命周期管理
 * - 不负责：UI 渲染、业务决策、本地风控
 */

#pragma once

#include "Result.h"
#include "SecureChannel.h"

#include <string>
#include <vector>
#include <cstdint>

namespace csc {

// ============================================================
// 数据结构定义
// ============================================================

/**
 * @brief 执法上下文 (EnforcementContext) - 高密级
 *
 * 存储敏感凭证，仅心跳线程和认证流程可访问。
 * 绝对禁止 UI 线程直接读取此上下文！
 */
struct EnforcementContext {
    /** 访问令牌（JWT 格式） */
    std::string accessToken;

    /** 硬件指纹（设备唯一标识） */
    std::string hardwareFingerprint;

    /** 绝对时间戳（服务端签发时间） */
    int64_t serverTimestamp = 0;

    /**
     * @brief 安全重置 - 凭证失效时调用
     *
     * 使用 SecureZeroMemory 物理擦除内存
     */
    void secureReset() {
        if (!accessToken.empty()) {
            // 使用 Windows 核心安全保障 API，确保内存物理阅后即焚，绝不被编译器优化薅掉
            ::SecureZeroMemory(const_cast<char*>(accessToken.data()), accessToken.size());
            accessToken.clear();
        }
        if (!hardwareFingerprint.empty()) {
            ::SecureZeroMemory(const_cast<char*>(hardwareFingerprint.data()), hardwareFingerprint.size());
            hardwareFingerprint.clear();
        }
        serverTimestamp = 0;
    }
};

/**
 * @brief 显示快照 (DisplaySnapshot) - 低密级
 *
 * 只读数据，用于 UI 渲染。
 * 可由 UI 线程安全读取。
 */
struct DisplaySnapshot {
    /** 用户名 */
    std::string username;

    /** 用户等级 */
    std::string userLevel;

    /** 剩余天数 */
    int remainingDays = 0;

    /** 是否有效 */
    bool isValid = false;
};

/**
 * @brief 认证请求参数
 */
struct AuthRequest {
    /** 认证标识（用户名/凭证 ID） */
    std::string identifier;

    /** 认证凭证（密码/令牌） */
    std::string credential;

    /** 硬件指纹 */
    std::string hardwareFingerprint;

    /** 工作量证明 nonce */
    uint64_t powNonce = 0;

    /** 工作量证明解 */
    uint64_t powSolution = 0;
};

/**
 * @brief 认证响应数据
 */
struct AuthResponse {
    /** 访问令牌 */
    std::string accessToken;

    /** 服务端时间戳 */
    int64_t serverTimestamp = 0;

    /** 用户名 */
    std::string username;

    /** 用户等级 */
    std::string userLevel;

    /** 剩余天数 */
    int remainingDays = 0;

    /** 心跳间隔（秒） */
    int heartbeatInterval = 60;

    /** 会话 AES Session Key（32 字节，Base64 编码） */
    std::string sessionKeyBase64;
};

/**
 * @brief 心跳请求参数
 */
struct HeartbeatRequest {
    /** 访问令牌 */
    std::string accessToken;

    /** 硬件指纹 */
    std::string hardwareFingerprint;

    /** 客户端时间戳 */
    int64_t clientTimestamp = 0;
};

/**
 * @brief 心跳响应数据
 */
struct HeartbeatResponse {
    /** 是否有效 */
    bool valid = false;

    /** 服务端时间戳 */
    int64_t serverTimestamp = 0;

    /** 剩余天数 */
    int remainingDays = 0;
};

// ============================================================
// AuthGateway - 认证网关
// ============================================================

/**
 * @brief 认证网关类
 *
 * 绝对无状态设计：
 * - 严禁类成员变量持有密钥或会话态
 * - Session Key 在栈内存生成、使用、销毁
 * - 所有凭证在单次函数调用生命周期内完成流转
 *
 * 使用示例:
 * @code
 * AuthGateway gateway;
 * EnforcementContext ctx;
 * DisplaySnapshot snapshot;
 *
 * AuthRequest req;
 * req.identifier = "user123";
 * req.credential = "password";
 * req.hardwareFingerprint = DeviceFingerprint::generate();
 *
 * auto result = gateway.authenticate(req, ctx, snapshot);
 * if (result.success) {
 *     // 认证成功，ctx 已更新凭证，snapshot 已更新显示数据
 * } else {
 *     // 认证失败，根据 errorClass 决定用户交互策略
 * }
 * @endcode
 */
class AuthGateway {
public:
    /**
     * @brief 构造函数
     *
     * @param baseUrl API 基础 URL
     * @param rsaPublicKeyPEM RSA-2048 公钥（PEM 格式）
     */
    AuthGateway(const std::string& baseUrl, const std::string& rsaPublicKeyPEM);

    /**
     * @brief 析构函数
     *
     * 确保所有敏感数据被安全擦除
     */
    ~AuthGateway();

    // 禁绝拷贝和赋值
    AuthGateway(const AuthGateway&) = delete;
    AuthGateway& operator=(const AuthGateway&) = delete;

    /**
     * @brief 执行认证流程
     *
     * 完整的认证生命周期：
     * 1. 构建认证请求 JSON
     * 2. 通过 SecureChannel 混合加密
     * 3. 发送 HTTP POST 请求
     * 4. 解密响应数据
     * 5. 更新 EnforcementContext 和 DisplaySnapshot
     * 6. 阅后即焚：擦除栈内存中的 Session Key
     *
     * @param request 认证请求参数
     * @param ctx 执法上下文（输出：更新凭证）
     * @param snapshot 显示快照（输出：更新显示数据）
     * @return ResultT<AuthResponse> 认证结果
     */
    ResultT<AuthResponse> authenticate(const AuthRequest& request,
                                        EnforcementContext& ctx,
                                        DisplaySnapshot& snapshot);

    /**
     * @brief 执行心跳校验
     *
     * 心跳生命周期：
     * 1. 构建心跳请求 JSON
     * 2. 使用缓存的 Session Key 加密
     * 3. 发送 HTTP POST 请求
     * 4. 解密响应数据
     * 5. 更新 DisplaySnapshot
     *
     * @param request 心跳请求参数
     * @param sessionKey AES Session Key（32 字节）
     * @param snapshot 显示快照（输出：更新显示数据）
     * @return ResultT<HeartbeatResponse> 心跳结果
     */
    ResultT<HeartbeatResponse> heartbeat(const HeartbeatRequest& request,
                                          const std::string& sessionKey,
                                          DisplaySnapshot& snapshot);

    /**
     * @brief 执行凭证变更（改密/改绑）
     *
     * 凭证变更生命周期：
     * 1. 验证旧凭证
     * 2. 提交变更请求
     * 3. 服务端返回二次验证票据
     * 4. 完成二次验证
     * 5. 重置 EnforcementContext
     *
     * @param oldCredential 旧凭证
     * @param newCredential 新凭证
     * @param ctx 执法上下文（输出：重置凭证）
     * @return Result 变更结果
     */
    Result changeCredential(const std::string& oldCredential,
                            const std::string& newCredential,
                            EnforcementContext& ctx);

    /**
     * @brief 执行登出流程
     *
     * 登出生命周期：
     * 1. 发送登出请求
     * 2. 重置 EnforcementContext
     * 3. 擦除所有缓存凭证
     *
     * @param ctx 执法上下文（输出：重置凭证）
     * @return Result 登出结果
     */
    Result logout(EnforcementContext& ctx);

private:
    /** API 基础 URL */
    std::string m_baseUrl;

    /** RSA 公钥（PEM 格式） */
    std::string m_rsaPublicKeyPEM;

    /**
     * @brief 构建 HTTP 请求头
     *
     * @param accessToken 访问令牌（可选）
     * @return std::vector<std::string> 请求头列表
     */
    std::vector<std::string> buildHeaders(const std::string& accessToken = "") const;

    /**
     * @brief 发送 HTTP POST 请求
     *
     * @param url 目标 URL
     * @param body 请求体
     * @param headers 请求头
     * @return std::pair<int, std::string> HTTP 状态码和响应体
     */
    std::pair<int, std::string> sendPostRequest(const std::string& url,
                                                  const std::string& body,
                                                  const std::vector<std::string>& headers) const;

    /**
     * @brief 解析服务端响应
     *
     * @param httpCode HTTP 状态码
     * @param responseBody 响应体
     * @param sessionKey AES Session Key（输出）
     * @return ResultT<AuthResponse> 解析结果
     */
    ResultT<AuthResponse> parseAuthResponse(int httpCode,
                                             const std::string& responseBody,
                                             std::string& sessionKey) const;

    /**
     * @brief 解析心跳响应
     *
     * @param httpCode HTTP 状态码
     * @param responseBody 响应体
     * @return ResultT<HeartbeatResponse> 解析结果
     */
    ResultT<HeartbeatResponse> parseHeartbeatResponse(int httpCode,
                                                       const std::string& responseBody) const;
};

} // namespace csc