/**
 * @file AuthGateway.h
 * @brief CN: 认证网关 | EN: Authentication Gateway
 *
 * CN: 企业级应用加固组件 - 零信任认证网关
 * EN: Enterprise-grade application hardening component - Zero-trust authentication gateway.
 *
 * CN: 核心设计哲学:
 * EN: Core design philosophy:
 * - CN: 网关绝对无状态：类成员变量不持有任何会话态凭证 | EN: Absolute stateless gateway: Class members hold no session credentials
 * - CN: 所有密钥流转在单次函数调用的栈内存中完成 | EN: All key流转 complete within stack memory of a single function call
 * - CN: 凭证阅后即焚：鉴权失败后立刻 SecureZeroMemory 擦除 | EN: Credentials annihilated after use: SecureZeroMemory wipe enforced after auth failure
 * - CN: 业务上下文彻底撕裂：执法上下文与显示快照物理隔离 | EN: Complete business context撕裂: EnforcementContext and DisplaySnapshot physically isolated
 *
 * CN: 职责边界:
 * EN: Responsibility boundaries:
 * - CN: 负责：网络请求编排、加密通道调用、凭证生命周期管理 | EN: Responsible: Network request orchestration, encrypted channel invocation, credential lifecycle management
 * - CN: 不负责：UI 渲染、业务决策、本地风控 | EN: Not responsible: UI rendering, business decisions, local risk control
 */

#pragma once

#include "Result.h"
#include "SecureChannel.h"

#include <string>
#include <vector>
#include <cstdint>

namespace csc {

// ============================================================
// CN: 数据结构定义 | EN: Data Structure Definitions
// ============================================================

/**
 * @brief CN: 执法上下文 (EnforcementContext) - 高密级 | EN: EnforcementContext - High security classification
 *
 * CN: 存储敏感凭证，仅心跳线程和认证流程可访问。
 * EN: Stores sensitive credentials, accessible only by heartbeat thread and authentication flow.
 * CN: 绝对禁止 UI 线程直接读取此上下文！
 * EN: UI thread is absolutely prohibited from directly reading this context!
 */
struct EnforcementContext {
    /** CN: 访问令牌（JWT 格式）| EN: Access token (JWT format) */
    std::string accessToken;

    /** CN: 硬件指纹（设备唯一标识）| EN: Hardware fingerprint (device unique identifier) */
    std::string hardwareFingerprint;

    /** CN: 绝对时间戳（服务端签发时间）| EN: Absolute timestamp (server issuance time) */
    int64_t serverTimestamp = 0;

    /**
     * @brief CN: 安全重置 - 凭证失效时调用 | EN: Secure reset - Called when credentials expire
     *
     * CN: 使用 SecureZeroMemory 物理擦除内存
     * EN: Uses SecureZeroMemory to physically erase memory
     */
    void secureReset() {
        if (!accessToken.empty()) {
            // CN: 使用 Windows 核心安全保障 API，确保内存物理阅后即焚，绝不被编译器优化薅掉
            // EN: Uses Windows core security API to ensure memory annihilation, never optimized away by compiler
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
 * @brief CN: 显示快照 (DisplaySnapshot) - 低密级 | EN: DisplaySnapshot - Low security classification
 *
 * CN: 只读数据，用于 UI 渲染。
 * EN: Read-only data for UI rendering.
 * CN: 可由 UI 线程安全读取。
 * EN: Can be safely read by UI thread.
 */
struct DisplaySnapshot {
    /** CN: 用户名 | EN: Username */
    std::string username;

    /** CN: 用户等级 | EN: User level */
    std::string userLevel;

    /** CN: 剩余天数 | EN: Remaining days */
    int remainingDays = 0;

    /** CN: 是否有效 | EN: Whether valid */
    bool isValid = false;
};

/**
 * @brief CN: 认证请求参数 | EN: Authentication request parameters
 */
struct AuthRequest {
    /** CN: 认证标识（用户名/凭证 ID）| EN: Authentication identifier (username/credential ID) */
    std::string identifier;

    /** CN: 认证凭证（密码/令牌）| EN: Authentication credential (password/token) */
    std::string credential;

    /** CN: 硬件指纹 | EN: Hardware fingerprint */
    std::string hardwareFingerprint;

    /** CN: 工作量证明 nonce | EN: Proof-of-Work nonce */
    uint64_t powNonce = 0;

    /** CN: 工作量证明解 | EN: Proof-of-Work solution */
    uint64_t powSolution = 0;
};

/**
 * @brief CN: 认证响应数据 | EN: Authentication response data
 */
struct AuthResponse {
    /** CN: 访问令牌 | EN: Access token */
    std::string accessToken;

    /** CN: 服务端时间戳 | EN: Server timestamp */
    int64_t serverTimestamp = 0;

    /** CN: 用户名 | EN: Username */
    std::string username;

    /** CN: 用户等级 | EN: User level */
    std::string userLevel;

    /** CN: 剩余天数 | EN: Remaining days */
    int remainingDays = 0;

    /** CN: 心跳间隔（秒）| EN: Heartbeat interval (seconds) */
    int heartbeatInterval = 60;

    /** CN: 会话 AES Session Key（32 字节，Base64 编码）| EN: Session AES Session Key (32 bytes, Base64 encoded) */
    std::string sessionKeyBase64;
};

/**
 * @brief CN: 心跳请求参数 | EN: Heartbeat request parameters
 */
struct HeartbeatRequest {
    /** CN: 访问令牌 | EN: Access token */
    std::string accessToken;

    /** CN: 硬件指纹 | EN: Hardware fingerprint */
    std::string hardwareFingerprint;

    /** CN: 客户端时间戳 | EN: Client timestamp */
    int64_t clientTimestamp = 0;
};

/**
 * @brief CN: 心跳响应数据 | EN: Heartbeat response data
 */
struct HeartbeatResponse {
    /** CN: 是否有效 | EN: Whether valid */
    bool valid = false;

    /** CN: 服务端时间戳 | EN: Server timestamp */
    int64_t serverTimestamp = 0;

    /** CN: 剩余天数 | EN: Remaining days */
    int remainingDays = 0;
};

// ============================================================
// CN: AuthGateway - 认证网关 | EN: AuthGateway - Authentication Gateway
// ============================================================

/**
 * @brief CN: 认证网关类 | EN: Authentication gateway class
 *
 * CN: 绝对无状态设计：
 * EN: Absolute stateless design:
 * - CN: 严禁类成员变量持有密钥或会话态 | EN: Class members are strictly prohibited from holding keys or session state
 * - CN: Session Key 在栈内存生成、使用、销毁 | EN: Session Key generated, used, and destroyed in stack memory
 * - CN: 所有凭证在单次函数调用生命周期内完成流转 | EN: All credentials complete their lifecycle within a single function call
 *
 * CN: 使用示例:
 * EN: Usage example:
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
 *     // CN: 认证成功，ctx 已更新凭证，snapshot 已更新显示数据
 *     // EN: Auth successful, ctx updated credentials, snapshot updated display data
 * } else {
 *     // CN: 认证失败，根据 errorClass 决定用户交互策略
 *     // EN: Auth failed, determine user interaction strategy based on errorClass
 * }
 * @endcode
 */
class AuthGateway {
public:
    /**
     * @brief CN: 构造函数 | EN: Constructor
     *
     * @param baseUrl CN: API 基础 URL | EN: API base URL
     * @param rsaPublicKeyPEM CN: RSA-2048 公钥（PEM 格式）| EN: RSA-2048 public key (PEM format)
     */
    AuthGateway(const std::string& baseUrl, const std::string& rsaPublicKeyPEM);

    /**
     * @brief CN: 析构函数 | EN: Destructor
     *
     * CN: 确保所有敏感数据被安全擦除
     * EN: Ensures all sensitive data is securely erased
     */
    ~AuthGateway();

    // CN: 禁绝拷贝和赋值 | EN: Copy and assignment deleted
    AuthGateway(const AuthGateway&) = delete;
    AuthGateway& operator=(const AuthGateway&) = delete;

    /**
     * @brief CN: 执行认证流程 | EN: Execute authentication flow
     *
     * CN: 完整的认证生命周期：
     * EN: Complete authentication lifecycle:
     * 1. CN: 构建认证请求 JSON | EN: Build authentication request JSON
     * 2. CN: 通过 SecureChannel 混合加密 | EN: Hybrid encryption via SecureChannel
     * 3. CN: 发送 HTTP POST 请求 | EN: Send HTTP POST request
     * 4. CN: 解密响应数据 | EN: Decrypt response data
     * 5. CN: 更新 EnforcementContext 和 DisplaySnapshot | EN: Update EnforcementContext and DisplaySnapshot
     * 6. CN: 阅后即焚：擦除栈内存中的 Session Key | EN: Annihilate after use: Erase Session Key from stack memory
     *
     * @param request CN: 认证请求参数 | EN: Authentication request parameters
     * @param ctx CN: 执法上下文（输出：更新凭证）| EN: EnforcementContext (output: updated credentials)
     * @param snapshot CN: 显示快照（输出：更新显示数据）| EN: DisplaySnapshot (output: updated display data)
     * @return CN: ResultT<AuthResponse> 认证结果 | EN: ResultT<AuthResponse> Authentication result
     */
    ResultT<AuthResponse> authenticate(const AuthRequest& request,
                                        EnforcementContext& ctx,
                                        DisplaySnapshot& snapshot);

    /**
     * @brief CN: 执行心跳校验 | EN: Execute heartbeat verification
     *
     * CN: 心跳生命周期：
     * EN: Heartbeat lifecycle:
     * 1. CN: 构建心跳请求 JSON | EN: Build heartbeat request JSON
     * 2. CN: 使用缓存的 Session Key 加密 | EN: Encrypt using cached Session Key
     * 3. CN: 发送 HTTP POST 请求 | EN: Send HTTP POST request
     * 4. CN: 解密响应数据 | EN: Decrypt response data
     * 5. CN: 更新 DisplaySnapshot | EN: Update DisplaySnapshot
     *
     * @param request CN: 心跳请求参数 | EN: Heartbeat request parameters
     * @param sessionKey CN: AES Session Key（32 字节）| EN: AES Session Key (32 bytes)
     * @param snapshot CN: 显示快照（输出：更新显示数据）| EN: DisplaySnapshot (output: updated display data)
     * @return CN: ResultT<HeartbeatResponse> 心跳结果 | EN: ResultT<HeartbeatResponse> Heartbeat result
     */
    ResultT<HeartbeatResponse> heartbeat(const HeartbeatRequest& request,
                                          const std::string& sessionKey,
                                          DisplaySnapshot& snapshot);

    /**
     * @brief CN: 执行凭证变更（改密/改绑）| EN: Execute credential change (password/binding change)
     *
     * CN: 凭证变更生命周期：
     * EN: Credential change lifecycle:
     * 1. CN: 验证旧凭证 | EN: Validate old credential
     * 2. CN: 提交变更请求 | EN: Submit change request
     * 3. CN: 服务端返回二次验证票据 | EN: Server returns secondary verification ticket
     * 4. CN: 完成二次验证 | EN: Complete secondary verification
     * 5. CN: 重置 EnforcementContext | EN: Reset EnforcementContext
     *
     * @param oldCredential CN: 旧凭证 | EN: Old credential
     * @param newCredential CN: 新凭证 | EN: New credential
     * @param ctx CN: 执法上下文（输出：重置凭证）| EN: EnforcementContext (output: reset credentials)
     * @return CN: Result 变更结果 | EN: Result Change result
     */
    Result changeCredential(const std::string& oldCredential,
                            const std::string& newCredential,
                            EnforcementContext& ctx);

    /**
     * @brief CN: 执行登出流程 | EN: Execute logout flow
     *
     * CN: 登出生命周期：
     * EN: Logout lifecycle:
     * 1. CN: 发送登出请求 | EN: Send logout request
     * 2. CN: 重置 EnforcementContext | EN: Reset EnforcementContext
     * 3. CN: 擦除所有缓存凭证 | EN: Erase all cached credentials
     *
     * @param ctx CN: 执法上下文（输出：重置凭证）| EN: EnforcementContext (output: reset credentials)
     * @return CN: Result 登出结果 | EN: Result Logout result
     */
    Result logout(EnforcementContext& ctx);

private:
    /** CN: API 基础 URL | EN: API base URL */
    std::string m_baseUrl;

    /** CN: RSA 公钥（PEM 格式）| EN: RSA public key (PEM format) */
    std::string m_rsaPublicKeyPEM;

    /**
     * @brief CN: 构建 HTTP 请求头 | EN: Build HTTP request headers
     *
     * @param accessToken CN: 访问令牌（可选）| EN: Access token (optional)
     * @return CN: std::vector<std::string> 请求头列表 | EN: std::vector<std::string> Request header list
     */
    std::vector<std::string> buildHeaders(const std::string& accessToken = "") const;

    /**
     * @brief CN: 发送 HTTP POST 请求 | EN: Send HTTP POST request
     *
     * @param url CN: 目标 URL | EN: Target URL
     * @param body CN: 请求体 | EN: Request body
     * @param headers CN: 请求头 | EN: Request headers
     * @return CN: std::pair<int, std::string> HTTP 状态码和响应体 | EN: std::pair<int, std::string> HTTP status code and response body
     */
    std::pair<int, std::string> sendPostRequest(const std::string& url,
                                                  const std::string& body,
                                                  const std::vector<std::string>& headers) const;

    /**
     * @brief CN: 解析服务端响应 | EN: Parse server response
     *
     * @param httpCode CN: HTTP 状态码 | EN: HTTP status code
     * @param responseBody CN: 响应体 | EN: Response body
     * @param sessionKey CN: AES Session Key（输出）| EN: AES Session Key (output)
     * @return CN: ResultT<AuthResponse> 解析结果 | EN: ResultT<AuthResponse> Parse result
     */
    ResultT<AuthResponse> parseAuthResponse(int httpCode,
                                             const std::string& responseBody,
                                             std::string& sessionKey) const;

    /**
     * @brief CN: 解析心跳响应 | EN: Parse heartbeat response
     *
     * @param httpCode CN: HTTP 状态码 | EN: HTTP status code
     * @param responseBody CN: 响应体 | EN: Response body
     * @return CN: ResultT<HeartbeatResponse> 解析结果 | EN: ResultT<HeartbeatResponse> Parse result
     */
    ResultT<HeartbeatResponse> parseHeartbeatResponse(int httpCode,
                                                       const std::string& responseBody) const;
};

} // namespace csc