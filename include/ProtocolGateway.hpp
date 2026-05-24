/**
 * @file ProtocolGateway.hpp
 * @brief CN: 协议网关泛型引擎 | EN: Protocol Gateway Generic Engine
 *
 * CN: 本模块实现了白皮书 4.1 节定义的协议规范模式（Protocol Specification Pattern）。
 * EN: This module implements the Protocol Specification Pattern defined in White Paper Section 4.1.
 *
 * CN: 核心设计哲学:
 * EN: Core design philosophy:
 * - CN: 策略类 + 泛型执行引擎：每个业务接口抽象为独立的协议规范类 | EN: Strategy class + generic execution engine: Each business interface abstracted as an independent protocol specification class
 * - CN: 编译期类型安全：请求/响应类型在编译期绑定 | EN: Compile-time type safety: Request/response types bound at compile time
 * - CN: 日志可追溯：每个请求携带唯一 RequestID | EN: Traceable logging: Each request carries a unique RequestID
 * - CN: 错误分类标准化：统一 ResultT<T> 模板 | EN: Standardized error classification: Unified ResultT<T> template
 *
 * CN: 协议规范类接口:
 * EN: Protocol specification class interface:
 * - CN: Endpoint() -> 接口 URL | EN: Endpoint() -> Interface URL
 * - CN: RequestType -> 请求结构体 | EN: RequestType -> Request structure
 * - CN: ResponseType -> 响应结构体 | EN: ResponseType -> Response structure
 * - CN: ValidateLocal() -> 本地预审规则 | EN: ValidateLocal() -> Local pre-validation rules
 * - CN: BuildJson() -> JSON 组装逻辑 | EN: BuildJson() -> JSON assembly logic
 * - CN: ParseJson() -> JSON 解析逻辑 | EN: ParseJson() -> JSON parsing logic
 * - CN: BuildCustomHeaders() -> 自定义 Header 注入 | EN: BuildCustomHeaders() -> Custom header injection
 *
 * CN: 泛型执行引擎执行流程:
 * EN: Generic execution engine workflow:
 * 1. CN: 生成唯一 RequestID（防并发日志错乱）| EN: Generate unique RequestID (prevent concurrent log interleaving)
 * 2. CN: 本地预审 -> 失败直接返回 | EN: Local pre-validation -> return immediately on failure
 * 3. CN: JSON 组装 | EN: JSON assembly
 * 4. CN: SecureChannel 无状态加密 -> 提取会话密钥（栈分配）| EN: SecureChannel stateless encryption -> extract session key (stack allocated)
 * 5. CN: HttpTransport 阻塞发送 | EN: HttpTransport blocking send
 * 6. CN: HTTP 状态码分流 -> 非 200 直接返回 | EN: HTTP status code routing -> return immediately if not 200
 * 7. CN: SecureChannel 无状态解密 -> 传入会话密钥 | EN: SecureChannel stateless decryption -> pass session key
 * 8. CN: 协议专属解析（Nonce 回显校验等）| EN: Protocol-specific parsing (Nonce echo validation, etc.)
 * 9. CN: 强类型组装返回 | EN: Strongly-typed assembly and return
 * 10. CN: 返回成功结果（会话密钥已在 SecureChannel 内部擦除）| EN: Return success result (session key already erased within SecureChannel)
 *
 * CN: 使用示例:
 * EN: Usage example:
 * @code
 * // CN: 1. 定义协议规范类 | EN: 1. Define protocol specification class
 * struct LoginProtocol {
 *     struct Request {
 *         std::string username;
 *         std::string password;
 *         std::string hwid;
 *     };
 *
 *     struct Response {
 *         std::string token;
 *         int expireDays;
 *         std::string nonce;  // CN: 用于心跳回显 | EN: Used for heartbeat echo
 *     };
 *
 *     static std::string Endpoint() { return "/api/v1/login"; }
 *
 *     static ResultT<Request> ValidateLocal(const Request& req) {
 *         if (req.username.empty()) {
 *             return ResultT<Request>::AuthFatal(400, "用户名不能为空");
 *         }
 *         if (req.password.length() < 6) {
 *             return ResultT<Request>::AuthFatal(400, "密码长度不足");
 *         }
 *         return ResultT<Request>::Ok(req);
 *     }
 *
 *     static std::string BuildJson(const Request& req) {
 *         return R"({"username":")" + req.username +
 *                R"(","password":")" + req.password +
 *                R"(","hwid":")" + req.hwid + R"("})";
 *     }
 *
 *     static ResultT<Response> ParseJson(const std::string& json) {
 *         Response resp;
 *         // CN: 解析 JSON... | EN: Parse JSON...
 *         return ResultT<Response>::Ok(resp);
 *     }
 *
 *     static std::map<std::string, std::string> BuildCustomHeaders() {
 *         return {{"X-Protocol-Version", "2.0"}};
 *     }
 * };
 *
 * // CN: 2. 执行请求 | EN: 2. Execute request
 * LoginProtocol::Request req{"user", "pass123", "hwid-xxx"};
 * auto result = ProtocolGateway::Execute<LoginProtocol>(req, rsaPublicKey);
 * if (result.success) {
 *     std::cout << "Token: " << result.data.token << std::endl;
 * }
 * @endcode
 */

#pragma once

#include "Result.h"
#include "SecureChannel.h"

#include <string>
#include <map>
#include <functional>
#include <chrono>
#include <sstream>
#include <atomic>
#include <cstdint>

namespace csc {

// ========== CN: HTTP 传输层抽象接口 | EN: HTTP Transport Layer Abstract Interface ==========

/**
 * @brief CN: HTTP 传输层抽象接口 | EN: HTTP transport layer abstract interface
 *
 * CN: 此接口用于解耦协议网关与具体的 HTTP 实现。
 * EN: This interface decouples the protocol gateway from specific HTTP implementations.
 * CN: 使用者需要实现此接口以适配自己的 HTTP 客户端（如 WinHTTP、libcurl 等）。
 * EN: Users need to implement this interface to adapt to their HTTP client (e.g., WinHTTP, libcurl, etc.).
 */
class IHttpTransport {
public:
    virtual ~IHttpTransport() = default;

    /**
     * @brief CN: 发送 HTTP POST 请求 | EN: Send HTTP POST request
     *
     * @param url CN: 请求 URL | EN: Request URL
     * @param body CN: 请求体 | EN: Request body
     * @param headers CN: 自定义请求头 | EN: Custom request headers
     * @param timeoutMs CN: 超时时间（毫秒）| EN: Timeout (milliseconds)
     * @param statusCode CN: 输出：HTTP 状态码 | EN: Output: HTTP status code
     * @param responseBody CN: 输出：响应体 | EN: Output: Response body
     * @return CN: bool 网络请求是否成功（不代表业务成功）| EN: bool Whether network request succeeded (does not represent business success)
     */
    virtual bool Post(const std::string& url,
                      const std::string& body,
                      const std::map<std::string, std::string>& headers,
                      int timeoutMs,
                      int& statusCode,
                      std::string& responseBody) = 0;
};

// ========== CN: 协议规范类基类约束 | EN: Protocol Specification Class Base Constraints ==========

/**
 * @brief CN: 协议规范类概念约束 | EN: Protocol specification class conceptual constraints
 *
 * CN: 协议规范类必须满足以下接口约束：
 * EN: Protocol specification classes must satisfy the following interface constraints:
 *
 * @code
 * struct MyProtocol {
 *     // CN: 必须：请求类型 | EN: Required: Request type
 *     struct Request { ... };
 *
 *     // CN: 必须：响应类型 | EN: Required: Response type
 *     struct Response { ... };
 *
 *     // CN: 必须：接口端点 | EN: Required: Interface endpoint
 *     static std::string Endpoint();
 *
 *     // CN: 必须：本地预审（可选返回错误）| EN: Required: Local pre-validation (may return error)
 *     static ResultT<Request> ValidateLocal(const Request& req);
 *
 *     // CN: 必须：JSON 组装 | EN: Required: JSON assembly
 *     static std::string BuildJson(const Request& req);
 *
 *     // CN: 必须：JSON 解析 | EN: Required: JSON parsing
 *     static ResultT<Response> ParseJson(const std::string& json);
 *
 *     // CN: 可选：自定义请求头 | EN: Optional: Custom request headers
 *     static std::map<std::string, std::string> BuildCustomHeaders();
 *
 *     // CN: 可选：请求超时（毫秒）| EN: Optional: Request timeout (milliseconds)
 *     static int TimeoutMs();
 * };
 * @endcode
 */

// ========== CN: RequestID 生成器 | EN: RequestID Generator ==========

/**
 * @brief CN: 全局唯一 RequestID 生成器 | EN: Globally unique RequestID generator
 *
 * CN: 使用原子计数器 + 时间戳生成唯一标识，用于并发场景下的日志追踪和问题排查。
 * EN: Generates unique identifiers using atomic counter + timestamp for log tracing and troubleshooting in concurrent scenarios.
 */
class RequestIdGenerator {
public:
    /**
     * @brief CN: 生成唯一 RequestID | EN: Generate unique RequestID
     *
     * CN: 格式: "REQ-{timestamp}-{counter}"
     * EN: Format: "REQ-{timestamp}-{counter}"
     * CN: 示例: "REQ-1716547200-000001"
     * EN: Example: "REQ-1716547200-000001"
     *
     * @return CN: std::string 唯一 RequestID | EN: std::string Unique RequestID
     */
    static std::string Generate() {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        uint64_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);

        std::ostringstream oss;
        oss << "REQ-" << timestamp << "-" << std::setw(6) << std::setfill('0') << (counter % 1000000);
        return oss.str();
    }

private:
    static inline std::atomic<uint64_t> s_counter{0};
};

// ========== CN: 协议网关泛型引擎 | EN: Protocol Gateway Generic Engine ==========

/**
 * @brief CN: 协议网关泛型引擎 | EN: Protocol gateway generic engine
 *
 * CN: 此类不持有任何会话态成员变量，所有密码学操作在单次函数调用的栈内存中完成。
 * EN: This class holds no session state member variables; all cryptographic operations complete within stack memory of a single function call.
 *
 * CN: 线程安全：此类的静态方法是线程安全的（无共享可变状态）。
 * EN: Thread safety: Static methods of this class are thread-safe (no shared mutable state).
 */
class ProtocolGateway {
public:
    /**
     * @brief CN: 执行协议请求（泛型方法）| EN: Execute protocol request (generic method)
     *
     * CN: 完整的请求-响应生命周期：
     * EN: Complete request-response lifecycle:
     * 1. CN: 生成 RequestID | EN: Generate RequestID
     * 2. CN: 本地预审 | EN: Local pre-validation
     * 3. CN: JSON 组装 | EN: JSON assembly
     * 4. CN: SecureChannel 加密 | EN: SecureChannel encryption
     * 5. CN: HTTP 发送 | EN: HTTP send
     * 6. CN: HTTP 状态码分流 | EN: HTTP status code routing
     * 7. CN: SecureChannel 解密 | EN: SecureChannel decryption
     * 8. CN: 协议解析 | EN: Protocol parsing
     * 9. CN: 内存擦除 | EN: Memory erasure
     *
     * @tparam TProtocol CN: 协议规范类 | EN: Protocol specification class
     * @param request CN: 请求数据 | EN: Request data
     * @param transport CN: HTTP 传输层实现 | EN: HTTP transport layer implementation
     * @param rsaPublicKeyPEM CN: RSA 公钥（PEM 格式）| EN: RSA public key (PEM format)
     * @param baseUrl CN: 基础 URL（如 "https://api.example.com"）| EN: Base URL (e.g., "https://api.example.com")
     * @return CN: ResultT<typename TProtocol::Response> 执行结果 | EN: ResultT<typename TProtocol::Response> Execution result
     */
    template<typename TProtocol>
    static ResultT<typename TProtocol::Response> Execute(
        const typename TProtocol::Request& request,
        IHttpTransport& transport,
        const std::string& rsaPublicKeyPEM,
        const std::string& baseUrl = "") {

        using Response = typename TProtocol::Response;

        // =========================================================
        // CN: 步骤 1: 生成唯一 RequestID | EN: Step 1: Generate unique RequestID
        // =========================================================
        std::string requestId = RequestIdGenerator::Generate();

        // =========================================================
        // CN: 步骤 2: 本地预审 | EN: Step 2: Local pre-validation
        // =========================================================
        auto validationResult = TProtocol::ValidateLocal(request);
        if (!validationResult.success) {
            return ResultT<Response>(validationResult);
        }

        // =========================================================
        // CN: 步骤 3: JSON 组装 | EN: Step 3: JSON assembly
        // =========================================================
        std::string jsonBody = TProtocol::BuildJson(request);
        if (jsonBody.empty()) {
            return ResultT<Response>::TamperedEnv(500, "请求数据组装失败");
        }

        // =========================================================
        // CN: 步骤 4: SecureChannel 无状态加密 | EN: Step 4: SecureChannel stateless encryption
        // =========================================================
        EncryptedPayload encrypted = SecureChannel::Encrypt(jsonBody, rsaPublicKeyPEM);
        if (encrypted.base64Data.empty()) {
            return ResultT<Response>::TamperedEnv(500, "数据加密失败");
        }

        // CN: 包装为外层 JSON | EN: Wrap as outer JSON
        std::string requestBody = "{\"data\": \"" + encrypted.base64Data + "\"}";

        // =========================================================
        // CN: 步骤 5: 构建请求头 | EN: Step 5: Build request headers
        // =========================================================
        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-Request-ID"] = requestId;
        headers["X-Protocol-Version"] = CSC_PROTOCOL_VERSION;

        // CN: 合并协议自定义请求头 | EN: Merge protocol custom headers
        auto customHeaders = TProtocol::BuildCustomHeaders();
        headers.insert(customHeaders.begin(), customHeaders.end());

        // =========================================================
        // CN: 步骤 6: HTTP 发送 | EN: Step 6: HTTP send
        // =========================================================
        std::string url = baseUrl + TProtocol::Endpoint();
        int timeoutMs = TProtocol::TimeoutMs();

        int httpStatusCode = 0;
        std::string responseBody;

        bool httpSuccess = transport.Post(url, requestBody, headers, timeoutMs,
                                           httpStatusCode, responseBody);

        if (!httpSuccess) {
            // CN: 网络层失败 -> C 类错误（允许重试）| EN: Network layer failure -> Class C error (retry allowed)
            return ResultT<Response>::NetworkRetry(0, "网络连接失败，请检查网络后重试");
        }

        // =========================================================
        // CN: 步骤 7: HTTP 状态码分流 | EN: Step 7: HTTP status code routing
        // =========================================================
        if (httpStatusCode == 401 || httpStatusCode == 403) {
            // CN: 授权失败 -> A 类错误 | EN: Authorization failure -> Class A error
            return ResultT<Response>::AuthFatal(httpStatusCode, "认证失败，请重新登录");
        }

        if (httpStatusCode == 429) {
            // CN: 限流 -> B 类错误 | EN: Rate limiting -> Class B error
            return ResultT<Response>::RateLimit(httpStatusCode, "请求过于频繁，请稍后重试");
        }

        if (httpStatusCode != 200) {
            // CN: 其他服务器错误 -> C 类错误 | EN: Other server errors -> Class C error
            return ResultT<Response>::NetworkRetry(httpStatusCode, "服务器异常，请稍后重试");
        }

        // =========================================================
        // CN: 步骤 8: SecureChannel 无状态解密 | EN: Step 8: SecureChannel stateless decryption
        // =========================================================
        // CN: 注意：此处假设服务端使用相同的混合加密格式返回
        // EN: Note: Assumes server returns using the same hybrid encryption format
        // CN: 实际项目中可能需要根据服务端实现调整解密逻辑
        // EN: Actual projects may need to adjust decryption logic based on server implementation
        DecryptedPayload decrypted = SecureChannel::Decrypt(responseBody, rsaPublicKeyPEM);

        if (!decrypted.success) {
            // CN: 解密失败 -> D 类错误（可能是数据被篡改）| EN: Decryption failure -> Class D error (possible data tampering)
            return ResultT<Response>::TamperedEnv(0, "响应数据校验失败");
        }

        // =========================================================
        // CN: 步骤 9: 协议专属解析 | EN: Step 9: Protocol-specific parsing
        // =========================================================
        auto parseResult = TProtocol::ParseJson(decrypted.plaintext);
        if (!parseResult.success) {
            return ResultT<Response>::TamperedEnv(0, "响应数据格式异常");
        }

        // =========================================================
        // CN: 步骤 10: 返回成功结果 | EN: Step 10: Return success result
        // =========================================================
        return ResultT<Response>::Ok(parseResult.data);
    }

    /**
     * @brief CN: 执行协议请求（带自定义 RSA 私钥解密版本）| EN: Execute protocol request (with custom RSA private key decryption version)
     *
     * CN: 此版本允许使用不同的密钥对进行解密，适用于响应端使用不同密钥加密的场景。
     * EN: This version allows decryption using different key pairs, suitable for scenarios where the response end uses different keys for encryption.
     *
     * @tparam TProtocol CN: 协议规范类 | EN: Protocol specification class
     * @param request CN: 请求数据 | EN: Request data
     * @param transport CN: HTTP 传输层实现 | EN: HTTP transport layer implementation
     * @param rsaPublicKeyPEM CN: 请求加密用的 RSA 公钥 | EN: RSA public key for request encryption
     * @param rsaPrivateKeyPEM CN: 响应解密用的 RSA 私钥 | EN: RSA private key for response decryption
     * @param baseUrl CN: 基础 URL | EN: Base URL
     * @return CN: ResultT<typename TProtocol::Response> 执行结果 | EN: ResultT<typename TProtocol::Response> Execution result
     */
    template<typename TProtocol>
    static ResultT<typename TProtocol::Response> ExecuteWithKeyPair(
        const typename TProtocol::Request& request,
        IHttpTransport& transport,
        const std::string& rsaPublicKeyPEM,
        const std::string& rsaPrivateKeyPEM,
        const std::string& baseUrl = "") {

        using Response = typename TProtocol::Response;

        // CN: 生成 RequestID | EN: Generate RequestID
        std::string requestId = RequestIdGenerator::Generate();

        // CN: 本地预审 | EN: Local pre-validation
        auto validationResult = TProtocol::ValidateLocal(request);
        if (!validationResult.success) {
            return ResultT<Response>(validationResult);
        }

        // CN: JSON 组装 | EN: JSON assembly
        std::string jsonBody = TProtocol::BuildJson(request);
        if (jsonBody.empty()) {
            return ResultT<Response>::TamperedEnv(500, "请求数据组装失败");
        }

        // CN: 加密 | EN: Encryption
        EncryptedPayload encrypted = SecureChannel::Encrypt(jsonBody, rsaPublicKeyPEM);
        if (encrypted.base64Data.empty()) {
            return ResultT<Response>::TamperedEnv(500, "数据加密失败");
        }

        std::string requestBody = "{\"data\": \"" + encrypted.base64Data + "\"}";

        // CN: 构建请求头 | EN: Build request headers
        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-Request-ID"] = requestId;
        headers["X-Protocol-Version"] = CSC_PROTOCOL_VERSION;

        auto customHeaders = TProtocol::BuildCustomHeaders();
        headers.insert(customHeaders.begin(), customHeaders.end());

        // CN: HTTP 发送 | EN: HTTP send
        std::string url = baseUrl + TProtocol::Endpoint();
        int timeoutMs = TProtocol::TimeoutMs();

        int httpStatusCode = 0;
        std::string responseBody;

        bool httpSuccess = transport.Post(url, requestBody, headers, timeoutMs,
                                           httpStatusCode, responseBody);

        if (!httpSuccess) {
            return ResultT<Response>::NetworkRetry(0, "网络连接失败，请检查网络后重试");
        }

        // CN: HTTP 状态码分流 | EN: HTTP status code routing
        if (httpStatusCode == 401 || httpStatusCode == 403) {
            return ResultT<Response>::AuthFatal(httpStatusCode, "认证失败，请重新登录");
        }

        if (httpStatusCode == 429) {
            return ResultT<Response>::RateLimit(httpStatusCode, "请求过于频繁，请稍后重试");
        }

        if (httpStatusCode != 200) {
            return ResultT<Response>::NetworkRetry(httpStatusCode, "服务器异常，请稍后重试");
        }

        // CN: 解密（使用私钥）| EN: Decryption (using private key)
        DecryptedPayload decrypted = SecureChannel::Decrypt(responseBody, rsaPrivateKeyPEM);

        if (!decrypted.success) {
            return ResultT<Response>::TamperedEnv(0, "响应数据校验失败");
        }

        // CN: 协议解析 | EN: Protocol parsing
        auto parseResult = TProtocol::ParseJson(decrypted.plaintext);
        if (!parseResult.success) {
            return ResultT<Response>::TamperedEnv(0, "响应数据格式异常");
        }

        return ResultT<Response>::Ok(parseResult.data);
    }
};

// ========== CN: 协议规范类默认实现辅助宏 | EN: Protocol Specification Class Default Implementation Helper Macros ==========

/**
 * @brief CN: 协议规范类默认超时宏 | EN: Protocol specification class default timeout macro
 *
 * CN: 在协议规范类中使用此宏提供默认超时值。
 * EN: Use this macro in protocol specification classes to provide default timeout values.
 */
#define CSC_PROTOCOL_DEFAULT_TIMEOUT 30000  // CN: 30 秒 | EN: 30 seconds

/**
 * @brief CN: 协议规范类默认端点前缀宏 | EN: Protocol specification class default endpoint prefix macro
 *
 * CN: 在协议规范类中使用此宏提供默认端点。
 * EN: Use this macro in protocol specification classes to provide default endpoints.
 */
#define CSC_PROTOCOL_DEFAULT_ENDPOINT "/api/v1"

} // namespace csc