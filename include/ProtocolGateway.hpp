/**
 * @file ProtocolGateway.hpp
 * @brief 协议网关泛型引擎 (Protocol Gateway Generic Engine)
 * 
 * 本模块实现了白皮书 4.1 节定义的协议规范模式（Protocol Specification Pattern）。
 * 
 * 核心设计哲学:
 * - 策略类 + 泛型执行引擎：每个业务接口抽象为独立的协议规范类
 * - 编译期类型安全：请求/响应类型在编译期绑定
 * - 日志可追溯：每个请求携带唯一 RequestID
 * - 错误分类标准化：统一 ResultT<T> 模板
 * 
 * 协议规范类接口:
 * - Endpoint()        → 接口 URL
 * - RequestType       → 请求结构体
 * - ResponseType      → 响应结构体
 * - ValidateLocal()   → 本地预审规则
 * - BuildJson()       → JSON 组装逻辑
 * - ParseJson()       → JSON 解析逻辑
 * - BuildCustomHeaders() → 自定义 Header 注入
 * 
 * 泛型执行引擎执行流程:
 * 1. 生成唯一 RequestID（防并发日志错乱）
 * 2. 本地预审 → 失败直接返回
 * 3. JSON 组装
 * 4. SecureChannel 无状态加密 → 提取会话密钥（栈分配）
 * 5. HttpTransport 阻塞发送
 * 6. HTTP 状态码分流 → 非 200 直接返回
 * 7. SecureChannel 无状态解密 → 传入会话密钥
 * 8. 协议专属解析（Nonce 回显校验等）
 * 9. 强类型组装返回
 * 10. 返回成功结果（会话密钥已在 SecureChannel 内部擦除）
 * 
 * 使用示例:
 * @code
 * // 1. 定义协议规范类
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
 *         std::string nonce;  // 用于心跳回显
 *     };
 *     
 *     static std::string Endpoint() { return "/api/v1/login"; }
 *     
 *     static ResultT<Request::Request> ValidateLocal(const Request& req) {
 *         if (req.username.empty()) {
 *             return ResultT<Request::Request>::AuthFatal(400, "用户名不能为空");
 *         }
 *         if (req.password.length() < 6) {
 *             return ResultT<Request::Request>::AuthFatal(400, "密码长度不足");
 *         }
 *         return ResultT<Request::Request>::Ok(req);
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
 *         // 解析 JSON...
 *         return ResultT<Response>::Ok(resp);
 *     }
 *     
 *     static std::map<std::string, std::string> BuildCustomHeaders() {
 *         return {{"X-Protocol-Version", "2.0"}};
 *     }
 * };
 * 
 * // 2. 执行请求
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

// ========== HTTP 传输层抽象接口 ==========

/**
 * @brief HTTP 传输层抽象接口
 * 
 * 此接口用于解耦协议网关与具体的 HTTP 实现。
 * 使用者需要实现此接口以适配自己的 HTTP 客户端（如 WinHTTP、libcurl 等）。
 */
class IHttpTransport {
public:
    virtual ~IHttpTransport() = default;
    
    /**
     * @brief 发送 HTTP POST 请求
     * 
     * @param url 请求 URL
     * @param body 请求体
     * @param headers 自定义请求头
     * @param timeoutMs 超时时间（毫秒）
     * @param statusCode 输出：HTTP 状态码
     * @param responseBody 输出：响应体
     * @return bool 网络请求是否成功（不代表业务成功）
     */
    virtual bool Post(const std::string& url,
                      const std::string& body,
                      const std::map<std::string, std::string>& headers,
                      int timeoutMs,
                      int& statusCode,
                      std::string& responseBody) = 0;
};

// ========== 协议规范类基类约束 ==========

/**
 * @brief 协议规范类概念约束
 * 
 * 协议规范类必须满足以下接口约束：
 * 
 * @code
 * struct MyProtocol {
 *     // 必须：请求类型
 *     struct Request { ... };
 *     
 *     // 必须：响应类型
 *     struct Response { ... };
 *     
 *     // 必须：接口端点
 *     static std::string Endpoint();
 *     
 *     // 必须：本地预审（可选返回错误）
 *     static ResultT<Request> ValidateLocal(const Request& req);
 *     
 *     // 必须：JSON 组装
 *     static std::string BuildJson(const Request& req);
 *     
 *     // 必须：JSON 解析
 *     static ResultT<Response> ParseJson(const std::string& json);
 *     
 *     // 可选：自定义请求头
 *     static std::map<std::string, std::string> BuildCustomHeaders();
 *     
 *     // 可选：请求超时（毫秒）
 *     static int TimeoutMs();
 * };
 * @endcode
 */

// ========== RequestID 生成器 ==========

/**
 * @brief 全局唯一 RequestID 生成器
 * 
 * 使用原子计数器 + 时间戳生成唯一标识，
 * 用于并发场景下的日志追踪和问题排查。
 */
class RequestIdGenerator {
public:
    /**
     * @brief 生成唯一 RequestID
     * 
     * 格式: "REQ-{timestamp}-{counter}"
     * 示例: "REQ-1716547200-000001"
     * 
     * @return std::string 唯一 RequestID
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

// ========== 协议网关泛型引擎 ==========

/**
 * @brief 协议网关泛型引擎
 * 
 * 此类不持有任何会话态成员变量，所有密码学操作在单次函数调用的栈内存中完成。
 * 
 * 线程安全：此类的静态方法是线程安全的（无共享可变状态）。
 */
class ProtocolGateway {
public:
    /**
     * @brief 执行协议请求（泛型方法）
     * 
     * 完整的请求-响应生命周期：
     * 1. 生成 RequestID
     * 2. 本地预审
     * 3. JSON 组装
     * 4. SecureChannel 加密
     * 5. HTTP 发送
     * 6. HTTP 状态码分流
     * 7. SecureChannel 解密
     * 8. 协议解析
     * 9. 内存擦除
     * 
     * @tparam TProtocol 协议规范类
     * @param request 请求数据
     * @param transport HTTP 传输层实现
     * @param rsaPublicKeyPEM RSA 公钥（PEM 格式）
     * @param baseUrl 基础 URL（如 "https://api.example.com"）
     * @return ResultT<typename TProtocol::Response> 执行结果
     */
    template<typename TProtocol>
    static ResultT<typename TProtocol::Response> Execute(
        const typename TProtocol::Request& request,
        IHttpTransport& transport,
        const std::string& rsaPublicKeyPEM,
        const std::string& baseUrl = "") {
        
        using Response = typename TProtocol::Response;
        
        // =========================================================
        // 步骤 1: 生成唯一 RequestID
        // =========================================================
        std::string requestId = RequestIdGenerator::Generate();
        
        // =========================================================
        // 步骤 2: 本地预审
        // =========================================================
        auto validationResult = TProtocol::ValidateLocal(request);
        if (!validationResult.success) {
            return ResultT<Response>(validationResult);
        }
        
        // =========================================================
        // 步骤 3: JSON 组装
        // =========================================================
        std::string jsonBody = TProtocol::BuildJson(request);
        if (jsonBody.empty()) {
            return ResultT<Response>::TamperedEnv(500, "请求数据组装失败");
        }
        
        // =========================================================
        // 步骤 4: SecureChannel 无状态加密
        // =========================================================
        EncryptedPayload encrypted = SecureChannel::Encrypt(jsonBody, rsaPublicKeyPEM);
        if (encrypted.base64Data.empty()) {
            return ResultT<Response>::TamperedEnv(500, "数据加密失败");
        }
        
        // 包装为外层 JSON
        std::string requestBody = "{\"data\": \"" + encrypted.base64Data + "\"}";
        
        // =========================================================
        // 步骤 5: 构建请求头
        // =========================================================
        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-Request-ID"] = requestId;
        headers["X-Protocol-Version"] = CSC_PROTOCOL_VERSION;
        
        // 合并协议自定义请求头
        auto customHeaders = TProtocol::BuildCustomHeaders();
        headers.insert(customHeaders.begin(), customHeaders.end());
        
        // =========================================================
        // 步骤 6: HTTP 发送
        // =========================================================
        std::string url = baseUrl + TProtocol::Endpoint();
        int timeoutMs = TProtocol::TimeoutMs();
        
        int httpStatusCode = 0;
        std::string responseBody;
        
        bool httpSuccess = transport.Post(url, requestBody, headers, timeoutMs, 
                                           httpStatusCode, responseBody);
        
        if (!httpSuccess) {
            // 网络层失败 → C 类错误（允许重试）
            return ResultT<Response>::NetworkRetry(0, "网络连接失败，请检查网络后重试");
        }
        
        // =========================================================
        // 步骤 7: HTTP 状态码分流
        // =========================================================
        if (httpStatusCode == 401 || httpStatusCode == 403) {
            // 授权失败 → A 类错误
            return ResultT<Response>::AuthFatal(httpStatusCode, "认证失败，请重新登录");
        }
        
        if (httpStatusCode == 429) {
            // 限流 → B 类错误
            return ResultT<Response>::RateLimit(httpStatusCode, "请求过于频繁，请稍后重试");
        }
        
        if (httpStatusCode != 200) {
            // 其他服务器错误 → C 类错误
            return ResultT<Response>::NetworkRetry(httpStatusCode, "服务器异常，请稍后重试");
        }
        
        // =========================================================
        // 步骤 8: SecureChannel 无状态解密
        // =========================================================
        // 注意：此处假设服务端使用相同的混合加密格式返回
        // 实际项目中可能需要根据服务端实现调整解密逻辑
        DecryptedPayload decrypted = SecureChannel::Decrypt(responseBody, rsaPublicKeyPEM);
        
        if (!decrypted.valid) {
            // 解密失败 → D 类错误（可能是数据被篡改）
            return ResultT<Response>::TamperedEnv(0, "响应数据校验失败");
        }
        
        // =========================================================
        // 步骤 9: 协议专属解析
        // =========================================================
        auto parseResult = TProtocol::ParseJson(decrypted.plaintext);
        if (!parseResult.success) {
            return ResultT<Response>::TamperedEnv(0, "响应数据格式异常");
        }
        
        // =========================================================
        // 步骤 10: 返回成功结果
        // =========================================================
        return ResultT<Response>::Ok(parseResult.data);
    }
    
    /**
     * @brief 执行协议请求（带自定义 RSA 私钥解密版本）
     * 
     * 此版本允许使用不同的密钥对进行解密，
     * 适用于响应端使用不同密钥加密的场景。
     * 
     * @tparam TProtocol 协议规范类
     * @param request 请求数据
     * @param transport HTTP 传输层实现
     * @param rsaPublicKeyPEM 请求加密用的 RSA 公钥
     * @param rsaPrivateKeyPEM 响应解密用的 RSA 私钥
     * @param baseUrl 基础 URL
     * @return ResultT<typename TProtocol::Response> 执行结果
     */
    template<typename TProtocol>
    static ResultT<typename TProtocol::Response> ExecuteWithKeyPair(
        const typename TProtocol::Request& request,
        IHttpTransport& transport,
        const std::string& rsaPublicKeyPEM,
        const std::string& rsaPrivateKeyPEM,
        const std::string& baseUrl = "") {
        
        using Response = typename TProtocol::Response;
        
        // 生成 RequestID
        std::string requestId = RequestIdGenerator::Generate();
        
        // 本地预审
        auto validationResult = TProtocol::ValidateLocal(request);
        if (!validationResult.success) {
            return ResultT<Response>(validationResult);
        }
        
        // JSON 组装
        std::string jsonBody = TProtocol::BuildJson(request);
        if (jsonBody.empty()) {
            return ResultT<Response>::TamperedEnv(500, "请求数据组装失败");
        }
        
        // 加密
        EncryptedPayload encrypted = SecureChannel::Encrypt(jsonBody, rsaPublicKeyPEM);
        if (encrypted.base64Data.empty()) {
            return ResultT<Response>::TamperedEnv(500, "数据加密失败");
        }
        
        std::string requestBody = "{\"data\": \"" + encrypted.base64Data + "\"}";
        
        // 构建请求头
        std::map<std::string, std::string> headers;
        headers["Content-Type"] = "application/json";
        headers["X-Request-ID"] = requestId;
        headers["X-Protocol-Version"] = CSC_PROTOCOL_VERSION;
        
        auto customHeaders = TProtocol::BuildCustomHeaders();
        headers.insert(customHeaders.begin(), customHeaders.end());
        
        // HTTP 发送
        std::string url = baseUrl + TProtocol::Endpoint();
        int timeoutMs = TProtocol::TimeoutMs();
        
        int httpStatusCode = 0;
        std::string responseBody;
        
        bool httpSuccess = transport.Post(url, requestBody, headers, timeoutMs,
                                           httpStatusCode, responseBody);
        
        if (!httpSuccess) {
            return ResultT<Response>::NetworkRetry(0, "网络连接失败，请检查网络后重试");
        }
        
        // HTTP 状态码分流
        if (httpStatusCode == 401 || httpStatusCode == 403) {
            return ResultT<Response>::AuthFatal(httpStatusCode, "认证失败，请重新登录");
        }
        
        if (httpStatusCode == 429) {
            return ResultT<Response>::RateLimit(httpStatusCode, "请求过于频繁，请稍后重试");
        }
        
        if (httpStatusCode != 200) {
            return ResultT<Response>::NetworkRetry(httpStatusCode, "服务器异常，请稍后重试");
        }
        
        // 解密（使用私钥）
        DecryptedPayload decrypted = SecureChannel::Decrypt(responseBody, rsaPrivateKeyPEM);
        
        if (!decrypted.valid) {
            return ResultT<Response>::TamperedEnv(0, "响应数据校验失败");
        }
        
        // 协议解析
        auto parseResult = TProtocol::ParseJson(decrypted.plaintext);
        if (!parseResult.success) {
            return ResultT<Response>::TamperedEnv(0, "响应数据格式异常");
        }
        
        return ResultT<Response>::Ok(parseResult.data);
    }
};

// ========== 协议规范类默认实现辅助宏 ==========

/**
 * @brief 协议规范类默认超时宏
 * 
 * 在协议规范类中使用此宏提供默认超时值。
 */
#define CSC_PROTOCOL_DEFAULT_TIMEOUT 30000  // 30 秒

/**
 * @brief 协议规范类默认端点前缀宏
 * 
 * 在协议规范类中使用此宏提供默认端点。
 */
#define CSC_PROTOCOL_DEFAULT_ENDPOINT "/api/v1"

} // namespace csc