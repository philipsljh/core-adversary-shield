/**
 * @file protocol_example.cpp
 * @brief CN: 协议规范类使用示例 | EN: Protocol specification class usage example
 *
 * CN: 本文件演示如何定义协议规范类并使用 ProtocolGateway 执行请求。
 * EN: This file demonstrates how to define protocol specification classes and execute requests using ProtocolGateway.
 *
 * CN: 编译命令（示例）:
 * EN: Compilation command (example):
 * g++ -std=c++17 -I../include protocol_example.cpp -lcryptopp -o protocol_example
 */

#include "ProtocolGateway.hpp"

#include <iostream>
#include <string>
#include <map>

// ============================================================
// CN: 示例 1: 登录协议规范类 | EN: Example 1: Login Protocol Specification Class
// ============================================================

/**
 * @brief CN: 登录协议规范类 | EN: Login protocol specification class
 *
 * CN: 此类定义了登录接口的完整协议规范，包括：
 * EN: This class defines the complete protocol specification for the login interface, including:
 * - CN: 请求/响应数据结构 | EN: Request/response data structures
 * - CN: 本地预审规则 | EN: Local pre-validation rules
 * - CN: JSON 组装/解析逻辑 | EN: JSON assembly/parsing logic
 * - CN: 自定义请求头 | EN: Custom request headers
 */
struct LoginProtocol {
    // ========== CN: 请求结构体 | EN: Request structure ==========
    struct Request {
        std::string username;   // CN: 用户名 | EN: Username
        std::string password;   // CN: 密码 | EN: Password
        std::string hwid;       // CN: 硬件指纹 | EN: Hardware fingerprint
        std::string powAnswer;  // CN: PoW 算力答案 | EN: PoW computation answer
    };

    // ========== CN: 响应结构体 | EN: Response structure ==========
    struct Response {
        std::string token;          // CN: 会话令牌 | EN: Session token
        std::string sessionToken;   // CN: 单点执法令牌 | EN: Single-point enforcement token
        int expireDays;             // CN: 剩余天数（仅用于 UI 展示）| EN: Remaining days (for UI display only)
        std::string nonce;          // CN: 随机数（用于心跳回显）| EN: Nonce (for heartbeat echo)
        int expireTimestamp;        // CN: 绝对到期时间戳 | EN: Absolute expiration timestamp
    };

    // ========== CN: 接口端点 | EN: Interface endpoint ==========
    static std::string Endpoint() {
        return "/api/v1/auth/login";
    }

    // ========== CN: 本地预审 | EN: Local pre-validation ==========
    /**
     * @brief CN: 本地预审规则 | EN: Local pre-validation rules
     *
     * CN: 仅执行最低成本的格式防呆，不模拟服务端状态机。
     * EN: Only performs lowest-cost format validation, does not simulate server state machine.
     */
    static ResultT<Request> ValidateLocal(const Request& req) {
        if (req.username.empty()) {
            return ResultT<Request>::AuthFatal(400, "用户名不能为空");
        }
        if (req.username.length() > 64) {
            return ResultT<Request>::AuthFatal(400, "用户名过长");
        }
        if (req.password.length() < 6) {
            return ResultT<Request>::AuthFatal(400, "密码长度不足（至少6位）");
        }
        if (req.hwid.empty()) {
            return ResultT<Request>::AuthFatal(400, "设备指纹获取失败");
        }
        if (req.powAnswer.empty()) {
            return ResultT<Request>::AuthFatal(400, "算力验证未完成");
        }
        return ResultT<Request>::Ok(req);
    }

    // ========== CN: JSON 组装 | EN: JSON assembly ==========
    static std::string BuildJson(const Request& req) {
        // CN: 注意：生产环境应使用 nlohmann/json 等库进行安全的 JSON 序列化
        // EN: Note: Production environment should use nlohmann/json or similar library for safe JSON serialization
        std::string json = "{";
        json += "\"username\":\"" + escapeJson(req.username) + "\",";
        json += "\"password\":\"" + escapeJson(req.password) + "\",";
        json += "\"hwid\":\"" + escapeJson(req.hwid) + "\",";
        json += "\"pow_answer\":\"" + escapeJson(req.powAnswer) + "\"";
        json += "}";
        return json;
    }

    // ========== CN: JSON 解析 | EN: JSON parsing ==========
    static ResultT<Response> ParseJson(const std::string& json) {
        Response resp;

        // CN: 注意：生产环境应使用 nlohmann/json 等库进行安全的 JSON 解析
        // EN: Note: Production environment should use nlohmann/json or similar library for safe JSON parsing
        // CN: 此处为简化示例 | EN: Simplified example here

        // CN: 提取 token | EN: Extract token
        size_t tokenPos = json.find("\"token\":\"");
        if (tokenPos == std::string::npos) {
            return ResultT<Response>::TamperedEnv(0, "响应缺少 token 字段");
        }
        size_t tokenStart = json.find('"', tokenPos + 9);
        size_t tokenEnd = json.find('"', tokenStart + 1);
        resp.token = json.substr(tokenStart + 1, tokenEnd - tokenStart - 1);

        // CN: 提取 nonce | EN: Extract nonce
        size_t noncePos = json.find("\"nonce\":\"");
        if (noncePos != std::string::npos) {
            size_t nonceStart = json.find('"', noncePos + 9);
            size_t nonceEnd = json.find('"', nonceStart + 1);
            resp.nonce = json.substr(nonceStart + 1, nonceEnd - nonceStart - 1);
        }

        // CN: 提取 expire_timestamp（无异常解析）| EN: Extract expire_timestamp (exception-free parsing)
        size_t expirePos = json.find("\"expire_timestamp\":");
        if (expirePos != std::string::npos) {
            size_t expireStart = expirePos + 19;
            size_t expireEnd = json.find_first_of(",}", expireStart);
            if (expireEnd != std::string::npos) {
                std::string expireStr = json.substr(expireStart, expireEnd - expireStart);
                int expireVal = 0;
                if (!parseInteger(expireStr, expireVal)) {
                    return ResultT<Response>::TamperedEnv(0, "响应时间戳格式异常");
                }
                resp.expireTimestamp = expireVal;
            }
        }

        return ResultT<Response>::Ok(resp);
    }

    // ========== CN: 自定义请求头 | EN: Custom request headers ==========
    static std::map<std::string, std::string> BuildCustomHeaders() {
        return {
            {"X-Auth-Protocol", "hybrid-rsa-aes"},
            {"X-Client-Version", "2.9.0"}
        };
    }

    // ========== CN: 请求超时 | EN: Request timeout ==========
    static int TimeoutMs() {
        return 30000;  // CN: 30 秒 | EN: 30 seconds
    }

private:
    /**
     * @brief CN: 无异常字符串转整数解析 | EN: Exception-free string to integer parsing
     *
     * CN: 逐字符解析，不使用 std::stoi，避免 throw 异常。
     * EN: Character-by-character parsing, does not use std::stoi, avoids throw exceptions.
     *
     * @param s CN: 输入字符串 | EN: Input string
     * @param out CN: 输出整数 | EN: Output integer
     * @return CN: true 解析成功 | EN: true Parsing succeeded
     * @return CN: false 解析失败（空字符串、非数字字符等）| EN: false Parsing failed (empty string, non-digit characters, etc.)
     */
    static bool parseInteger(const std::string& s, int& out) {
        if (s.empty()) return false;

        int result = 0;
        int sign = 1;
        size_t start = 0;

        // CN: 处理符号 | EN: Handle sign
        if (s[0] == '-') {
            sign = -1;
            start = 1;
        } else if (s[0] == '+') {
            start = 1;
        }

        // CN: 逐位解析 | EN: Parse digit by digit
        for (size_t i = start; i < s.size(); i++) {
            if (s[i] < '0' || s[i] > '9') return false;
            int digit = s[i] - '0';
            // CN: 溢出检查 | EN: Overflow check
            if (result > (2147483647 - digit) / 10) return false;
            result = result * 10 + digit;
        }

        out = result * sign;
        return true;
    }

    // CN: JSON 字符串转义 | EN: JSON string escape
    static std::string escapeJson(const std::string& s) {
        std::string result;
        result.reserve(s.size() + 10);
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:   result += c; break;
            }
        }
        return result;
    }
};

// ============================================================
// CN: 示例 2: 心跳协议规范类 | EN: Example 2: Heartbeat Protocol Specification Class
// ============================================================

/**
 * @brief CN: 心跳协议规范类 | EN: Heartbeat protocol specification class
 *
 * CN: 心跳接口是系统防时光机白嫖与防协议伪造的核心防线。
 * EN: The heartbeat interface is the core defense against time-machine abuse and protocol forgery.
 */
struct HeartbeatProtocol {
    struct Request {
        std::string username;
        std::string hwid;
        std::string nonce;          // CN: 密码学安全随机数 | EN: Cryptographically secure random number
        std::string sessionToken;   // CN: 单点执法令牌 | EN: Single-point enforcement token
    };

    struct Response {
        std::string serverSign;     // CN: Ed25519 签名 | EN: Ed25519 signature
        int expireTimestamp;        // CN: 绝对到期时间戳 | EN: Absolute expiration timestamp
        std::string nonce;          // CN: 回显随机数 | EN: Echo nonce
        std::string scriptHash;     // CN: 脚本字节码 SHA-256 | EN: Script bytecode SHA-256
    };

    static std::string Endpoint() {
        return "/api/v1/auth/heartbeat";
    }

    static ResultT<Request> ValidateLocal(const Request& req) {
        if (req.sessionToken.empty()) {
            return ResultT<Request>::AuthFatal(401, "未登录");
        }
        if (req.nonce.empty()) {
            return ResultT<Request>::TamperedEnv(0, "Nonce 生成失败");
        }
        return ResultT<Request>::Ok(req);
    }

    static std::string BuildJson(const Request& req) {
        std::string json = "{";
        json += "\"username\":\"" + escapeJson(req.username) + "\",";
        json += "\"hwid\":\"" + escapeJson(req.hwid) + "\",";
        json += "\"nonce\":\"" + escapeJson(req.nonce) + "\",";
        json += "\"session_token\":\"" + escapeJson(req.sessionToken) + "\"";
        json += "}";
        return json;
    }

    static ResultT<Response> ParseJson(const std::string& json) {
        Response resp;

        // CN: 提取 server_sign | EN: Extract server_sign
        size_t signPos = json.find("\"server_sign\":\"");
        if (signPos == std::string::npos) {
            return ResultT<Response>::TamperedEnv(0, "响应缺少签名");
        }
        size_t signStart = json.find('"', signPos + 15);
        size_t signEnd = json.find('"', signStart + 1);
        resp.serverSign = json.substr(signStart + 1, signEnd - signStart - 1);

        // CN: 提取 nonce 回显 | EN: Extract nonce echo
        size_t noncePos = json.find("\"nonce\":\"");
        if (noncePos != std::string::npos) {
            size_t nonceStart = json.find('"', noncePos + 9);
            size_t nonceEnd = json.find('"', nonceStart + 1);
            resp.nonce = json.substr(nonceStart + 1, nonceEnd - nonceStart - 1);
        }

        return ResultT<Response>::Ok(resp);
    }

    static std::map<std::string, std::string> BuildCustomHeaders() {
        return {{"X-Heartbeat-Version", "1.0"}};
    }

    static int TimeoutMs() {
        return 15000;  // CN: 15 秒 | EN: 15 seconds
    }

private:
    static std::string escapeJson(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                default:   result += c; break;
            }
        }
        return result;
    }
};

// ============================================================
// CN: 示例 3: Mock HTTP 传输层实现（用于测试）| EN: Example 3: Mock HTTP Transport Layer Implementation (for testing)
// ============================================================

/**
 * @brief CN: Mock HTTP 传输层实现 | EN: Mock HTTP transport layer implementation
 *
 * CN: WARNING: 请勿在生产环境中使用。仅用于本地测试。
 * EN: WARNING: DO NOT USE IN PRODUCTION. For local testing only.
 * CN: 仅用于演示，生产环境应使用 WinHTTP、libcurl 等真实实现。
 * EN: For demonstration only; production environment should use real implementations like WinHTTP, libcurl, etc.
 */
class MockHttpTransport : public csc::IHttpTransport {
public:
    bool Post(const std::string& url,
              const std::string& body,
              const std::map<std::string, std::string>& headers,
              int timeoutMs,
              int& statusCode,
              std::string& responseBody) override {
#ifdef CSC_DEBUG_MOCK
        // CN: 仅调试模式打印请求体，生产环境严禁启用
        // EN: Debug mode only: print request body, strictly prohibited in production
        std::cout << "[MockHTTP] POST " << url << std::endl;
        std::cout << "[MockHTTP] Headers:" << std::endl;
        for (const auto& [key, value] : headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "[MockHTTP] Body (first 100 chars): " << body.substr(0, 100) << "..." << std::endl;
#endif

        // CN: 模拟成功响应 | EN: Simulate success response
        statusCode = 200;
        responseBody = R"({"data": "mock_encrypted_response"})";

        return true;
    }
};

// ============================================================
// CN: 主函数：演示使用方式 | EN: Main function: Demonstrate usage
// ============================================================

int main() {
    std::cout << "=== Core Security Client - Protocol Gateway Example ===" << std::endl;
    std::cout << std::endl;

    // CN: 准备 RSA 密钥对（示例用，生产环境应使用真实密钥）
    // EN: Prepare RSA key pair (for example only, production should use real keys)
    static const char* const RSA_PUBLIC_KEY_PEM_PLACEHOLDER =
        "<REPLACE_WITH_REAL_RSA_PUBLIC_KEY_PEM_FORMAT>";
    std::string rsaPublicKeyPEM = RSA_PUBLIC_KEY_PEM_PLACEHOLDER;

    // CN: 创建 HTTP 传输层 | EN: Create HTTP transport layer
    MockHttpTransport transport;

    // =========================================================
    // CN: 示例 1: 执行登录请求 | EN: Example 1: Execute login request
    // =========================================================
    std::cout << "--- Login Request ---" << std::endl;

    LoginProtocol::Request loginReq;
    loginReq.username = "<USERNAME_PLACEHOLDER>";
    loginReq.password = "<PASSWORD_PLACEHOLDER>";
    loginReq.hwid = "<HWID_PLACEHOLDER>";
    loginReq.powAnswer = "<POW_ANSWER_PLACEHOLDER>";

    auto loginResult = csc::ProtocolGateway::Execute<LoginProtocol>(
        loginReq, transport, rsaPublicKeyPEM, "https://api.example.com");

    if (loginResult.success) {
        std::cout << "[Login] Success! Token: " << loginResult.data.token << std::endl;
        std::cout << "[Login] Nonce: " << loginResult.data.nonce << std::endl;
    } else {
        std::cout << "[Login] Failed: " << loginResult.message << std::endl;
        std::cout << "[Login] Error Class: " << static_cast<int>(loginResult.errorClass) << std::endl;
    }

    std::cout << std::endl;

    // =========================================================
    // CN: 示例 2: 执行心跳请求 | EN: Example 2: Execute heartbeat request
    // =========================================================
    std::cout << "--- Heartbeat Request ---" << std::endl;

    HeartbeatProtocol::Request heartbeatReq;
    heartbeatReq.username = "<USERNAME_PLACEHOLDER>";
    heartbeatReq.hwid = "<HWID_PLACEHOLDER>";
    heartbeatReq.nonce = "<NONCE_PLACEHOLDER>";
    heartbeatReq.sessionToken = "<SESSION_TOKEN_PLACEHOLDER>";

    auto heartbeatResult = csc::ProtocolGateway::Execute<HeartbeatProtocol>(
        heartbeatReq, transport, rsaPublicKeyPEM, "https://api.example.com");

    if (heartbeatResult.success) {
        std::cout << "[Heartbeat] Success! Server Sign: " << heartbeatResult.data.serverSign << std::endl;
    } else {
        std::cout << "[Heartbeat] Failed: " << heartbeatResult.message << std::endl;
        std::cout << "[Heartbeat] Error Class: " << static_cast<int>(heartbeatResult.errorClass) << std::endl;
    }

    std::cout << std::endl;
    std::cout << "=== Example Complete ===" << std::endl;

    return 0;
}