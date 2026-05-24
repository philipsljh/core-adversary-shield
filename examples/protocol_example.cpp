/**
 * @file protocol_example.cpp
 * @brief 协议规范类使用示例
 * 
 * 本文件演示如何定义协议规范类并使用 ProtocolGateway 执行请求。
 * 
 * 编译命令（示例）:
 * g++ -std=c++17 -I../include protocol_example.cpp -lcryptopp -o protocol_example
 */

#include "ProtocolGateway.hpp"

#include <iostream>
#include <string>
#include <map>

// ============================================================
// 示例 1: 登录协议规范类
// ============================================================

/**
 * @brief 登录协议规范类
 * 
 * 此类定义了登录接口的完整协议规范，包括：
 * - 请求/响应数据结构
 * - 本地预审规则
 * - JSON 组装/解析逻辑
 * - 自定义请求头
 */
struct LoginProtocol {
    // ========== 请求结构体 ==========
    struct Request {
        std::string username;   // 用户名
        std::string password;   // 密码
        std::string hwid;       // 硬件指纹
        std::string powAnswer;  // PoW 算力答案
    };
    
    // ========== 响应结构体 ==========
    struct Response {
        std::string token;          // 会话令牌
        std::string sessionToken;   // 单点执法令牌
        int expireDays;             // 剩余天数（仅用于 UI 展示）
        std::string nonce;          // 随机数（用于心跳回显）
        int expireTimestamp;        // 绝对到期时间戳
    };
    
    // ========== 接口端点 ==========
    static std::string Endpoint() {
        return "/api/v1/auth/login";
    }
    
    // ========== 本地预审 ==========
    /**
     * @brief 本地预审规则
     * 
     * 仅执行最低成本的格式防呆，不模拟服务端状态机。
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
    
    // ========== JSON 组装 ==========
    static std::string BuildJson(const Request& req) {
        // 注意：生产环境应使用 nlohmann/json 等库进行安全的 JSON 序列化
        std::string json = "{";
        json += "\"username\":\"" + escapeJson(req.username) + "\",";
        json += "\"password\":\"" + escapeJson(req.password) + "\",";
        json += "\"hwid\":\"" + escapeJson(req.hwid) + "\",";
        json += "\"pow_answer\":\"" + escapeJson(req.powAnswer) + "\"";
        json += "}";
        return json;
    }
    
    // ========== JSON 解析 ==========
    static ResultT<Response> ParseJson(const std::string& json) {
        Response resp;
        
        // 注意：生产环境应使用 nlohmann/json 等库进行安全的 JSON 解析
        // 此处为简化示例
        
        // 提取 token
        size_t tokenPos = json.find("\"token\":\"");
        if (tokenPos == std::string::npos) {
            return ResultT<Response>::TamperedEnv(0, "响应缺少 token 字段");
        }
        size_t tokenStart = json.find('"', tokenPos + 9);
        size_t tokenEnd = json.find('"', tokenStart + 1);
        resp.token = json.substr(tokenStart + 1, tokenEnd - tokenStart - 1);
        
        // 提取 nonce
        size_t noncePos = json.find("\"nonce\":\"");
        if (noncePos != std::string::npos) {
            size_t nonceStart = json.find('"', noncePos + 9);
            size_t nonceEnd = json.find('"', nonceStart + 1);
            resp.nonce = json.substr(nonceStart + 1, nonceEnd - nonceStart - 1);
        }
        
        // 提取 expire_timestamp（无异常解析）
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
    
    // ========== 自定义请求头 ==========
    static std::map<std::string, std::string> BuildCustomHeaders() {
        return {
            {"X-Auth-Protocol", "hybrid-rsa-aes"},
            {"X-Client-Version", "2.9.0"}
        };
    }
    
    // ========== 请求超时 ==========
    static int TimeoutMs() {
        return 30000;  // 30 秒
    }
    
private:
    /**
     * @brief 无异常字符串转整数解析
     * 
     * 逐字符解析，不使用 std::stoi，避免 throw 异常。
     * 
     * @param s 输入字符串
     * @param out 输出整数
     * @return true 解析成功
     * @return false 解析失败（空字符串、非数字字符等）
     */
    static bool parseInteger(const std::string& s, int& out) {
        if (s.empty()) return false;
        
        int result = 0;
        int sign = 1;
        size_t start = 0;
        
        // 处理符号
        if (s[0] == '-') {
            sign = -1;
            start = 1;
        } else if (s[0] == '+') {
            start = 1;
        }
        
        // 逐位解析
        for (size_t i = start; i < s.size(); i++) {
            if (s[i] < '0' || s[i] > '9') return false;
            int digit = s[i] - '0';
            // 溢出检查
            if (result > (2147483647 - digit) / 10) return false;
            result = result * 10 + digit;
        }
        
        out = result * sign;
        return true;
    }
    
    // JSON 字符串转义
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
// 示例 2: 心跳协议规范类
// ============================================================

/**
 * @brief 心跳协议规范类
 * 
 * 心跳接口是系统防时光机白嫖与防协议伪造的核心防线。
 */
struct HeartbeatProtocol {
    struct Request {
        std::string username;
        std::string hwid;
        std::string nonce;          // 密码学安全随机数
        std::string sessionToken;   // 单点执法令牌
    };
    
    struct Response {
        std::string serverSign;     // Ed25519 签名
        int expireTimestamp;        // 绝对到期时间戳
        std::string nonce;          // 回显随机数
        std::string scriptHash;     // 脚本字节码 SHA-256
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
        
        // 提取 server_sign
        size_t signPos = json.find("\"server_sign\":\"");
        if (signPos == std::string::npos) {
            return ResultT<Response>::TamperedEnv(0, "响应缺少签名");
        }
        size_t signStart = json.find('"', signPos + 15);
        size_t signEnd = json.find('"', signStart + 1);
        resp.serverSign = json.substr(signStart + 1, signEnd - signStart - 1);
        
        // 提取 nonce 回显
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
        return 15000;  // 15 秒
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
// 示例 3: Mock HTTP 传输层实现（用于测试）
// ============================================================

/**
 * @brief Mock HTTP 传输层实现
 * 
 * ?? WARNING: DO NOT USE IN PRODUCTION. For local testing only.
 * 仅用于演示，生产环境应使用 WinHTTP、libcurl 等真实实现。
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
        // ?? 仅调试模式打印请求体，生产环境严禁启用
        std::cout << "[MockHTTP] POST " << url << std::endl;
        std::cout << "[MockHTTP] Headers:" << std::endl;
        for (const auto& [key, value] : headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "[MockHTTP] Body (first 100 chars): " << body.substr(0, 100) << "..." << std::endl;
#endif
        
        // 模拟成功响应
        statusCode = 200;
        responseBody = R"({"data": "mock_encrypted_response"})";
        
        return true;
    }
};

// ============================================================
// 主函数：演示使用方式
// ============================================================

int main() {
    std::cout << "=== Core Security Client - Protocol Gateway Example ===" << std::endl;
    std::cout << std::endl;
    
    // 准备 RSA 密钥对（示例用，生产环境应使用真实密钥）
    static const char* const RSA_PUBLIC_KEY_PEM_PLACEHOLDER = 
        "<REPLACE_WITH_REAL_RSA_PUBLIC_KEY_PEM_FORMAT>";
    std::string rsaPublicKeyPEM = RSA_PUBLIC_KEY_PEM_PLACEHOLDER;
    
    // 创建 HTTP 传输层
    MockHttpTransport transport;
    
    // =========================================================
    // 示例 1: 执行登录请求
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
    // 示例 2: 执行心跳请求
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