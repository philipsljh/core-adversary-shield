/**
 * @file ApiRegistry.cpp
 * @brief CN: API 注册中心实现 - 39 个原子 API 元数据 | EN: API registry implementation - 39 atomic API metadata
 *
 * CN: 企业级应用加固组件 - 动态策略编排 API 注册中心实现
 * EN: Enterprise-grade application hardening component - Dynamic policy orchestration API registry implementation.
 */

#include "ApiRegistry.h"

namespace csc {

// ============================================================
// CN: 39 个原子 API 元数据表 | EN: 39 Atomic API Metadata Table
// ============================================================

static const ApiMetadata API_METADATA_TABLE[] = {
    // ========== CN: 认证类 (Auth) ==========
    { AtomicApiId::AUTHENTICATE,      "/api/v1/auth/authenticate",      "身份认证",           true,  true,  30000, 3 },
    { AtomicApiId::REFRESH_TOKEN,     "/api/v1/auth/refresh",           "令牌刷新",           true,  false, 15000, 2 },
    { AtomicApiId::REVOKE_TOKEN,      "/api/v1/auth/revoke",            "令牌吊销",           true,  false, 15000, 1 },
    { AtomicApiId::CHANGE_CREDENTIAL, "/api/v1/auth/credential",        "凭证变更",           true,  true,  30000, 2 },
    { AtomicApiId::REGISTER_DEVICE,   "/api/v1/auth/device/register",   "设备注册",           true,  true,  30000, 3 },
    { AtomicApiId::UNBIND_DEVICE,     "/api/v1/auth/device/unbind",     "设备解绑",           true,  false, 15000, 1 },
    { AtomicApiId::QUERY_SESSION,     "/api/v1/auth/session",           "会话查询",           true,  false, 10000, 2 },
    { AtomicApiId::LOGOUT,            "/api/v1/auth/logout",            "登出",               true,  false, 10000, 1 },

    // ========== CN: 策略类 (Policy) ==========
    { AtomicApiId::GET_POLICY,          "/api/v1/policy/get",           "策略获取",           true,  false, 15000, 2 },
    { AtomicApiId::UPDATE_POLICY,       "/api/v1/policy/update",        "策略更新",           true,  false, 30000, 1 },
    { AtomicApiId::EXECUTE_POLICY,      "/api/v1/policy/execute",       "策略执行",           true,  false, 60000, 1 },
    { AtomicApiId::ROLLBACK_POLICY,     "/api/v1/policy/rollback",      "策略回滚",           true,  false, 30000, 1 },
    { AtomicApiId::GET_POLICY_TEMPLATE, "/api/v1/policy/template",      "策略模板获取",       true,  false, 15000, 2 },
    { AtomicApiId::VALIDATE_POLICY,     "/api/v1/policy/validate",      "策略验证",           true,  false, 15000, 2 },
    { AtomicApiId::SIMULATE_POLICY,     "/api/v1/policy/simulate",      "策略模拟",           true,  false, 30000, 1 },
    { AtomicApiId::EXPORT_POLICY,       "/api/v1/policy/export",        "策略导出",           true,  false, 30000, 2 },

    // ========== CN: 资源类 (Resource) ==========
    { AtomicApiId::GET_RESOURCE,    "/api/v1/resource/get",           "资源获取",           true,  false, 15000, 2 },
    { AtomicApiId::UPLOAD_RESOURCE, "/api/v1/resource/upload",        "资源上传",           true,  false, 60000, 1 },
    { AtomicApiId::DELETE_RESOURCE, "/api/v1/resource/delete",        "资源删除",           true,  false, 15000, 1 },
    { AtomicApiId::LIST_RESOURCES,  "/api/v1/resource/list",          "资源列表",           true,  false, 15000, 2 },
    { AtomicApiId::SYNC_RESOURCE,   "/api/v1/resource/sync",          "资源同步",           true,  false, 30000, 2 },
    { AtomicApiId::VERIFY_RESOURCE, "/api/v1/resource/verify",        "资源校验",           true,  false, 15000, 2 },
    { AtomicApiId::LOCK_RESOURCE,   "/api/v1/resource/lock",          "资源锁定",           true,  false, 15000, 1 },
    { AtomicApiId::UNLOCK_RESOURCE, "/api/v1/resource/unlock",        "资源解锁",           true,  false, 15000, 1 },

    // ========== CN: 审计类 (Audit) ==========
    { AtomicApiId::HEARTBEAT,       "/api/v1/audit/heartbeat",        "心跳校验",           true,  false, 10000, 3 },
    { AtomicApiId::REPORT_EVENT,    "/api/v1/audit/event",            "事件上报",           true,  false, 15000, 2 },
    { AtomicApiId::UPLOAD_LOG,      "/api/v1/audit/log",              "日志上传",           true,  false, 30000, 2 },
    { AtomicApiId::QUERY_AUDIT,     "/api/v1/audit/query",            "审计查询",           true,  false, 15000, 2 },
    { AtomicApiId::REPORT_STATUS,   "/api/v1/audit/status",           "状态报告",           true,  false, 10000, 2 },
    { AtomicApiId::COLLECT_METRICS, "/api/v1/audit/metrics",          "指标采集",           true,  false, 15000, 2 },

    // ========== CN: 配置类 (Config) ==========
    { AtomicApiId::GET_CONFIG,      "/api/v1/config/get",             "配置获取",           true,  false, 10000, 2 },
    { AtomicApiId::UPDATE_CONFIG,   "/api/v1/config/update",          "配置更新",           true,  false, 15000, 1 },
    { AtomicApiId::RESET_CONFIG,    "/api/v1/config/reset",           "配置重置",           true,  false, 15000, 1 },
    { AtomicApiId::SYNC_CONFIG,     "/api/v1/config/sync",            "配置同步",           true,  false, 15000, 2 },
    { AtomicApiId::VALIDATE_CONFIG, "/api/v1/config/validate",        "配置验证",           true,  false, 10000, 2 },

    // ========== CN: 系统类 (System) ==========
    { AtomicApiId::GET_SYSTEM_INFO, "/api/v1/system/info",            "系统信息",           false, false, 10000, 2 },
    { AtomicApiId::HEALTH_CHECK,    "/api/v1/system/health",          "健康检查",           false, false, 5000,  3 },
    { AtomicApiId::VERSION_CHECK,   "/api/v1/system/version",         "版本检查",           false, false, 10000, 2 },
    { AtomicApiId::TIME_SYNC,       "/api/v1/system/time",            "时间同步",           false, false, 10000, 3 }
};

static constexpr size_t API_METADATA_COUNT = sizeof(API_METADATA_TABLE) / sizeof(API_METADATA_TABLE[0]);

// ============================================================
// CN: ApiRegistry 实现 | EN: ApiRegistry Implementation
// ============================================================

const ApiMetadata* ApiRegistry::getMetadata(AtomicApiId apiId) {
    for (size_t i = 0; i < API_METADATA_COUNT; ++i) {
        if (API_METADATA_TABLE[i].id == apiId) {
            return &API_METADATA_TABLE[i];
        }
    }
    return nullptr;
}

AtomicApiId ApiRegistry::findByPath(const std::string& path) {
    for (size_t i = 0; i < API_METADATA_COUNT; ++i) {
        if (path == API_METADATA_TABLE[i].path) {
            return API_METADATA_TABLE[i].id;
        }
    }
    return static_cast<AtomicApiId>(0x00000000);
}

std::vector<const ApiMetadata*> ApiRegistry::getAllMetadata() {
    std::vector<const ApiMetadata*> result;
    result.reserve(API_METADATA_COUNT);
    for (size_t i = 0; i < API_METADATA_COUNT; ++i) {
        result.push_back(&API_METADATA_TABLE[i]);
    }
    return result;
}

size_t ApiRegistry::count() {
    return API_METADATA_COUNT;
}

} // namespace csc