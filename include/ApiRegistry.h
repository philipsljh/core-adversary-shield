/**
 * @file ApiRegistry.h
 * @brief CN: API 注册中心 | EN: API Registry
 *
 * CN: 企业级应用加固组件 - 动态策略编排 API 注册中心
 * EN: Enterprise-grade application hardening component - Dynamic policy orchestration API registry.
 *
 * CN: 本模块定义了 39 个原子 API 的注册逻辑，每个 API 对应一个独立的策略执行端点。
 * EN: This module defines the registration logic for 39 atomic APIs, each corresponding to an independent policy execution endpoint.
 * CN: 所有 API 遵循统一的请求/响应格式，通过加密通道传输。
 * EN: All APIs follow a unified request/response format, transmitted through encrypted channels.
 *
 * CN: 设计原则:
 * EN: Design principles:
 * - CN: 原子性：每个 API 执行单一职责 | EN: Atomicity: Each API performs a single responsibility
 * - CN: 无状态：API 之间不共享会话态 | EN: Statelessness: APIs do not share session state
 * - CN: 可审计：所有 API 调用记录可追溯 | EN: Auditability: All API call records are traceable
 * - CN: 可编排：支持动态策略组合 | EN: Orchestratable: Supports dynamic policy composition
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace csc {

// ============================================================
// CN: API 枚举定义（39 个原子 API）| EN: API Enum Definitions (39 Atomic APIs)
// ============================================================

/**
 * @brief CN: 原子 API 枚举 | EN: Atomic API enum
 *
 * CN: 共 39 个原子 API，分为 6 大类：
 * EN: Total 39 atomic APIs, divided into 6 major categories:
 * - CN: 认证类 (Auth): 0x01-0x08 (8 个) | EN: Auth: 0x01-0x08 (8 APIs)
 * - CN: 策略类 (Policy): 0x09-0x10 (8 个) | EN: Policy: 0x09-0x10 (8 APIs)
 * - CN: 资源类 (Resource): 0x11-0x18 (8 个) | EN: Resource: 0x11-0x18 (8 APIs)
 * - CN: 审计类 (Audit): 0x19-0x1E (6 个) | EN: Audit: 0x19-0x1E (6 APIs)
 * - CN: 配置类 (Config): 0x1F-0x23 (5 个) | EN: Config: 0x1F-0x23 (5 APIs)
 * - CN: 系统类 (System): 0x24-0x27 (4 个) | EN: System: 0x24-0x27 (4 APIs)
 */
enum class AtomicApiId : uint32_t {
    // ========== CN: 认证类 (Auth) ==========
    /** CN: 0x00000001: 身份认证 | EN: 0x00000001: Identity authentication */
    AUTHENTICATE = 0x00000001,

    /** CN: 0x00000002: 令牌刷新 | EN: 0x00000002: Token refresh */
    REFRESH_TOKEN = 0x00000002,

    /** CN: 0x00000003: 令牌吊销 | EN: 0x00000003: Token revocation */
    REVOKE_TOKEN = 0x00000003,

    /** CN: 0x00000004: 凭证变更 | EN: 0x00000004: Credential change */
    CHANGE_CREDENTIAL = 0x00000004,

    /** CN: 0x00000005: 设备注册 | EN: 0x00000005: Device registration */
    REGISTER_DEVICE = 0x00000005,

    /** CN: 0x00000006: 设备解绑 | EN: 0x00000006: Device unbinding */
    UNBIND_DEVICE = 0x00000006,

    /** CN: 0x00000007: 会话查询 | EN: 0x00000007: Session query */
    QUERY_SESSION = 0x00000007,

    /** CN: 0x00000008: 登出 | EN: 0x00000008: Logout */
    LOGOUT = 0x00000008,

    // ========== CN: 策略类 (Policy) ==========
    /** CN: 0x00000009: 策略获取 | EN: 0x00000009: Policy retrieval */
    GET_POLICY = 0x00000009,

    /** CN: 0x0000000A: 策略更新 | EN: 0x0000000A: Policy update */
    UPDATE_POLICY = 0x0000000A,

    /** CN: 0x0000000B: 策略执行 | EN: 0x0000000B: Policy execution */
    EXECUTE_POLICY = 0x0000000B,

    /** CN: 0x0000000C: 策略回滚 | EN: 0x0000000C: Policy rollback */
    ROLLBACK_POLICY = 0x0000000C,

    /** CN: 0x0000000D: 策略模板获取 | EN: 0x0000000D: Policy template retrieval */
    GET_POLICY_TEMPLATE = 0x0000000D,

    /** CN: 0x0000000E: 策略验证 | EN: 0x0000000E: Policy validation */
    VALIDATE_POLICY = 0x0000000E,

    /** CN: 0x0000000F: 策略模拟 | EN: 0x0000000F: Policy simulation */
    SIMULATE_POLICY = 0x0000000F,

    /** CN: 0x00000010: 策略导出 | EN: 0x00000010: Policy export */
    EXPORT_POLICY = 0x00000010,

    // ========== CN: 资源类 (Resource) ==========
    /** CN: 0x00000011: 资源获取 | EN: 0x00000011: Resource retrieval */
    GET_RESOURCE = 0x00000011,

    /** CN: 0x00000012: 资源上传 | EN: 0x00000012: Resource upload */
    UPLOAD_RESOURCE = 0x00000012,

    /** CN: 0x00000013: 资源删除 | EN: 0x00000013: Resource deletion */
    DELETE_RESOURCE = 0x00000013,

    /** CN: 0x00000014: 资源列表 | EN: 0x00000014: Resource listing */
    LIST_RESOURCES = 0x00000014,

    /** CN: 0x00000015: 资源同步 | EN: 0x00000015: Resource synchronization */
    SYNC_RESOURCE = 0x00000015,

    /** CN: 0x00000016: 资源校验 | EN: 0x00000016: Resource verification */
    VERIFY_RESOURCE = 0x00000016,

    /** CN: 0x00000017: 资源锁定 | EN: 0x00000017: Resource locking */
    LOCK_RESOURCE = 0x00000017,

    /** CN: 0x00000018: 资源解锁 | EN: 0x00000018: Resource unlocking */
    UNLOCK_RESOURCE = 0x00000018,

    // ========== CN: 审计类 (Audit) ==========
    /** CN: 0x00000019: 心跳校验 | EN: 0x00000019: Heartbeat verification */
    HEARTBEAT = 0x00000019,

    /** CN: 0x0000001A: 事件上报 | EN: 0x0000001A: Event reporting */
    REPORT_EVENT = 0x0000001A,

    /** CN: 0x0000001B: 日志上传 | EN: 0x0000001B: Log upload */
    UPLOAD_LOG = 0x0000001B,

    /** CN: 0x0000001C: 审计查询 | EN: 0x0000001C: Audit query */
    QUERY_AUDIT = 0x0000001C,

    /** CN: 0x0000001D: 状态报告 | EN: 0x0000001D: Status report */
    REPORT_STATUS = 0x0000001D,

    /** CN: 0x0000001E: 指标采集 | EN: 0x0000001E: Metrics collection */
    COLLECT_METRICS = 0x0000001E,

    // ========== CN: 配置类 (Config) ==========
    /** CN: 0x0000001F: 配置获取 | EN: 0x0000001F: Configuration retrieval */
    GET_CONFIG = 0x0000001F,

    /** CN: 0x00000020: 配置更新 | EN: 0x00000020: Configuration update */
    UPDATE_CONFIG = 0x00000020,

    /** CN: 0x00000021: 配置重置 | EN: 0x00000021: Configuration reset */
    RESET_CONFIG = 0x00000021,

    /** CN: 0x00000022: 配置同步 | EN: 0x00000022: Configuration synchronization */
    SYNC_CONFIG = 0x00000022,

    /** CN: 0x00000023: 配置验证 | EN: 0x00000023: Configuration validation */
    VALIDATE_CONFIG = 0x00000023,

    // ========== CN: 系统类 (System) ==========
    /** CN: 0x00000024: 系统信息 | EN: 0x00000024: System information */
    GET_SYSTEM_INFO = 0x00000024,

    /** CN: 0x00000025: 健康检查 | EN: 0x00000025: Health check */
    HEALTH_CHECK = 0x00000025,

    /** CN: 0x00000026: 版本检查 | EN: 0x00000026: Version check */
    VERSION_CHECK = 0x00000026,

    /** CN: 0x00000027: 时间同步 | EN: 0x00000027: Time synchronization */
    TIME_SYNC = 0x00000027
};

// ============================================================
// CN: API 元数据 | EN: API Metadata
// ============================================================

/**
 * @brief CN: API 元数据结构 | EN: API metadata structure
 */
struct ApiMetadata {
    /** CN: API ID | EN: API ID */
    AtomicApiId id;

    /** CN: API 路径 | EN: API path */
    const char* path;

    /** CN: API 描述 | EN: API description */
    const char* description;

    /** CN: 是否需要认证 | EN: Whether authentication is required */
    bool requiresAuth;

    /** CN: 是否需要工作量证明 | EN: Whether Proof-of-Work is required */
    bool requiresPoW;

    /** CN: 请求超时（毫秒）| EN: Request timeout (milliseconds) */
    uint32_t timeoutMs;

    /** CN: 最大重试次数 | EN: Maximum retry count */
    uint32_t maxRetries;
};

// ============================================================
// CN: API 注册表 | EN: API Registry
// ============================================================

/**
 * @brief CN: API 注册表类 | EN: API registry class
 *
 * CN: 提供 39 个原子 API 的元数据查询和路由功能。
 * EN: Provides metadata query and routing functionality for 39 atomic APIs.
 */
class ApiRegistry {
public:
    /**
     * @brief CN: 获取 API 元数据 | EN: Get API metadata
     *
     * @param apiId CN: API ID | EN: API ID
     * @return CN: const ApiMetadata* API 元数据指针，未找到返回 nullptr | EN: const ApiMetadata* API metadata pointer, nullptr if not found
     */
    static const ApiMetadata* getMetadata(AtomicApiId apiId);

    /**
     * @brief CN: 根据路径查找 API ID | EN: Find API ID by path
     *
     * @param path CN: API 路径 | EN: API path
     * @return CN: AtomicApiId API ID，未找到返回 0 | EN: AtomicApiId API ID, 0 if not found
     */
    static AtomicApiId findByPath(const std::string& path);

    /**
     * @brief CN: 获取所有已注册的 API 元数据 | EN: Get all registered API metadata
     *
     * @return CN: std::vector<const ApiMetadata*> 元数据列表 | EN: std::vector<const ApiMetadata*> Metadata list
     */
    static std::vector<const ApiMetadata*> getAllMetadata();

    /**
     * @brief CN: 获取 API 总数 | EN: Get total API count
     *
     * @return CN: size_t API 总数 | EN: size_t Total API count
     */
    static size_t count();

private:
    // CN: 禁止实例化 | EN: Instantiation prohibited
    ApiRegistry() = delete;
    ~ApiRegistry() = delete;
};

} // namespace csc