/**
 * @file ApiRegistry.h
 * @brief API 注册中心 (API Registry)
 *
 * 企业级应用加固组件 - 动态策略编排 API 注册中心
 *
 * 本模块定义了 39 个原子 API 的注册逻辑，每个 API 对应一个独立的
 * 策略执行端点。所有 API 遵循统一的请求/响应格式，通过加密通道传输。
 *
 * 设计原则:
 * - 原子性：每个 API 执行单一职责
 * - 无状态：API 之间不共享会话态
 * - 可审计：所有 API 调用记录可追溯
 * - 可编排：支持动态策略组合
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace csc {

// ============================================================
// API 枚举定义 (39 个原子 API)
// ============================================================

/**
 * @brief 原子 API 枚举
 *
 * 共 39 个原子 API，分为 6 大类：
 * - 认证类 (Auth): 0x01-0x08 (8 个)
 * - 策略类 (Policy): 0x09-0x10 (8 个)
 * - 资源类 (Resource): 0x11-0x18 (8 个)
 * - 审计类 (Audit): 0x19-0x1E (6 个)
 * - 配置类 (Config): 0x1F-0x23 (5 个)
 * - 系统类 (System): 0x24-0x27 (4 个)
 */
enum class AtomicApiId : uint32_t {
    // ========== 认证类 (Auth) ==========
    /** 0x00000001: 身份认证 */
    AUTHENTICATE = 0x00000001,

    /** 0x00000002: 令牌刷新 */
    REFRESH_TOKEN = 0x00000002,

    /** 0x00000003: 令牌吊销 */
    REVOKE_TOKEN = 0x00000003,

    /** 0x00000004: 凭证变更 */
    CHANGE_CREDENTIAL = 0x00000004,

    /** 0x00000005: 设备注册 */
    REGISTER_DEVICE = 0x00000005,

    /** 0x00000006: 设备解绑 */
    UNBIND_DEVICE = 0x00000006,

    /** 0x00000007: 会话查询 */
    QUERY_SESSION = 0x00000007,

    /** 0x00000008: 登出 */
    LOGOUT = 0x00000008,

    // ========== 策略类 (Policy) ==========
    /** 0x00000009: 策略获取 */
    GET_POLICY = 0x00000009,

    /** 0x0000000A: 策略更新 */
    UPDATE_POLICY = 0x0000000A,

    /** 0x0000000B: 策略执行 */
    EXECUTE_POLICY = 0x0000000B,

    /** 0x0000000C: 策略回滚 */
    ROLLBACK_POLICY = 0x0000000C,

    /** 0x0000000D: 策略模板获取 */
    GET_POLICY_TEMPLATE = 0x0000000D,

    /** 0x0000000E: 策略验证 */
    VALIDATE_POLICY = 0x0000000E,

    /** 0x0000000F: 策略模拟 */
    SIMULATE_POLICY = 0x0000000F,

    /** 0x00000010: 策略导出 */
    EXPORT_POLICY = 0x00000010,

    // ========== 资源类 (Resource) ==========
    /** 0x00000011: 资源获取 */
    GET_RESOURCE = 0x00000011,

    /** 0x00000012: 资源上传 */
    UPLOAD_RESOURCE = 0x00000012,

    /** 0x00000013: 资源删除 */
    DELETE_RESOURCE = 0x00000013,

    /** 0x00000014: 资源列表 */
    LIST_RESOURCES = 0x00000014,

    /** 0x00000015: 资源同步 */
    SYNC_RESOURCE = 0x00000015,

    /** 0x00000016: 资源校验 */
    VERIFY_RESOURCE = 0x00000016,

    /** 0x00000017: 资源锁定 */
    LOCK_RESOURCE = 0x00000017,

    /** 0x00000018: 资源解锁 */
    UNLOCK_RESOURCE = 0x00000018,

    // ========== 审计类 (Audit) ==========
    /** 0x00000019: 心跳校验 */
    HEARTBEAT = 0x00000019,

    /** 0x0000001A: 事件上报 */
    REPORT_EVENT = 0x0000001A,

    /** 0x0000001B: 日志上传 */
    UPLOAD_LOG = 0x0000001B,

    /** 0x0000001C: 审计查询 */
    QUERY_AUDIT = 0x0000001C,

    /** 0x0000001D: 状态报告 */
    REPORT_STATUS = 0x0000001D,

    /** 0x0000001E: 指标采集 */
    COLLECT_METRICS = 0x0000001E,

    // ========== 配置类 (Config) ==========
    /** 0x0000001F: 配置获取 */
    GET_CONFIG = 0x0000001F,

    /** 0x00000020: 配置更新 */
    UPDATE_CONFIG = 0x00000020,

    /** 0x00000021: 配置重置 */
    RESET_CONFIG = 0x00000021,

    /** 0x00000022: 配置同步 */
    SYNC_CONFIG = 0x00000022,

    /** 0x00000023: 配置验证 */
    VALIDATE_CONFIG = 0x00000023,

    // ========== 系统类 (System) ==========
    /** 0x00000024: 系统信息 */
    GET_SYSTEM_INFO = 0x00000024,

    /** 0x00000025: 健康检查 */
    HEALTH_CHECK = 0x00000025,

    /** 0x00000026: 版本检查 */
    VERSION_CHECK = 0x00000026,

    /** 0x00000027: 时间同步 */
    TIME_SYNC = 0x00000027
};

// ============================================================
// API 元数据
// ============================================================

/**
 * @brief API 元数据结构
 */
struct ApiMetadata {
    /** API ID */
    AtomicApiId id;

    /** API 路径 */
    const char* path;

    /** API 描述 */
    const char* description;

    /** 是否需要认证 */
    bool requiresAuth;

    /** 是否需要工作量证明 */
    bool requiresPoW;

    /** 请求超时（毫秒） */
    uint32_t timeoutMs;

    /** 最大重试次数 */
    uint32_t maxRetries;
};

// ============================================================
// API 注册表
// ============================================================

/**
 * @brief API 注册表类
 *
 * 提供 39 个原子 API 的元数据查询和路由功能。
 */
class ApiRegistry {
public:
    /**
     * @brief 获取 API 元数据
     *
     * @param apiId API ID
     * @return const ApiMetadata* API 元数据指针，未找到返回 nullptr
     */
    static const ApiMetadata* getMetadata(AtomicApiId apiId);

    /**
     * @brief 根据路径查找 API ID
     *
     * @param path API 路径
     * @return AtomicApiId API ID，未找到返回 0
     */
    static AtomicApiId findByPath(const std::string& path);

    /**
     * @brief 获取所有已注册的 API 元数据
     *
     * @return std::vector<const ApiMetadata*> 元数据列表
     */
    static std::vector<const ApiMetadata*> getAllMetadata();

    /**
     * @brief 获取 API 总数
     *
     * @return size_t API 总数
     */
    static size_t count();

private:
    // 禁止实例化
    ApiRegistry() = delete;
    ~ApiRegistry() = delete;
};

} // namespace csc