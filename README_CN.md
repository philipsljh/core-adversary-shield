[简体中文](README_CN.md) | [English](README.md)

# Core Security Client (CSC) — 企业级零信任策略编排框架

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/)

## 概述

Core Security Client (CSC) 是一套开源的企业级 **零信任策略编排框架** 参考实现。本项目展示了工业强度的安全防御模式，包括：

- **端到端混合加密链路**：RSA-2048 + AES-256-GCM 混合加密协议
- **绝对无状态认证**：零状态网关配合瞬时会话密钥生命周期
- **算力挑战限流体系**：基于工作量证明（PoW）的抗洪水攻击防护
- **基于 Ed25519 盲神谕者的分布式异步数字签名**：会话证明机制
- **运行态物理内存页锁定与内核级凭证阅后即焚工程**：VirtualLock、SecureZeroMemory、纯栈密钥材料
- **针对 SQLite 并发死锁的自适应指数退避与安全随机数抖动重试写外壳**：WAL 模式配合指数退避重试

本项目专为安全架构师、工程师与研究人员设计，旨在帮助理解与实现企业级纵深防御模式。

## 架构总览

### 客户端 (C++17)

```
┌─────────────────────────────────────────────────────────────┐
│                    应用层                                    │
├─────────────────────────────────────────────────────────────┤
│  AuthGateway  │  ProtocolGateway  │  ApiRegistry (39 APIs)  │
├─────────────────────────────────────────────────────────────┤
│              SecureChannel (RSA + AES-GCM)                  │
├─────────────────────────────────────────────────────────────┤
│           CryptoCore │ XorKeyStorage │ ResultT<T>           │
├─────────────────────────────────────────────────────────────┤
│         Windows BCrypt / OpenSSL (跨平台)                   │
└─────────────────────────────────────────────────────────────┘
```

### 服务端 (Go)

```
┌─────────────────────────────────────────────────────────────┐
│                   HTTP 处理层                                │
├─────────────────────────────────────────────────────────────┤
│         洋葱模型中间件流水线                                  │
│   BaseInfo → VerifyPoW → Oracle Signer                      │
├─────────────────────────────────────────────────────────────┤
│         Ed25519 盲神谕者 │ PoW 验证器                        │
├─────────────────────────────────────────────────────────────┤
│         SQLite WAL (无死锁写外壳)                            │
└─────────────────────────────────────────────────────────────┘
```

## 核心安全特性

### 1. 无状态通信网络层 (C++)

`SecureChannel` 类实现了绝对零状态的混合加密协议：

- **类成员不持有任何会话态凭证** — 所有密钥材料仅存活于栈内存
- **一次一密** — 每次请求独立生成 32 字节 AES 会话密钥，绝不复用
- **内存阅后即焚** — 函数返回前 `SecureZeroMemory` 强制擦除所有敏感材料
- **物理内存页锁定** — `VirtualLock` 防止密钥材料被交换至磁盘

`ProtocolGateway` 泛型引擎通过 `IHttpTransport` 纯虚接口实施网络层完全解耦。所有密码学操作在单次函数调用的栈内存中完成，函数返回前即刻执行物理级内存粉碎，确保密钥材料零残留。

### 2. 编译期类型安全的 ResultT 无异常严格错误分流体系 (C++)

所有操作均返回强类型结果结构体，彻底消除异常抛出机制：

```cpp
ResultT<AuthResponse> result = gateway.authenticate(request, ctx, snapshot);
if (!result.success) {
    switch (result.errorClass) {
        case GatewayErrorClass::CLASS_A_AUTH_FATAL:
            // A 类错误：授权失败，需重新登录
            break;
        case GatewayErrorClass::CLASS_B_RATE_LIMIT:
            // B 类错误：请求速率限制，需等待冷却
            break;
        case GatewayErrorClass::CLASS_C_NETWORK_RETRY:
            // C 类错误：瞬时网络异常，允许有限重试
            break;
        case GatewayErrorClass::CLASS_D_TAMPERED_ENV:
            // D 类错误：高危环境投毒，立即终止通信
            break;
    }
}
```

标准化网关错误体系通过编译期类型安全的 `ResultT<T>` 模板结构体进行交互层解耦：

| 错误分类 | 语义 | 处置策略 |
|----------|------|----------|
| **A 类 (AUTH_FATAL)** | 授权致命失败 | 立即终止会话，要求用户重新认证 |
| **B 类 (RATE_LIMIT)** | 请求速率超限 | 启动冷却计时器，禁止隐式重试 |
| **C 类 (NETWORK_RETRY)** | 瞬时网络异常 | 允许有限次数显式重试 |
| **D 类 (TAMPERED_ENV)** | 高危环境投毒 | 立即熔断通信链路，触发安全告警 |

### 3. 39 个原子 API

`ApiRegistry` 定义了跨越 6 大分类的 39 个原子 API 端点：

| 分类 | 数量 | 描述 |
|------|------|------|
| 认证类 (Auth) | 8 | 身份认证、令牌管理、设备注册 |
| 策略类 (Policy) | 8 | 策略 CRUD、验证、模拟、导出 |
| 资源类 (Resource) | 8 | 资源管理、同步、校验 |
| 审计类 (Audit) | 6 | 心跳校验、事件上报、日志上传 |
| 配置类 (Config) | 5 | 配置管理与验证 |
| 系统类 (System) | 4 | 系统信息、健康检查、版本校验、时间同步 |

### 4. 基于 Ed25519 盲神谕者的分布式异步数字签名

服务端实现了盲神谕者签名机制：

- 私钥从环境变量加载（**绝不明文硬编码**）
- 签名源文格式：`identifier|nonce|expire_timestamp|resource_hash`
- 签名结果经 Base64 编码后传输
- 所有中间字节数组在使用完毕后立即清零

### 5. 针对 SQLite 并发死锁的自适应指数退避与安全随机数抖动重试写外壳

数据库层实现了工业级并发写保护：

- DSN 中隐式注入 `_txlock=immediate` 强行将事务自动升级为 SQLite 的 WAL 串行写锁
- 指数退避配合安全随机数抖动（20-80ms）
- 最大 5 次重试后放弃
- WAL 日志模式支持并发读写

## 分布式云端控制流 (Go)

服务端采用 **洋葱模型中间件流水线** 架构：

```
HTTP Request → BaseInfoMiddleware → VerifyPoW → OracleSigner → Business Handler
```

1. **BaseInfoMiddleware**：提取并校验客户端基础信息（IP、User-Agent、时间戳）
2. **VerifyPoW（工作量证明算力防刷）**：验证客户端提交的 PoW 票据，防止暴力请求洪水攻击
3. **OracleSigner**：Ed25519 盲神谕者签名中间件，为响应数据附加数字签名
4. **Business Handler**：业务逻辑处理器

每一层中间件均可独立拦截请求并返回错误响应，形成纵深防御体系。

## 快速开始

### 编译 C++ 客户端

```bash
# Linux/macOS
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Windows (MSVC)
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

### 运行 Go 服务端

```bash
cd server

# 开发模式（自动生成临时密钥）
POLICY_SERVER_DEV_MODE=1 go run main.go

# 生产模式（需要 Ed25519 私钥）
export POLICY_SERVER_ED25519_PRIVATE_KEY=$(base64 -w0 < private_key.bin)
go build -o server && ./server
```

### 环境变量

| 变量名 | 描述 | 是否必需 |
|--------|------|----------|
| `POLICY_SERVER_ED25519_PRIVATE_KEY` | Base64 编码的 Ed25519 私钥 | 生产环境 |
| `POLICY_SERVER_DEV_MODE` | 设为 `1` 启用开发模式 | 开发环境 |
| `POLICY_SERVER_RESOURCE_HASH` | 资源字节码哈希（用于签名） | 生产环境 |

## 项目结构

```
.
├── CMakeLists.txt              # 跨平台编译配置
├── LICENSE                     # MIT 许可证
├── README.md                   # 英文版说明
├── README_CN.md                # 中文版说明
├── include/                    # 公共头文件
│   ├── ApiRegistry.h           # 39 个原子 API 定义
│   ├── AuthGateway.h           # 无状态认证网关
│   ├── CryptoCore.h            # 密码学原语
│   ├── Result.h                # ResultT<T> 错误分流模板
│   ├── SecureChannel.h         # 混合加密通道
│   ├── SecurityDef.h           # 编译期字符串混淆
│   ├── ProtocolGateway.hpp     # 协议网关泛型引擎
│   └── RuntimeEnvironmentValidator.h
├── src/                        # 实现文件
│   ├── ApiRegistry.cpp         # API 元数据表
│   ├── AuthGateway.cpp         # 网关实现（Stub）
│   ├── CryptoCore.cpp          # 跨平台密码学实现
│   ├── SecureChannel.cpp       # RSA + AES-GCM 实现
│   └── RuntimeEnvironmentValidator.cpp
├── examples/                   # 使用示例
│   └── protocol_example.cpp
├── server/                     # Go 服务端实现
│   ├── go.mod
│   ├── go.sum
│   ├── main.go                 # 服务入口
│   ├── db/
│   │   └── db_sqlite_wallet.go # 无死锁写外壳
│   ├── middleware/
│   │   ├── oracle_signer.go    # Ed25519 盲神谕者
│   │   └── pow_verifier.go     # PoW 验证中间件
│   └── internal/
│       └── utils/
│           ├── context.go      # 上下文工具
│           └── log.go          # 日志工具
└── docs/
    └── lua_architecture.md     # Lua 虚拟机架构文档
```

## 安全考量

### 内存安全

- 所有会话密钥均在栈上分配，函数返回前强制擦除
- `SecureZeroMemory`（Windows）或 volatile 指针擦除（POSIX）防止编译器优化
- `VirtualLock` 防止敏感页面被交换至磁盘

### 密钥管理

- 私钥 **绝不明文硬编码** — 从环境变量加载
- 会话密钥使用密码学安全随机数生成器（BCryptGenRandom / OpenSSL RAND_bytes）
- 密钥材料在 `XorKeyStorage` 中进行 XOR 掩码混淆以提供额外保护

### 网络安全

- 所有请求使用 RSA-2048 + AES-256-GCM 混合加密
- RSA 使用 OAEP 填充 + SHA-256（防止填充预言攻击）
- GCM 模式提供认证加密（防止篡改）

### 限流体系

- 基于 PoW 的算力挑战防止暴力攻击
- 每 IP 滑动窗口限流
- 基于票据的重放攻击防护

## 许可证

本项目采用 MIT 许可证 — 详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎贡献代码！请阅读我们的贡献指南并提交 Pull Request。

## 免责声明

> **?? 架构解耦说明 (Architecture Stub Notice)**:
> 开源版本中的 `AuthGateway` 采用安全空转（Stub）实现并返回标准 Mock 响应，旨在展示全栈通信流契约。
> 生产环境部署时，请根据组织内部实际的基础设施（如 WinHTTP、cURL 传输层及企业级 API 网关）自行接入真实的物理网络分发链。

本实现仅用于教育与架构演示目的。生产环境部署时应：

1. 由合格的专业人员进行全面安全审计
2. 将 Stub 实现替换为实际的网络传输层
3. 配置适当的密码学密钥管理系统
4. 实施完善的日志与监控基础设施
5. 遵循组织内部的安全合规要求

---

## 验证状态

本开源版本已彻底废弃原版的 Mock 方案，全面升级为企业级原生 Windows BCrypt AES-256-GCM 安全底座，所有测试用例均已通过静态审计与动态断言验证。

### 自动化测试套件结果

```text
  CAS 核心安全测试套件 v1.0

[ RUN      ] T01_内存阅后即焚验证
[       OK ] T01_内存阅后即焚验证 (0 ms)
[ RUN      ] T02_volatile 指针擦除验证
[       OK ] T02_volatile 指针擦除验证 (0 ms)
[ RUN      ] T03_密钥上下文生命周期验证
[       OK ] T03_密钥上下文生命周期验证 (0 ms)
[ RUN      ] T04_XOR 密钥存储投毒验证
[       OK ] T04_XOR 密钥存储投毒验证 (1 ms)
[ RUN      ] T05_AES 加解密冒烟测试
[       OK ] T05_AES 加解密冒烟测试 (0 ms)
[ RUN      ] T06_Base64 编解码双向一致性验证
[       OK ] T06_Base64 编解码双向一致性验证 (0 ms)
[ RUN      ] T07_AuthGateway 桩点空转验证
[       OK ] T07_AuthGateway 桩点空转验证 (0 ms)
[ RUN      ] T08_运行环境验证器测试
[       OK ] T08_运行环境验证器测试 (0 ms)

测试执行汇总
总任务数:      8
通过:          8 [ 100% ]
失败:          0
总耗时:        1 ms
[  通过  ] 所有测试已通过
```

### 测试覆盖范围

| 测试编号 | 描述 | 状态 |
|---------|------|------|
| T01 | 内存阅后即焚验证 (SecureZeroMemory) | ? 通过 |
| T02 | volatile 指针擦除验证 | ? 通过 |
| T03 | 密钥上下文生命周期验证 | ? 通过 |
| T04 | XOR 密钥存储投毒验证 | ? 通过 |
| T05 | AES-256-GCM 冒烟测试 | ? 通过 |
| T06 | Base64 编解码双向一致性验证 | ? 通过 |
| T07 | AuthGateway 桩点空转验证 | ? 通过 |
| T08 | 运行环境验证器测试 | ? 通过 |
