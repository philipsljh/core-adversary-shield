# Core Security Client (CSC) — Open Source Reference Implementation

> **文档版本**: v1.0  
> **许可证**: MIT License  
> **适用对象**: 安全工程师、系统架构师、技术决策者

## 项目简介

本项目是一个**具备边缘协同校验的高可用、强隔离的客户端/服务端联动安全框架**的技术展示仓库。系统面向高对抗环境设计，核心目标是在不可信终端环境中建立一条从边缘网关到进程内执行引擎的**零信任安全链路**。

## 核心设计哲学

| 原则 | 说明 |
|------|------|
| **物理隔离优先** | 进程内执行引擎与网络通信组件通过加密通道隔离 |
| **零状态网关** | 所有网络加解密操作在单次函数调用的栈内存中完成 |
| **密码学驱动决策** | 客户端本地禁止模拟服务端状态机 |
| **内存阅后即焚** | 敏感数据采用 VirtualLock 防分页、SecureZeroMemory 强制擦除 |
| **动态符号解析** | 所有系统级 API 调用通过运行时动态地址解析完成 |

## 技术栈

| 组件 | 技术栈 |
|------|--------|
| 客户端 | C++17 / 标准密码学库 |
| 服务端 | Go 1.21+ / SQLite / Redis |
| 加密算法 | RSA-2048 / AES-256-GCM / Ed25519 / ECDH / SHA-256 |

## 目录结构

```
├── include/
│   ├── Result.h                        # 无异常模式错误处理模板
│   ├── SecureChannel.h                 # 无状态加密通道
│   ├── ProtocolGateway.hpp             # 协议网关泛型引擎
│   └── RuntimeEnvironmentValidator.h   # 运行环境验证层
├── src/
│   ├── SecureChannel.cpp               # AES-256-GCM 和 RSA-2048 混合解密实现
│   └── RuntimeEnvironmentValidator.cpp # XOR 密钥混淆/延迟投毒/动态符号解析
├── examples/
│   └── protocol_example.cpp            # 协议规范类示例
└── README.md
```

## 安全特性

### 1. 无状态加密通道 (SecureChannel)

所有密码学操作遵循**绝对零状态设计**：
- 会话密钥在栈上生成、使用、销毁
- 类成员变量不持有任何会话态凭证
- 函数返回前强制 `SecureZeroMemory` 擦除

### 2. 协议规范模式 (ProtocolGateway)

采用**策略类 + 泛型执行引擎**架构：
- 每个业务接口抽象为独立的协议规范类
- 编译期类型安全，请求/响应类型在编译期绑定
- 错误分类标准化，统一 `ResultT<T>` 模板

### 3. 无异常模式 (No Exceptions)

- 废弃所有 `throw` 或 `std::runtime_error`
- 所有返回值强制包装在 `ResultT<T>` 模板结构体中
- 错误分为 A/B/C/D 四类供上层决策

### 4. 运行环境验证层 (RuntimeEnvironmentValidator)

- **SecureKeyContext**：XOR 混淆密钥存储，`shadowBuffer[32]` + `entropyMask[32]`，栈帧内还原，阅后即焚
- **延迟随机投毒**：检测到调试器后延迟 3~8 次心跳触发内存投毒，不直接崩溃暴露检测逻辑
- **API 动态符号解析**：通过预计算哈希值动态解析系统 API 地址，静态二进制不暴露导入表

## 构建要求

- C++17 或更高版本
- Crypto++ 库 (https://www.cryptopp.com/)
- 支持 Windows 7 及以上操作系统

## 开源版本局限性声明

> **重要提示**: 本开源版本为**精简参考实现**，旨在展示高对抗环境下的核心安全架构设计理念。
> 生产环境部署时，请务必完成以下安全对齐：

| 模块 | 开源版本状态 | 生产环境要求 |
|------|-------------|-------------|
| **服务端响应加密** | 心跳/登录接口返回明文 JSON（Ed25519 签名与 Nonce 回显安全闭环完整） | 必须启用 RSA+AES 混合加密反向传输，与客户端 `SecureChannel::Decrypt` 对齐 |
| **script_hash** | 通过 `RXXL_SCRIPT_HASH` 环境变量加载，未设置时使用全零占位 | 生产环境必须设置为实际脚本字节码的 SHA-256 哈希值 |
| **PoW 难度** | 默认 4 个前导零（16 位） | 根据实际算力威胁模型调整 `LeadingZeros` 参数 |
| **反调试检测** | 基础 PEB + `IsDebuggerPresent` 检测 | 建议叠加 `CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`、时间差检测等 |
| **速率限制** | 进程内内存限流器（100 次/60秒/IP） | 生产环境建议叠加 Redis 分布式限流 |

## 许可证

MIT License - 详见 LICENSE 文件

## 免责声明

本项目仅用于技术学习和研究目的，不得用于任何商业攻击或非法用途。
