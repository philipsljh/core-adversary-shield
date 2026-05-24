# Core Adversary Shield (CAS) — Open Source Reference Implementation

> **项目定位**: 不可信终端环境下的全栈纵深防御与高对抗安全框架
> **母品牌生态**: Part of the **RXXL Full-Stack Security Ecosystem**
> **许可证**: MIT License 

## ⚖️ 项目简介

Core Adversary Shield (CAS) 是一个**具备边缘协同校验的高可用、强隔离的全栈联动安全框架**。系统面向极端高对抗环境设计，核心目标是在不可信的客户端终端环境中，建立一条从边缘网关到进程内执行引擎的**零信任安全链路**，从物理内存、运行态反调试、密码学通信及服务端并发治理四个维度构建闭环防御体系。

---

## 🧠 核心设计哲学

| 原则 | 说明 |
|------|------|
| **物理隔离优先** | 进程内执行引擎与网络通信组件通过加密通道解耦，切断静态分析链路。 |
| **零状态网关** | 客户端所有网络加解密操作在单次函数调用的栈内存中完成，阅后即焚。 |
| **密码学驱动决策** | 客户端本地禁止模拟服务端状态机，一切行为由服务端盲目神谕者（Oracle）签名驱动。 |
| **高并发死锁免疫** | 服务端引入 WAL 强锁与指数退避重试，物理级免疫 SQLite 并发死锁。 |
| **内存隐写与动态解析** | 敏感符号运行时动态哈希解析，核心密钥栈帧内 XOR 混淆，拒绝持久化。 |

---

## 🛠️ 技术栈全景

*   **客户端域 (C++ Domain)**: C++17 标准 / 纯静态无状态设计 / 动态符号解析引擎
*   **服务端域 (Go Domain)**: Go 1.21+ / 洋葱模型流水线中间件 / 响应式限流器
*   **数据结构与存储**: SQLite 工业级写入外壳 (WAL 模式) / Redis 分布式协同 (生产建议)
*   **密码学矩阵**: RSA-2048 / AES-256-GCM / Ed25519 异步签名 / SHA-256 哈希

---

## 📂 完整目录结构

```text
├── include/                           # C++ 客户端核心头文件
│   ├── Result.h                       # 无异常模式严格错误处理模板 (ResultT<T>)
│   ├── SecureChannel.h                # 绝对无状态加密通道 (AES-GCM / RSA)
│   ├── ProtocolGateway.hpp            # 编译期类型安全泛型协议网关
│   └── RuntimeEnvironmentValidator.h  # 运行期环境校验与反调试
├── src/                               # C++ 客户端核心源文件
│   ├── SecureChannel.cpp              # 混合加解密与内存物理阅后即焚实现
│   └── RuntimeEnvironmentValidator.cpp # XOR混淆 / 延迟暗桩投毒 / PEB动态遍历
├── server/                            # Go 服务端完整域
│   ├── db/                            # SQLite 工业级无死锁写入外壳 (_txlock=immediate)
│   ├── middleware/                    # 洋葱流水线 (BaseInfo -> VerifyPoW -> Ticket防重放)
│   ├── internal/utils/                # 全局上下文控制与生产级无痕日志路由
│   └── main.go                        # 服务端高并发守护主入口
├── examples/                          # 通用占位符与协议规范类演示
│   └── protocol_example.cpp
├── CMakeLists.txt                     # C++ 严格构建脚本 (已开启 /WX 警告即错误)
├── .gitignore                         # 覆盖全栈敏感/垃圾产物的严苛忽略规则
└── LICENSE                            # MIT 开源许可证
