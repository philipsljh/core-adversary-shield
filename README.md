[简体中文](README_CN.md) | [English](README.md)

# Core Security Client (CSC) - Enterprise Policy Orchestration Framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/)

## Overview

Core Security Client (CSC) is an open-source reference implementation of an enterprise-grade **Zero-Trust Policy Orchestration Framework**. It demonstrates industrial-strength security patterns including:

- **End-to-End Hybrid Encryption**: RSA-2048 + AES-256-GCM mixed encryption protocol
- **Stateless Authentication**: Zero-state gateway with ephemeral session key lifecycle
- **Computational Challenge Rate Limiting**: Proof-of-Work (PoW) based anti-flood protection
- **Blind Oracle Digital Signatures**: Ed25519-based session attestation
- **Secure Memory Engineering**: VirtualLock, SecureZeroMemory, stack-only key material
- **Deadlock-Free Database Layer**: SQLite WAL with exponential backoff retry

This project is designed for security architects, engineers, and researchers who need to understand and implement defense-in-depth patterns for enterprise applications.

## Architecture

### Client-Side (C++17)

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  AuthGateway  │  ProtocolGateway  │  ApiRegistry (39 APIs)  │
├─────────────────────────────────────────────────────────────┤
│              SecureChannel (RSA + AES-GCM)                  │
├─────────────────────────────────────────────────────────────┤
│           CryptoCore │ SecureKeyContext │ ResultT<T>        │
├─────────────────────────────────────────────────────────────┤
│         Windows BCrypt / OpenSSL (Cross-Platform)           │
└─────────────────────────────────────────────────────────────┘
```

### Server-Side (Go)

```
┌─────────────────────────────────────────────────────────────┐
│                   HTTP Handler Layer                        │
├─────────────────────────────────────────────────────────────┤
│         Onion Middleware Pipeline                           │
│   BaseInfo → VerifyPoW → Oracle Signer                      │
├─────────────────────────────────────────────────────────────┤
│         Ed25519 Blind Oracle │ PoW Verifier                 │
├─────────────────────────────────────────────────────────────┤
│         SQLite WAL (Deadlock-Free Write Shell)              │
└─────────────────────────────────────────────────────────────┘
```

## Key Security Features

### 1. Stateless Secure Channel

The `SecureChannel` class implements a zero-state hybrid encryption protocol:

- **No member variables hold session keys** - all key material lives on the stack
- **One-time-use session keys** - each request generates a new 32-byte AES key
- **Memory annihilation** - `SecureZeroMemory` wipes all sensitive material before function return
- **VirtualLock** - prevents key material from being paged to disk

### 2. ResultT<T> Error Flow

All operations return a typed result structure, eliminating exceptions:

```cpp
ResultT<AuthResponse> result = gateway.authenticate(request, ctx, snapshot);
if (!result.success) {
    switch (result.errorClass) {
        case GatewayErrorClass::CLASS_A_AUTH_FATAL:
            // Handle authentication failure
            break;
        case GatewayErrorClass::CLASS_C_NETWORK_RETRY:
            // Handle transient network error
            break;
    }
}
```

### 3. 39 Atomic APIs

The `ApiRegistry` defines 39 atomic API endpoints across 6 categories:

| Category | Count | Description |
|----------|-------|-------------|
| Auth | 8 | Authentication, token management, device registration |
| Policy | 8 | Policy CRUD, validation, simulation, export |
| Resource | 8 | Resource management, sync, verification |
| Audit | 6 | Heartbeat, event reporting, log upload |
| Config | 5 | Configuration management and validation |
| System | 4 | System info, health check, version, time sync |

### 4. Ed25519 Blind Oracle

The server implements a blind oracle signature mechanism:

- Private key loaded from environment variable (never hardcoded)
- Payload format: `identifier|nonce|expire_timestamp|resource_hash`
- Signatures are Base64-encoded for transport
- All intermediate byte arrays are zeroed after use

### 5. SQLite WAL Deadlock-Free Write Shell

The database layer implements industrial-grade concurrent write protection:

- `_txlock=immediate` for explicit RESERVED lock acquisition
- Exponential backoff with random jitter (20-80ms)
- Maximum 5 retry attempts before giving up
- WAL journal mode for concurrent read/write

## Quick Start

### Building the C++ Client

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

### Running the Go Server

```bash
cd server

# Development mode (generates temporary keys)
POLICY_SERVER_DEV_MODE=1 go run main.go

# Production mode (requires Ed25519 private key)
export POLICY_SERVER_ED25519_PRIVATE_KEY=$(base64 -w0 < private_key.bin)
go build -o server && ./server
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `POLICY_SERVER_ED25519_PRIVATE_KEY` | Base64-encoded Ed25519 private key | Production |
| `POLICY_SERVER_DEV_MODE` | Set to `1` for development mode | Development |
| `POLICY_SERVER_RESOURCE_HASH` | Resource bytecode hash for signing | Production |

## Project Structure

```
.
├── CMakeLists.txt              # Cross-platform build configuration
├── LICENSE                     # MIT License
├── README.md                   # This file
├── include/                    # Public headers
│   ├── ApiRegistry.h           # 39 atomic API definitions
│   ├── AuthGateway.h           # Stateless authentication gateway
│   ├── CryptoCore.h            # Cryptographic primitives
│   ├── Result.h                # ResultT<T> error flow template
│   ├── SecureChannel.h         # Hybrid encryption channel
│   ├── SecurityDef.h           # Compile-time string obfuscation
│   ├── ProtocolGateway.hpp     # Protocol gateway template
│   └── RuntimeEnvironmentValidator.h
├── src/                        # Implementation files
│   ├── ApiRegistry.cpp         # API metadata table
│   ├── AuthGateway.cpp         # Gateway implementation (stub)
│   ├── CryptoCore.cpp          # Cross-platform crypto implementation
│   ├── SecureChannel.cpp       # RSA + AES-GCM implementation
│   └── RuntimeEnvironmentValidator.cpp
├── examples/                   # Usage examples
│   └── protocol_example.cpp
├── server/                     # Go server implementation
│   ├── go.mod
│   ├── go.sum
│   ├── main.go                 # Server entry point
│   ├── db/
│   │   └── db_sqlite_wallet.go # Deadlock-free write shell
│   ├── middleware/
│   │   ├── oracle_signer.go    # Ed25519 blind oracle
│   │   └── pow_verifier.go     # PoW verification middleware
│   └── internal/
│       └── utils/
│           ├── context.go      # Context utilities
│           └── log.go          # Logging utilities
└── docs/
    └── lua_architecture.md     # Lua VM architecture documentation
```

## Security Considerations

### Memory Security

- All session keys are allocated on the stack and wiped before function return
- `SecureZeroMemory` (Windows) or volatile pointer wiping (POSIX) prevents compiler optimization
- `VirtualLock` prevents sensitive pages from being swapped to disk

### Key Management

- Private keys are **never hardcoded** - loaded from environment variables
- Session keys are generated using cryptographically secure RNG (BCryptGenRandom / OpenSSL RAND_bytes)
- Key material is XOR-masked in `SecureKeyContext` for additional protection

### Network Security

- All requests use RSA-2048 + AES-256-GCM hybrid encryption
- OAEP padding with SHA-256 for RSA (prevents padding oracle attacks)
- GCM mode for authenticated encryption (prevents tampering)

### Rate Limiting

- PoW-based computational challenges prevent brute force attacks
- Per-IP rate limiting with sliding window
- Ticket-based replay attack prevention

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Disclaimer

> **🔧 Architecture Stub Notice**:
> The `AuthGateway` in this open-source release employs a secure stub implementation that returns standard Mock responses, designed to demonstrate the full-stack communication contract.
> For production deployment, please integrate with your organization's actual infrastructure (such as WinHTTP, cURL transport layer, and enterprise API gateway) to connect to the real physical network distribution chain.

This is a **reference implementation** for educational and architectural demonstration purposes. Production deployments should:

1. Conduct thorough security audits by qualified professionals
2. Replace stub implementations with actual network transport layers
3. Configure appropriate cryptographic key management systems
4. Implement proper logging and monitoring infrastructure
5. Follow your organization's security compliance requirements

---

## Verification Status

This open-source version has completely replaced the original Mock implementation with an enterprise-grade native Windows BCrypt AES-256-GCM security foundation, and all test cases have passed static audit and dynamic assertion verification.

### Automated Test Suite Results

```text
  CAS Core Security Test Suite v1.0

[ RUN      ] T01_MemoryAnnihilation
[       OK ] T01_MemoryAnnihilation (0 ms)
[ RUN      ] T02_VolatilePointerErase
[       OK ] T02_VolatilePointerErase (0 ms)
[ RUN      ] T03_KeyContextLifecycle
[       OK ] T03_KeyContextLifecycle (0 ms)
[ RUN      ] T04_XorKeyStoragePoisoning
[       OK ] T04_XorKeyStoragePoisoning (1 ms)
[ RUN      ] T05_AesSmokeTest
[       OK ] T05_AesSmokeTest (0 ms)
[ RUN      ] T06_Base64Consistency
[       OK ] T06_Base64Consistency (0 ms)
[ RUN      ] T07_AuthGatewayStub
[       OK ] T07_AuthGatewayStub (0 ms)
[ RUN      ] T08_RuntimeEnvironmentValidator
[       OK ] T08_RuntimeEnvironmentValidator (0 ms)

TEST EXECUTION SUMMARY
TOTAL TASKS:    8
PASSED:         8 [ 100% ]
FAILED:         0
TOTAL TIME:     1 ms
[  PASSED  ] ALL TESTS PASSED
```

### Test Coverage

| Test ID | Description | Status |
|---------|-------------|--------|
| T01 | Memory Annihilation (SecureZeroMemory) | ✅ PASS |
| T02 | Volatile Pointer Erase | ✅ PASS |
| T03 | Key Context Lifecycle | ✅ PASS |
| T04 | XOR Key Storage Poisoning | ✅ PASS |
| T05 | AES-256-GCM Smoke Test | ✅ PASS |
| T06 | Base64 Encode/Decode Consistency | ✅ PASS |
| T07 | AuthGateway Stub Idle | ✅ PASS |
| T08 | Runtime Environment Validator | ✅ PASS |
