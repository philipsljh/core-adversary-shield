cmake_minimum_required(VERSION 3.15)
project(CoreSecurityClient LANGUAGES CXX)

# ============================================================================
# 基础配置
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# 外部依赖：OpenSSL 或 Windows BCrypt
# ============================================================================
# 本开源版本使用跨平台密码学实现：
# - Windows: 使用内置 BCrypt API（无需额外依赖）
# - Linux/macOS: 需要 OpenSSL 3.x
#
# 使用方法:
#   - Ubuntu/Debian: sudo apt-get install libssl-dev
#   - macOS: brew install openssl
#   - Windows: 无需额外依赖，使用内置 BCrypt
# ============================================================================

option(USE_OPENSSL "Use OpenSSL instead of Windows BCrypt" OFF)

if(WIN32 AND NOT USE_OPENSSL)
    # Windows 平台使用内置 BCrypt，无需额外依赖
    message(STATUS "Using Windows BCrypt for cryptographic operations")
    set(CSC_CRYPTO_LIBS bcrypt)
else()
    # 非 Windows 平台或强制使用 OpenSSL
    set(USE_OPENSSL ON)
    find_package(OpenSSL REQUIRED)
    message(STATUS "Using OpenSSL for cryptographic operations")
    set(CSC_CRYPTO_LIBS OpenSSL::Crypto)
endif()

# ============================================================================
# 源文件
# ============================================================================
set(CSC_HEADERS
    include/Result.h
    include/SecureChannel.h
    include/CryptoCore.h
    include/SecurityDef.h
    include/AuthGateway.h
    include/ApiRegistry.h
    include/ProtocolGateway.hpp
    include/RuntimeEnvironmentValidator.h
)

set(CSC_SOURCES
    src/SecureChannel.cpp
    src/CryptoCore.cpp
    src/AuthGateway.cpp
    src/ApiRegistry.cpp
    src/RuntimeEnvironmentValidator.cpp
)

# ============================================================================
# 示例源文件
# ============================================================================
set(EXAMPLE_SOURCES
    examples/protocol_example.cpp
)

# ============================================================================
# 编译目标：静态库
# ============================================================================
add_library(csc_core STATIC ${CSC_SOURCES})

target_include_directories(csc_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(csc_core PUBLIC
    ${CSC_CRYPTO_LIBS}
)

# Windows 特定链接
if(WIN32)
    target_link_libraries(csc_core PUBLIC
        crypt32
        advapi32
    )
endif()

# 编译选项
target_compile_options(csc_core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

# 注入协议版本号编译宏
# 生产环境可通过 -DCSC_PROTOCOL_VERSION="x.x.x" 覆盖
if(NOT DEFINED CSC_PROTOCOL_VERSION)
    set(CSC_PROTOCOL_VERSION "2.0")
endif()
target_compile_definitions(csc_core PRIVATE CSC_PROTOCOL_VERSION="${CSC_PROTOCOL_VERSION}")

# ============================================================================
# 编译目标：示例程序
# ============================================================================
add_executable(csc_example ${EXAMPLE_SOURCES})

target_link_libraries(csc_example PRIVATE
    csc_core
)

# ============================================================================
# 安装规则
# ============================================================================
install(TARGETS csc_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${CSC_HEADERS}
    DESTINATION include/csc
)