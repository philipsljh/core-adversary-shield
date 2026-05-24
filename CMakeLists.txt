cmake_minimum_required(VERSION 3.15)
project(CoreSecurityClient LANGUAGES CXX)

# ============================================================================
# 基础配置
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# 外部依赖：Crypto++ 静态库
# ============================================================================
# 使用方法:
#   1. 从 https://www.cryptopp.com/ 下载并编译 Crypto++
#   2. 设置 CRYPTOPP_ROOT 环境变量或 CMake 变量指向 Crypto++ 安装目录
#   3. 或者使用系统包管理器安装:
#      - Ubuntu/Debian: sudo apt-get install libcrypto++-dev
#      - Windows (vcpkg): vcpkg install cryptopp
#
# 示例:
#   cmake -DCRYPTOPP_ROOT=/path/to/cryptopp ..
# ============================================================================

find_path(CRYPTOPP_INCLUDE_DIR
    NAMES cryptopp/aes.h cryptopp/rsa.h
    PATHS ${CRYPTOPP_ROOT} /usr/include /usr/local/include
    PATH_SUFFIXES include
)

find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp libcrypto++
    PATHS ${CRYPTOPP_ROOT} /usr/lib /usr/local/lib
    PATH_SUFFIXES lib
)

if(NOT CRYPTOPP_INCLUDE_DIR)
    message(FATAL_ERROR "Crypto++ headers not found. Set CRYPTOPP_ROOT or install libcrypto++-dev")
endif()

if(NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found. Set CRYPTOPP_ROOT or install libcrypto++-dev")
endif()

message(STATUS "Crypto++ include: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")

# ============================================================================
# 源文件
# ============================================================================
set(CSC_HEADERS
    include/Result.h
    include/SecureChannel.h
    include/ProtocolGateway.hpp
    include/RuntimeEnvironmentValidator.h
)

set(CSC_SOURCES
    src/SecureChannel.cpp
    src/RuntimeEnvironmentValidator.cpp
)

# ============================================================================
# 示例可执行文件
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
    ${CRYPTOPP_INCLUDE_DIR}
)

target_link_libraries(csc_core PUBLIC
    ${CRYPTOPP_LIBRARY}
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

# 彻底关闭 Crypto++ 异常支持，对齐"全面废弃异常"的设计哲学
target_compile_definitions(csc_core PRIVATE CRYPTOPP_DISABLE_EXCEPTIONS)

# 注入协议版本号编译宏，避免静态特征码暴露
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