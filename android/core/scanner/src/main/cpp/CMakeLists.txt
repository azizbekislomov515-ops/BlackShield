cmake_minimum_required(VERSION 3.22.1...4.1)

project(blackshield_scanner LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BLACKSHIELD_BUILD_TESTS "Build the GoogleTest suite (run on a device with :core:scanner:connectedNativeTest)" OFF)

set(BLACKSHIELD_WARNINGS -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Werror)

# --- libyara, pinned and built from source (see cmake/libyara.cmake) ---
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/libyara.cmake)

# --- Scan primitives: pure C++17 + POSIX, no JNI. Shared by the JNI library and the tests. ---
add_library(blackshield_scanner_core STATIC
    hash/block_hasher.cpp
    hash/hash_engine.cpp
    hash/hasher.cpp
    hash/md5.cpp
    hash/sha1.cpp
    hash/sha256.cpp
    scanner_engine.cpp
    yara/yara_scanner.cpp
)
target_include_directories(blackshield_scanner_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(blackshield_scanner_core PUBLIC yara)
# 64-bit off_t on 32-bit ABIs so files over 2 GiB hash correctly (bionic supports it from API 24).
target_compile_definitions(blackshield_scanner_core PUBLIC _FILE_OFFSET_BITS=64)
target_compile_options(blackshield_scanner_core PRIVATE
    ${BLACKSHIELD_WARNINGS}
    -fvisibility=hidden
    # Digest loops are unusably slow at -O0; keep them optimised in Debug (debug info stays).
    $<$<CONFIG:Debug>:-O2>
)

# --- JNI library loaded by the app ---
add_library(blackshield_scanner SHARED
    hash_jni.cpp
    jni_bridge.cpp
    jni_util.cpp
    yara_jni.cpp
)
target_link_libraries(blackshield_scanner PRIVATE blackshield_scanner_core)
target_compile_options(blackshield_scanner PRIVATE ${BLACKSHIELD_WARNINGS} -fvisibility=hidden)
# Keep the shared library small and only export JNI symbols.
target_link_options(blackshield_scanner PRIVATE
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
)
find_library(log-lib log)
target_link_libraries(blackshield_scanner PRIVATE ${log-lib})

# --- GoogleTest suite (device executable) ---
if(BLACKSHIELD_BUILD_TESTS)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../nativeTest/cpp ${CMAKE_CURRENT_BINARY_DIR}/native-tests)
endif()
