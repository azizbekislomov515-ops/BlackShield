cmake_minimum_required(VERSION 3.22.1...4.1)

project(blackshield_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(blackshield_scanner SHARED
    jni_bridge.cpp
    scanner_engine.cpp
)

target_include_directories(blackshield_scanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(blackshield_scanner PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
)

# Keep the shared library small and only export JNI symbols.
target_link_options(blackshield_scanner PRIVATE
    -Wl,--gc-sections
    -Wl,--exclude-libs,ALL
)

find_library(log-lib log)
target_link_libraries(blackshield_scanner PRIVATE ${log-lib})
