# GoogleTest suite for blackshield_scanner_core. Included from src/main/cpp/CMakeLists.txt when
# BLACKSHIELD_BUILD_TESTS=ON. GoogleTest comes from the NDK, so no download is needed.

set(BLACKSHIELD_GTEST_DIR ${ANDROID_NDK}/sources/third_party/googletest)
if(NOT EXISTS ${BLACKSHIELD_GTEST_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "GoogleTest not found in the NDK at ${BLACKSHIELD_GTEST_DIR}")
endif()

# Normally set by GoogleTest's top-level project; only used for package metadata.
set(GOOGLETEST_VERSION 1.0.0)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
add_subdirectory(${BLACKSHIELD_GTEST_DIR} ${CMAKE_CURRENT_BINARY_DIR}/googletest EXCLUDE_FROM_ALL)

add_executable(blackshield_scanner_tests
    hash_engine_test.cpp
    hasher_test.cpp
    test_util.cpp
)
target_link_libraries(blackshield_scanner_tests PRIVATE blackshield_scanner_core gtest gtest_main)
target_compile_options(blackshield_scanner_tests PRIVATE ${BLACKSHIELD_WARNINGS})
