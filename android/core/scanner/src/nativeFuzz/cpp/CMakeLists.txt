# libFuzzer targets for the code that parses untrusted input. Included from src/main/cpp/CMakeLists.txt when
# BLACKSHIELD_BUILD_FUZZERS=ON; built with -fsanitize=fuzzer plus BLACKSHIELD_SANITIZE (normally
# address,undefined) and run on a device by :core:scanner:connectedNativeFuzz. libFuzzer ships with the NDK.

add_executable(yara_scan_fuzzer yara_scan_fuzzer.cpp)
target_link_libraries(yara_scan_fuzzer PRIVATE blackshield_scanner_core)
target_compile_options(yara_scan_fuzzer PRIVATE ${BLACKSHIELD_WARNINGS} -fsanitize=fuzzer)
target_link_options(yara_scan_fuzzer PRIVATE -fsanitize=fuzzer)
