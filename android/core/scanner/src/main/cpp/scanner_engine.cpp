#include "scanner_engine.h"

static_assert(__cplusplus >= 201703L, "The BlackShield scanner requires C++17 or newer");

namespace blackshield::scanner {

std::string_view CompiledAbi() noexcept {
#if defined(__aarch64__)
    return "arm64-v8a";
#elif defined(__arm__)
    return "armeabi-v7a";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#else
    return "unknown";
#endif
}

std::string Ping() {
    std::string message{"pong from native scanner (C++"};
    message += std::to_string(__cplusplus / 100 % 100);
    message += ", ";
    message += CompiledAbi();
    message += ')';
    return message;
}

}  // namespace blackshield::scanner
