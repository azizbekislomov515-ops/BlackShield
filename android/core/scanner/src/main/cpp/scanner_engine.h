#pragma once

#include <string>
#include <string_view>

namespace blackshield::scanner {

/** ABI this library was compiled for, e.g. "arm64-v8a". */
std::string_view CompiledAbi() noexcept;

/** Health check for the native pipeline: returns a short "pong" message. */
std::string Ping();

}  // namespace blackshield::scanner
