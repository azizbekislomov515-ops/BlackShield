#pragma once

#include <cstdint>
#include <string>

namespace blackshield::test {

/** Byte `i` of every generated test file is `i % 251` (prime period: never aligned to blocks). */
inline std::uint8_t PatternByte(std::uint64_t index) { return static_cast<std::uint8_t>(index % 251); }

/** Unique path under the test's temp directory (TMPDIR or GoogleTest's TempDir()). */
std::string TempPath(const std::string& name);

/** Writes `content` to `path`, replacing it. */
void WriteFile(const std::string& path, const std::string& content);

/** Streams `size` pattern bytes to `path` through a 1 MiB buffer. */
void WritePatternFile(const std::string& path, std::uint64_t size);

/** A /proc/self/status field in KiB (e.g. "VmRSS", "VmHWM"); -1 if unavailable. */
long ReadStatusKib(const char* field);

}  // namespace blackshield::test
