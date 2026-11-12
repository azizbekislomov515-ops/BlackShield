#include "test_util.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace blackshield::test {

std::string TempPath(const std::string& name) {
    static std::atomic<int> counter{0};
    const char* dir = std::getenv("TMPDIR");
    std::string base = dir != nullptr ? dir : ::testing::TempDir();
    if (!base.empty() && base.back() != '/') {
        base += '/';
    }
    return base + std::to_string(getpid()) + "_" + std::to_string(counter++) + "_" + name;
}

void WriteFile(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) {
        throw std::runtime_error("cannot write " + path);
    }
}

void WritePatternFile(const std::string& path, std::uint64_t size) {
    // 1 MiB rounded down to a multiple of the 251-byte period, so every chunk is identical.
    constexpr std::size_t kChunk = (1024 * 1024 / 251) * 251;
    std::vector<char> chunk(kChunk);
    for (std::size_t i = 0; i < kChunk; ++i) {
        chunk[i] = static_cast<char>(PatternByte(i));
    }
    std::FILE* file = std::fopen(path.c_str(), "wb");
    if (file == nullptr) {
        throw std::runtime_error("cannot create " + path);
    }
    std::uint64_t written = 0;
    while (written < size) {
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, size - written));
        if (std::fwrite(chunk.data(), 1, n, file) != n) {
            std::fclose(file);
            throw std::runtime_error("short write to " + path);
        }
        written += n;
    }
    std::fclose(file);
}

long ReadStatusKib(const char* field) {
    std::ifstream status("/proc/self/status");
    std::string line;
    const std::size_t field_length = std::strlen(field);
    while (std::getline(status, line)) {
        if (line.compare(0, field_length, field) == 0 && line.size() > field_length && line[field_length] == ':') {
            return std::strtol(line.c_str() + field_length + 1, nullptr, 10);
        }
    }
    return -1;
}

}  // namespace blackshield::test
