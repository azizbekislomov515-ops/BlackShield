#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "hash/cancellation.h"
#include "hash/hasher.h"

namespace blackshield::hash {

/** Outcome category. The numeric values are part of the JNI contract (see NativeHasher.kt). */
enum class HashStatus : int {
    kOk = 0,
    kNotFound = 1,
    kPermissionDenied = 2,
    kCancelled = 3,
    kIoError = 4,
    kInvalidArgument = 5,
    kInternalError = 6,
};

struct HashOutcome {
    HashStatus status = HashStatus::kInternalError;
    /** errno of the failing system call, 0 if none. */
    int error_number = 0;
    /** Bytes fed to the digest (also set for failures and cancellation). */
    std::uint64_t bytes_hashed = 0;
    /** Lower-case hex digest; empty unless status == kOk. */
    std::string hex_digest;

    bool ok() const noexcept { return status == HashStatus::kOk; }
};

/**
 * Streams files through a digest in fixed-size chunks, so memory use is independent of the
 * file size. Stateless and safe to share between threads.
 */
class HashEngine {
public:
    static constexpr std::size_t kChunkSize = 64 * 1024;
    /** Longest a blocked read on a pipe/socket can delay noticing cancellation. */
    static constexpr int kPollIntervalMillis = 50;

    /** Hashes the file at `path`. `cancel` may be null. Never throws. */
    HashOutcome HashFile(const std::string& path, HashAlgorithm algorithm,
                         const CancellationFlag* cancel = nullptr) const noexcept;

    /**
     * Hashes the content behind an open file descriptor, which stays owned by the caller.
     * Seekable regular files are hashed from offset 0 with pread(), leaving the descriptor's
     * offset untouched; pipes and sockets are read from their current position until EOF.
     */
    HashOutcome HashFd(int fd, HashAlgorithm algorithm, const CancellationFlag* cancel = nullptr) const noexcept;
};

}  // namespace blackshield::hash
