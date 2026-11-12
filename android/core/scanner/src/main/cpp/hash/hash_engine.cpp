#include "hash/hash_engine.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <exception>
#include <memory>
#include <new>

namespace blackshield::hash {
namespace {

HashOutcome Failure(HashStatus status, int error_number, std::uint64_t bytes = 0) {
    HashOutcome outcome;
    outcome.status = status;
    outcome.error_number = error_number;
    outcome.bytes_hashed = bytes;
    return outcome;
}

HashOutcome FailureFromErrno(int error_number, std::uint64_t bytes = 0) {
    switch (error_number) {
        case ENOENT:
        case ENOTDIR:
            return Failure(HashStatus::kNotFound, error_number, bytes);
        case EACCES:
        case EPERM:
            return Failure(HashStatus::kPermissionDenied, error_number, bytes);
        case EBADF:
        case EINVAL:
        case ENAMETOOLONG:
            return Failure(HashStatus::kInvalidArgument, error_number, bytes);
        default:
            return Failure(HashStatus::kIoError, error_number, bytes);
    }
}

bool IsCancelled(const CancellationFlag* cancel) noexcept { return cancel != nullptr && cancel->IsCancelled(); }

/** Closes the descriptor on scope exit (only for descriptors this file opened). */
class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const noexcept { return fd_; }

private:
    int fd_;
};

enum class ReadMode { kPositional, kStreaming };

/**
 * Core loop: one heap-allocated chunk buffer, one digest state. Cancellation is checked
 * before every chunk; streaming descriptors are polled with a timeout so a stalled writer
 * cannot block cancellation.
 */
HashOutcome HashDescriptor(int fd, ReadMode mode, HashAlgorithm algorithm, const CancellationFlag* cancel) {
    const std::unique_ptr<Hasher> hasher = CreateHasher(algorithm);
    const std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[HashEngine::kChunkSize]);
    std::uint64_t offset = 0;

    if (mode == ReadMode::kPositional) {
        // Advisory only; failure is harmless.
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }

    for (;;) {
        if (IsCancelled(cancel)) {
            return Failure(HashStatus::kCancelled, 0, offset);
        }

        if (mode == ReadMode::kStreaming) {
            pollfd request{fd, POLLIN, 0};
            const int ready = poll(&request, 1, HashEngine::kPollIntervalMillis);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return FailureFromErrno(errno, offset);
            }
            if (ready == 0) {
                continue;  // Timed out: re-check cancellation.
            }
            if ((request.revents & POLLNVAL) != 0) {
                return Failure(HashStatus::kInvalidArgument, EBADF, offset);
            }
            // POLLIN, POLLHUP or POLLERR: read() below returns data, EOF or the error.
        }

        const ssize_t count = mode == ReadMode::kPositional
                                  ? pread(fd, buffer.get(), HashEngine::kChunkSize, static_cast<off_t>(offset))
                                  : read(fd, buffer.get(), HashEngine::kChunkSize);
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            return FailureFromErrno(errno, offset);
        }
        if (count == 0) {
            break;  // EOF
        }
        hasher->Update(buffer.get(), static_cast<std::size_t>(count));
        offset += static_cast<std::uint64_t>(count);
    }

    HashOutcome outcome;
    outcome.status = HashStatus::kOk;
    outcome.bytes_hashed = offset;
    outcome.hex_digest = ToHex(hasher->Finish());
    return outcome;
}

HashOutcome HashOpenDescriptor(int fd, HashAlgorithm algorithm, const CancellationFlag* cancel) {
    struct stat info {};
    if (fstat(fd, &info) != 0) {
        return FailureFromErrno(errno);
    }
    if (S_ISDIR(info.st_mode)) {
        return Failure(HashStatus::kIoError, EISDIR);
    }
    const bool seekable = S_ISREG(info.st_mode) && lseek(fd, 0, SEEK_CUR) >= 0;
    return HashDescriptor(fd, seekable ? ReadMode::kPositional : ReadMode::kStreaming, algorithm, cancel);
}

template <typename Fn>
HashOutcome NoThrow(Fn&& fn) noexcept {
    try {
        return fn();
    } catch (const std::bad_alloc&) {
        return Failure(HashStatus::kInternalError, ENOMEM);
    } catch (...) {
        return Failure(HashStatus::kInternalError, 0);
    }
}

}  // namespace

HashOutcome HashEngine::HashFile(const std::string& path, HashAlgorithm algorithm,
                                 const CancellationFlag* cancel) const noexcept {
    return NoThrow([&]() -> HashOutcome {
        if (path.empty() || path.find('\0') != std::string::npos) {
            return Failure(HashStatus::kInvalidArgument, EINVAL);
        }
        if (IsCancelled(cancel)) {
            return Failure(HashStatus::kCancelled, 0);
        }
        int raw_fd;
        do {
            // O_NONBLOCK so opening a FIFO cannot hang; cleared again below for regular files.
            raw_fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        } while (raw_fd < 0 && errno == EINTR);
        if (raw_fd < 0) {
            return FailureFromErrno(errno);
        }
        const ScopedFd fd(raw_fd);
        const int flags = fcntl(fd.get(), F_GETFL);
        if (flags >= 0) {
            fcntl(fd.get(), F_SETFL, flags & ~O_NONBLOCK);
        }
        return HashOpenDescriptor(fd.get(), algorithm, cancel);
    });
}

HashOutcome HashEngine::HashFd(int fd, HashAlgorithm algorithm, const CancellationFlag* cancel) const noexcept {
    return NoThrow([&]() -> HashOutcome {
        if (fd < 0) {
            return Failure(HashStatus::kInvalidArgument, EBADF);
        }
        if (IsCancelled(cancel)) {
            return Failure(HashStatus::kCancelled, 0);
        }
        return HashOpenDescriptor(fd, algorithm, cancel);
    });
}

}  // namespace blackshield::hash
