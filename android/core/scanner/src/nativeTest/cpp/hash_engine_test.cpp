// File/descriptor tests for HashEngine: edge cases, large files, memory, cancellation, errors.

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include "hash/hash_engine.h"
#include "test_util.h"

namespace blackshield::hash {
namespace {

using std::chrono::milliseconds;
using std::chrono::steady_clock;

constexpr std::uint64_t kMiB = 1024 * 1024;
constexpr std::uint64_t kLargeSize = 100 * kMiB + 13;  // > 100 MB, deliberately not chunk-aligned
constexpr std::uint64_t kHugeSize = 512 * kMiB;        // for memory and cancellation checks
constexpr auto kCancelDeadline = milliseconds(200);

const HashAlgorithm kAllAlgorithms[] = {HashAlgorithm::kMd5, HashAlgorithm::kSha1, HashAlgorithm::kSha256};

double MillisSince(steady_clock::time_point start) {
    return std::chrono::duration<double, std::milli>(steady_clock::now() - start).count();
}

class HashEngineTest : public ::testing::Test {
protected:
    void TearDown() override {
        for (const auto& path : created_) {
            chmod(path.c_str(), 0600);
            std::remove(path.c_str());
        }
    }

    std::string NewFile(const std::string& name, const std::string& content) {
        std::string path = test::TempPath(name);
        test::WriteFile(path, content);
        created_.push_back(path);
        return path;
    }

    HashEngine engine_;
    std::vector<std::string> created_;
};

// --- Small files -------------------------------------------------------------------------

TEST_F(HashEngineTest, EmptyFile) {
    const std::string path = NewFile("empty", "");
    const char* expected[] = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };
    for (std::size_t i = 0; i < 3; ++i) {
        const HashOutcome outcome = engine_.HashFile(path, kAllAlgorithms[i]);
        ASSERT_TRUE(outcome.ok()) << AlgorithmName(kAllAlgorithms[i]);
        EXPECT_EQ(outcome.hex_digest, expected[i]);
        EXPECT_EQ(outcome.bytes_hashed, 0U);
    }
}

TEST_F(HashEngineTest, OneByteFile) {
    const std::string path = NewFile("one_byte", "a");
    const char* expected[] = {
        "0cc175b9c0f1b6a831c399e269772661",
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    };
    for (std::size_t i = 0; i < 3; ++i) {
        const HashOutcome outcome = engine_.HashFile(path, kAllAlgorithms[i]);
        ASSERT_TRUE(outcome.ok());
        EXPECT_EQ(outcome.hex_digest, expected[i]) << AlgorithmName(kAllAlgorithms[i]);
        EXPECT_EQ(outcome.bytes_hashed, 1U);
    }
}

TEST_F(HashEngineTest, FileMatchesInMemoryDigestAcrossChunkBoundary) {
    // 3 chunks + a tail, compared against the in-memory digest of the same bytes.
    std::string content(3 * HashEngine::kChunkSize + 7, '\0');
    for (std::size_t i = 0; i < content.size(); ++i) {
        content[i] = static_cast<char>(test::PatternByte(i));
    }
    const std::string path = NewFile("multi_chunk", content);
    for (const auto algorithm : kAllAlgorithms) {
        EXPECT_EQ(engine_.HashFile(path, algorithm).hex_digest,
                  HashBufferHex(algorithm, content.data(), content.size()))
            << AlgorithmName(algorithm);
    }
}

TEST_F(HashEngineTest, Utf8PathWithSupplementaryCharacters) {
    const std::string path = NewFile("\xF0\x9F\x9B\xA1\xEF\xB8\x8F_shield.bin", "abc");  // 🛡️
    EXPECT_EQ(engine_.HashFile(path, HashAlgorithm::kSha256).hex_digest,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// --- Descriptors -------------------------------------------------------------------------

TEST_F(HashEngineTest, SeekableFdIsHashedFromStartWithoutMovingOffset) {
    const std::string path = NewFile("fd", "abc");
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(lseek(fd, 2, SEEK_SET), 2);

    const HashOutcome outcome = engine_.HashFd(fd, HashAlgorithm::kMd5);

    EXPECT_EQ(outcome.hex_digest, "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(lseek(fd, 0, SEEK_CUR), 2) << "caller's offset must be preserved";
    EXPECT_EQ(fcntl(fd, F_GETFD), FD_CLOEXEC) << "descriptor must stay open";
    close(fd);
}

TEST_F(HashEngineTest, PipeIsHashedUntilEof) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    std::thread writer([w = fds[1]] {
        const std::string data = "abc";
        EXPECT_EQ(write(w, data.data(), data.size()), 3);
        close(w);
    });

    const HashOutcome outcome = engine_.HashFd(fds[0], HashAlgorithm::kSha1);
    writer.join();
    close(fds[0]);

    EXPECT_EQ(outcome.hex_digest, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

// --- Errors ------------------------------------------------------------------------------

TEST_F(HashEngineTest, MissingFileIsNotFound) {
    const HashOutcome outcome = engine_.HashFile(test::TempPath("does_not_exist"), HashAlgorithm::kSha256);
    EXPECT_EQ(outcome.status, HashStatus::kNotFound);
    EXPECT_EQ(outcome.error_number, ENOENT);
    EXPECT_TRUE(outcome.hex_digest.empty());
}

TEST_F(HashEngineTest, PathThroughRegularFileIsNotFound) {
    const std::string file = NewFile("not_a_dir", "x");
    EXPECT_EQ(engine_.HashFile(file + "/child", HashAlgorithm::kSha256).status, HashStatus::kNotFound);
}

TEST_F(HashEngineTest, UnreadableFileIsPermissionDenied) {
    if (geteuid() == 0) {
        GTEST_SKIP() << "root ignores file permissions (run without `adb root`)";
    }
    const std::string path = NewFile("unreadable", "secret");
    ASSERT_EQ(chmod(path.c_str(), 0000), 0);

    const HashOutcome outcome = engine_.HashFile(path, HashAlgorithm::kSha256);

    EXPECT_EQ(outcome.status, HashStatus::kPermissionDenied);
    EXPECT_EQ(outcome.error_number, EACCES);
}

TEST_F(HashEngineTest, DirectoryIsIoError) {
    const std::string dir = test::TempPath("dir");
    ASSERT_EQ(mkdir(dir.c_str(), 0700), 0);

    const HashOutcome outcome = engine_.HashFile(dir, HashAlgorithm::kSha256);
    rmdir(dir.c_str());

    EXPECT_EQ(outcome.status, HashStatus::kIoError);
    EXPECT_EQ(outcome.error_number, EISDIR);
}

TEST_F(HashEngineTest, InvalidArgumentsAreRejected) {
    EXPECT_EQ(engine_.HashFile("", HashAlgorithm::kSha256).status, HashStatus::kInvalidArgument);
    EXPECT_EQ(engine_.HashFile(std::string("/data\0/x", 8), HashAlgorithm::kSha256).status,
              HashStatus::kInvalidArgument);
    EXPECT_EQ(engine_.HashFd(-1, HashAlgorithm::kSha256).status, HashStatus::kInvalidArgument);

    const int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    close(fd);
    const HashOutcome closed = engine_.HashFd(fd, HashAlgorithm::kSha256);  // stale descriptor
    EXPECT_EQ(closed.status, HashStatus::kInvalidArgument);
    EXPECT_EQ(closed.error_number, EBADF);
}

TEST_F(HashEngineTest, AlreadyCancelledReturnsImmediately) {
    const std::string path = NewFile("pre_cancelled", "abc");
    CancellationFlag flag;
    flag.Cancel();

    const HashOutcome outcome = engine_.HashFile(path, HashAlgorithm::kSha256, &flag);

    EXPECT_EQ(outcome.status, HashStatus::kCancelled);
    EXPECT_EQ(outcome.bytes_hashed, 0U);
}

TEST_F(HashEngineTest, CancelStopsBlockedPipeWithinDeadline) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);  // Writer stays open and never writes: read() would block forever.
    CancellationFlag flag;

    auto pending = std::async(std::launch::async, [&] { return engine_.HashFd(fds[0], HashAlgorithm::kSha256, &flag); });
    // Not a multiple of kPollIntervalMillis, so the cancel lands mid-poll (the realistic case).
    std::this_thread::sleep_for(milliseconds(130));
    const auto cancelled_at = steady_clock::now();
    flag.Cancel();
    const HashOutcome outcome = pending.get();
    const double latency_ms = MillisSince(cancelled_at);
    close(fds[0]);
    close(fds[1]);

    EXPECT_EQ(outcome.status, HashStatus::kCancelled);
    EXPECT_LT(latency_ms, kCancelDeadline.count());
    std::printf("[ CANCEL   ] stalled pipe: stopped %.2f ms after cancel\n", latency_ms);
    RecordProperty("pipe_cancel_latency_ms", std::to_string(latency_ms));
}

// --- Large files (shared fixtures, generated once) ---------------------------------------

class LargeFileTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        large_path_ = new std::string(test::TempPath("large.bin"));
        huge_path_ = new std::string(test::TempPath("huge.bin"));
        test::WritePatternFile(*large_path_, kLargeSize);
        test::WritePatternFile(*huge_path_, kHugeSize);
    }

    static void TearDownTestSuite() {
        std::remove(large_path_->c_str());
        std::remove(huge_path_->c_str());
        delete large_path_;
        delete huge_path_;
    }

    static std::string* large_path_;
    static std::string* huge_path_;
    HashEngine engine_;
};

std::string* LargeFileTest::large_path_ = nullptr;
std::string* LargeFileTest::huge_path_ = nullptr;

TEST_F(LargeFileTest, Over100MiBMatchesReferenceDigests) {
    // Reference digests computed with Python hashlib over the same generated content.
    const char* expected[] = {
        "477188cd97c8fee68f5eaa82bab5063e",
        "120b209b4b9f711711f6878f1fc38348dcdf6dc4",
        "4036a5fcda813e5adf90a2b38f8999110eb4ada8374db91a36cff56b32a3febd",
    };
    for (std::size_t i = 0; i < 3; ++i) {
        const HashOutcome outcome = engine_.HashFile(*large_path_, kAllAlgorithms[i]);
        ASSERT_TRUE(outcome.ok()) << AlgorithmName(kAllAlgorithms[i]);
        EXPECT_EQ(outcome.hex_digest, expected[i]) << AlgorithmName(kAllAlgorithms[i]);
        EXPECT_EQ(outcome.bytes_hashed, kLargeSize);
    }
}

TEST_F(LargeFileTest, ConcurrentHashesAreIndependent) {
    std::vector<std::future<HashOutcome>> results;
    for (int i = 0; i < 4; ++i) {
        results.push_back(std::async(std::launch::async, [this] {
            return engine_.HashFile(*large_path_, HashAlgorithm::kSha256);
        }));
    }
    for (auto& result : results) {
        EXPECT_EQ(result.get().hex_digest, "4036a5fcda813e5adf90a2b38f8999110eb4ada8374db91a36cff56b32a3febd");
    }
}

TEST_F(LargeFileTest, MemoryStaysFlatWhileHashing512MiB) {
    std::atomic<bool> done{false};
    std::atomic<long> peak_kib{0};
    std::atomic<int> samples{0};
    std::thread sampler([&] {
        while (!done.load()) {
            const long rss = test::ReadStatusKib("VmRSS");
            ++samples;
            long previous = peak_kib.load();
            while (rss > previous && !peak_kib.compare_exchange_weak(previous, rss)) {
            }
            std::this_thread::sleep_for(milliseconds(5));
        }
    });
    // Baseline once the sampler itself is running, so its stack and buffers are not counted.
    std::this_thread::sleep_for(milliseconds(50));
    const long baseline_kib = test::ReadStatusKib("VmRSS");
    ASSERT_GT(baseline_kib, 0);
    peak_kib = baseline_kib;
    const int samples_before = samples.load();

    const HashOutcome outcome = engine_.HashFile(*huge_path_, HashAlgorithm::kSha256);
    done = true;
    sampler.join();
    const int samples_during = samples.load() - samples_before;

    ASSERT_TRUE(outcome.ok());
    EXPECT_EQ(outcome.bytes_hashed, kHugeSize);
    ASSERT_GE(samples_during, 20) << "sampler did not observe the hash";
    const long growth_kib = peak_kib.load() - baseline_kib;
    std::printf("[ MEMORY   ] 512 MiB SHA-256: baseline RSS %ld KiB, peak %ld KiB, growth %ld KiB (%d samples)\n",
                baseline_kib, peak_kib.load(), growth_kib, samples_during);
    // 64 KiB chunk buffer + a sampler thread stack; anything near file size would be ~512 MiB.
    EXPECT_LT(growth_kib, 1024);
    RecordProperty("rss_growth_kib", std::to_string(growth_kib));
}

TEST_F(LargeFileTest, CancelStopsHashingWithinDeadline) {
    for (const auto algorithm : kAllAlgorithms) {
        CancellationFlag flag;
        auto pending = std::async(std::launch::async, [&] { return engine_.HashFile(*huge_path_, algorithm, &flag); });
        std::this_thread::sleep_for(milliseconds(100));
        const auto cancelled_at = steady_clock::now();
        flag.Cancel();
        const HashOutcome outcome = pending.get();
        const double latency_ms = MillisSince(cancelled_at);

        EXPECT_EQ(outcome.status, HashStatus::kCancelled) << AlgorithmName(algorithm);
        EXPECT_GT(outcome.bytes_hashed, 0U);
        EXPECT_LT(outcome.bytes_hashed, kHugeSize);
        EXPECT_LT(latency_ms, kCancelDeadline.count()) << AlgorithmName(algorithm);
        std::printf("[ CANCEL   ] %s: stopped %.2f ms after cancel, after %llu bytes\n",
                    std::string(AlgorithmName(algorithm)).c_str(), latency_ms,
                    static_cast<unsigned long long>(outcome.bytes_hashed));
    }
}

TEST_F(LargeFileTest, Throughput) {
    for (const auto algorithm : kAllAlgorithms) {
        engine_.HashFile(*huge_path_, algorithm);  // warm page cache and CPU
        const auto start = steady_clock::now();
        const HashOutcome outcome = engine_.HashFile(*huge_path_, algorithm);
        const double seconds = MillisSince(start) / 1000.0;
        ASSERT_TRUE(outcome.ok());
        std::printf("[ THROUGHPUT ] %-7s %7.1f MiB/s (512 MiB in %.2f s)\n",
                    std::string(AlgorithmName(algorithm)).c_str(),
                    static_cast<double>(kHugeSize) / kMiB / seconds, seconds);
    }
}

}  // namespace
}  // namespace blackshield::hash
