#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackshield::hash {

/** Supported digests. The numeric values are part of the JNI contract (see HashAlgorithm.kt). */
enum class HashAlgorithm : int {
    kMd5 = 0,
    kSha1 = 1,
    kSha256 = 2,
};

/** Maps the JNI integer to an algorithm; std::nullopt for unknown values. */
std::optional<HashAlgorithm> AlgorithmFromInt(int value) noexcept;

std::string_view AlgorithmName(HashAlgorithm algorithm) noexcept;

/** Incremental (streaming) message digest. Not thread-safe; one instance per stream. */
class Hasher {
public:
    virtual ~Hasher() = default;

    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;

    /** Feeds `size` bytes. May be called any number of times, with any chunk sizes. */
    virtual void Update(const std::uint8_t* data, std::size_t size) noexcept = 0;

    /** Completes the digest and resets the hasher so it can be reused. */
    virtual std::vector<std::uint8_t> Finish() = 0;

    /** Discards all input fed so far. */
    virtual void Reset() noexcept = 0;

    virtual std::size_t DigestSize() const noexcept = 0;

protected:
    Hasher() = default;
};

std::unique_ptr<Hasher> CreateHasher(HashAlgorithm algorithm);

/** Lower-case hexadecimal encoding. */
std::string ToHex(const std::vector<std::uint8_t>& bytes);

/** One-shot digest of an in-memory buffer, as lower-case hex. */
std::string HashBufferHex(HashAlgorithm algorithm, const void* data, std::size_t size);

}  // namespace blackshield::hash
