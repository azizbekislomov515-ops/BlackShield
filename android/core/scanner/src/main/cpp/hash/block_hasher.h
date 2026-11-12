#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "hash/hasher.h"

namespace blackshield::hash {

/**
 * Shared buffering and Merkle-Damgard padding for MD5, SHA-1 and SHA-256, which all use
 * 64-byte blocks and append the message length in bits as a 64-bit integer.
 */
class BlockHasher : public Hasher {
public:
    static constexpr std::size_t kBlockSize = 64;

    void Update(const std::uint8_t* data, std::size_t size) noexcept final;
    std::vector<std::uint8_t> Finish() final;
    void Reset() noexcept final;

protected:
    enum class LengthEncoding { kLittleEndian, kBigEndian };

    explicit BlockHasher(LengthEncoding length_encoding) noexcept : length_encoding_(length_encoding) {}

    /** Compresses one 64-byte block into the chaining state. */
    virtual void ProcessBlock(const std::uint8_t* block) noexcept = 0;
    /** Restores the algorithm's initial chaining state. */
    virtual void ResetState() noexcept = 0;
    /** Serialises the chaining state into `DigestSize()` bytes. */
    virtual void WriteDigest(std::uint8_t* out) const noexcept = 0;

private:
    const LengthEncoding length_encoding_;
    std::array<std::uint8_t, kBlockSize> buffer_{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bytes_ = 0;
};

// Endian helpers shared by the algorithm implementations.
inline std::uint32_t LoadBigEndian32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline std::uint32_t LoadLittleEndian32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline void StoreBigEndian32(std::uint32_t v, std::uint8_t* p) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

inline void StoreLittleEndian32(std::uint32_t v, std::uint8_t* p) noexcept {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

inline constexpr std::uint32_t RotateLeft(std::uint32_t v, int bits) noexcept {
    return (v << bits) | (v >> (32 - bits));
}

inline constexpr std::uint32_t RotateRight(std::uint32_t v, int bits) noexcept {
    return (v >> bits) | (v << (32 - bits));
}

}  // namespace blackshield::hash
