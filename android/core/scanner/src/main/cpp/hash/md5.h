#pragma once

#include <array>
#include <cstdint>

#include "hash/block_hasher.h"

namespace blackshield::hash {

/**
 * MD5 as specified in RFC 1321. Cryptographically broken; provided only to match signature
 * feeds that still publish MD5 hashes.
 */
class Md5 final : public BlockHasher {
public:
    static constexpr std::size_t kDigestSize = 16;

    Md5() noexcept;

    std::size_t DigestSize() const noexcept override { return kDigestSize; }

protected:
    void ProcessBlock(const std::uint8_t* block) noexcept override;
    void ResetState() noexcept override;
    void WriteDigest(std::uint8_t* out) const noexcept override;

private:
    std::array<std::uint32_t, 4> state_{};
};

}  // namespace blackshield::hash
