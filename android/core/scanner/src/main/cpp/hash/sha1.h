#pragma once

#include <array>
#include <cstdint>

#include "hash/block_hasher.h"

namespace blackshield::hash {

/**
 * SHA-1 as specified in FIPS 180-4. Cryptographically broken; provided only to match
 * signature feeds that still publish SHA-1 hashes.
 */
class Sha1 final : public BlockHasher {
public:
    static constexpr std::size_t kDigestSize = 20;

    Sha1() noexcept;

    std::size_t DigestSize() const noexcept override { return kDigestSize; }

protected:
    void ProcessBlock(const std::uint8_t* block) noexcept override;
    void ResetState() noexcept override;
    void WriteDigest(std::uint8_t* out) const noexcept override;

private:
    std::array<std::uint32_t, 5> state_{};
};

}  // namespace blackshield::hash
