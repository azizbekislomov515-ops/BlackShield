#pragma once

#include <array>
#include <cstdint>

#include "hash/block_hasher.h"

namespace blackshield::hash {

/** SHA-256 as specified in FIPS 180-4. */
class Sha256 final : public BlockHasher {
public:
    static constexpr std::size_t kDigestSize = 32;

    Sha256() noexcept;

    std::size_t DigestSize() const noexcept override { return kDigestSize; }

protected:
    void ProcessBlock(const std::uint8_t* block) noexcept override;
    void ResetState() noexcept override;
    void WriteDigest(std::uint8_t* out) const noexcept override;

private:
    std::array<std::uint32_t, 8> state_{};
};

}  // namespace blackshield::hash
