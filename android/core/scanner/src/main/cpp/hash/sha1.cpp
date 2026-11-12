#include "hash/sha1.h"

namespace blackshield::hash {
namespace {

constexpr std::array<std::uint32_t, 5> kInitialState = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
};

}  // namespace

Sha1::Sha1() noexcept : BlockHasher(LengthEncoding::kBigEndian) { ResetState(); }

void Sha1::ResetState() noexcept { state_ = kInitialState; }

void Sha1::ProcessBlock(const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 80> w;
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = LoadBigEndian32(block + 4 * i);
    }
    for (std::size_t i = 16; i < 80; ++i) {
        w[i] = RotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];

    for (std::size_t i = 0; i < 80; ++i) {
        std::uint32_t f;
        std::uint32_t k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        const std::uint32_t temp = RotateLeft(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = RotateLeft(b, 30);
        b = a;
        a = temp;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
}

void Sha1::WriteDigest(std::uint8_t* out) const noexcept {
    for (std::size_t i = 0; i < state_.size(); ++i) {
        StoreBigEndian32(state_[i], out + 4 * i);
    }
}

}  // namespace blackshield::hash
