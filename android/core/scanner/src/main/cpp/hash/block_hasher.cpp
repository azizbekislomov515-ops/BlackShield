#include "hash/block_hasher.h"

#include <algorithm>
#include <cstring>

namespace blackshield::hash {

void BlockHasher::Update(const std::uint8_t* data, std::size_t size) noexcept {
    if (size == 0) {
        return;
    }
    total_bytes_ += size;

    // Top up a partially filled block first.
    if (buffered_ > 0) {
        const std::size_t take = std::min(kBlockSize - buffered_, size);
        std::memcpy(buffer_.data() + buffered_, data, take);
        buffered_ += take;
        data += take;
        size -= take;
        if (buffered_ < kBlockSize) {
            return;
        }
        ProcessBlock(buffer_.data());
        buffered_ = 0;
    }

    // Whole blocks straight from the caller's buffer, no copy.
    while (size >= kBlockSize) {
        ProcessBlock(data);
        data += kBlockSize;
        size -= kBlockSize;
    }

    if (size > 0) {
        std::memcpy(buffer_.data(), data, size);
        buffered_ = size;
    }
}

std::vector<std::uint8_t> BlockHasher::Finish() {
    constexpr std::size_t kLengthOffset = kBlockSize - sizeof(std::uint64_t);
    const std::uint64_t bit_length = total_bytes_ * 8U;

    buffer_[buffered_++] = 0x80;
    if (buffered_ > kLengthOffset) {
        std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_), buffer_.end(), 0);
        ProcessBlock(buffer_.data());
        buffered_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_),
              buffer_.begin() + static_cast<std::ptrdiff_t>(kLengthOffset), 0);

    for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
        const std::size_t shift = length_encoding_ == LengthEncoding::kBigEndian ? 56 - 8 * i : 8 * i;
        buffer_[kLengthOffset + i] = static_cast<std::uint8_t>(bit_length >> shift);
    }
    ProcessBlock(buffer_.data());

    std::vector<std::uint8_t> digest(DigestSize());
    WriteDigest(digest.data());
    Reset();
    return digest;
}

void BlockHasher::Reset() noexcept {
    ResetState();
    buffer_.fill(0);
    buffered_ = 0;
    total_bytes_ = 0;
}

}  // namespace blackshield::hash
