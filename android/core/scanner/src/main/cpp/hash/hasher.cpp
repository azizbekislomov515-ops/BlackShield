#include "hash/hasher.h"

#include "hash/md5.h"
#include "hash/sha1.h"
#include "hash/sha256.h"

namespace blackshield::hash {

std::optional<HashAlgorithm> AlgorithmFromInt(int value) noexcept {
    switch (value) {
        case static_cast<int>(HashAlgorithm::kMd5):
            return HashAlgorithm::kMd5;
        case static_cast<int>(HashAlgorithm::kSha1):
            return HashAlgorithm::kSha1;
        case static_cast<int>(HashAlgorithm::kSha256):
            return HashAlgorithm::kSha256;
        default:
            return std::nullopt;
    }
}

std::string_view AlgorithmName(HashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case HashAlgorithm::kMd5:
            return "MD5";
        case HashAlgorithm::kSha1:
            return "SHA-1";
        case HashAlgorithm::kSha256:
            return "SHA-256";
    }
    return "unknown";
}

std::unique_ptr<Hasher> CreateHasher(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::kMd5:
            return std::make_unique<Md5>();
        case HashAlgorithm::kSha1:
            return std::make_unique<Sha1>();
        case HashAlgorithm::kSha256:
            return std::make_unique<Sha256>();
    }
    return nullptr;
}

std::string ToHex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (const std::uint8_t byte : bytes) {
        hex.push_back(kDigits[byte >> 4]);
        hex.push_back(kDigits[byte & 0x0f]);
    }
    return hex;
}

std::string HashBufferHex(HashAlgorithm algorithm, const void* data, std::size_t size) {
    const auto hasher = CreateHasher(algorithm);
    hasher->Update(static_cast<const std::uint8_t*>(data), size);
    return ToHex(hasher->Finish());
}

}  // namespace blackshield::hash
