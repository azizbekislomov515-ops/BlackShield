// Known-answer and streaming-consistency tests for the digest implementations.
// Expected values come from RFC 1321, FIPS 180-4 examples and Python's hashlib.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "hash/hasher.h"
#include "test_util.h"

namespace blackshield::hash {
namespace {

struct Vector {
    HashAlgorithm algorithm;
    std::string input;
    const char* expected;
};

std::string Pattern(std::size_t length) {
    std::string s(length, '\0');
    for (std::size_t i = 0; i < length; ++i) {
        s[i] = static_cast<char>(test::PatternByte(i));
    }
    return s;
}

std::vector<Vector> KnownVectors() {
    using A = HashAlgorithm;
    const std::string kFox = "The quick brown fox jumps over the lazy dog";
    const std::string k448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    return {
        // MD5 - RFC 1321 appendix A.5
        {A::kMd5, "", "d41d8cd98f00b204e9800998ecf8427e"},
        {A::kMd5, "a", "0cc175b9c0f1b6a831c399e269772661"},
        {A::kMd5, "abc", "900150983cd24fb0d6963f7d28e17f72"},
        {A::kMd5, "message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {A::kMd5, "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {A::kMd5, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "d174ab98d277d9f5a5611c2c9f419d9f"},
        {A::kMd5, "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"},
        {A::kMd5, kFox, "9e107d9d372bb6826bd81d3542a419d6"},
        // SHA-1 - FIPS 180 examples
        {A::kSha1, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {A::kSha1, "a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"},
        {A::kSha1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {A::kSha1, k448, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {A::kSha1, kFox, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
        // SHA-256 - FIPS 180 examples
        {A::kSha256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {A::kSha256, "a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
        {A::kSha256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {A::kSha256, k448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {A::kSha256, kFox, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
        // Padding boundaries (55/56 bytes: length fits / spills; 64: exact block), via hashlib.
        {A::kMd5, Pattern(55), "6912ee65fff2d9f9ce2508cddf8bcda0"},
        {A::kMd5, Pattern(56), "51fdd1acda72405dfdfa03fcb85896d7"},
        {A::kMd5, Pattern(63), "48a6295221902e8e0938f773a7185e72"},
        {A::kMd5, Pattern(64), "b2d3f56bc197fd985d5965079b5e7148"},
        {A::kMd5, Pattern(65), "8bd7053801c768420faf816fadba971c"},
        {A::kMd5, Pattern(119), "1c772251899a7ff007400b888d6b2042"},
        {A::kMd5, Pattern(120), "b7ba1efc6022e9ed272f00b8831e26e6"},
        {A::kMd5, Pattern(128), "37eff01866ba3f538421b30b7cbefcac"},
        {A::kSha1, Pattern(55), "8ae2d46729cfe68ff927af5eec9c7d1b66d65ac2"},
        {A::kSha1, Pattern(56), "636e2ec698dac903498e648bd2f3af641d3c88cb"},
        {A::kSha1, Pattern(63), "6d942da0c4392b123528f2905c713a3ce28364bd"},
        {A::kSha1, Pattern(64), "c6138d514ffa2135bfce0ed0b8fac65669917ec7"},
        {A::kSha1, Pattern(65), "69bd728ad6e13cd76ff19751fde427b00e395746"},
        {A::kSha1, Pattern(119), "41c89d06001bab4ab78736b44efe7ce18ce6ae08"},
        {A::kSha1, Pattern(120), "d3dbd653bd8597b7475321b60a36891278e6a04a"},
        {A::kSha1, Pattern(128), "e6434bc401f98603d7eda504790c98c67385d535"},
        {A::kSha256, Pattern(55), "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59"},
        {A::kSha256, Pattern(56), "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562"},
        {A::kSha256, Pattern(63), "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"},
        {A::kSha256, Pattern(64), "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"},
        {A::kSha256, Pattern(65), "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781"},
        {A::kSha256, Pattern(119), "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6"},
        {A::kSha256, Pattern(120), "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c"},
        {A::kSha256, Pattern(128), "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"},
    };
}

class KnownVectorTest : public ::testing::TestWithParam<Vector> {};

TEST_P(KnownVectorTest, OneShotMatches) {
    const Vector& v = GetParam();
    EXPECT_EQ(HashBufferHex(v.algorithm, v.input.data(), v.input.size()), v.expected);
}

TEST_P(KnownVectorTest, ByteAtATimeMatches) {
    const Vector& v = GetParam();
    const auto hasher = CreateHasher(v.algorithm);
    for (const char c : v.input) {
        const auto byte = static_cast<std::uint8_t>(c);
        hasher->Update(&byte, 1);
    }
    EXPECT_EQ(ToHex(hasher->Finish()), v.expected);
}

INSTANTIATE_TEST_SUITE_P(Rfc1321AndFips180, KnownVectorTest, ::testing::ValuesIn(KnownVectors()),
                         [](const ::testing::TestParamInfo<Vector>& info) {
                             return std::string(AlgorithmName(info.param.algorithm)).substr(0, 3) + "_" +
                                    std::to_string(info.index);
                         });

TEST(HasherTest, MillionAsInIrregularChunks) {
    struct {
        HashAlgorithm algorithm;
        const char* expected;
    } const cases[] = {
        {HashAlgorithm::kMd5, "7707d6ae4e027c70eea2a935c2296f21"},
        {HashAlgorithm::kSha1, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
        {HashAlgorithm::kSha256, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
    };
    const std::string as(1'000'000, 'a');
    for (const auto& c : cases) {
        const auto hasher = CreateHasher(c.algorithm);
        std::size_t offset = 0;
        std::size_t step = 1;
        while (offset < as.size()) {
            const std::size_t n = std::min(step, as.size() - offset);
            hasher->Update(reinterpret_cast<const std::uint8_t*>(as.data()) + offset, n);
            offset += n;
            step = step * 7 % 1021 + 1;  // 1..1021 bytes, crossing block boundaries unevenly
        }
        EXPECT_EQ(ToHex(hasher->Finish()), c.expected) << AlgorithmName(c.algorithm);
    }
}

TEST(HasherTest, FinishResetsForReuse) {
    for (const auto algorithm : {HashAlgorithm::kMd5, HashAlgorithm::kSha1, HashAlgorithm::kSha256}) {
        const auto hasher = CreateHasher(algorithm);
        const std::string abc = "abc";
        hasher->Update(reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size());
        const auto first = hasher->Finish();
        hasher->Update(reinterpret_cast<const std::uint8_t*>(abc.data()), abc.size());
        EXPECT_EQ(hasher->Finish(), first) << AlgorithmName(algorithm);
    }
}

TEST(HasherTest, DigestSizes) {
    EXPECT_EQ(CreateHasher(HashAlgorithm::kMd5)->DigestSize(), 16U);
    EXPECT_EQ(CreateHasher(HashAlgorithm::kSha1)->DigestSize(), 20U);
    EXPECT_EQ(CreateHasher(HashAlgorithm::kSha256)->DigestSize(), 32U);
}

TEST(HasherTest, AlgorithmFromIntRejectsUnknownValues) {
    EXPECT_EQ(AlgorithmFromInt(0), HashAlgorithm::kMd5);
    EXPECT_EQ(AlgorithmFromInt(1), HashAlgorithm::kSha1);
    EXPECT_EQ(AlgorithmFromInt(2), HashAlgorithm::kSha256);
    EXPECT_FALSE(AlgorithmFromInt(-1).has_value());
    EXPECT_FALSE(AlgorithmFromInt(3).has_value());
}

}  // namespace
}  // namespace blackshield::hash
