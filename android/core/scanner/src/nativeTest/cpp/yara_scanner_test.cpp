// YaraScanner: matching (positive/negative, metadata), compile errors, timeouts, files, caching
// and concurrent scans. Every sample is a harmless test string; nothing here is real malware.

#include <gtest/gtest.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <future>
#include <string>
#include <vector>

#include "test_util.h"
#include "yara/yara_scanner.h"

namespace blackshield::yara {
namespace {

using std::chrono::steady_clock;

constexpr char kMarker[] = "BLACKSHIELD-YARA-TEST-MARKER-7f3a";

constexpr char kMarkerRule[] = R"(
rule test_marker : test harmless {
    meta:
        severity = "critical"
        score = 90
        is_test = true
        description = "Harmless BlackShield YARA test marker"
    strings:
        $marker = "BLACKSHIELD-YARA-TEST-MARKER-7f3a"
    condition:
        $marker
}

rule hex_and_size {
    strings:
        $hex = { 42 53 [2-8] 4D 4B }   // "BS" .. "MK"
    condition:
        $hex and filesize < 1MB
}
)";

std::shared_ptr<const YaraScanner> CompileOrFail(const std::string& source) {
    auto outcome = YaraScanner::Compile(source);
    EXPECT_EQ(outcome.status, YaraStatus::kOk);
    for (const auto& error : outcome.errors) {
        ADD_FAILURE() << error;
    }
    return outcome.scanner;
}

ScanOutcome ScanString(const YaraScanner& scanner, const std::string& data, int timeout_ms = 0) {
    return scanner.ScanMemory(reinterpret_cast<const std::uint8_t*>(data.data()), data.size(), timeout_ms);
}

std::vector<std::string> RuleNames(const ScanOutcome& outcome) {
    std::vector<std::string> names;
    for (const auto& match : outcome.matches) {
        names.push_back(match.rule);
    }
    return names;
}

const YaraMeta* FindMeta(const YaraMatch& match, const std::string& key) {
    for (const auto& meta : match.metas) {
        if (meta.key == key) {
            return &meta;
        }
    }
    return nullptr;
}

// --- Matching -----------------------------------------------------------------------------------

TEST(YaraScannerTest, MatchesMarkerAndReportsMetadata) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    EXPECT_EQ(scanner->RuleCount(), 2u);

    const auto outcome = ScanString(*scanner, std::string("prefix ") + kMarker + " suffix");
    ASSERT_TRUE(outcome.ok());
    ASSERT_EQ(outcome.matches.size(), 1u);
    const YaraMatch& match = outcome.matches[0];
    EXPECT_EQ(match.rule, "test_marker");
    EXPECT_EQ(match.rule_namespace, "default");
    EXPECT_EQ(match.tags, (std::vector<std::string>{"test", "harmless"}));

    const YaraMeta* severity = FindMeta(match, "severity");
    ASSERT_NE(severity, nullptr);
    EXPECT_EQ(severity->type, YaraMeta::Type::kString);
    EXPECT_EQ(severity->value, "critical");
    const YaraMeta* score = FindMeta(match, "score");
    ASSERT_NE(score, nullptr);
    EXPECT_EQ(score->type, YaraMeta::Type::kInteger);
    EXPECT_EQ(score->value, "90");
    const YaraMeta* is_test = FindMeta(match, "is_test");
    ASSERT_NE(is_test, nullptr);
    EXPECT_EQ(is_test->type, YaraMeta::Type::kBoolean);
    EXPECT_EQ(is_test->value, "true");
}

TEST(YaraScannerTest, CleanDataHasNoMatches) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    for (const std::string& data : {std::string(), std::string("hello world"),
                                    std::string("BLACKSHIELD-YARA-TEST-MARKER-7f3"),  // one byte short
                                    std::string(4096, '\0')}) {
        const auto outcome = ScanString(*scanner, data);
        EXPECT_TRUE(outcome.ok());
        EXPECT_TRUE(outcome.matches.empty()) << "data: " << data;
    }
}

TEST(YaraScannerTest, HexStringsWithJumpsAndConditions) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    EXPECT_EQ(RuleNames(ScanString(*scanner, "xxBS1234MKxx")), (std::vector<std::string>{"hex_and_size"}));
    EXPECT_TRUE(ScanString(*scanner, "xxBS123456789MKxx").matches.empty());  // jump too long

    // The filesize condition: the same bytes in a 2 MB buffer do not match.
    std::string large(2 * 1024 * 1024, 'a');
    large.replace(100, 10, "BS1234MK..");
    EXPECT_TRUE(ScanString(*scanner, large).matches.empty());
}

TEST(YaraScannerTest, MatchAtEveryPositionOfALargeBuffer) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    std::string data(8 * 1024 * 1024, 'x');
    const std::size_t marker_size = sizeof(kMarker) - 1;
    for (const std::size_t at : {std::size_t{0}, std::size_t{4093}, data.size() - marker_size}) {
        std::string copy = data;
        copy.replace(at, marker_size, kMarker);
        EXPECT_EQ(RuleNames(ScanString(*scanner, copy)), (std::vector<std::string>{"test_marker"})) << "at " << at;
    }
}

TEST(YaraScannerTest, ModulesShippedWithTheEngineWork) {
    const auto scanner = CompileOrFail(R"(
import "dex"
import "math"
rule not_a_dex { condition: not defined dex.header.magic }
rule low_entropy { condition: math.entropy(0, filesize) < 1.0 }
)");
    ASSERT_NE(scanner, nullptr);
    EXPECT_EQ(RuleNames(ScanString(*scanner, std::string(1024, 'z'))),
              (std::vector<std::string>{"not_a_dex", "low_entropy"}));
}

TEST(YaraScannerTest, ReportedMatchesAreCapped) {
    std::string source;
    for (std::size_t i = 0; i < YaraScanner::kMaxMatches + 20; ++i) {
        source += "rule always_" + std::to_string(i) + " { condition: true }\n";
    }
    const auto scanner = CompileOrFail(source);
    ASSERT_NE(scanner, nullptr);
    const auto outcome = ScanString(*scanner, "x");
    EXPECT_TRUE(outcome.ok());
    EXPECT_EQ(outcome.matches.size(), YaraScanner::kMaxMatches);
}

// --- Malformed rules ----------------------------------------------------------------------------

TEST(YaraScannerTest, SyntaxErrorIsReportedWithItsLine) {
    const auto outcome = YaraScanner::Compile("rule ok { condition: true }\nrule broken { condition: and }\n");
    EXPECT_EQ(outcome.status, YaraStatus::kCompileError);
    EXPECT_EQ(outcome.scanner, nullptr);
    ASSERT_FALSE(outcome.errors.empty());
    EXPECT_EQ(outcome.errors[0].rfind("line 2: ", 0), 0u) << outcome.errors[0];
}

TEST(YaraScannerTest, RejectsMalformedRules) {
    const char* const kBroken[] = {
        "rule { condition: true }",                                 // missing identifier
        "rule a { strings: $s = \"x\" condition: $t }",             // undefined string
        "rule a { condition: true }\nrule a { condition: true }",   // duplicate rule
        "rule a { strings: $h = { 4G } condition: $h }",            // bad hex
        "rule a { strings: $r = /ab(/ condition: $r }",             // bad regex
        "import \"pe\"\nrule a { condition: pe.is_pe }",            // module not built in
        "include \"/etc/hosts\"\nrule a { condition: true }",       // includes are disabled
        "rule a { condition: true ",                                // truncated
    };
    for (const char* source : kBroken) {
        const auto outcome = YaraScanner::Compile(source);
        EXPECT_EQ(outcome.status, YaraStatus::kCompileError) << source;
        EXPECT_FALSE(outcome.errors.empty()) << source;
        EXPECT_EQ(outcome.scanner, nullptr) << source;
    }
}

TEST(YaraScannerTest, RejectsEmptyOrBinarySource) {
    EXPECT_EQ(YaraScanner::Compile("").status, YaraStatus::kInvalidArgument);
    EXPECT_EQ(YaraScanner::Compile(std::string("rule a { condition: true }\0junk", 31)).status,
              YaraStatus::kInvalidArgument);
}

TEST(YaraScannerTest, GarbageInputNeverCrashesTheCompiler) {
    std::string garbage;
    for (int i = 0; i < 4096; ++i) {
        garbage.push_back(static_cast<char>(1 + (i * 131) % 255));  // every byte value except NUL
    }
    const auto outcome = YaraScanner::Compile(garbage);
    EXPECT_EQ(outcome.status, YaraStatus::kCompileError);
}

// --- Timeouts -----------------------------------------------------------------------------------

TEST(YaraScannerTest, SlowConditionStopsAtTheTimeout) {
    // ~10^12 loop iterations over 1 MiB: would run for hours without a timeout.
    const auto scanner = CompileOrFail(R"(
rule slow {
    condition:
        for all i in (0..filesize - 1) : (for all j in (0..filesize - 1) : (uint8(i) == uint8(j)))
}
)");
    ASSERT_NE(scanner, nullptr);
    const std::string data(1024 * 1024, 'q');
    const auto start = steady_clock::now();
    const auto outcome = ScanString(*scanner, data, /* timeout_ms= */ 200);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - start);
    EXPECT_EQ(outcome.status, YaraStatus::kTimeout);
    EXPECT_TRUE(outcome.matches.empty());
    EXPECT_GE(elapsed.count(), 150);
    EXPECT_LT(elapsed.count(), 3000);
}

TEST(YaraScannerTest, FastScansFinishWellInsideTheTimeout) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    std::string data(32 * 1024 * 1024, 'x');
    data.replace(data.size() / 2, sizeof(kMarker) - 1, kMarker);
    const auto start = steady_clock::now();
    const auto outcome = ScanString(*scanner, data, /* timeout_ms= */ 10000);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - start);
    EXPECT_TRUE(outcome.ok());
    EXPECT_EQ(RuleNames(outcome), (std::vector<std::string>{"test_marker"}));
    std::printf("[ perf     ] 32 MiB scanned in %lld ms\n", static_cast<long long>(elapsed.count()));
    EXPECT_LT(elapsed.count(), 5000);
}

// --- Files --------------------------------------------------------------------------------------

TEST(YaraScannerTest, ScansFiles) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    const std::string infected = test::TempPath("marker.bin");
    const std::string clean = test::TempPath("clean.bin");
    test::WriteFile(infected, std::string(10000, 'a') + kMarker);
    test::WriteFile(clean, std::string(10000, 'a'));

    const auto hit = scanner->ScanFile(infected, 1000);
    EXPECT_TRUE(hit.ok());
    EXPECT_EQ(RuleNames(hit), (std::vector<std::string>{"test_marker"}));
    const auto miss = scanner->ScanFile(clean, 1000);
    EXPECT_TRUE(miss.ok());
    EXPECT_TRUE(miss.matches.empty());

    unlink(infected.c_str());
    unlink(clean.c_str());
}

TEST(YaraScannerTest, MissingFileIsAFileError) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    EXPECT_EQ(scanner->ScanFile(test::TempPath("does-not-exist"), 1000).status, YaraStatus::kFileError);
    EXPECT_EQ(scanner->ScanFile("", 1000).status, YaraStatus::kInvalidArgument);
}

TEST(YaraScannerTest, NullBufferIsInvalid) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    EXPECT_EQ(scanner->ScanMemory(nullptr, 10, 0).status, YaraStatus::kInvalidArgument);
    EXPECT_TRUE(scanner->ScanMemory(nullptr, 0, 0).ok());
}

// --- Caching and concurrency --------------------------------------------------------------------

TEST(YaraScannerTest, IdenticalSourcesShareOneCompiledRuleset) {
    const auto first = CompileOrFail(kMarkerRule);
    const auto second = CompileOrFail(kMarkerRule);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first.get(), second.get());
    const auto other = CompileOrFail(std::string(kMarkerRule) + "\nrule extra { condition: false }");
    EXPECT_NE(first.get(), other.get());
}

TEST(YaraScannerTest, ConcurrentScansShareTheRules) {
    const auto scanner = CompileOrFail(kMarkerRule);
    ASSERT_NE(scanner, nullptr);
    const std::string infected = std::string(256 * 1024, 'y') + kMarker;
    const std::string clean(256 * 1024, 'y');
    std::vector<std::future<bool>> results;
    for (int t = 0; t < 8; ++t) {
        results.push_back(std::async(std::launch::async, [&, t] {
            bool all_right = true;
            for (int i = 0; i < 20; ++i) {
                const bool expect_hit = (t + i) % 2 == 0;
                const auto outcome = ScanString(*scanner, expect_hit ? infected : clean);
                all_right = all_right && outcome.ok() && outcome.matches.size() == (expect_hit ? 1u : 0u);
            }
            return all_right;
        }));
    }
    for (auto& result : results) {
        EXPECT_TRUE(result.get());
    }
}

}  // namespace
}  // namespace blackshield::yara
