#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Forward declaration of libyara's compiled ruleset; <yara.h> stays out of this header.
struct YR_RULES;

namespace blackshield::yara {

/** Result codes. The numeric values are part of the JNI contract (see NativeYaraBridge.kt). */
enum class YaraStatus : int {
    kOk = 0,
    /** The scan ran out of time; matches found so far are still returned. */
    kTimeout = 1,
    /** The rules did not compile; see CompileOutcome::errors. */
    kCompileError = 2,
    /** The file could not be opened or mapped. */
    kFileError = 3,
    kInvalidArgument = 4,
    /** Out of memory, too many concurrent scans, or any other libyara failure. */
    kInternalError = 5,
};

struct YaraMeta {
    enum class Type : int { kInteger = 0, kString = 1, kBoolean = 2 };

    std::string key;
    Type type = Type::kString;
    /** Integers in decimal, booleans as "true"/"false"; strings as written in the rule. */
    std::string value;
};

struct YaraMatch {
    std::string rule;
    std::string rule_namespace;
    std::vector<std::string> tags;
    std::vector<YaraMeta> metas;
};

struct ScanOutcome {
    YaraStatus status = YaraStatus::kInternalError;
    /** libyara's ERROR_* code for diagnostics; 0 on success. */
    int yara_error = 0;
    std::vector<YaraMatch> matches;

    bool ok() const noexcept { return status == YaraStatus::kOk; }
};

class YaraScanner;

struct CompileOutcome {
    YaraStatus status = YaraStatus::kInternalError;
    /** "line N: message" for every compile error (empty on success). */
    std::vector<std::string> errors;
    /** Set when status is kOk. */
    std::shared_ptr<const YaraScanner> scanner;
};

/**
 * A compiled YARA ruleset. Compiling is the expensive part, so a scanner is built once per
 * ruleset and then shared: it is immutable, and Scan* may be called from any number of threads
 * at once (each call gets its own libyara scanner; libyara allows up to 32 concurrent scans).
 *
 * Nothing here throws: allocation failures and libyara errors become result codes.
 */
class YaraScanner {
public:
    /** Upper bound on matches reported by one scan; further matching rules are not listed. */
    static constexpr std::size_t kMaxMatches = 256;

    /**
     * Compiles `source`. Identical sources share one compiled ruleset while any user still holds
     * it (cache keyed by the SHA-256 of the source). `include` directives are rejected: rules come
     * in one signed file and must never read other files.
     */
    static CompileOutcome Compile(std::string_view source) noexcept;

    ~YaraScanner();
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    /** Scans a file (memory-mapped by libyara). `timeout_ms` <= 0 means no timeout. */
    ScanOutcome ScanFile(const std::string& path, int timeout_ms) const noexcept;

    /** Scans an in-memory buffer, e.g. a DEX file streamed out of an APK. */
    ScanOutcome ScanMemory(const std::uint8_t* data, std::size_t size, int timeout_ms) const noexcept;

    /** Number of rules in the compiled set. */
    std::size_t RuleCount() const noexcept;

private:
    explicit YaraScanner(YR_RULES* rules) noexcept : rules_(rules) {}

    template <typename ScanFn>
    ScanOutcome Run(int timeout_ms, ScanFn&& scan) const noexcept;

    YR_RULES* const rules_;
};

/** Initialises libyara once per process; false if it failed (all calls then fail cleanly). */
bool EnsureYaraInitialized() noexcept;

}  // namespace blackshield::yara
