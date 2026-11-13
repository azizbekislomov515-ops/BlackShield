#include "yara/yara_scanner.h"

#include <yara.h>

#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>

#include "hash/hasher.h"

namespace blackshield::yara {

namespace {

constexpr std::uint64_t kNanosPerMilli = 1000000ULL;

bool InitializeOnce() noexcept {
    // yr_initialize is reference counted; it is never finalized (libyara lives as long as the
    // process, like the JNI library).
    static const bool initialized = yr_initialize() == ERROR_SUCCESS;
    return initialized;
}

YaraStatus StatusOf(int yara_error) noexcept {
    switch (yara_error) {
        case ERROR_SUCCESS:
            return YaraStatus::kOk;
        case ERROR_SCAN_TIMEOUT:
            return YaraStatus::kTimeout;
        case ERROR_COULD_NOT_OPEN_FILE:
        case ERROR_COULD_NOT_MAP_FILE:
            return YaraStatus::kFileError;
        default:
            return YaraStatus::kInternalError;
    }
}

struct CompileErrors {
    std::vector<std::string> messages;
    bool out_of_memory = false;
};

void OnCompileMessage(int error_level, const char* /* file_name */, int line_number, const YR_RULE* /* rule */,
                      const char* message, void* user_data) {
    if (error_level != YARA_ERROR_LEVEL_ERROR) {
        return;  // Warnings (e.g. slow strings) do not stop a ruleset from loading.
    }
    auto* errors = static_cast<CompileErrors*>(user_data);
    try {
        errors->messages.push_back("line " + std::to_string(line_number) + ": " + (message ? message : "?"));
    } catch (...) {
        errors->out_of_memory = true;  // Called from C: nothing may propagate.
    }
}

struct ScanState {
    std::vector<YaraMatch> matches;
    bool out_of_memory = false;
};

YaraMeta MetaOf(const YR_META* meta) {
    YaraMeta out;
    out.key = meta->identifier ? meta->identifier : "";
    switch (meta->type) {
        case META_TYPE_INTEGER:
            out.type = YaraMeta::Type::kInteger;
            out.value = std::to_string(meta->integer);
            break;
        case META_TYPE_BOOLEAN:
            out.type = YaraMeta::Type::kBoolean;
            out.value = meta->integer ? "true" : "false";
            break;
        default:
            out.type = YaraMeta::Type::kString;
            out.value = meta->string ? meta->string : "";
            break;
    }
    return out;
}

int OnScanMessage(YR_SCAN_CONTEXT* /* context */, int message, void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;  // Includes CALLBACK_MSG_TOO_MANY_MATCHES: keep scanning other rules.
    }
    auto* state = static_cast<ScanState*>(user_data);
    if (state->matches.size() >= YaraScanner::kMaxMatches) {
        return CALLBACK_CONTINUE;
    }
    const auto* rule = static_cast<const YR_RULE*>(message_data);
    try {
        YaraMatch match;
        match.rule = rule->identifier ? rule->identifier : "";
        match.rule_namespace = (rule->ns && rule->ns->name) ? rule->ns->name : "default";
        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) { match.tags.emplace_back(tag); }
        const YR_META* meta = nullptr;
        yr_rule_metas_foreach(rule, meta) { match.metas.push_back(MetaOf(meta)); }
        state->matches.push_back(std::move(match));
    } catch (...) {
        state->out_of_memory = true;
        return CALLBACK_ABORT;
    }
    return CALLBACK_CONTINUE;
}

/** Compiled rulesets by source digest, held weakly: the cache never keeps a ruleset alive. */
class CompiledCache {
public:
    static CompiledCache& Instance() {
        static auto* cache = new CompiledCache();  // Intentionally leaked: no exit-time destructor.
        return *cache;
    }

    std::shared_ptr<const YaraScanner> Find(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : it->second.lock();
    }

    void Put(const std::string& key, const std::shared_ptr<const YaraScanner>& scanner) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = entries_.begin(); it != entries_.end();) {
            it = it->second.expired() ? entries_.erase(it) : std::next(it);  // Drop released rulesets.
        }
        entries_[key] = scanner;
    }

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::weak_ptr<const YaraScanner>> entries_;
};

std::string SourceDigest(std::string_view source) {
    auto hasher = hash::CreateHasher(hash::HashAlgorithm::kSha256);
    hasher->Update(reinterpret_cast<const std::uint8_t*>(source.data()), source.size());
    return hash::ToHex(hasher->Finish());
}

CompileOutcome CompileFailure(YaraStatus status, std::vector<std::string> errors = {}) {
    CompileOutcome outcome;
    outcome.status = status;
    outcome.errors = std::move(errors);
    return outcome;
}

}  // namespace

bool EnsureYaraInitialized() noexcept { return InitializeOnce(); }

CompileOutcome YaraScanner::Compile(std::string_view source) noexcept {
    try {
        if (!EnsureYaraInitialized()) {
            return CompileFailure(YaraStatus::kInternalError);
        }
        if (source.empty() || source.find('\0') != std::string_view::npos) {
            return CompileFailure(YaraStatus::kInvalidArgument);  // libyara reads a C string.
        }
        const std::string key = SourceDigest(source);
        if (auto cached = CompiledCache::Instance().Find(key)) {
            CompileOutcome outcome;
            outcome.status = YaraStatus::kOk;
            outcome.scanner = std::move(cached);
            return outcome;
        }

        YR_COMPILER* compiler = nullptr;
        if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
            return CompileFailure(YaraStatus::kInternalError);
        }
        const std::unique_ptr<YR_COMPILER, decltype(&yr_compiler_destroy)> compiler_guard(compiler,
                                                                                           yr_compiler_destroy);
        // No include callback: `include "..."` fails with "includes are disabled".
        yr_compiler_set_include_callback(compiler, nullptr, nullptr, nullptr);
        CompileErrors errors;
        yr_compiler_set_callback(compiler, OnCompileMessage, &errors);

        const std::string terminated(source);
        const int error_count = yr_compiler_add_string(compiler, terminated.c_str(), nullptr);
        if (errors.out_of_memory) {
            return CompileFailure(YaraStatus::kInternalError);
        }
        if (error_count > 0) {
            if (errors.messages.empty()) {
                errors.messages.emplace_back("rules did not compile");
            }
            return CompileFailure(YaraStatus::kCompileError, std::move(errors.messages));
        }

        YR_RULES* rules = nullptr;
        if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS || rules == nullptr) {
            return CompileFailure(YaraStatus::kInternalError);
        }
        // The constructor is private, so make_shared cannot be used; a failed allocation must
        // still free the rules.
        auto* raw = new (std::nothrow) YaraScanner(rules);
        if (raw == nullptr) {
            yr_rules_destroy(rules);
            return CompileFailure(YaraStatus::kInternalError);
        }
        std::shared_ptr<const YaraScanner> scanner(raw);
        CompiledCache::Instance().Put(key, scanner);

        CompileOutcome outcome;
        outcome.status = YaraStatus::kOk;
        outcome.scanner = std::move(scanner);
        return outcome;
    } catch (...) {
        return CompileFailure(YaraStatus::kInternalError);
    }
}

YaraScanner::~YaraScanner() { yr_rules_destroy(rules_); }

std::size_t YaraScanner::RuleCount() const noexcept {
    YR_RULES_STATS stats{};
    return yr_rules_get_stats(rules_, &stats) == ERROR_SUCCESS ? stats.num_rules : 0;
}

template <typename ScanFn>
ScanOutcome YaraScanner::Run(int timeout_ms, ScanFn&& scan) const noexcept {
    ScanOutcome outcome;
    try {
        YR_SCANNER* scanner = nullptr;
        const int created = yr_scanner_create(rules_, &scanner);
        if (created != ERROR_SUCCESS) {
            outcome.status = YaraStatus::kInternalError;
            outcome.yara_error = created;
            return outcome;
        }
        const std::unique_ptr<YR_SCANNER, decltype(&yr_scanner_destroy)> guard(scanner, yr_scanner_destroy);

        ScanState state;
        yr_scanner_set_callback(scanner, OnScanMessage, &state);
        // Fast mode stops looking for a string after its first hit: only rule matches are reported.
        yr_scanner_set_flags(scanner, SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING);
        // yr_scanner_set_timeout takes whole seconds; the field itself is in nanoseconds, which
        // gives millisecond timeouts. libyara checks it every 4 KiB of input and every 100
        // condition instructions.
        scanner->timeout = timeout_ms > 0 ? static_cast<std::uint64_t>(timeout_ms) * kNanosPerMilli : 0;

        const int result = scan(scanner);
        outcome.yara_error = result;
        outcome.status = state.out_of_memory ? YaraStatus::kInternalError : StatusOf(result);
        outcome.matches = std::move(state.matches);
    } catch (...) {
        outcome.status = YaraStatus::kInternalError;
        outcome.matches.clear();
    }
    return outcome;
}

ScanOutcome YaraScanner::ScanFile(const std::string& path, int timeout_ms) const noexcept {
    if (path.empty() || path.find('\0') != std::string::npos) {
        ScanOutcome outcome;
        outcome.status = YaraStatus::kInvalidArgument;
        return outcome;
    }
    return Run(timeout_ms, [&](YR_SCANNER* scanner) { return yr_scanner_scan_file(scanner, path.c_str()); });
}

ScanOutcome YaraScanner::ScanMemory(const std::uint8_t* data, std::size_t size, int timeout_ms) const noexcept {
    if (data == nullptr && size > 0) {
        ScanOutcome outcome;
        outcome.status = YaraStatus::kInvalidArgument;
        return outcome;
    }
    static const std::uint8_t kEmpty = 0;
    return Run(timeout_ms, [&](YR_SCANNER* scanner) {
        return yr_scanner_scan_mem(scanner, data != nullptr ? data : &kEmpty, size);
    });
}

}  // namespace blackshield::yara
