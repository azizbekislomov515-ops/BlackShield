// Fuzzes YaraScanner::ScanMemory, the path that runs libyara over DEX files streamed out of untrusted APKs.
//
// The rules import libyara's `dex` and `math` modules, the only modules the engine is built with, so every input
// goes through the full DEX parser (the module parses the whole file on load) and the entropy code, and the
// string rules run the matcher. Signed rule updates may use both modules, so both are attack surface.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>

#include "yara/yara_scanner.h"

namespace {

// YARA escapes (\n, \x00, \/) must reach libyara as written, hence the raw string.
constexpr const char* kRules = R"(
import "dex"
import "math"

rule dex_structure
{
    condition:
        dex.header.magic == "dex\n035\x00" or
        dex.header.file_size > 0 and dex.number_of_methods > 0 and
        for any i in (0..dex.number_of_methods - 1): (
            dex.method[i].name == "onCreate" or dex.method[i].class_name contains "Activity" or
            dex.method[i].code_item.insns_size > 1000
        ) or
        // The header's count is attacker-controlled; bound it so one input cannot spin until the timeout.
        dex.header.string_ids_size < 65536 and
        for any j in (0..dex.header.string_ids_size - 1): (dex.string_ids[j].value contains "http") or
        for any k in (0..dex.number_of_fields - 1): (dex.field[k].name == "TAG") or
        dex.has_method("Landroid/app/Activity;", "onCreate") or dex.has_class(/Lcom\/example\//)
}

rule entropy
{
    condition:
        filesize > 16 and math.entropy(0, filesize) > 7.5
}

rule marker
{
    strings:
        $marker = "X5O-BLACKSHIELD-YARA-TEST-FILE-1d8e"
        $hex = { 64 65 78 0A 30 33 ?? 00 }
        $re = /L[a-z]+\/[A-Za-z]+;/
    condition:
        any of them
}
)";

const blackshield::yara::YaraScanner& Scanner() {
    static const std::shared_ptr<const blackshield::yara::YaraScanner> scanner = [] {
        auto outcome = blackshield::yara::YaraScanner::Compile(kRules);
        if (!outcome.scanner) {  // a broken fuzz rule set must fail loudly, not fuzz nothing
            for (const auto& error : outcome.errors) std::fprintf(stderr, "fuzz rules: %s\n", error.c_str());
            std::abort();
        }
        return outcome.scanner;
    }();
    return *scanner;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // The app scans with a timeout too; one second keeps slow inputs from stalling the run.
    (void)Scanner().ScanMemory(data, size, /*timeout_ms=*/1000);
    return 0;
}
