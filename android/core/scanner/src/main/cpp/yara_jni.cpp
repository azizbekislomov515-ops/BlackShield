// JNI bridge for com.blackshield.core.scanner.yara.NativeYaraBridge.
//
// Contract (mirrored in NativeYaraBridge.kt):
//  - compile(source, result): `source` is the UTF-8 rule text. result (LongArray >= 2) receives
//    [status, handle]. Returns the compile error messages (empty on success), or null when out of
//    memory. A handle is an opaque id in a registry: a stale or forged value is never dereferenced.
//  - scanFile / scanBuffer: result (LongArray >= 2) receives [status, libyaraError]. Return the
//    matches flattened into one String[]: for each match
//      rule, namespace, tagCount, tag..., metaCount, (key, type, value)...
//    with counts and types as decimal strings; null when out of memory or the handle is unknown.
//  - scanBuffer takes a direct ByteBuffer, so DEX data streamed out of an APK is not copied again.
//  - No function lets a C++ exception escape or leaves a Java exception pending.

#include <jni.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "jni_util.h"
#include "yara/yara_scanner.h"

namespace {

using blackshield::jni::ClearPendingException;
using blackshield::jni::JavaStringToUtf8;
using blackshield::jni::Utf8ToJavaString;
using blackshield::yara::ScanOutcome;
using blackshield::yara::YaraScanner;
using blackshield::yara::YaraStatus;

constexpr jsize kResultSlots = 2;

class RulesRegistry {
public:
    static RulesRegistry& Instance() {
        static auto* registry = new RulesRegistry();  // Intentionally leaked: no exit-time destructor.
        return *registry;
    }

    jlong Add(std::shared_ptr<const YaraScanner> scanner) {
        std::lock_guard<std::mutex> lock(mutex_);
        const jlong id = next_id_++;
        scanners_.emplace(id, std::move(scanner));
        return id;
    }

    /** Shared ownership keeps the rules alive for in-flight scans even if the handle is released. */
    std::shared_ptr<const YaraScanner> Find(jlong id) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = scanners_.find(id);
        return it == scanners_.end() ? nullptr : it->second;
    }

    void Release(jlong id) {
        std::lock_guard<std::mutex> lock(mutex_);
        scanners_.erase(id);
    }

private:
    RulesRegistry() = default;

    std::mutex mutex_;
    std::unordered_map<jlong, std::shared_ptr<const YaraScanner>> scanners_;
    jlong next_id_ = 1;
};

void WriteResult(JNIEnv* env, jlongArray result, jlong first, jlong second) {
    const jlong values[kResultSlots] = {first, second};
    env->SetLongArrayRegion(result, 0, kResultSlots, values);
    ClearPendingException(env);
}

bool ResultUsable(JNIEnv* env, jlongArray result) {
    const bool usable = result != nullptr && env->GetArrayLength(result) >= kResultSlots;
    ClearPendingException(env);
    return usable;
}

/** A String[] from UTF-8 values; null (no exception pending) when out of memory. */
jobjectArray ToJavaArray(JNIEnv* env, const std::vector<std::string>& values) {
    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        ClearPendingException(env);
        return nullptr;
    }
    jobjectArray array = env->NewObjectArray(static_cast<jsize>(values.size()), string_class, nullptr);
    env->DeleteLocalRef(string_class);
    if (array == nullptr) {
        ClearPendingException(env);
        return nullptr;
    }
    for (std::size_t i = 0; i < values.size(); ++i) {
        jstring value = Utf8ToJavaString(env, values[i]);
        if (value == nullptr) {
            env->DeleteLocalRef(array);
            return nullptr;
        }
        env->SetObjectArrayElement(array, static_cast<jsize>(i), value);
        env->DeleteLocalRef(value);  // Keeps the local reference table small for large results.
        if (env->ExceptionCheck()) {
            ClearPendingException(env);
            env->DeleteLocalRef(array);
            return nullptr;
        }
    }
    return array;
}

std::vector<std::string> Flatten(const ScanOutcome& outcome) {
    std::vector<std::string> flat;
    for (const auto& match : outcome.matches) {
        flat.push_back(match.rule);
        flat.push_back(match.rule_namespace);
        flat.push_back(std::to_string(match.tags.size()));
        flat.insert(flat.end(), match.tags.begin(), match.tags.end());
        flat.push_back(std::to_string(match.metas.size()));
        for (const auto& meta : match.metas) {
            flat.push_back(meta.key);
            flat.push_back(std::to_string(static_cast<int>(meta.type)));
            flat.push_back(meta.value);
        }
    }
    return flat;
}

ScanOutcome InvalidScan() {
    ScanOutcome invalid;
    invalid.status = YaraStatus::kInvalidArgument;
    return invalid;
}

/** Shared handle lookup, result reporting and exception barrier for both scan entry points. */
template <typename ScanFn>
jobjectArray RunScan(JNIEnv* env, jlong handle, jlongArray result, ScanFn&& scan) noexcept {
    try {
        if (!ResultUsable(env, result)) {
            return nullptr;
        }
        const auto scanner = RulesRegistry::Instance().Find(handle);
        if (!scanner) {
            WriteResult(env, result, static_cast<jlong>(YaraStatus::kInvalidArgument), 0);
            return nullptr;
        }
        const ScanOutcome outcome = scan(*scanner);
        jobjectArray matches = ToJavaArray(env, Flatten(outcome));
        const YaraStatus status = matches == nullptr ? YaraStatus::kInternalError : outcome.status;
        WriteResult(env, result, static_cast<jlong>(status), outcome.yara_error);
        return matches;
    } catch (...) {
        ClearPendingException(env);
        return nullptr;
    }
}

}  // namespace

extern "C" {

JNIEXPORT jobjectArray JNICALL Java_com_blackshield_core_scanner_yara_NativeYaraBridge_compile(JNIEnv* env,
                                                                                               jobject /* this */,
                                                                                               jbyteArray source,
                                                                                               jlongArray result) {
    try {
        if (!ResultUsable(env, result)) {
            return nullptr;
        }
        if (source == nullptr) {
            WriteResult(env, result, static_cast<jlong>(YaraStatus::kInvalidArgument), 0);
            return ToJavaArray(env, {});
        }
        const jsize length = env->GetArrayLength(source);
        std::string text(static_cast<std::size_t>(length), '\0');
        env->GetByteArrayRegion(source, 0, length, reinterpret_cast<jbyte*>(text.data()));
        ClearPendingException(env);

        auto outcome = YaraScanner::Compile(text);
        jlong handle = 0;
        if (outcome.status == YaraStatus::kOk) {
            handle = RulesRegistry::Instance().Add(std::move(outcome.scanner));
        }
        jobjectArray errors = ToJavaArray(env, outcome.errors);
        if (errors == nullptr && handle != 0) {
            RulesRegistry::Instance().Release(handle);  // Cannot report success; do not leak the handle.
            handle = 0;
        }
        const YaraStatus status = errors == nullptr ? YaraStatus::kInternalError : outcome.status;
        WriteResult(env, result, static_cast<jlong>(status), handle);
        return errors;
    } catch (...) {
        ClearPendingException(env);
        return nullptr;
    }
}

JNIEXPORT jobjectArray JNICALL Java_com_blackshield_core_scanner_yara_NativeYaraBridge_scanFile(
    JNIEnv* env, jobject /* this */, jlong handle, jstring path, jint timeout_ms, jlongArray result) {
    std::string utf8_path;
    bool path_ok = false;
    try {
        path_ok = path != nullptr && JavaStringToUtf8(env, path, &utf8_path);
    } catch (...) {
        ClearPendingException(env);
    }
    return RunScan(env, handle, result, [&](const YaraScanner& scanner) {
        return path_ok ? scanner.ScanFile(utf8_path, timeout_ms) : InvalidScan();
    });
}

JNIEXPORT jobjectArray JNICALL Java_com_blackshield_core_scanner_yara_NativeYaraBridge_scanBuffer(
    JNIEnv* env, jobject /* this */, jlong handle, jobject buffer, jint length, jint timeout_ms, jlongArray result) {
    return RunScan(env, handle, result, [&](const YaraScanner& scanner) {
        void* address = buffer != nullptr ? env->GetDirectBufferAddress(buffer) : nullptr;
        const jlong capacity = buffer != nullptr ? env->GetDirectBufferCapacity(buffer) : -1;
        ClearPendingException(env);
        if (address == nullptr || length < 0 || capacity < 0 || length > capacity) {
            return InvalidScan();
        }
        return scanner.ScanMemory(static_cast<const std::uint8_t*>(address), static_cast<std::size_t>(length),
                                  timeout_ms);
    });
}

JNIEXPORT jint JNICALL Java_com_blackshield_core_scanner_yara_NativeYaraBridge_ruleCount(JNIEnv* /* env */,
                                                                                         jobject /* this */,
                                                                                         jlong handle) {
    try {
        const auto scanner = RulesRegistry::Instance().Find(handle);
        return scanner ? static_cast<jint>(scanner->RuleCount()) : -1;
    } catch (...) {
        return -1;
    }
}

JNIEXPORT void JNICALL Java_com_blackshield_core_scanner_yara_NativeYaraBridge_release(JNIEnv* /* env */,
                                                                                       jobject /* this */,
                                                                                       jlong handle) {
    try {
        RulesRegistry::Instance().Release(handle);
    } catch (...) {
    }
}

}  // extern "C"
