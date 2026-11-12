// JNI bridge for com.blackshield.core.scanner.hash.NativeHashBridge.
//
// Contract (mirrored in NativeHashBridge.kt):
//  - hashFile/hashFd return the lower-case hex digest, or null on any failure.
//  - `result` (nullable LongArray of size >= 3) receives [status, errno, bytesHashed].
//  - `cancelToken` is 0 (not cancellable) or a handle from createCancelToken(). Handles are
//    opaque ids looked up in a registry, so a stale or forged value can never be dereferenced.
//  - No function lets a C++ exception escape or leaves a Java exception pending.

#include <jni.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "hash/hash_engine.h"

namespace {

using blackshield::hash::AlgorithmFromInt;
using blackshield::hash::CancellationFlag;
using blackshield::hash::HashEngine;
using blackshield::hash::HashOutcome;
using blackshield::hash::HashStatus;

constexpr jsize kResultSlots = 3;

class CancellationRegistry {
public:
    static CancellationRegistry& Instance() {
        static auto* registry = new CancellationRegistry();  // Intentionally leaked: no exit-time destructor.
        return *registry;
    }

    jlong Create() {
        std::lock_guard<std::mutex> lock(mutex_);
        const jlong id = next_id_++;
        flags_.emplace(id, std::make_shared<CancellationFlag>());
        return id;
    }

    void Cancel(jlong id) {
        if (const auto flag = Find(id)) {
            flag->Cancel();
        }
    }

    void Release(jlong id) {
        std::lock_guard<std::mutex> lock(mutex_);
        flags_.erase(id);
    }

    /** Shared ownership keeps the flag alive for an in-flight hash even if it is released. */
    std::shared_ptr<CancellationFlag> Find(jlong id) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = flags_.find(id);
        return it == flags_.end() ? nullptr : it->second;
    }

private:
    CancellationRegistry() = default;

    std::mutex mutex_;
    std::unordered_map<jlong, std::shared_ptr<CancellationFlag>> flags_;
    jlong next_id_ = 1;
};

HashOutcome Invalid(int error_number = EINVAL) {
    HashOutcome outcome;
    outcome.status = HashStatus::kInvalidArgument;
    outcome.error_number = error_number;
    return outcome;
}

void ClearPendingException(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

/** Java strings are UTF-16; paths are UTF-8. (GetStringUTFChars yields *modified* UTF-8.) */
bool JavaStringToUtf8(JNIEnv* env, jstring value, std::string* out) {
    const jsize length = env->GetStringLength(value);
    std::u16string utf16(static_cast<std::size_t>(length), u'\0');
    env->GetStringRegion(value, 0, length, reinterpret_cast<jchar*>(utf16.data()));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    out->clear();
    out->reserve(utf16.size());
    for (std::size_t i = 0; i < utf16.size(); ++i) {
        std::uint32_t cp = utf16[i];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 1 >= utf16.size() || utf16[i + 1] < 0xDC00 || utf16[i + 1] > 0xDFFF) {
                return false;  // Unpaired high surrogate.
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (static_cast<std::uint32_t>(utf16[++i]) - 0xDC00);
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return false;  // Unpaired low surrogate.
        }

        if (cp < 0x80) {
            out->push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out->push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out->push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return true;
}

/** Writes the outcome into `result` and returns the digest string (or null). */
jstring Complete(JNIEnv* env, jlongArray result, HashOutcome outcome) {
    jstring digest = nullptr;
    if (outcome.ok()) {
        digest = env->NewStringUTF(outcome.hex_digest.c_str());
        if (digest == nullptr || env->ExceptionCheck()) {
            ClearPendingException(env);  // OutOfMemoryError: report instead of throwing.
            digest = nullptr;
            outcome.status = HashStatus::kInternalError;
            outcome.error_number = ENOMEM;
        }
    }
    if (result != nullptr) {
        const jlong values[kResultSlots] = {
            static_cast<jlong>(outcome.status),
            static_cast<jlong>(outcome.error_number),
            static_cast<jlong>(outcome.bytes_hashed),
        };
        env->SetLongArrayRegion(result, 0, kResultSlots, values);
        ClearPendingException(env);
    }
    return digest;
}

/** Shared argument validation and exception barrier for both entry points. */
template <typename HashFn>
jstring RunHash(JNIEnv* env, jint algorithm, jlong cancel_token, jlongArray result, HashFn&& hash) noexcept {
    try {
        if (result != nullptr && env->GetArrayLength(result) < kResultSlots) {
            return nullptr;  // Cannot report into an undersized array; treat as invalid input.
        }
        const auto parsed_algorithm = AlgorithmFromInt(algorithm);
        if (!parsed_algorithm) {
            return Complete(env, result, Invalid());
        }
        std::shared_ptr<CancellationFlag> flag;
        if (cancel_token != 0) {
            flag = CancellationRegistry::Instance().Find(cancel_token);
            if (!flag) {
                return Complete(env, result, Invalid());
            }
        }
        return Complete(env, result, hash(*parsed_algorithm, flag.get()));
    } catch (...) {
        ClearPendingException(env);
        HashOutcome outcome;
        outcome.status = HashStatus::kInternalError;
        try {
            return Complete(env, result, outcome);
        } catch (...) {
            return nullptr;
        }
    }
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL Java_com_blackshield_core_scanner_hash_NativeHashBridge_hashFile(
    JNIEnv* env, jobject /* this */, jstring path, jint algorithm, jlong cancel_token, jlongArray result) {
    return RunHash(env, algorithm, cancel_token, result, [&](auto parsed, const CancellationFlag* flag) {
        std::string utf8_path;
        if (path == nullptr || !JavaStringToUtf8(env, path, &utf8_path)) {
            return Invalid();
        }
        return HashEngine{}.HashFile(utf8_path, parsed, flag);
    });
}

JNIEXPORT jstring JNICALL Java_com_blackshield_core_scanner_hash_NativeHashBridge_hashFd(
    JNIEnv* env, jobject /* this */, jint fd, jint algorithm, jlong cancel_token, jlongArray result) {
    return RunHash(env, algorithm, cancel_token, result, [&](auto parsed, const CancellationFlag* flag) {
        return HashEngine{}.HashFd(fd, parsed, flag);
    });
}

JNIEXPORT jlong JNICALL Java_com_blackshield_core_scanner_hash_NativeHashBridge_createCancelToken(JNIEnv* /* env */,
                                                                                                   jobject /* this */) {
    try {
        return CancellationRegistry::Instance().Create();
    } catch (...) {
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_blackshield_core_scanner_hash_NativeHashBridge_cancel(JNIEnv* /* env */,
                                                                                     jobject /* this */,
                                                                                     jlong token) {
    try {
        CancellationRegistry::Instance().Cancel(token);
    } catch (...) {
    }
}

JNIEXPORT void JNICALL Java_com_blackshield_core_scanner_hash_NativeHashBridge_releaseCancelToken(
    JNIEnv* /* env */, jobject /* this */, jlong token) {
    try {
        CancellationRegistry::Instance().Release(token);
    } catch (...) {
    }
}

}  // extern "C"
