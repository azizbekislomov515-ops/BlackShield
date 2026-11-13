#include "jni_util.h"

#include <cstdint>
#include <string>

namespace blackshield::jni {

void ClearPendingException(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

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

jstring Utf8ToJavaString(JNIEnv* env, std::string_view utf8) {
    constexpr char16_t kReplacement = 0xFFFD;
    std::u16string utf16;
    try {
        utf16.reserve(utf8.size());
        std::size_t i = 0;
        while (i < utf8.size()) {
            const auto lead = static_cast<unsigned char>(utf8[i]);
            std::size_t length = 0;
            std::uint32_t cp = 0;
            std::uint32_t min = 0;
            if (lead < 0x80) {
                length = 1;
                cp = lead;
            } else if ((lead & 0xE0) == 0xC0) {
                length = 2;
                cp = lead & 0x1F;
                min = 0x80;
            } else if ((lead & 0xF0) == 0xE0) {
                length = 3;
                cp = lead & 0x0F;
                min = 0x800;
            } else if ((lead & 0xF8) == 0xF0) {
                length = 4;
                cp = lead & 0x07;
                min = 0x10000;
            }
            bool valid = length > 0 && i + length <= utf8.size();
            for (std::size_t k = 1; valid && k < length; ++k) {
                const auto next = static_cast<unsigned char>(utf8[i + k]);
                valid = (next & 0xC0) == 0x80;
                cp = (cp << 6) | (next & 0x3F);
            }
            valid = valid && cp >= min && cp <= 0x10FFFF && (cp < 0xD800 || cp > 0xDFFF);
            if (!valid) {
                utf16.push_back(kReplacement);
                ++i;  // Resynchronise on the next byte.
                continue;
            }
            if (cp >= 0x10000) {
                cp -= 0x10000;
                utf16.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
                utf16.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FF)));
            } else {
                utf16.push_back(static_cast<char16_t>(cp));
            }
            i += length;
        }
    } catch (...) {
        return nullptr;
    }
    jstring result = env->NewString(reinterpret_cast<const jchar*>(utf16.data()), static_cast<jsize>(utf16.size()));
    if (result == nullptr || env->ExceptionCheck()) {
        ClearPendingException(env);
        return nullptr;
    }
    return result;
}

}  // namespace blackshield::jni
