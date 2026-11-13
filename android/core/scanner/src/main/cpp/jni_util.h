#pragma once

#include <jni.h>

#include <string>
#include <string_view>

// Helpers shared by the JNI entry points. None of them throws or leaves a Java exception pending.
namespace blackshield::jni {

void ClearPendingException(JNIEnv* env);

/** Java strings are UTF-16; paths are UTF-8. (GetStringUTFChars yields *modified* UTF-8.) */
bool JavaStringToUtf8(JNIEnv* env, jstring value, std::string* out);

/**
 * A Java string from arbitrary bytes that should be UTF-8 (rule names, metadata). Invalid
 * sequences become U+FFFD instead of crashing the VM, as NewStringUTF would under CheckJNI.
 * Returns null (with no exception pending) only when out of memory.
 */
jstring Utf8ToJavaString(JNIEnv* env, std::string_view utf8);

}  // namespace blackshield::jni
