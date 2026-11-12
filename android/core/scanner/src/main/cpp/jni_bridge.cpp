#include <jni.h>

#include "scanner_engine.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_blackshield_core_scanner_NativeScanner_nativePing(JNIEnv* env, jobject /* this */) {
    const std::string pong = blackshield::scanner::Ping();
    return env->NewStringUTF(pong.c_str());
}
