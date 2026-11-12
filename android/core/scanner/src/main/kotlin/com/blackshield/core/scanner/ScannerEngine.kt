package com.blackshield.core.scanner

/** Entry point to the native scanning engine. */
interface ScannerEngine {
    /** Round-trips through JNI and returns the native library's "pong" message. */
    fun ping(): String
}
