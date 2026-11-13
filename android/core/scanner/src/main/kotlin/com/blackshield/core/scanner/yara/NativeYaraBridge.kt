package com.blackshield.core.scanner.yara

import java.nio.ByteBuffer

/**
 * Raw JNI surface of the YARA engine (yara_jni.cpp). Blocking; call off the main thread.
 *
 * - [compile] takes the UTF-8 rule text; `result` (>= [RESULT_SIZE] slots) receives
 *   `[status, handle]`. Returns the compile errors (empty on success), or null when out of memory.
 * - [scanFile] / [scanBuffer] write `[status, libyaraError]` into `result` and return the matches
 *   flattened as `rule, namespace, tagCount, tag..., metaCount, (key, type, value)...` (see
 *   [YaraMatches.parse]); null when the handle is unknown or memory ran out.
 * - [scanBuffer] needs a direct [ByteBuffer]; only its first `length` bytes are scanned.
 * - Every handle must be released with [release]; unknown handles are rejected safely.
 */
internal interface YaraBridge {
    fun compile(source: ByteArray, result: LongArray): Array<String>?

    fun scanFile(handle: Long, path: String, timeoutMillis: Int, result: LongArray): Array<String>?

    fun scanBuffer(handle: Long, buffer: ByteBuffer, length: Int, timeoutMillis: Int, result: LongArray): Array<String>?

    fun ruleCount(handle: Long): Int

    fun release(handle: Long)

    companion object {
        const val RESULT_SIZE = 2
        const val RESULT_STATUS = 0
        const val RESULT_HANDLE = 1
        const val RESULT_YARA_ERROR = 1
    }
}

/** JNI implementation. Method names must stay public and unchanged: they are JNI symbol names. */
internal object NativeYaraBridge : YaraBridge {
    init {
        System.loadLibrary("blackshield_scanner")
    }

    external override fun compile(source: ByteArray, result: LongArray): Array<String>?

    external override fun scanFile(handle: Long, path: String, timeoutMillis: Int, result: LongArray): Array<String>?

    external override fun scanBuffer(
        handle: Long,
        buffer: ByteBuffer,
        length: Int,
        timeoutMillis: Int,
        result: LongArray
    ): Array<String>?

    external override fun ruleCount(handle: Long): Int

    external override fun release(handle: Long)
}
