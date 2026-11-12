package com.blackshield.core.scanner.hash

/**
 * Raw JNI surface of the hash engine (hash_jni.cpp). Blocking; call off the main thread.
 *
 * - [hashFile] / [hashFd] return the hex digest, or null on any error.
 * - [result], when non-null, must have at least [RESULT_SIZE] slots and receives
 *   `[status, errno, bytesHashed]`; status values are the `STATUS_*` constants.
 * - [cancelToken] is [NO_CANCEL_TOKEN] or a handle from [createCancelToken]. Calling [cancel]
 *   from another thread stops the hash within one 64 KiB chunk (or 50 ms for a stalled pipe).
 *   Every token must be released with [releaseCancelToken]; unknown tokens are rejected safely.
 */
internal interface HashBridge {
    fun hashFile(path: String, algorithm: Int, cancelToken: Long, result: LongArray?): String?

    fun hashFd(fd: Int, algorithm: Int, cancelToken: Long, result: LongArray?): String?

    fun createCancelToken(): Long

    fun cancel(token: Long)

    fun releaseCancelToken(token: Long)

    companion object {
        const val NO_CANCEL_TOKEN = 0L
        const val RESULT_SIZE = 3
        const val RESULT_STATUS = 0
        const val RESULT_ERRNO = 1
        const val RESULT_BYTES = 2

        // Must match blackshield::hash::HashStatus.
        const val STATUS_OK = 0L
        const val STATUS_NOT_FOUND = 1L
        const val STATUS_PERMISSION_DENIED = 2L
        const val STATUS_CANCELLED = 3L
        const val STATUS_IO_ERROR = 4L
        const val STATUS_INVALID_ARGUMENT = 5L
        const val STATUS_INTERNAL_ERROR = 6L
    }
}

/** JNI implementation. Method names must stay public and unchanged: they are JNI symbol names. */
internal object NativeHashBridge : HashBridge {
    init {
        System.loadLibrary("blackshield_scanner")
    }

    external override fun hashFile(path: String, algorithm: Int, cancelToken: Long, result: LongArray?): String?

    external override fun hashFd(fd: Int, algorithm: Int, cancelToken: Long, result: LongArray?): String?

    external override fun createCancelToken(): Long

    external override fun cancel(token: Long)

    external override fun releaseCancelToken(token: Long)
}
