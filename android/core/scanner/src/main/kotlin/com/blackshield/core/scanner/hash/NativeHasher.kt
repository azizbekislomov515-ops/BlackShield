package com.blackshield.core.scanner.hash

import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import com.blackshield.core.scanner.hash.HashBridge.Companion.RESULT_BYTES
import com.blackshield.core.scanner.hash.HashBridge.Companion.RESULT_ERRNO
import com.blackshield.core.scanner.hash.HashBridge.Companion.RESULT_SIZE
import com.blackshield.core.scanner.hash.HashBridge.Companion.RESULT_STATUS
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/**
 * Streaming file hashing backed by the native engine. Reads in 64 KiB chunks, so memory use
 * does not grow with file size.
 *
 * Cancellation:
 * - Cancelling the calling coroutine stops the native hash promptly and rethrows
 *   [CancellationException], as usual for coroutines.
 * - Cancelling the optional [CancellationSignal] stops it and returns [HashResult.Cancelled].
 */
@Singleton
class NativeHasher internal constructor(private val bridge: HashBridge, private val ioDispatcher: CoroutineDispatcher) {
    @Inject
    constructor() : this(NativeHashBridge, Dispatchers.IO)

    suspend fun hashFile(
        path: String,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        cancellationSignal: CancellationSignal? = null
    ): HashResult = runCancellable(algorithm, cancellationSignal) { token, result ->
        bridge.hashFile(path, algorithm.nativeId, token, result)
    }

    /**
     * Hashes the content behind [descriptor], e.g. from
     * `ContentResolver.openFileDescriptor(uri, "r")`. The descriptor is not closed. Seekable
     * files are hashed from offset 0 without moving the descriptor's offset; pipes are read
     * from their current position to EOF.
     */
    suspend fun hashFd(
        descriptor: ParcelFileDescriptor,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        cancellationSignal: CancellationSignal? = null
    ): HashResult = hashFd(descriptor.fd, algorithm, cancellationSignal)

    internal suspend fun hashFd(
        fd: Int,
        algorithm: HashAlgorithm,
        cancellationSignal: CancellationSignal?
    ): HashResult = runCancellable(algorithm, cancellationSignal) { token, result ->
        bridge.hashFd(fd, algorithm.nativeId, token, result)
    }

    private suspend fun runCancellable(
        algorithm: HashAlgorithm,
        cancellationSignal: CancellationSignal?,
        call: (token: Long, result: LongArray) -> String?
    ): HashResult {
        val token = bridge.createCancelToken()
        if (token == HashBridge.NO_CANCEL_TOKEN) {
            return HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, errno = 0)
        }
        try {
            // Invoked immediately if the signal is already cancelled.
            cancellationSignal?.setOnCancelListener { bridge.cancel(token) }
            return coroutineScope {
                // The native call blocks and does not observe coroutine cancellation, so it
                // runs as a child while this coroutine waits; on cancellation we set the native
                // flag, and coroutineScope waits for the child to return before rethrowing.
                val work =
                    async(ioDispatcher) {
                        val result = LongArray(RESULT_SIZE)
                        val digest = call(token, result)
                        toHashResult(algorithm, digest, result)
                    }
                try {
                    work.await()
                } catch (e: CancellationException) {
                    bridge.cancel(token)
                    throw e
                }
            }
        } finally {
            // Waits for a running listener, so cancel() never races with the release below.
            cancellationSignal?.setOnCancelListener(null)
            bridge.releaseCancelToken(token)
        }
    }

    internal companion object {
        fun toHashResult(algorithm: HashAlgorithm, digest: String?, result: LongArray): HashResult {
            val errno = result[RESULT_ERRNO].toInt()
            return when (result[RESULT_STATUS]) {
                HashBridge.STATUS_OK ->
                    if (digest != null) {
                        HashResult.Success(algorithm, digest, bytesHashed = result[RESULT_BYTES])
                    } else {
                        HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, errno)
                    }

                HashBridge.STATUS_NOT_FOUND -> HashResult.FileNotFound

                HashBridge.STATUS_PERMISSION_DENIED -> HashResult.PermissionDenied

                HashBridge.STATUS_CANCELLED -> HashResult.Cancelled

                HashBridge.STATUS_IO_ERROR -> HashResult.Error(HashResult.Error.Reason.IO_ERROR, errno)

                HashBridge.STATUS_INVALID_ARGUMENT ->
                    HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, errno)

                else -> HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, errno)
            }
        }
    }
}
