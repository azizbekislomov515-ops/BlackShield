package com.blackshield.core.scanner.hash

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** JVM tests of the Kotlin wrapper logic, using a fake bridge (no native library). */
class NativeHasherTest {
    @Test
    fun `maps every native status to a HashResult`() {
        val cases =
            mapOf(
                HashBridge.STATUS_NOT_FOUND to HashResult.FileNotFound,
                HashBridge.STATUS_PERMISSION_DENIED to HashResult.PermissionDenied,
                HashBridge.STATUS_CANCELLED to HashResult.Cancelled,
                HashBridge.STATUS_IO_ERROR to HashResult.Error(HashResult.Error.Reason.IO_ERROR, 21),
                HashBridge.STATUS_INVALID_ARGUMENT to HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, 21),
                HashBridge.STATUS_INTERNAL_ERROR to HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, 21),
                99L to HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, 21)
            )
        cases.forEach { (status, expected) ->
            val actual = NativeHasher.toHashResult(HashAlgorithm.SHA256, null, longArrayOf(status, 21, 0))
            assertEquals("status $status", expected, actual)
        }
    }

    @Test
    fun `success carries digest, algorithm and byte count`() = runBlocking {
        val bridge = FakeBridge(onHash = { _, result -> succeed(result, bytes = 3) })
        val hasher = NativeHasher(bridge, Dispatchers.IO)

        val result = hasher.hashFile("/data/x", HashAlgorithm.MD5)

        assertEquals(HashResult.Success(HashAlgorithm.MD5, "abc123", 3), result)
        assertEquals(HashAlgorithm.MD5.nativeId, bridge.lastAlgorithm)
        assertTrue("token released", bridge.liveTokens.isEmpty())
    }

    @Test
    fun `ok status without a digest is an internal error`() {
        val result = NativeHasher.toHashResult(HashAlgorithm.SHA1, null, longArrayOf(HashBridge.STATUS_OK, 0, 0))

        assertEquals(HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, 0), result)
    }

    @Test
    fun `failure to allocate a cancel token is reported, not thrown`() = runBlocking {
        val bridge = FakeBridge(tokenToIssue = HashBridge.NO_CANCEL_TOKEN)

        val result = NativeHasher(bridge, Dispatchers.IO).hashFile("/data/x")

        assertEquals(HashResult.Error(HashResult.Error.Reason.INTERNAL_ERROR, 0), result)
    }

    @Test
    fun `cancelling the coroutine sets the native flag and waits for the native call`() = runBlocking {
        val started = CountDownLatch(1)
        val bridge =
            FakeBridge(onHash = { token, result ->
                started.countDown()
                // Simulates the native loop: blocks until the flag for this token is set.
                check(cancelled(token).await(5, TimeUnit.SECONDS)) { "never cancelled" }
                result[HashBridge.RESULT_STATUS] = HashBridge.STATUS_CANCELLED
                nativeReturned.countDown()
                null
            })
        val hasher = NativeHasher(bridge, Dispatchers.IO)

        val job = async(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) { hasher.hashFile("/big") }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        withTimeout(5_000) {
            job.cancel()
            job.join()
        }

        assertTrue("job cancelled", job.isCancelled)
        assertEquals("native call finished before the job completed", 0, bridge.nativeReturned.count)
        assertTrue("token released after native return", bridge.liveTokens.isEmpty())
    }

    private fun succeed(result: LongArray, bytes: Long): String {
        result[HashBridge.RESULT_STATUS] = HashBridge.STATUS_OK
        result[HashBridge.RESULT_BYTES] = bytes
        return "abc123"
    }

    private class FakeBridge(
        private val tokenToIssue: Long = 42L,
        private val onHash: FakeBridge.(token: Long, result: LongArray) -> String? = { _, _ -> null }
    ) : HashBridge {
        val liveTokens: MutableSet<Long> = java.util.concurrent.ConcurrentHashMap.newKeySet()
        val nativeReturned = CountDownLatch(1)
        private val cancelLatches = java.util.concurrent.ConcurrentHashMap<Long, CountDownLatch>()

        @Volatile
        var lastAlgorithm: Int = -1

        fun cancelled(token: Long): CountDownLatch = cancelLatches.getOrPut(token) { CountDownLatch(1) }

        override fun hashFile(path: String, algorithm: Int, cancelToken: Long, result: LongArray?): String? {
            lastAlgorithm = algorithm
            return onHash(cancelToken, requireNotNull(result))
        }

        override fun hashFd(fd: Int, algorithm: Int, cancelToken: Long, result: LongArray?): String? =
            hashFile("fd:$fd", algorithm, cancelToken, result)

        override fun createCancelToken(): Long = tokenToIssue.also { if (it != 0L) liveTokens += it }

        override fun cancel(token: Long) {
            cancelled(token).countDown()
        }

        override fun releaseCancelToken(token: Long) {
            liveTokens -= token
        }
    }
}
