package com.blackshield.core.scanner.hash

import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/** Acceptance checks on a 500 MiB file: flat memory and cancellation within 200 ms. */
@LargeTest
@RunWith(AndroidJUnit4::class)
class NativeHasherLargeFileTest {
    private val hasher = NativeHasher()

    @Test
    fun memoryStaysFlatWhileHashing500MiB() = runBlocking {
        val peak = AtomicLong()
        val sampler =
            launch(Dispatchers.Default) {
                while (isActive) {
                    peak.accumulateAndGet(TestFiles.rssKib(), ::maxOf)
                    delay(SAMPLE_INTERVAL_MS)
                }
            }
        delay(BASELINE_SETTLE_MS) // let the sampler start before taking the baseline
        Runtime.getRuntime().gc()
        val baseline = TestFiles.rssKib()
        peak.set(baseline)

        val result = hasher.hashFile(hugeFile.path)
        sampler.cancel()
        sampler.join()

        val growth = peak.get() - baseline
        Log.i(TAG, "500 MiB SHA-256: baseline RSS $baseline KiB, peak ${peak.get()} KiB, growth $growth KiB")
        assertEquals(HashResult.Success(HashAlgorithm.SHA256, hugeSha256, HUGE_SIZE), result)
        // The file is 512,000 KiB; streaming keeps growth to the chunk buffer plus runtime noise.
        assertTrue("RSS grew by $growth KiB", growth < MAX_RSS_GROWTH_KIB)
    }

    @Test
    fun cancellingTheCoroutineStopsWithin200ms() = runBlocking {
        for (algorithm in HashAlgorithm.entries) {
            val job = async(Dispatchers.Default) { hasher.hashFile(hugeFile.path, algorithm) }
            delay(RUN_BEFORE_CANCEL_MS)
            assertTrue("$algorithm still hashing when cancelled", job.isActive)
            val cancelledAt = SystemClock.elapsedRealtimeNanos()
            job.cancel()
            job.join() // completes only after the native call has returned
            val latencyMs = (SystemClock.elapsedRealtimeNanos() - cancelledAt) / NANOS_PER_MS

            Log.i(TAG, "coroutine cancel ($algorithm): native call returned after $latencyMs ms")
            assertTrue("$algorithm job cancelled", job.isCancelled)
            assertTrue("$algorithm took $latencyMs ms", latencyMs < CANCEL_DEADLINE_MS)
        }
    }

    @Test
    fun cancellationSignalStopsWithin200msAndReturnsCancelled() = runBlocking {
        val signal = CancellationSignal()
        val pending = async(Dispatchers.Default) { hasher.hashFile(hugeFile.path, cancellationSignal = signal) }
        delay(RUN_BEFORE_CANCEL_MS)
        val cancelledAt = SystemClock.elapsedRealtimeNanos()
        signal.cancel()
        val result = pending.await()
        val latencyMs = (SystemClock.elapsedRealtimeNanos() - cancelledAt) / NANOS_PER_MS

        Log.i(TAG, "CancellationSignal: returned after $latencyMs ms")
        assertEquals(HashResult.Cancelled, result)
        assertTrue("took $latencyMs ms", latencyMs < CANCEL_DEADLINE_MS)
    }

    @Test
    fun cancellingAStalledPipeStopsWithin200ms() = runBlocking {
        val (read, write) = ParcelFileDescriptor.createPipe() // writer never writes
        read.use {
            write.use {
                val job = async(Dispatchers.Default) { hasher.hashFd(read) }
                delay(PIPE_RUN_BEFORE_CANCEL_MS)
                assertTrue("still blocked on the pipe when cancelled", job.isActive)
                val cancelledAt = SystemClock.elapsedRealtimeNanos()
                job.cancel()
                job.join()
                val latencyMs = (SystemClock.elapsedRealtimeNanos() - cancelledAt) / NANOS_PER_MS

                Log.i(TAG, "stalled pipe cancel: returned after $latencyMs ms")
                assertTrue("job cancelled", job.isCancelled)
                assertTrue("took $latencyMs ms", latencyMs < CANCEL_DEADLINE_MS)
            }
        }
    }

    companion object {
        private const val TAG = "NativeHasherLargeFile"
        private const val HUGE_SIZE = 500 * TestFiles.MIB
        private const val MAX_RSS_GROWTH_KIB = 8 * 1024L
        private const val CANCEL_DEADLINE_MS = 200L
        private const val RUN_BEFORE_CANCEL_MS = 150L

        // Deliberately not a multiple of the native 50 ms poll interval, so the cancel lands
        // mid-poll instead of right as a poll times out.
        private const val PIPE_RUN_BEFORE_CANCEL_MS = 130L
        private const val SAMPLE_INTERVAL_MS = 5L
        private const val BASELINE_SETTLE_MS = 100L
        private const val NANOS_PER_MS = 1_000_000L

        private lateinit var hugeFile: File
        private lateinit var hugeSha256: String

        @JvmStatic
        @BeforeClass
        fun createFile() {
            val (file, digests) = TestFiles.writePattern("huge.bin", HUGE_SIZE, listOf(HashAlgorithm.SHA256))
            hugeFile = file
            hugeSha256 = digests.getValue(HashAlgorithm.SHA256)
        }

        @JvmStatic
        @AfterClass
        fun deleteFile() {
            hugeFile.delete()
        }
    }
}
