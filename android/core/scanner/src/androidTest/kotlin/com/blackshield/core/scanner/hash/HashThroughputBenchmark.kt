package com.blackshield.core.scanner.hash

import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Simple timing benchmark: hashes a 256 MiB file (hot page cache) with every algorithm through
 * the full Kotlin -> JNI -> C++ path and, for reference, with java.security.MessageDigest.
 * Results go to logcat (tag HashThroughput) and the instrumentation status output.
 * Record them in docs/performance.md.
 */
@LargeTest
@RunWith(AndroidJUnit4::class)
class HashThroughputBenchmark {
    @Test
    fun throughput() = runBlocking {
        val hasher = NativeHasher()
        val report = StringBuilder("device=${Build.MANUFACTURER} ${Build.MODEL} abi=${Build.SUPPORTED_ABIS[0]}\n")
        for (algorithm in HashAlgorithm.entries) {
            hasher.hashFile(file.path, algorithm) // warm-up
            val native = bestOf { assertTrue(hasher.hashFile(file.path, algorithm) is HashResult.Success) }
            val jca = bestOf { messageDigest(algorithm) }
            report.append(
                "%-7s native %7.1f MiB/s   MessageDigest %7.1f MiB/s\n".format(
                    algorithm.name,
                    SIZE_MIB / native,
                    SIZE_MIB / jca
                )
            )
        }
        Log.i(TAG, report.toString())
        InstrumentationRegistry.getInstrumentation().sendStatus(
            0,
            Bundle().apply {
                putString("stream", "\n$report")
            }
        )
    }

    /** Best wall time in seconds over [RUNS] runs. */
    private inline fun bestOf(block: () -> Unit): Double = (1..RUNS).minOf {
        val start = SystemClock.elapsedRealtimeNanos()
        block()
        (SystemClock.elapsedRealtimeNanos() - start) / 1e9
    }

    private fun messageDigest(algorithm: HashAlgorithm) {
        val md =
            MessageDigest.getInstance(
                when (algorithm) {
                    HashAlgorithm.MD5 -> "MD5"
                    HashAlgorithm.SHA1 -> "SHA-1"
                    HashAlgorithm.SHA256 -> "SHA-256"
                }
            )
        val buffer = ByteArray(CHUNK)
        file.inputStream().use { input ->
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                md.update(buffer, 0, n)
            }
        }
        md.digest()
    }

    companion object {
        private const val TAG = "HashThroughput"
        private const val SIZE_MIB = 256.0
        private const val RUNS = 3
        private const val CHUNK = 64 * 1024

        private lateinit var file: File

        @JvmStatic
        @BeforeClass
        fun createFile() {
            file = TestFiles.writePattern("bench.bin", 256 * TestFiles.MIB, emptyList()).first
        }

        @JvmStatic
        @AfterClass
        fun deleteFile() {
            file.delete()
        }
    }
}
