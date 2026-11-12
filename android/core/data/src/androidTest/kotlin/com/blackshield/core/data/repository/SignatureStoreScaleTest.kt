package com.blackshield.core.data.repository

import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.blackshield.core.data.db.BlackShieldDatabase
import com.blackshield.core.data.db.MultiRowSignatureWriter
import com.blackshield.core.data.db.TestDatabases
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** 1,000,000 SHA-256 signatures on a real on-device database: import time, lookups, file size. */
@LargeTest
@RunWith(AndroidJUnit4::class)
class SignatureStoreScaleTest {
    private lateinit var db: BlackShieldDatabase
    private lateinit var repository: SignatureRepository

    @Before
    fun setUp() {
        TestDatabases.delete(DB)
        db = TestDatabases.open(DB)
        repository =
            OfflineSignatureRepository(db.signatureDao(), MultiRowSignatureWriter(db), TestDatabases.transactions(db))
    }

    @After
    fun tearDown() {
        db.close()
        TestDatabases.delete(DB)
    }

    @Test
    fun oneMillionSignatures() = runBlocking {
        // Lazily generated: the import never holds more than one batch in memory.
        val feed = (0 until ROWS).asSequence().map { signature(it) }
        val importMs = timed { assertEquals(ImportResult(ROWS, 0), repository.insertAll(feed)) }
        assertEquals(ROWS.toLong(), repository.count())

        // Batch lookup: 1,000 digests, half of them known (as for ~100 apps x base+splits).
        val batch = (0 until 1_000).map {
            if (it % 2 ==
                0
            ) {
                hex(it * 997)
            } else {
                "f".repeat(64 - 4) + "%04x".format(it)
            }
        }
        lateinit var matches: Map<String, MalwareSignature>
        val batchMs = timed { matches = repository.findMatches(batch) }
        assertEquals(500, matches.size)

        val singleMs = timed { repeat(SINGLE_LOOKUPS) { repository.isKnownMalicious(hex(it * 31)) } }

        val fileMb = TestDatabases.context.getDatabasePath(DB).length() / (1024.0 * 1024.0)
        Log.i(
            TAG,
            "1M signatures: import ${importMs}ms, batch lookup of 1000 ${batchMs}ms, " +
                "$SINGLE_LOOKUPS single lookups ${singleMs}ms (${singleMs * 1000.0 / SINGLE_LOOKUPS}us each), " +
                "db file %.1f MB".format(fileMb)
        )

        assertTrue("batch lookup took ${batchMs}ms", batchMs < 1_000)
        assertTrue("single lookups took ${singleMs}ms", singleMs < 5_000)
    }

    private inline fun timed(block: () -> Unit): Long {
        val start = SystemClock.elapsedRealtime()
        block()
        return SystemClock.elapsedRealtime() - start
    }

    // Cheap hex (String.format costs ~6 us/row on debuggable ART and would dominate the timing).
    private fun hex(i: Int) = java.lang.Long.toHexString(i.toLong() * 2_654_435_761L).padStart(64, '0')

    private fun signature(i: Int) =
        MalwareSignature(hex(i), SignatureAlgorithm.SHA256, "Scale.Family${i % 100}", "scale-test", Severity.HIGH, 0)

    private companion object {
        const val TAG = "SignatureStoreScale"
        const val DB = "scale-test.db"
        const val ROWS = 1_000_000
        const val SINGLE_LOOKUPS = 10_000
    }
}
