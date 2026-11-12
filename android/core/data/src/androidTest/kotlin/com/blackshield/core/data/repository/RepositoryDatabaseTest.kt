package com.blackshield.core.data.repository

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.blackshield.core.data.db.BlackShieldDatabase
import com.blackshield.core.data.db.MultiRowSignatureWriter
import com.blackshield.core.data.db.TestDatabases
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import java.time.Clock
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Repositories against a real SQLite database on the device. */
@RunWith(AndroidJUnit4::class)
class RepositoryDatabaseTest {
    private lateinit var db: BlackShieldDatabase
    private lateinit var signatures: SignatureRepository
    private lateinit var results: ScanResultRepository

    @Before
    fun setUp() {
        TestDatabases.delete(DB)
        db = TestDatabases.open(DB)
        signatures =
            OfflineSignatureRepository(db.signatureDao(), MultiRowSignatureWriter(db), TestDatabases.transactions(db))
        results = OfflineScanResultRepository(db.scanResultDao())
    }

    @After
    fun tearDown() {
        db.close()
        TestDatabases.delete(DB)
    }

    @Test
    fun signatureLookupIsCaseInsensitiveAndReplacesDuplicates() = runBlocking {
        signatures.insertAll(sequenceOf(sig("AA".repeat(32), "Old.Family"), sig("aa".repeat(32), "New.Family")))

        assertEquals(1L, signatures.count())
        assertTrue(signatures.isKnownMalicious("Aa".repeat(32)))
        assertEquals("New.Family", signatures.findMatches(listOf("AA".repeat(32))).values.single().family)
        assertFalse(signatures.isKnownMalicious("bb".repeat(32)))
    }

    @Test
    fun hashLookupUsesThePrimaryKeyIndex() {
        val plan =
            db.openHelper.readableDatabase
                .query("EXPLAIN QUERY PLAN SELECT * FROM malware_signatures WHERE hash IN ('a', 'b')")
                .use { cursor -> buildString { while (cursor.moveToNext()) append(cursor.getString(3)) } }

        assertTrue("plan: $plan", plan.contains("USING INDEX sqlite_autoindex_malware_signatures_1"))
    }

    @Test
    fun resultsPersistAcrossDatabaseRestart() = runBlocking {
        val result =
            ScanResult(
                packageName = "com.example",
                appLabel = "Example",
                versionCode = 7,
                apkSha256 = "cd".repeat(32),
                verdict = Verdict.SUSPICIOUS,
                riskScore = 60,
                reasons = listOf(ScanReason(ScanReason.Code.SMS_ACCESS, "READ_SMS", 20)),
                scannedAt = 123
            )
        results.save(result)
        results.save(result.copy(versionCode = 8)) // rescan replaces, does not duplicate
        db.close()

        db = TestDatabases.open(DB) // "app restart"
        val reloaded = OfflineScanResultRepository(db.scanResultDao()).observeLatest().first()

        assertEquals(listOf(result.copy(versionCode = 8)), reloaded.map { it.copy(id = 0) })
    }

    @Test
    fun allowListRoundTrip() = runBlocking {
        val allowList = OfflineAllowListRepository(db.allowListDao(), Clock.systemUTC())
        allowList.allow("com.trusted")
        assertEquals(setOf("com.trusted"), allowList.observeAllowedPackages().first())
        allowList.remove("com.trusted")
        assertEquals(emptySet<String>(), allowList.allowedPackages())
    }

    private fun sig(hash: String, family: String) =
        MalwareSignature(hash, SignatureAlgorithm.SHA256, family, "test", Severity.HIGH, 0)

    private companion object {
        const val DB = "repository-test.db"
    }
}
