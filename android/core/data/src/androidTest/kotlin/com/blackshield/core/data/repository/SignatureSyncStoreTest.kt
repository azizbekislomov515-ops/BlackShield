package com.blackshield.core.data.repository

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.blackshield.core.data.db.BlackShieldDatabase
import com.blackshield.core.data.db.MultiRowSignatureWriter
import com.blackshield.core.data.db.TestDatabases
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Atomicity of sync writes against the production database configuration. */
@RunWith(AndroidJUnit4::class)
class SignatureSyncStoreTest {
    private lateinit var db: BlackShieldDatabase
    private lateinit var store: SignatureSyncStore
    private lateinit var signatures: SignatureRepository

    @Before
    fun setUp() {
        TestDatabases.delete(NAME)
        db = TestDatabases.open(NAME)
        val transactions = TestDatabases.transactions(db)
        val writer = MultiRowSignatureWriter(db)
        store = RoomSignatureSyncStore(db.signatureSyncDao(), db.signatureDao(), writer, transactions)
        signatures = OfflineSignatureRepository(db.signatureDao(), writer, transactions)
    }

    @After
    fun tearDown() {
        db.close()
        TestDatabases.delete(NAME)
    }

    @Test
    fun applyDeltaUpsertsAndRemovesSyncedRowsOnly() = runTest {
        store.replaceAll { sink ->
            sink.write(listOf(synced(1), synced(2)))
            2
        }
        signatures.insertAll(sequenceOf(seed(3)))

        store.applyDelta(
            upserts = listOf(synced(4), synced(1, Severity.CRITICAL)),
            removals = listOf(hash(2), seedHash(3))
        )

        assertEquals(setOf(hash(1), hash(4)), syncedHashes())
        assertEquals(Severity.CRITICAL, find(hash(1))!!.severity)
        assertNotNull("rows from other sources are never removed by sync", find(seedHash(3)))
        assertEquals(2L, store.syncedCount())
        assertEquals(3L, store.observeSignatureCount().first())
        assertTrue(SignatureAlgorithm.MD5 in signatures.algorithmsInUse())
    }

    @Test
    fun replaceAllSwapsTheSyncedSetAndKeepsOtherSources() = runTest {
        store.replaceAll { sink ->
            sink.write(listOf(synced(1), synced(2)))
            2
        }
        signatures.insertAll(sequenceOf(seed(9)))

        val count = store.replaceAll { sink ->
            sink.write(listOf(synced(5)))
            sink.write(listOf(synced(6), synced(7)))
            3
        }

        assertEquals(3L, count)
        assertEquals(setOf(hash(5), hash(6), hash(7)), syncedHashes())
        assertNotNull(find(seedHash(9)))
    }

    @Test
    fun failureInsideReplaceAllRollsEverythingBack() = runTest {
        store.replaceAll { sink ->
            sink.write(listOf(synced(1), synced(2)))
            2
        }

        assertFails<IllegalStateException> {
            store.replaceAll { sink ->
                sink.write((10 until 1_010).map(::synced)) // a thousand rows already written...
                error("download corrupted") // ...then the payload turns out to be bad
            }
        }

        assertEquals(setOf(hash(1), hash(2)), syncedHashes())
    }

    @Test
    fun countMismatchRollsBack() = runTest {
        store.replaceAll { sink ->
            sink.write(listOf(synced(1)))
            1
        }

        assertFails<StoreVerificationException> {
            store.replaceAll { sink ->
                sink.write(listOf(synced(2), synced(2))) // duplicate: one row stored
                2
            }
        }

        assertEquals(setOf(hash(1)), syncedHashes())
    }

    @Test
    fun failureInsideApplyDeltaRollsBack() = runTest {
        store.replaceAll { sink ->
            sink.write(listOf(synced(1), synced(2)))
            2
        }
        val bad = synced(3).copy(source = "elsewhere") // rejected after the removals ran

        assertFails<IllegalArgumentException> { store.applyDelta(upserts = listOf(bad), removals = listOf(hash(1))) }

        assertEquals(setOf(hash(1), hash(2)), syncedHashes())
        assertNull(find(hash(3)))
    }

    private suspend fun find(hash: String) = signatures.findMatches(listOf(hash))[hash]

    private suspend fun syncedHashes(): Set<String> = signatures
        .findMatches((0..1_100).map(::hash))
        .values
        .filter { it.source == SignatureSyncStore.SOURCE }
        .mapTo(HashSet()) { it.hash }

    private suspend inline fun <reified T : Throwable> assertFails(block: () -> Unit) {
        val error = runCatching { block() }.exceptionOrNull()
        assertTrue("expected ${T::class.simpleName}, got $error", error is T)
    }

    private companion object {
        const val NAME = "sync-store-test.db"

        fun hash(n: Int) = "%064x".format(n)

        fun synced(n: Int, severity: Severity = Severity.HIGH) =
            MalwareSignature(hash(n), SignatureAlgorithm.SHA256, "Family$n", SignatureSyncStore.SOURCE, severity, 0)

        fun seedHash(n: Int) = "%032x".format(n)

        fun seed(n: Int) = MalwareSignature(seedHash(n), SignatureAlgorithm.MD5, "Seed", "debug-seed", Severity.HIGH, 0)
    }
}
