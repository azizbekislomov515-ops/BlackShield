package com.blackshield.core.data.repository

import com.blackshield.core.data.db.ScanResultDao
import com.blackshield.core.data.db.SignatureBulkWriter
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.SignatureAlgorithmEntry
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SignatureRepositoryTest {
    private val dao = FakeSignatureDao()
    private val transactions = CountingTransactionRunner()
    private val repository = OfflineSignatureRepository(dao, dao, transactions)

    @Test
    fun `insertAll normalises case and rejects malformed hashes`() = runTest {
        val result =
            repository.insertAll(
                sequenceOf(
                    sig("AB".repeat(32)), // upper case: accepted, stored lower case
                    sig("ab".repeat(16), SignatureAlgorithm.MD5),
                    sig("zz".repeat(32)), // not hex
                    sig("ab".repeat(20)), // SHA-1 length labelled as SHA-256
                    sig("")
                )
            )

        assertEquals(ImportResult(inserted = 2, rejected = 3), result)
        assertTrue(dao.rows.containsKey("ab".repeat(32)))
        assertTrue(repository.isKnownMalicious("AB".repeat(32)))
    }

    @Test
    fun `insertAll writes in transactions of batchSize without materialising the input`() = runTest {
        var produced = 0
        val lazy = generateSequence(0) { it + 1 }.take(12_345).map {
            produced++
            sig(hex64(it))
        }

        val result = repository.insertAll(lazy, batchSize = 1_000)

        assertEquals(12_345, result.inserted)
        assertEquals(12_345, produced)
        assertEquals("13 batches: 12 full + 1 partial", 13, transactions.count)
        assertEquals(1_000, dao.largestBatch)
        assertEquals(12_345L, repository.count())
    }

    @Test
    fun `findMatches looks up in chunks below the SQLite variable limit`() = runTest {
        repository.insertAll((0 until 2_000).asSequence().map { sig(hex64(it)) })
        val queried = (0 until 2_500).map { hex64(it).uppercase() } // 2,000 known + 500 unknown

        val matches = repository.findMatches(queried)

        assertEquals(2_000, matches.size)
        assertEquals(listOf(900, 900, 700), dao.lookupSizes)
        assertTrue(dao.lookupSizes.all { it <= SignatureDao.SQLITE_MAX_VARIABLES })
    }

    @Test
    fun `findMatches with no hashes does not query`() = runTest {
        assertEquals(emptyMap<String, MalwareSignature>(), repository.findMatches(emptyList()))
        assertTrue(dao.lookupSizes.isEmpty())
    }

    @Test
    fun `algorithmsInUse reports only algorithms with signatures`() = runTest {
        repository.insertAll(sequenceOf(sig(hex64(1)), sig("cd".repeat(20), SignatureAlgorithm.SHA1)))

        assertEquals(setOf(SignatureAlgorithm.SHA256, SignatureAlgorithm.SHA1), repository.algorithmsInUse())
    }

    @Test
    fun `isKnownMalicious is false for unknown hashes`() = runTest {
        assertFalse(repository.isKnownMalicious(hex64(42)))
    }

    @Test
    fun `retainOnly deletes results of uninstalled packages in chunks`() = runTest {
        val resultDao = FakeScanResultDao((0 until 2_000).map { "pkg.$it" })
        val results = OfflineScanResultRepository(resultDao)

        results.retainOnly(setOf("pkg.0", "pkg.1"))

        assertEquals(listOf("pkg.0", "pkg.1"), resultDao.packages)
        assertTrue(resultDao.deleteSizes.all { it <= SignatureDao.SQLITE_MAX_VARIABLES })
    }

    private fun sig(hash: String, algorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256) = MalwareSignature(
        hash,
        algorithm,
        family = "Test.Family",
        source = "unit-test",
        severity = Severity.HIGH,
        addedAt = 1
    )

    private fun hex64(i: Int) = "%064x".format(i)

    private class CountingTransactionRunner : TransactionRunner {
        var count = 0

        override suspend fun <R> inTransaction(block: suspend () -> R): R {
            count++
            return block()
        }
    }

    private class FakeSignatureDao :
        SignatureDao,
        SignatureBulkWriter {
        val rows = LinkedHashMap<String, MalwareSignature>()
        val lookupSizes = mutableListOf<Int>()
        var largestBatch = 0
        private val algorithms = mutableSetOf<SignatureAlgorithm>()

        override suspend fun upsertAll(signatures: List<MalwareSignature>) {
            largestBatch = maxOf(largestBatch, signatures.size)
            signatures.forEach { rows[it.hash] = it }
        }

        override suspend fun exists(hash: String) = rows.containsKey(hash)

        override suspend fun findByHashes(hashes: List<String>): List<MalwareSignature> {
            lookupSizes += hashes.size
            return hashes.mapNotNull { rows[it] }
        }

        override suspend fun markAlgorithms(entries: List<SignatureAlgorithmEntry>) {
            algorithms += entries.map { it.algorithm }
        }

        override suspend fun algorithms() = algorithms.toList()

        override suspend fun count() = rows.size.toLong()

        override suspend fun deleteBySource(source: String): Int {
            val doomed = rows.values.filter { it.source == source }.map { it.hash }
            doomed.forEach(rows::remove)
            return doomed.size
        }
    }

    private class FakeScanResultDao(initial: List<String>) : ScanResultDao {
        val packages = initial.toMutableList()
        val deleteSizes = mutableListOf<Int>()

        override suspend fun upsert(result: ScanResult) = Unit

        override fun observeAll(): Flow<List<ScanResult>> = flowOf(emptyList())

        override suspend fun find(packageName: String): ScanResult? = null

        override suspend fun packageNames() = packages.toList()

        override suspend fun delete(packageNames: List<String>) {
            deleteSizes += packageNames.size
            packages.removeAll(packageNames.toSet())
        }
    }
}
