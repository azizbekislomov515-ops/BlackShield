package com.blackshield.core.data.repository

import com.blackshield.core.data.db.SignatureBulkWriter
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.SignatureAlgorithmEntry
import javax.inject.Inject

/** Result of a bulk import. */
data class ImportResult(val inserted: Int, val rejected: Int)

interface SignatureRepository {
    suspend fun isKnownMalicious(hash: String): Boolean

    /** Batch lookup: the signatures among [hashes] (any case), keyed by lower-case hash. */
    suspend fun findMatches(hashes: Collection<String>): Map<String, MalwareSignature>

    /** Algorithms with at least one signature, so scanners only compute digests that can match. */
    suspend fun algorithmsInUse(): Set<SignatureAlgorithm>

    /**
     * Streams [signatures] into the store in transactions of [batchSize] rows. Hashes are
     * normalised to lower case; entries whose hash is not valid hex of the algorithm's length are
     * rejected. Existing hashes are replaced. Memory use is bounded by [batchSize], so a
     * multi-million-row feed can be imported from a lazy [Sequence].
     */
    suspend fun insertAll(signatures: Sequence<MalwareSignature>, batchSize: Int = DEFAULT_BATCH_SIZE): ImportResult

    suspend fun count(): Long

    companion object {
        const val DEFAULT_BATCH_SIZE = 20_000
    }
}

/** Runs a block in one database transaction. Abstracted so the repository is unit-testable. */
interface TransactionRunner {
    suspend fun <R> inTransaction(block: suspend () -> R): R
}

internal class OfflineSignatureRepository
@Inject
constructor(
    private val dao: SignatureDao,
    private val writer: SignatureBulkWriter,
    private val transactions: TransactionRunner
) : SignatureRepository {
    override suspend fun isKnownMalicious(hash: String): Boolean = dao.exists(hash.lowercase())

    override suspend fun findMatches(hashes: Collection<String>): Map<String, MalwareSignature> {
        if (hashes.isEmpty()) return emptyMap()
        val matches = HashMap<String, MalwareSignature>()
        for (chunk in hashes.map { it.lowercase() }.distinct().chunked(SignatureDao.SQLITE_MAX_VARIABLES)) {
            dao.findByHashes(chunk).associateByTo(matches) { it.hash }
        }
        return matches
    }

    override suspend fun algorithmsInUse(): Set<SignatureAlgorithm> = dao.algorithms().toSet()

    override suspend fun insertAll(signatures: Sequence<MalwareSignature>, batchSize: Int): ImportResult {
        require(batchSize > 0) { "batchSize must be positive" }
        var inserted = 0
        var rejected = 0
        val batch = ArrayList<MalwareSignature>(batchSize)

        suspend fun flush() {
            if (batch.isEmpty()) return
            // Sorted keys touch neighbouring index pages instead of random ones.
            val rows = batch.sortedBy { it.hash }
            val algorithms = rows.mapTo(HashSet()) { it.algorithm }.map(::SignatureAlgorithmEntry)
            transactions.inTransaction {
                writer.upsertAll(rows)
                dao.markAlgorithms(algorithms)
            }
            inserted += rows.size
            batch.clear()
        }

        for (signature in signatures) {
            val normalized = signature.normalizedOrNull()
            if (normalized == null) {
                rejected++
                continue
            }
            batch += normalized
            if (batch.size == batchSize) flush()
        }
        flush()
        return ImportResult(inserted, rejected)
    }

    override suspend fun count(): Long = dao.count()
}

private val HEX = Regex("^[0-9a-f]+$")

internal fun MalwareSignature.normalizedOrNull(): MalwareSignature? {
    val lower = hash.trim().lowercase()
    return if (lower.length == algorithm.hexLength && HEX.matches(lower)) copy(hash = lower) else null
}
