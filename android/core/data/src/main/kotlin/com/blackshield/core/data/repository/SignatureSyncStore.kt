package com.blackshield.core.data.repository

import com.blackshield.core.data.db.SignatureBulkWriter
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.db.SignatureSyncDao
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.SignatureAlgorithmEntry
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow

/** Receives one batch of signatures inside a [SignatureSyncStore.replaceAll] transaction. */
fun interface SignatureBatchSink {
    suspend fun write(batch: List<MalwareSignature>)
}

/** The store's row count did not match what the payload promised; the transaction was rolled back. */
class StoreVerificationException(message: String) : IllegalStateException(message)

/**
 * Local side of signature sync. Every write is one database transaction: a crash, a killed
 * process or an exception anywhere inside leaves the table exactly as it was before the call.
 *
 * Synced rows carry [SOURCE]. Rows from other sources (debug seeds) are never deleted by sync;
 * an addition for the same hash replaces such a row and takes it over.
 */
interface SignatureSyncStore {
    /** Rows owned by sync; compared with the server's count to detect a damaged store. */
    suspend fun syncedCount(): Long

    /** All signatures, any source. */
    fun observeSignatureCount(): Flow<Long>

    /** Upserts [upserts] and deletes the synced rows in [removals], atomically. */
    suspend fun applyDelta(upserts: List<MalwareSignature>, removals: Collection<String>)

    /**
     * Replaces every synced row, atomically: deletes them, then lets [producer] write the new set
     * in batches. The producer returns the number of rows it promised to write; when the store
     * then holds a different number of synced rows (duplicates, a short read), everything is
     * rolled back with [StoreVerificationException]. Any exception from [producer] also rolls
     * back.
     */
    suspend fun replaceAll(producer: suspend (SignatureBatchSink) -> Long): Long

    companion object {
        /** `source` of rows that came from the BlackShield backend. */
        const val SOURCE = "blackshield-cloud"
    }
}

internal class RoomSignatureSyncStore
@Inject
constructor(
    private val syncDao: SignatureSyncDao,
    private val signatureDao: SignatureDao,
    private val writer: SignatureBulkWriter,
    private val transactions: TransactionRunner
) : SignatureSyncStore {
    override suspend fun syncedCount(): Long = syncDao.countFromSource(SignatureSyncStore.SOURCE)

    override fun observeSignatureCount(): Flow<Long> = syncDao.observeCount()

    override suspend fun applyDelta(upserts: List<MalwareSignature>, removals: Collection<String>) {
        if (upserts.isEmpty() && removals.isEmpty()) return
        transactions.inTransaction {
            for (chunk in removals.chunked(SignatureDao.SQLITE_MAX_VARIABLES - 1)) {
                syncDao.deleteFromSource(SignatureSyncStore.SOURCE, chunk)
            }
            writeBatch(upserts)
        }
    }

    override suspend fun replaceAll(producer: suspend (SignatureBatchSink) -> Long): Long = transactions.inTransaction {
        signatureDao.deleteBySource(SignatureSyncStore.SOURCE)
        val expected = producer(SignatureBatchSink(::writeBatch))
        val actual = syncDao.countFromSource(SignatureSyncStore.SOURCE)
        if (actual != expected) {
            throw StoreVerificationException("expected $expected synced signatures, store holds $actual")
        }
        actual
    }

    private suspend fun writeBatch(batch: List<MalwareSignature>) {
        if (batch.isEmpty()) return
        require(
            batch.all {
                it.source == SignatureSyncStore.SOURCE
            }
        ) { "synced rows must use SignatureSyncStore.SOURCE" }
        // Sorted keys touch neighbouring index pages instead of random ones.
        writer.upsertAll(batch.sortedBy { it.hash })
        signatureDao.markAlgorithms(batch.mapTo(HashSet()) { it.algorithm }.map(::SignatureAlgorithmEntry))
    }
}
