package com.blackshield.core.sync

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.InvalidPayloadException
import com.blackshield.core.network.model.SignatureDeltaResponse
import com.blackshield.core.network.model.SignatureVersionResponse
import com.blackshield.core.sync.di.SyncWorkDirectory
import java.io.File
import java.time.Clock
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import timber.log.Timber

data class SyncConfig(
    /** Delta page size requested from the server (server default 5,000, cap 20,000). */
    val pageSize: Int = 5_000,
    /** A delta with more changes than this is abandoned for a full snapshot (bounds memory). */
    val maxDeltaEntries: Int = 100_000,
    /** Rows per write batch when applying a snapshot. */
    val snapshotBatchSize: Int = 20_000,
    /** A larger snapshot download is refused, so a broken server cannot fill the disk. */
    val maxSnapshotBytes: Long = DEFAULT_MAX_SNAPSHOT_BYTES
) {
    companion object {
        const val DEFAULT_MAX_SNAPSHOT_BYTES = 512L * 1024 * 1024
    }
}

enum class FullSyncReason {
    /** Nothing synced yet (or the sync state was lost). */
    FIRST_SYNC,

    /** The server cannot serve a delta from our version: 409/410, or our version is ahead of it. */
    SERVER_RESET,

    /** The delta is too large to hold; the snapshot is cheaper. */
    DELTA_TOO_LARGE,

    /** The local synced row count disagrees with the server's: the store is damaged. */
    STORE_MISMATCH
}

sealed interface SyncOutcome {
    data class UpToDate(val version: Long) : SyncOutcome

    data class DeltaApplied(val fromVersion: Long, val toVersion: Long, val upserts: Int, val removals: Int) :
        SyncOutcome

    data class SnapshotApplied(val version: Long, val count: Long, val reason: FullSyncReason) : SyncOutcome
}

sealed interface SyncResult {
    data class Success(val outcome: SyncOutcome) : SyncResult

    data class Failure(val error: SyncErrorKind, val cause: Throwable) : SyncResult
}

/**
 * Brings the local signature store up to the server's latest version (docs/sync-protocol.md).
 *
 * Consistency: all network I/O happens before any database write. A delta's pages are collected
 * and validated in memory, a snapshot is downloaded to a file; then a single transaction applies
 * the change ([SignatureSyncStore]). Only after it commits is the new version recorded. A failure,
 * cancellation or killed process at any point leaves the store at its previous, complete version.
 */
@Singleton
class SignatureSyncEngine
@Inject
constructor(
    private val api: BlackShieldApi,
    private val store: SignatureSyncStore,
    private val state: SyncStateRepository,
    @param:SyncWorkDirectory private val workDirectory: File,
    private val clock: Clock,
    private val config: SyncConfig
) {
    private val mutex = Mutex()
    private val snapshots = SnapshotStaging(api, workDirectory, config.maxSnapshotBytes)

    /** Runs one sync and records the result in [SyncStateRepository]. Concurrent calls run one at a time. */
    suspend fun sync(): SyncResult = mutex.withLock {
        val result =
            try {
                SyncResult.Success(withContext(Dispatchers.IO) { runSync() })
            } catch (e: CancellationException) {
                throw e
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception
            ) {
                SyncResult.Failure(SyncErrors.classify(e), e)
            }
        when (result) {
            is SyncResult.Success -> {
                state.recordSuccess(clock.instant())
                Timber.i("Signature sync: %s", result.outcome)
            }

            is SyncResult.Failure -> {
                state.recordFailure(result.error, clock.instant())
                Timber.w(result.cause, "Signature sync failed: %s", result.error)
            }
        }
        result
    }

    private suspend fun runSync(): SyncOutcome {
        val local = state.current().version
        val remote = api.signatureVersion()
        return when {
            local > remote.version -> fullSync(FullSyncReason.SERVER_RESET)
            local == remote.version -> verifyUpToDate(local, remote)
            local == 0L -> fullSync(FullSyncReason.FIRST_SYNC)
            else -> deltaSync(local, remote)
        }
    }

    private suspend fun verifyUpToDate(local: Long, remote: SignatureVersionResponse): SyncOutcome {
        val synced = store.syncedCount()
        if (synced != remote.count) {
            Timber.w("Store holds %d synced signatures, server has %d at version %d", synced, remote.count, local)
            return fullSync(FullSyncReason.STORE_MISMATCH)
        }
        return SyncOutcome.UpToDate(local)
    }

    // --- Delta ---------------------------------------------------------------------------------

    private class Delta(val until: Long, val upserts: List<MalwareSignature>, val removals: Set<String>) {
        val size: Int get() = upserts.size + removals.size
    }

    private suspend fun deltaSync(local: Long, remote: SignatureVersionResponse): SyncOutcome {
        val delta = fetchDelta(local)
        return when {
            delta == null -> fullSync(FullSyncReason.SERVER_RESET)
            delta.size > config.maxDeltaEntries -> fullSync(FullSyncReason.DELTA_TOO_LARGE)
            else -> applyDelta(local, delta, remote)
        }
    }

    private suspend fun applyDelta(local: Long, delta: Delta, remote: SignatureVersionResponse): SyncOutcome {
        store.applyDelta(delta.upserts, delta.removals)
        state.setVersion(delta.until)
        // Only comparable when the delta ended at the version the count belongs to.
        val damaged = delta.until == remote.version && store.syncedCount() != remote.count
        return if (damaged) {
            Timber.w("After the delta to %d the synced count differs from the server's %d", delta.until, remote.count)
            fullSync(FullSyncReason.STORE_MISMATCH)
        } else {
            SyncOutcome.DeltaApplied(local, delta.until, delta.upserts.size, delta.removals.size)
        }
    }

    /**
     * Collects every page of the delta from [since], validated and folded to one change per hash.
     * Returns null when the server cannot serve one (409/410). Stops paging once the delta holds
     * more than [SyncConfig.maxDeltaEntries] changes: the caller switches to a snapshot.
     */
    private suspend fun fetchDelta(since: Long): Delta? {
        val addedAt = clock.millis()
        val upserts = LinkedHashMap<String, MalwareSignature>()
        val removals = LinkedHashSet<String>()
        var until: Long? = null
        var cursor: String? = null
        do {
            val page = fetchDeltaPage(since, cursor) ?: return null
            requireConsistent(page, since, until)
            until = page.until
            for (addition in page.additions) {
                val signature =
                    SignatureMapper.signature(
                        addition.hash,
                        addition.algorithm,
                        addition.family,
                        addition.severity,
                        addedAt
                    )
                removals.remove(signature.hash)
                upserts[signature.hash] = signature
            }
            for (removal in page.removals) {
                val hash = SignatureMapper.hash(removal.hash, SignatureMapper.algorithm(removal.algorithm))
                upserts.remove(hash)
                removals.add(hash)
            }
            cursor = page.nextCursor
        } while (cursor != null && upserts.size + removals.size <= config.maxDeltaEntries)
        return Delta(checkNotNull(until), upserts.values.toList(), removals)
    }

    /** One page, or null when the server says a delta from [since] is impossible (409/410). */
    private suspend fun fetchDeltaPage(since: Long, cursor: String?): SignatureDeltaResponse? = try {
        api.signatureDelta(since = since, limit = config.pageSize, cursor = cursor)
    } catch (e: HttpException) {
        if (e.code() != HTTP_CONFLICT && e.code() != HTTP_GONE) throw e
        Timber.i("Server cannot serve a delta from version %d (HTTP %d)", since, e.code())
        null
    }

    private fun requireConsistent(page: SignatureDeltaResponse, since: Long, until: Long?) {
        val sameRange = page.since == since && page.until >= since && (until == null || page.until == until)
        if (!sameRange) invalid("delta page does not match the request")
        if (page.nextCursor != null && page.additions.isEmpty() && page.removals.isEmpty()) {
            invalid("empty delta page with a cursor")
        }
    }

    // --- Full snapshot -------------------------------------------------------------------------

    private suspend fun fullSync(reason: FullSyncReason): SyncOutcome = snapshots.withDownload { snapshot ->
        val addedAt = clock.millis()
        var version = -1L
        val count =
            store.replaceAll { sink ->
                snapshot.read { reader ->
                    val header = reader.readHeader()
                    version = header.version
                    val batch = ArrayList<MalwareSignature>(config.snapshotBatchSize)
                    while (true) {
                        val row = reader.next() ?: break
                        batch += SignatureMapper.signature(row.hash, row.algorithm, row.family, row.severity, addedAt)
                        if (batch.size == config.snapshotBatchSize) {
                            sink.write(batch.toList())
                            batch.clear()
                        }
                    }
                    sink.write(batch)
                    header.count
                }
            }
        state.setVersion(version)
        SyncOutcome.SnapshotApplied(version, count, reason)
    }

    private fun invalid(message: String): Nothing = throw InvalidPayloadException(message)

    private companion object {
        const val HTTP_CONFLICT = 409
        const val HTTP_GONE = 410
    }
}
