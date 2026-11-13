package com.blackshield.core.sync

import com.blackshield.core.data.model.BlockedDomain
import com.blackshield.core.data.model.DomainCategory
import com.blackshield.core.data.repository.DomainSyncStore
import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.InvalidPayloadException
import com.blackshield.core.network.model.DomainDeltaResponse
import com.blackshield.core.network.model.DomainVersionResponse
import com.blackshield.core.sync.di.DomainSyncState
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

sealed interface DomainSyncOutcome {
    data class UpToDate(val version: Long) : DomainSyncOutcome

    data class DeltaApplied(val fromVersion: Long, val toVersion: Long, val added: Int, val removed: Int) :
        DomainSyncOutcome

    /** The whole list was downloaded (as the delta from version 0) and replaced the local one. */
    data class FullApplied(val version: Long, val count: Int, val reason: FullSyncReason) : DomainSyncOutcome
}

sealed interface DomainSyncResult {
    data class Success(val outcome: DomainSyncOutcome) : DomainSyncResult

    data class Failure(val error: SyncErrorKind, val cause: Throwable) : DomainSyncResult
}

/**
 * Brings Web Shield's blocklist up to the server's version with the signature protocol
 * (docs/sync-protocol.md, section 8): `GET /v1/domains/version`, then the paged delta. A first
 * sync, a server reset or a damaged store fetches the delta from version 0 (every domain) and
 * replaces the local list. All pages are fetched and validated before one transaction applies
 * them, and the version is recorded only after it commits.
 */
@Singleton
class DomainSyncEngine
@Inject
constructor(
    private val api: BlackShieldApi,
    private val store: DomainSyncStore,
    @param:DomainSyncState private val state: SyncStateRepository,
    private val clock: Clock,
    private val config: SyncConfig
) {
    private val mutex = Mutex()

    suspend fun sync(): DomainSyncResult = mutex.withLock {
        val result =
            try {
                DomainSyncResult.Success(withContext(Dispatchers.IO) { runSync() })
            } catch (e: CancellationException) {
                throw e
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception
            ) {
                DomainSyncResult.Failure(SyncErrors.classify(e), e)
            }
        when (result) {
            is DomainSyncResult.Success -> {
                state.recordSuccess(clock.instant())
                Timber.i("Domain sync: %s", result.outcome)
            }

            is DomainSyncResult.Failure -> {
                state.recordFailure(result.error, clock.instant())
                Timber.w(result.cause, "Domain sync failed: %s", result.error)
            }
        }
        result
    }

    private suspend fun runSync(): DomainSyncOutcome {
        val local = state.current().version
        val remote = api.domainVersion()
        return when {
            local > remote.version -> fullSync(remote, FullSyncReason.SERVER_RESET)
            local == remote.version -> verifyUpToDate(local, remote)
            local == 0L -> fullSync(remote, FullSyncReason.FIRST_SYNC)
            else -> deltaSync(local, remote)
        }
    }

    private suspend fun verifyUpToDate(local: Long, remote: DomainVersionResponse): DomainSyncOutcome {
        if (store.count() != remote.count) return fullSync(remote, FullSyncReason.STORE_MISMATCH)
        return DomainSyncOutcome.UpToDate(local)
    }

    private suspend fun deltaSync(local: Long, remote: DomainVersionResponse): DomainSyncOutcome {
        val delta = fetchDelta(local, config.maxDeltaEntries)
        return when {
            delta == null -> fullSync(remote, FullSyncReason.SERVER_RESET)
            delta.truncated -> fullSync(remote, FullSyncReason.DELTA_TOO_LARGE)
            else -> applyDelta(local, delta, remote)
        }
    }

    private suspend fun applyDelta(local: Long, delta: Delta, remote: DomainVersionResponse): DomainSyncOutcome {
        store.applyDelta(delta.upserts, delta.removals)
        state.setVersion(delta.until)
        val damaged = delta.until == remote.version && store.count() != remote.count
        return if (damaged) {
            fullSync(remote, FullSyncReason.STORE_MISMATCH)
        } else {
            DomainSyncOutcome.DeltaApplied(local, delta.until, delta.upserts.size, delta.removals.size)
        }
    }

    private suspend fun fullSync(remote: DomainVersionResponse, reason: FullSyncReason): DomainSyncOutcome {
        val everything = fetchDelta(0, MAX_DOMAINS)
        val problem =
            when {
                everything == null -> "server refused a delta from version 0"
                everything.truncated -> "domain list larger than $MAX_DOMAINS entries"
                else -> null
            }
        if (problem != null || everything == null) throw InvalidPayloadException(problem ?: "no delta")
        store.replaceAll(everything.upserts)
        state.setVersion(everything.until)
        if (everything.until == remote.version && store.count() != remote.count) {
            throw InvalidPayloadException("server promised ${remote.count} domains, received ${store.count()}")
        }
        return DomainSyncOutcome.FullApplied(everything.until, everything.upserts.size, reason)
    }

    private class Delta(
        val until: Long,
        val upserts: List<BlockedDomain>,
        val removals: Set<String>,
        val truncated: Boolean
    )

    /** Every page from [since], folded to one change per domain; null on 409/410. */
    private suspend fun fetchDelta(since: Long, maxEntries: Int): Delta? {
        val addedAt = clock.millis()
        val upserts = LinkedHashMap<String, BlockedDomain>()
        val removals = LinkedHashSet<String>()
        var until: Long? = null
        var cursor: String? = null
        do {
            val page = fetchPage(since, cursor) ?: return null
            requireConsistent(page, since, until)
            until = page.until
            for (addition in page.additions) {
                val domain = DomainNames.validate(addition.domain)
                removals.remove(domain)
                upserts[domain] = BlockedDomain(domain, category(addition.category), addedAt)
            }
            for (removal in page.removals) {
                val domain = DomainNames.validate(removal.domain)
                upserts.remove(domain)
                removals.add(domain)
            }
            cursor = page.nextCursor
        } while (cursor != null && upserts.size + removals.size <= maxEntries)
        return Delta(checkNotNull(until), upserts.values.toList(), removals, truncated = cursor != null)
    }

    private suspend fun fetchPage(since: Long, cursor: String?): DomainDeltaResponse? = try {
        api.domainDelta(since = since, limit = config.pageSize, cursor = cursor)
    } catch (e: HttpException) {
        if (e.code() != HTTP_CONFLICT && e.code() != HTTP_GONE) throw e
        null
    }

    private fun requireConsistent(page: DomainDeltaResponse, since: Long, until: Long?) {
        val sameRange = page.since == since && page.until >= since && (until == null || page.until == until)
        if (!sameRange) throw InvalidPayloadException("delta page does not match the request")
        if (page.nextCursor != null && page.additions.isEmpty() && page.removals.isEmpty()) {
            throw InvalidPayloadException("empty delta page with a cursor")
        }
    }

    private fun category(value: String): DomainCategory = when (value) {
        "malware" -> DomainCategory.MALWARE
        "phishing" -> DomainCategory.PHISHING
        else -> throw InvalidPayloadException("unknown domain category '$value'")
    }

    private companion object {
        const val HTTP_CONFLICT = 409
        const val HTTP_GONE = 410

        /** Far above today's feeds (tens of thousands); bounds memory if the server misbehaves. */
        const val MAX_DOMAINS = 1_000_000
    }
}

/** Server-side names are already canonical; anything else means a broken or hostile payload. */
internal object DomainNames {
    private val VALID = Regex("^(?=.{3,253}$)[a-z0-9_-]{1,63}(\\.[a-z0-9_-]{1,63})+$")

    fun validate(domain: String): String {
        if (!VALID.matches(domain)) throw InvalidPayloadException("invalid domain in payload")
        return domain
    }
}
