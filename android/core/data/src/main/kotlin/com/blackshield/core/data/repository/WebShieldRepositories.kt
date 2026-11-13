package com.blackshield.core.data.repository

import com.blackshield.core.data.db.BlockedDomainDao
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.db.WebActivityDao
import com.blackshield.core.data.db.WebAllowListDao
import com.blackshield.core.data.model.BlockedDomain
import com.blackshield.core.data.model.WebActivityEntry
import com.blackshield.core.data.model.WebAllowListEntry
import java.time.Clock
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** Local side of the domain-list sync. Each write is one transaction. */
interface DomainSyncStore {
    suspend fun count(): Long

    fun observeCount(): Flow<Long>

    /** Every blocked domain, for building the in-memory matcher. */
    suspend fun all(): List<BlockedDomain>

    suspend fun applyDelta(upserts: List<BlockedDomain>, removals: Collection<String>)

    /** Replaces the whole list (first sync, or a server reset). */
    suspend fun replaceAll(domains: List<BlockedDomain>)
}

internal class RoomDomainSyncStore
@Inject
constructor(
    private val dao: BlockedDomainDao,
    private val transactions: TransactionRunner
) : DomainSyncStore {
    override suspend fun count(): Long = dao.count()

    override fun observeCount(): Flow<Long> = dao.observeCount()

    override suspend fun all(): List<BlockedDomain> = dao.all()

    override suspend fun applyDelta(upserts: List<BlockedDomain>, removals: Collection<String>) {
        if (upserts.isEmpty() && removals.isEmpty()) return
        transactions.inTransaction {
            removals.chunked(SignatureDao.SQLITE_MAX_VARIABLES - 1).forEach { dao.delete(it) }
            upserts.chunked(UPSERT_BATCH).forEach { dao.upsert(it) }
        }
    }

    override suspend fun replaceAll(domains: List<BlockedDomain>) {
        transactions.inTransaction {
            dao.deleteAll()
            domains.chunked(UPSERT_BATCH).forEach { dao.upsert(it) }
        }
    }

    private companion object {
        const val UPSERT_BATCH = 2_000
    }
}

/** Domains the user allows despite the blocklist (each with its subdomains). */
class WebAllowListRepository
@Inject
constructor(private val dao: WebAllowListDao, private val clock: Clock) {
    val domains: Flow<List<String>> = dao.observeAll().map { rows -> rows.map { it.domain } }

    suspend fun allow(domain: String) = dao.insert(WebAllowListEntry(domain, clock.millis()))

    suspend fun remove(domain: String) = dao.delete(domain)
}

/** The opt-in, local-only log of blocked lookups. */
class WebActivityRepository
@Inject
constructor(private val dao: WebActivityDao, private val clock: Clock) {
    fun recent(limit: Int = WebActivityEntry.MAX_ROWS): Flow<List<WebActivityEntry>> = dao.observeRecent(limit)

    suspend fun record(entries: List<WebActivityEntry>) {
        if (entries.isEmpty()) return
        dao.insert(entries)
        dao.prune(
            before = clock.millis() - TimeUnit.DAYS.toMillis(WebActivityEntry.RETENTION_DAYS.toLong()),
            keep = WebActivityEntry.MAX_ROWS
        )
    }

    suspend fun clear() = dao.clear()
}
