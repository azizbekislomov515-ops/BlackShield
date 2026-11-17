package com.blackshield.core.data.repository

import com.blackshield.core.data.db.HistoryDao
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import java.time.Clock
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow

/** How far back the history screen looks. */
@Suppress("MagicNumber") // the day counts are the definition
enum class HistoryPeriod(val days: Long?) {
    DAY(1),
    WEEK(7),
    MONTH(30),
    ALL(null)
}

data class HistoryFilter(
    val period: HistoryPeriod = HistoryPeriod.ALL,
    /** Empty means every verdict. */
    val verdicts: Set<Verdict> = emptySet(),
    /** Empty means every source. */
    val sources: Set<ScanSource> = emptySet()
)

/** The local scan history (never uploaded). Entries older than a year are dropped. */
@Singleton
class HistoryRepository
@Inject
constructor(private val dao: HistoryDao, private val clock: Clock) {
    suspend fun record(event: HistoryEvent) {
        dao.insert(event.copy(id = 0, occurredAt = event.occurredAt.takeIf { it > 0 } ?: clock.millis()))
        dao.deleteOlderThan(clock.millis() - TimeUnit.DAYS.toMillis(RETENTION_DAYS))
    }

    fun observe(filter: HistoryFilter, limit: Int = MAX_ROWS): Flow<List<HistoryEvent>> = dao.observe(
        since = filter.period.days?.let { clock.millis() - TimeUnit.DAYS.toMillis(it) } ?: 0L,
        verdicts = filter.verdicts.ifEmpty { Verdict.entries.toSet() }.toList(),
        sources = filter.sources.ifEmpty { ScanSource.entries.toSet() }.toList(),
        limit = limit
    )

    fun recent(limit: Int): Flow<List<HistoryEvent>> = dao.observeRecent(limit)

    fun lastFullScan(): Flow<HistoryEvent?> = dao.observeLastFullScan()

    suspend fun clear() = dao.clear()

    private companion object {
        const val RETENTION_DAYS = 365L
        const val MAX_ROWS = 2_000
    }
}
