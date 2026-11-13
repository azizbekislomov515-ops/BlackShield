package com.blackshield.core.data.prefs

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import java.time.Clock
import java.time.LocalDate
import java.time.ZoneId
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** Blocked-lookup counters. Aggregates only: no domain, app or time of a lookup is stored here. */
data class WebShieldStats(
    val today: Long = 0,
    val last7Days: Long = 0,
    val totalMalware: Long = 0,
    val totalPhishing: Long = 0
) {
    val total: Long get() = totalMalware + totalPhishing
}

@Singleton
class WebShieldStatsRepository
@Inject
constructor(
    private val dataStore: DataStore<Preferences>,
    private val clock: Clock
) {
    val stats: Flow<WebShieldStats> =
        dataStore.data.map { prefs ->
            val today = today()
            WebShieldStats(
                today = prefs[dayKey(today)] ?: 0,
                last7Days = (0L until WEEK).sumOf { prefs[dayKey(today.minusDays(it))] ?: 0 },
                totalMalware = prefs[TOTAL_MALWARE] ?: 0,
                totalPhishing = prefs[TOTAL_PHISHING] ?: 0
            )
        }

    /** Adds a batch of blocked lookups (the service flushes its counters periodically). */
    suspend fun add(malware: Long, phishing: Long) {
        if (malware == 0L && phishing == 0L) return
        val today = today()
        dataStore.edit { prefs ->
            prefs[TOTAL_MALWARE] = (prefs[TOTAL_MALWARE] ?: 0) + malware
            prefs[TOTAL_PHISHING] = (prefs[TOTAL_PHISHING] ?: 0) + phishing
            prefs[dayKey(today)] = (prefs[dayKey(today)] ?: 0) + malware + phishing
            // Keep a month of daily counts at most.
            val oldest = today.minusDays(KEEP_DAYS)
            prefs
                .asMap()
                .keys
                .filter { it.name.startsWith(DAY_PREFIX) }
                .filter { key -> LocalDate.parse(key.name.removePrefix(DAY_PREFIX)) < oldest }
                .forEach { prefs.remove(it) }
        }
    }

    suspend fun reset() {
        dataStore.edit { prefs ->
            prefs.remove(TOTAL_MALWARE)
            prefs.remove(TOTAL_PHISHING)
            prefs.asMap().keys.filter { it.name.startsWith(DAY_PREFIX) }.forEach { prefs.remove(it) }
        }
    }

    private fun today(): LocalDate = LocalDate.now(clock.withZone(ZoneId.systemDefault()))

    private fun dayKey(day: LocalDate) = longPreferencesKey(DAY_PREFIX + day)

    private companion object {
        const val DAY_PREFIX = "web_blocked_day_"
        const val WEEK = 7L
        const val KEEP_DAYS = 31L
        val TOTAL_MALWARE = longPreferencesKey("web_blocked_total_malware")
        val TOTAL_PHISHING = longPreferencesKey("web_blocked_total_phishing")
    }
}
