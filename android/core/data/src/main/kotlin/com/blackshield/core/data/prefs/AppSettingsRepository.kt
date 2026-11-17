package com.blackshield.core.data.prefs

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** How often the scheduled full scan runs. */
@Suppress("MagicNumber") // the day counts are the definition
enum class ScanFrequency(val days: Long?) {
    OFF(null),
    DAILY(1),
    WEEKLY(7),
    MONTHLY(30)
}

/** The scheduled scan: how often, and only while charging and/or idle (both save battery). */
data class ScanSchedule(
    val frequency: ScanFrequency = ScanFrequency.WEEKLY,
    val requiresCharging: Boolean = true,
    val requiresIdle: Boolean = false
)

/** App-level settings: onboarding, appearance, the scheduled scan and crash reports. */
@Singleton
class AppSettingsRepository
@Inject
constructor(private val dataStore: DataStore<Preferences>) {
    val onboardingCompleted: Flow<Boolean> = dataStore.data.map { it[ONBOARDING_DONE] ?: false }

    /** [done] false shows onboarding again on the next launch. */
    suspend fun setOnboardingCompleted(done: Boolean = true) {
        dataStore.edit { it[ONBOARDING_DONE] = done }
    }

    val themeMode: Flow<ThemeMode> = dataStore.data.map { prefs -> enumOr(prefs[THEME], ThemeMode.SYSTEM) }

    suspend fun setThemeMode(mode: ThemeMode) {
        dataStore.edit { it[THEME] = mode.name }
    }

    val scanSchedule: Flow<ScanSchedule> =
        dataStore.data.map { prefs ->
            ScanSchedule(
                frequency = enumOr(prefs[SCHEDULE_FREQUENCY], ScanFrequency.WEEKLY),
                requiresCharging = prefs[SCHEDULE_CHARGING] ?: true,
                requiresIdle = prefs[SCHEDULE_IDLE] ?: false
            )
        }

    suspend fun setScanSchedule(schedule: ScanSchedule) {
        dataStore.edit {
            it[SCHEDULE_FREQUENCY] = schedule.frequency.name
            it[SCHEDULE_CHARGING] = schedule.requiresCharging
            it[SCHEDULE_IDLE] = schedule.requiresIdle
        }
    }

    /** Crash reports leave the device only when this is on. Off by default (docs/privacy.md). */
    val crashReportsEnabled: Flow<Boolean> = dataStore.data.map { it[CRASH_REPORTS] ?: false }

    suspend fun setCrashReportsEnabled(enabled: Boolean) {
        dataStore.edit { it[CRASH_REPORTS] = enabled }
    }

    private companion object {
        val CRASH_REPORTS = booleanPreferencesKey("crash_reports_enabled")
        val ONBOARDING_DONE = booleanPreferencesKey("onboarding_done")
        val THEME = stringPreferencesKey("theme_mode")
        val SCHEDULE_FREQUENCY = stringPreferencesKey("scan_schedule_frequency")
        val SCHEDULE_CHARGING = booleanPreferencesKey("scan_schedule_charging")
        val SCHEDULE_IDLE = booleanPreferencesKey("scan_schedule_idle")

        inline fun <reified T : Enum<T>> enumOr(name: String?, default: T): T =
            enumValues<T>().firstOrNull { it.name == name } ?: default
    }
}
