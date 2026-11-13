package com.blackshield.core.data.prefs

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

@Singleton
class UserPreferencesRepository
@Inject
constructor(private val dataStore: DataStore<Preferences>) {
    val realTimeProtectionEnabled: Flow<Boolean> =
        dataStore.data.map { prefs -> prefs[Keys.REAL_TIME_PROTECTION] ?: true }

    suspend fun setRealTimeProtectionEnabled(enabled: Boolean) {
        dataStore.edit { prefs -> prefs[Keys.REAL_TIME_PROTECTION] = enabled }
    }

    /**
     * When true, background signature updates wait for an unmetered network (usually Wi-Fi).
     * Off by default: deltas are small and up-to-date signatures matter more. A manual
     * "Sync now" always uses any network.
     */
    val signatureSyncWifiOnly: Flow<Boolean> =
        dataStore.data.map { prefs -> prefs[Keys.SIGNATURE_SYNC_WIFI_ONLY] ?: false }

    suspend fun setSignatureSyncWifiOnly(wifiOnly: Boolean) {
        dataStore.edit { prefs -> prefs[Keys.SIGNATURE_SYNC_WIFI_ONLY] = wifiOnly }
    }

    private object Keys {
        val REAL_TIME_PROTECTION = booleanPreferencesKey("real_time_protection")
        val SIGNATURE_SYNC_WIFI_ONLY = booleanPreferencesKey("signature_sync_wifi_only")
    }
}
