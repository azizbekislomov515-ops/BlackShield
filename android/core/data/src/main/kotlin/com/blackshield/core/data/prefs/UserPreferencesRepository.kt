package com.blackshield.core.data.prefs

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
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

    /** Real-time protection also scans new APK files in Downloads (needs storage access; off by default). */
    val watchDownloads: Flow<Boolean> = dataStore.data.map { prefs -> prefs[Keys.WATCH_DOWNLOADS] ?: false }

    suspend fun setWatchDownloads(watch: Boolean) {
        dataStore.edit { prefs -> prefs[Keys.WATCH_DOWNLOADS] = watch }
    }

    /** Folders picked by the user (Storage Access Framework tree URIs) watched for new APK files. */
    val watchedFolders: Flow<Set<String>> = dataStore.data.map { prefs -> prefs[Keys.WATCHED_FOLDERS].orEmpty() }

    suspend fun addWatchedFolder(treeUri: String) {
        dataStore.edit { prefs -> prefs[Keys.WATCHED_FOLDERS] = prefs[Keys.WATCHED_FOLDERS].orEmpty() + treeUri }
    }

    suspend fun removeWatchedFolder(treeUri: String) {
        dataStore.edit { prefs -> prefs[Keys.WATCHED_FOLDERS] = prefs[Keys.WATCHED_FOLDERS].orEmpty() - treeUri }
    }

    private object Keys {
        val REAL_TIME_PROTECTION = booleanPreferencesKey("real_time_protection")
        val SIGNATURE_SYNC_WIFI_ONLY = booleanPreferencesKey("signature_sync_wifi_only")
        val WATCH_DOWNLOADS = booleanPreferencesKey("watch_downloads")
        val WATCHED_FOLDERS = stringSetPreferencesKey("watched_folders")
    }
}
