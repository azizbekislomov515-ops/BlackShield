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

    private object Keys {
        val REAL_TIME_PROTECTION = booleanPreferencesKey("real_time_protection")
    }
}
