package com.blackshield.feature.protection

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import com.blackshield.feature.protection.logic.PackageCatchUp
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/** Internal bookkeeping of real-time protection (not user settings). A corrupt file starts fresh. */
@Singleton
class ProtectionStateStore
@Inject
constructor(@ApplicationContext context: Context) {
    private val store: DataStore<Preferences> =
        PreferenceDataStoreFactory.create(
            corruptionHandler = ReplaceFileCorruptionHandler { emptyPreferences() },
            produceFile = { context.preferencesDataStoreFile("protection_state") }
        )

    private val data: Flow<Preferences> =
        store.data.catch { if (it is IOException) emit(emptyPreferences()) else throw it }

    /** SHA-256 of APKs the user chose to ignore from a warning. */
    val ignoredApks: Flow<Set<String>> = data.map { it[Keys.IGNORED].orEmpty() }

    suspend fun ignore(sha256: String) {
        store.edit { it[Keys.IGNORED] = it[Keys.IGNORED].orEmpty() + sha256 }
    }

    suspend fun packageCursor(): PackageCatchUp.Cursor? {
        val prefs = data.first()
        val boot = prefs[Keys.BOOT_COUNT] ?: return null
        return PackageCatchUp.Cursor(boot, prefs[Keys.PACKAGE_SEQUENCE] ?: 0)
    }

    suspend fun setPackageCursor(cursor: PackageCatchUp.Cursor) {
        store.edit {
            it[Keys.BOOT_COUNT] = cursor.bootCount
            it[Keys.PACKAGE_SEQUENCE] = cursor.sequence
        }
    }

    /** MediaStore position: the volume version and the last generation seen on it. */
    suspend fun mediaStorePosition(): Pair<String, Long>? {
        val prefs = data.first()
        val version = prefs[Keys.MEDIA_VERSION] ?: return null
        return version to (prefs[Keys.MEDIA_GENERATION] ?: 0)
    }

    suspend fun setMediaStorePosition(version: String, generation: Long) {
        store.edit {
            it[Keys.MEDIA_VERSION] = version
            it[Keys.MEDIA_GENERATION] = generation
        }
    }

    suspend fun notificationPromptShown(): Boolean = data.first()[Keys.NOTIFICATION_PROMPT] ?: false

    suspend fun setNotificationPromptShown() {
        store.edit { it[Keys.NOTIFICATION_PROMPT] = true }
    }

    private object Keys {
        val IGNORED = stringSetPreferencesKey("ignored_apk_sha256")
        val BOOT_COUNT = intPreferencesKey("package_cursor_boot")
        val PACKAGE_SEQUENCE = intPreferencesKey("package_cursor_sequence")
        val MEDIA_VERSION = stringPreferencesKey("media_store_version")
        val MEDIA_GENERATION = longPreferencesKey("media_store_generation")
        val NOTIFICATION_PROMPT = booleanPreferencesKey("notification_prompt_shown")
    }
}
