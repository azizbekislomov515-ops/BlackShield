package com.blackshield.core.sync

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.blackshield.core.sync.di.SyncStateStore
import java.io.File
import java.io.IOException
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/** Why the last sync attempt failed. [retryable] errors are retried with exponential backoff. */
enum class SyncErrorKind(val retryable: Boolean) {
    /** No connection, DNS failure, timeout. */
    NETWORK(retryable = true),

    /** The connection dropped mid-download, or the snapshot had no end line. */
    INCOMPLETE_DOWNLOAD(retryable = true),

    /** 5xx or an unexpected HTTP status. */
    SERVER(retryable = true),

    /** 429 Too Many Requests. */
    RATE_LIMITED(retryable = true),

    /** The payload failed validation (bad hash, unknown value, count mismatch). Nothing was applied. */
    CORRUPT_DATA(retryable = true),

    /** Disk full or a database error while saving. */
    STORAGE(retryable = true),

    /** 401/403: this build's API key is missing, revoked or blocked. Needs an app update. */
    UNAUTHORIZED(retryable = false),

    /** TLS failure or certificate pin mismatch: possible interception. Not retried until the next period. */
    CERTIFICATE(retryable = false),

    UNKNOWN(retryable = true)
}

/**
 * Persisted sync status. [version] is the signature version the local store is known to hold;
 * 0 means never synced (or the state was lost), which triggers a full snapshot. [lastError] is
 * null when the most recent attempt succeeded.
 */
data class SyncState(
    val version: Long = 0,
    val lastSuccessAt: Instant? = null,
    val lastAttemptAt: Instant? = null,
    val lastError: SyncErrorKind? = null
)

/**
 * Sync state in its own DataStore file. A corrupted file is replaced by an empty one, which reads
 * as version 0 and makes the next sync a full snapshot: the store is rebuilt from scratch rather
 * than trusted.
 *
 * Ordering rule: [setVersion] is called only after the database transaction that brought the
 * store to that version has committed. A crash between the two leaves an older version here,
 * and re-applying a delta from an older version is idempotent (every hash carries its final state).
 */
@Singleton
class SyncStateRepository
@Inject
constructor(@SyncStateStore private val dataStore: DataStore<Preferences>) {
    val state: Flow<SyncState> =
        dataStore.data
            .catch { error -> if (error is IOException) emit(emptyPreferences()) else throw error }
            .map(::toState)

    suspend fun current(): SyncState = state.first()

    suspend fun setVersion(version: Long) {
        dataStore.edit { it[Keys.VERSION] = version }
    }

    suspend fun recordSuccess(at: Instant) {
        dataStore.edit {
            it[Keys.LAST_SUCCESS_AT] = at.toEpochMilli()
            it[Keys.LAST_ATTEMPT_AT] = at.toEpochMilli()
            it.remove(Keys.LAST_ERROR)
        }
    }

    suspend fun recordFailure(error: SyncErrorKind, at: Instant) {
        dataStore.edit {
            it[Keys.LAST_ATTEMPT_AT] = at.toEpochMilli()
            it[Keys.LAST_ERROR] = error.name
        }
    }

    private fun toState(prefs: Preferences) = SyncState(
        version = prefs[Keys.VERSION] ?: 0,
        lastSuccessAt = prefs[Keys.LAST_SUCCESS_AT]?.let(Instant::ofEpochMilli),
        lastAttemptAt = prefs[Keys.LAST_ATTEMPT_AT]?.let(Instant::ofEpochMilli),
        lastError = prefs[Keys.LAST_ERROR]?.let { name -> SyncErrorKind.entries.firstOrNull { it.name == name } }
    )

    private object Keys {
        val VERSION = longPreferencesKey("version")
        val LAST_SUCCESS_AT = longPreferencesKey("last_success_at")
        val LAST_ATTEMPT_AT = longPreferencesKey("last_attempt_at")
        val LAST_ERROR = stringPreferencesKey("last_error")
    }

    companion object {
        /** The production DataStore; one instance per file per process. */
        fun createDataStore(file: File): DataStore<Preferences> = PreferenceDataStoreFactory.create(
            corruptionHandler = ReplaceFileCorruptionHandler { emptyPreferences() },
            produceFile = { file }
        )
    }
}
