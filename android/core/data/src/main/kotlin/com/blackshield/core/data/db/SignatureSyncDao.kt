package com.blackshield.core.data.db

import androidx.room.Dao
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/** Queries used by signature sync. Writes go through [SignatureBulkWriter] inside a transaction. */
@Dao
interface SignatureSyncDao {
    /** At most [SignatureDao.SQLITE_MAX_VARIABLES] - 1 hashes per call. */
    @Query("DELETE FROM malware_signatures WHERE source = :source AND hash IN (:hashes)")
    suspend fun deleteFromSource(source: String, hashes: List<String>): Int

    @Query("SELECT COUNT(*) FROM malware_signatures WHERE source = :source")
    suspend fun countFromSource(source: String): Long

    /** Re-emits after every write to the table. */
    @Query("SELECT COUNT(*) FROM malware_signatures")
    fun observeCount(): Flow<Long>
}
