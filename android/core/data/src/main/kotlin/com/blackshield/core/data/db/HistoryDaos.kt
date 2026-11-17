package com.blackshield.core.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.FileThreatState
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import kotlinx.coroutines.flow.Flow

@Dao
interface HistoryDao {
    @Insert
    suspend fun insert(event: HistoryEvent): Long

    /** Newest first. Empty [verdicts] or [sources] lists are not allowed: pass every value instead. */
    @Query(
        "SELECT * FROM history WHERE occurred_at >= :since AND verdict IN (:verdicts) AND source IN (:sources) " +
            "ORDER BY occurred_at DESC, id DESC LIMIT :limit"
    )
    fun observe(since: Long, verdicts: List<Verdict>, sources: List<ScanSource>, limit: Int): Flow<List<HistoryEvent>>

    @Query("SELECT * FROM history ORDER BY occurred_at DESC, id DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<HistoryEvent>>

    /** The latest full scan, for the dashboard. */
    @Query("SELECT * FROM history WHERE kind = 'SCAN_COMPLETED' ORDER BY occurred_at DESC, id DESC LIMIT 1")
    fun observeLastFullScan(): Flow<HistoryEvent?>

    @Query("DELETE FROM history WHERE occurred_at < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM history")
    suspend fun clear()
}

@Dao
interface FileThreatDao {
    @Insert
    suspend fun insert(threat: FileThreat): Long

    @Update
    suspend fun update(threat: FileThreat)

    @Query("DELETE FROM file_threats WHERE id = :id")
    suspend fun delete(id: Long)

    @Query("SELECT * FROM file_threats WHERE id = :id")
    suspend fun find(id: Long): FileThreat?

    /** The same file (location and content) already recorded and not yet handled. */
    @Query(
        "SELECT * FROM file_threats WHERE state = 'DETECTED' AND sha256 IS :sha256 AND " +
            "(source_path IS :path AND source_uri IS :uri) LIMIT 1"
    )
    suspend fun findDetected(path: String?, uri: String?, sha256: String?): FileThreat?

    @Query("SELECT * FROM file_threats WHERE state = :state ORDER BY COALESCE(quarantined_at, detected_at) DESC")
    fun observe(state: FileThreatState): Flow<List<FileThreat>>
}
