package com.blackshield.core.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanResultDao {
    @Insert
    suspend fun insert(result: ScanResultEntity): Long

    @Query("SELECT * FROM scan_results ORDER BY scannedAtEpochMillis DESC")
    fun observeAll(): Flow<List<ScanResultEntity>>
}
