package com.blackshield.core.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

/** One completed scan of a file, app or URL. */
@Entity(tableName = "scan_results")
data class ScanResultEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val target: String,
    val verdict: String,
    val scannedAtEpochMillis: Long
)
