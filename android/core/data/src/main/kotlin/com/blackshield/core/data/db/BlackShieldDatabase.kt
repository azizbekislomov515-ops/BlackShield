package com.blackshield.core.data.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [ScanResultEntity::class],
    version = 1,
    exportSchema = true
)
abstract class BlackShieldDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao
}
