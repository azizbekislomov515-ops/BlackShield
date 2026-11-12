package com.blackshield.core.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.sqlite.db.SupportSQLiteDatabase
import com.blackshield.core.data.model.AllowListEntry
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.QuarantineEntry
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.SignatureAlgorithmEntry

@Database(
    entities = [
        MalwareSignature::class,
        SignatureAlgorithmEntry::class,
        ScanResult::class,
        QuarantineEntry::class,
        AllowListEntry::class
    ],
    version = 2,
    exportSchema = true
)
@TypeConverters(Converters::class)
abstract class BlackShieldDatabase : RoomDatabase() {
    abstract fun signatureDao(): SignatureDao

    abstract fun scanResultDao(): ScanResultDao

    abstract fun allowListDao(): AllowListDao

    abstract fun quarantineDao(): QuarantineDao

    companion object {
        const val NAME = "blackshield.db"

        /**
         * Page cache of the writer connection, in KiB. SQLite's 2 MiB default thrashes when
         * inserting random hash keys into a 100+ MB index; pages are only allocated when used.
         */
        private const val WRITER_CACHE_KIB = 16 * 1024

        /** Builds the database with all migrations and tuning. Used by DI and tests alike. */
        @Suppress("SpreadOperator") // One call at startup; the array copy is irrelevant.
        fun build(context: Context, name: String = NAME): BlackShieldDatabase = Room
            .databaseBuilder(context, BlackShieldDatabase::class.java, name)
            .addMigrations(*ALL_MIGRATIONS)
            .addCallback(
                object : Callback() {
                    override fun onOpen(db: SupportSQLiteDatabase) {
                        db.execSQL("PRAGMA cache_size = -$WRITER_CACHE_KIB")
                    }
                }
            ).build()
    }
}
