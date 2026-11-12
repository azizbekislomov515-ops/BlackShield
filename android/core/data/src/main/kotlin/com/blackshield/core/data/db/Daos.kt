package com.blackshield.core.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.blackshield.core.data.model.AllowListEntry
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.QuarantineEntry
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.SignatureAlgorithmEntry
import kotlinx.coroutines.flow.Flow

@Dao
interface SignatureDao {
    /** Inserts or replaces; call inside a transaction for bulk imports. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(signatures: List<MalwareSignature>)

    @Query("SELECT EXISTS(SELECT 1 FROM malware_signatures WHERE hash = :hash)")
    suspend fun exists(hash: String): Boolean

    /** At most [SQLITE_MAX_VARIABLES] hashes per call. */
    @Query("SELECT * FROM malware_signatures WHERE hash IN (:hashes)")
    suspend fun findByHashes(hashes: List<String>): List<MalwareSignature>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun markAlgorithms(entries: List<SignatureAlgorithmEntry>)

    @Query("SELECT algorithm FROM signature_algorithms")
    suspend fun algorithms(): List<SignatureAlgorithm>

    @Query("SELECT COUNT(*) FROM malware_signatures")
    suspend fun count(): Long

    @Query("DELETE FROM malware_signatures WHERE source = :source")
    suspend fun deleteBySource(source: String): Int

    companion object {
        /** SQLite before 3.32 (Android < 11) allows 999 bound parameters per statement. */
        const val SQLITE_MAX_VARIABLES = 900
    }
}

@Dao
interface ScanResultDao {
    /** Replaces the previous result for the same package (unique index on package_name). */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(result: ScanResult)

    @Query("SELECT * FROM scan_results ORDER BY app_label COLLATE NOCASE")
    fun observeAll(): Flow<List<ScanResult>>

    @Query("SELECT * FROM scan_results WHERE package_name = :packageName")
    suspend fun find(packageName: String): ScanResult?

    @Query("SELECT package_name FROM scan_results")
    suspend fun packageNames(): List<String>

    @Query("DELETE FROM scan_results WHERE package_name IN (:packageNames)")
    suspend fun delete(packageNames: List<String>)
}

@Dao
interface AllowListDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: AllowListEntry)

    @Query("DELETE FROM allow_list WHERE package_name = :packageName")
    suspend fun delete(packageName: String)

    @Query("SELECT package_name FROM allow_list")
    suspend fun packageNames(): List<String>

    @Query("SELECT package_name FROM allow_list")
    fun observePackageNames(): Flow<List<String>>
}

@Dao
interface QuarantineDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: QuarantineEntry)

    @Query("DELETE FROM quarantine WHERE package_name = :packageName")
    suspend fun delete(packageName: String)

    @Query("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
    fun observeAll(): Flow<List<QuarantineEntry>>
}
