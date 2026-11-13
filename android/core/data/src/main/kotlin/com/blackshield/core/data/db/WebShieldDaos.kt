package com.blackshield.core.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Upsert
import com.blackshield.core.data.model.BlockedDomain
import com.blackshield.core.data.model.WebActivityEntry
import com.blackshield.core.data.model.WebAllowListEntry
import kotlinx.coroutines.flow.Flow

@Dao
interface BlockedDomainDao {
    @Upsert
    suspend fun upsert(domains: List<BlockedDomain>)

    /** At most [SignatureDao.SQLITE_MAX_VARIABLES] domains per call. */
    @Query("DELETE FROM blocked_domains WHERE domain IN (:domains)")
    suspend fun delete(domains: List<String>): Int

    @Query("DELETE FROM blocked_domains")
    suspend fun deleteAll()

    @Query("SELECT COUNT(*) FROM blocked_domains")
    suspend fun count(): Long

    /** Re-emits after every write to the table, which is when the in-memory matcher is rebuilt. */
    @Query("SELECT COUNT(*) FROM blocked_domains")
    fun observeCount(): Flow<Long>

    @Query("SELECT * FROM blocked_domains")
    suspend fun all(): List<BlockedDomain>
}

@Dao
interface WebAllowListDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: WebAllowListEntry)

    @Query("DELETE FROM web_allow_list WHERE domain = :domain")
    suspend fun delete(domain: String)

    @Query("SELECT * FROM web_allow_list ORDER BY domain")
    fun observeAll(): Flow<List<WebAllowListEntry>>
}

@Dao
interface WebActivityDao {
    @Insert
    suspend fun insert(entries: List<WebActivityEntry>)

    @Query("SELECT * FROM web_activity ORDER BY blocked_at DESC, id DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<WebActivityEntry>>

    /** Drops rows older than [before] and keeps at most [keep] rows. */
    @Query(
        "DELETE FROM web_activity WHERE blocked_at < :before OR id NOT IN " +
            "(SELECT id FROM web_activity ORDER BY blocked_at DESC, id DESC LIMIT :keep)"
    )
    suspend fun prune(before: Long, keep: Int)

    @Query("DELETE FROM web_activity")
    suspend fun clear()
}
