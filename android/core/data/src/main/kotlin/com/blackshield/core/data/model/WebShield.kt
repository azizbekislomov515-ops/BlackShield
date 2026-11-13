package com.blackshield.core.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Why a domain is blocked. */
enum class DomainCategory { MALWARE, PHISHING }

/**
 * A blocked domain from the backend's list (`GET /v1/domains/delta`). Blocking a domain blocks
 * every subdomain too. [domain] is lower-case ASCII (IDNA) without a trailing dot.
 */
@Entity(tableName = "blocked_domains")
data class BlockedDomain(
    @PrimaryKey val domain: String,
    val category: DomainCategory,
    @ColumnInfo(name = "added_at") val addedAt: Long
)

/** A domain the user chose to allow (with its subdomains), whatever the blocklist says. */
@Entity(tableName = "web_allow_list")
data class WebAllowListEntry(@PrimaryKey val domain: String, @ColumnInfo(name = "added_at") val addedAt: Long)

/**
 * One blocked lookup, recorded only when the user turned on the local activity log. Never
 * uploaded; pruned after [RETENTION_DAYS] days. Only blocked lookups are recorded, never the
 * domains the user visits.
 */
@Entity(tableName = "web_activity", indices = [Index("blocked_at")])
data class WebActivityEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val category: DomainCategory,
    @ColumnInfo(name = "blocked_at") val blockedAt: Long
) {
    companion object {
        const val RETENTION_DAYS = 7
        const val MAX_ROWS = 1_000
    }
}
