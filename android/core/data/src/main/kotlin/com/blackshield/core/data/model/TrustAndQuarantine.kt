package com.blackshield.core.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/** An app the user chose to trust: heuristic warnings are suppressed (known-malware matches are not). */
@Entity(tableName = "allow_list")
data class AllowListEntry(
    @PrimaryKey @ColumnInfo(name = "package_name") val packageName: String,
    @ColumnInfo(name = "added_at") val addedAt: Long
)

/**
 * An app or file the user put into quarantine. Installed apps cannot be moved without root, so
 * for apps this records the decision (and the APK digest at the time) for later handling.
 */
@Entity(tableName = "quarantine")
data class QuarantineEntry(
    @PrimaryKey @ColumnInfo(name = "package_name") val packageName: String,
    @ColumnInfo(name = "apk_sha256") val apkSha256: String?,
    /** Malware family or rule that caused the quarantine. */
    val reason: String,
    @ColumnInfo(name = "quarantined_at") val quarantinedAt: Long
)
