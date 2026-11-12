package com.blackshield.core.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

enum class Verdict { CLEAN, SUSPICIOUS, MALICIOUS }

/** Why a verdict was reached. Stored as JSON in [ScanResult.reasons]. */
@Serializable
data class ScanReason(
    val code: Code,
    /** Human-readable detail, e.g. the malware family or the permission name. */
    val detail: String = "",
    /** Points this reason added to the risk score. */
    val points: Int = 0
) {
    @Serializable
    enum class Code {
        KNOWN_MALWARE,
        SIDELOADED,
        SMS_ACCESS,
        INSTALLS_PACKAGES,
        DRAWS_OVER_APPS,
        DEBUGGABLE,
        ALLOW_LISTED,
        HASH_FAILED
    }
}

/**
 * Latest scan result for one installed app. One row per package ([packageName] is unique), so
 * a rescan replaces the previous result and results survive app restarts.
 */
@Entity(
    tableName = "scan_results",
    indices = [Index(value = ["package_name"], unique = true)]
)
data class ScanResult(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "package_name") val packageName: String,
    @ColumnInfo(name = "app_label") val appLabel: String,
    @ColumnInfo(name = "version_code") val versionCode: Long,
    /** SHA-256 of the base APK; null if it could not be read. */
    @ColumnInfo(name = "apk_sha256") val apkSha256: String?,
    val verdict: Verdict,
    /** 0 (no risk) to 100. */
    @ColumnInfo(name = "risk_score") val riskScore: Int,
    val reasons: List<ScanReason>,
    @ColumnInfo(name = "scanned_at") val scannedAt: Long
)
