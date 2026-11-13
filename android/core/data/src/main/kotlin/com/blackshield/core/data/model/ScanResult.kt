package com.blackshield.core.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

enum class Verdict { CLEAN, SUSPICIOUS, MALICIOUS }

/**
 * Why a verdict was reached. Stored as JSON in [ScanResult.reasons], so fields are added with
 * defaults and old rows keep decoding.
 */
@Serializable
data class ScanReason(
    val code: Code,
    /** Human-readable detail: the malware family, or for [Code.HEURISTIC] the rule's plain-language title. */
    val detail: String = "",
    /** Points this reason added to the risk score (negative for signs of trust). */
    val points: Int = 0,
    /** For [Code.HEURISTIC]: the risk rule that matched. */
    val ruleId: String? = null,
    /** For [Code.HEURISTIC]: the facts that triggered the rule. */
    val evidence: List<String> = emptyList(),
    /** For [Code.HEURISTIC]: the rule's full points when a group cap reduced [points]; else null. */
    val rulePoints: Int? = null
) {
    @Serializable
    enum class Code {
        KNOWN_MALWARE,

        /** A static-analysis risk rule matched (see RiskEngine). */
        HEURISTIC,

        /** Preinstalled system app: heuristics are not applied. */
        SYSTEM_APP,

        /** On the risk rules' known-good list. */
        KNOWN_GOOD,

        /** Part of the app could not be analyzed; the verdict is based on the rest. */
        ANALYSIS_INCOMPLETE,

        ALLOW_LISTED,
        HASH_FAILED,

        // Fixed heuristics from before the rule engine; still decoded and shown for older results.
        SIDELOADED,
        SMS_ACCESS,
        INSTALLS_PACKAGES,
        DRAWS_OVER_APPS,
        DEBUGGABLE
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
