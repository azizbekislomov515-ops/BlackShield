package com.blackshield.core.data.model

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

/** What triggered a scan or action. */
@Serializable
enum class ScanSource {
    /** The user tapped "Scan now". */
    MANUAL,

    /** A scheduled scan (WorkManager). */
    SCHEDULED,

    /** Real-time protection, right after an app was installed or updated. */
    REAL_TIME,

    /** An APK file: a new download, or one the user picked. */
    FILE
}

@Serializable
enum class HistoryKind {
    /** A full scan of installed apps finished. */
    SCAN_COMPLETED,

    /** One app or file was checked (real-time protection, a picked file). */
    ITEM_CHECKED,

    QUARANTINED,
    RESTORED,
    DELETED,
    UNINSTALLED
}

/**
 * One line of the scan history. Kept locally and never uploaded. Web Shield blocks are not
 * recorded here (only aggregate counters exist for those).
 */
@Entity(tableName = "history", indices = [Index("occurred_at")])
data class HistoryEvent(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "occurred_at") val occurredAt: Long,
    val kind: HistoryKind,
    val source: ScanSource,
    /** The worst verdict involved: the item's, or the worst found by a full scan. */
    val verdict: Verdict,
    /** App label or file name; empty for full scans. */
    val subject: String = "",
    /** Package name or file location, when there is one. */
    val target: String? = null,
    @ColumnInfo(name = "risk_score") val riskScore: Int = 0,
    /** Full scans: apps checked. */
    @ColumnInfo(name = "items_scanned") val itemsScanned: Int = 0,
    /** Full scans: malicious + suspicious apps found. */
    @ColumnInfo(name = "threats_found") val threatsFound: Int = 0,
    /** Full scans: how long it took. */
    @ColumnInfo(name = "duration_millis") val durationMillis: Long = 0,
    /** Short extra information (top reason, names of flagged apps). */
    val detail: String = ""
)

enum class FileThreatState {
    /** Found and not handled yet. */
    DETECTED,

    /** Moved into the encrypted vault; the original file is gone. */
    QUARANTINED
}

/**
 * A harmful APK file: found by a scan, then possibly quarantined. Restoring or deleting it removes
 * the row. Installed apps are not stored here: they live in `scan_results`, and handling them
 * means uninstalling.
 */
@Entity(tableName = "file_threats", indices = [Index("state"), Index("sha256")])
data class FileThreat(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "display_name") val displayName: String,
    /** Where the file was: an absolute path... */
    @ColumnInfo(name = "source_path") val sourcePath: String? = null,
    /** ...or a content:// URI. */
    @ColumnInfo(name = "source_uri") val sourceUri: String? = null,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Long,
    val sha256: String? = null,
    @ColumnInfo(name = "package_name") val packageName: String? = null,
    @ColumnInfo(name = "app_label") val appLabel: String? = null,
    val verdict: Verdict,
    @ColumnInfo(name = "risk_score") val riskScore: Int,
    val reasons: List<ScanReason>,
    @ColumnInfo(name = "detected_at") val detectedAt: Long,
    val state: FileThreatState = FileThreatState.DETECTED,
    /** The encrypted copy's file name inside the vault (set when quarantined). */
    @ColumnInfo(name = "vault_file") val vaultFile: String? = null,
    @ColumnInfo(name = "quarantined_at") val quarantinedAt: Long? = null
) {
    /** Where the file came from, for display. */
    val location: String get() = sourcePath ?: sourceUri.orEmpty()
}
