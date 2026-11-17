package com.blackshield.core.scanner

import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.quarantine.QuarantineVault
import com.blackshield.core.data.repository.HistoryRepository
import com.blackshield.core.scanner.files.FileScanResult
import javax.inject.Inject

/** A finished full scan. [flagged] are the harmful apps' labels. */
data class FullScanSummary(
    val source: ScanSource,
    val finishedAt: Long,
    val scanned: Int,
    val malicious: Int,
    val suspicious: Int,
    val durationMillis: Long,
    val flagged: List<String>
)

/** Writes scan outcomes to the history, and harmful files to the list of threats to handle. */
class ScanRecorder
@Inject
constructor(private val history: HistoryRepository, private val vault: QuarantineVault) {
    /** A single app checked (real-time protection). */
    suspend fun recordApp(result: ScanResult, source: ScanSource) {
        history.record(
            HistoryEvent(
                occurredAt = result.scannedAt,
                kind = HistoryKind.ITEM_CHECKED,
                source = source,
                verdict = result.verdict,
                subject = result.appLabel,
                target = result.packageName,
                riskScore = result.riskScore,
                detail = topReason(result.reasons)
            )
        )
    }

    /** A file checked. A harmful one is also kept for the Threats screen; returns its id then. */
    suspend fun recordFile(result: FileScanResult): Long? {
        history.record(
            HistoryEvent(
                occurredAt = result.scannedAt,
                kind = HistoryKind.ITEM_CHECKED,
                source = ScanSource.FILE,
                verdict = result.verdict,
                subject = result.appLabel ?: result.candidate.displayName,
                target = result.candidate.displayName,
                riskScore = result.riskScore,
                detail = topReason(result.reasons)
            )
        )
        if (result.verdict == Verdict.CLEAN) return null
        return vault.recordDetection(
            FileThreat(
                displayName = result.candidate.displayName,
                sourcePath = result.candidate.path,
                sourceUri = result.candidate.uri,
                sizeBytes = result.candidate.size,
                sha256 = result.sha256,
                packageName = result.packageName,
                appLabel = result.appLabel,
                verdict = result.verdict,
                riskScore = result.riskScore,
                reasons = result.reasons,
                detectedAt = result.scannedAt
            )
        )
    }

    /** A full scan of installed apps finished. */
    suspend fun recordFullScan(summary: FullScanSummary) = with(summary) {
        history.record(
            HistoryEvent(
                occurredAt = finishedAt,
                kind = HistoryKind.SCAN_COMPLETED,
                source = source,
                verdict =
                    when {
                        malicious > 0 -> Verdict.MALICIOUS
                        suspicious > 0 -> Verdict.SUSPICIOUS
                        else -> Verdict.CLEAN
                    },
                itemsScanned = scanned,
                threatsFound = malicious + suspicious,
                durationMillis = durationMillis,
                detail = flagged.take(MAX_NAMES).joinToString(", ")
            )
        )
    }

    /** An app the user uninstalled from the Threats screen. */
    suspend fun recordUninstall(result: ScanResult, at: Long) {
        history.record(
            HistoryEvent(
                occurredAt = at,
                kind = HistoryKind.UNINSTALLED,
                source = ScanSource.MANUAL,
                verdict = result.verdict,
                subject = result.appLabel,
                target = result.packageName,
                riskScore = result.riskScore
            )
        )
    }

    private fun topReason(reasons: List<ScanReason>): String =
        reasons.filter { it.points > 0 }.maxByOrNull { it.points }?.detail.orEmpty()

    private companion object {
        const val MAX_NAMES = 5
    }
}
