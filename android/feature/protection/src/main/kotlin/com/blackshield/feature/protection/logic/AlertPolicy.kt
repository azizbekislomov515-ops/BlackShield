package com.blackshield.feature.protection.logic

import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.Verdict

/** Whether a scan result warrants a heads-up warning. */
object AlertPolicy {
    /**
     * Alert on anything not CLEAN, unless the user chose "Ignore" for this exact APK (by SHA-256,
     * so an update or a different file with the same name alerts again).
     */
    fun shouldAlert(verdict: Verdict, sha256: String?, ignoredApks: Set<String>): Boolean =
        verdict != Verdict.CLEAN && (sha256 == null || sha256 !in ignoredApks)
}

/** What a threat notification says. Built from the scan result; plain language, no codes. */
data class ThreatAlert(
    /** Stable per app or file, so a rescan updates the same notification. */
    val key: String,
    val verdict: Verdict,
    val appName: String,
    /** Installed package, for Uninstall and Details; null for a file that is not installed. */
    val packageName: String?,
    /** For files: the file name. */
    val fileName: String?,
    val sha256: String?,
    val riskScore: Int,
    /** The strongest reasons, most points first. */
    val topReasons: List<String>
) {
    companion object {
        private const val MAX_REASONS = 3

        /** Known-malware first, then rule findings by points; trust and bookkeeping entries are left out. */
        fun topReasons(reasons: List<ScanReason>): List<String> = reasons
            .filter { it.points > 0 }
            .sortedWith(
                compareByDescending<ScanReason> {
                    it.code == ScanReason.Code.KNOWN_MALWARE
                }.thenByDescending { it.points }
            )
            .take(MAX_REASONS)
            .map { reason ->
                when (reason.code) {
                    ScanReason.Code.KNOWN_MALWARE -> "Known malware: ${reason.detail}"
                    else -> reason.detail
                }
            }
    }
}
