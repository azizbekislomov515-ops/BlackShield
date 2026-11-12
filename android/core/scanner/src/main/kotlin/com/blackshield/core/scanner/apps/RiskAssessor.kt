package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanReason.Code
import com.blackshield.core.data.model.Verdict

/** Verdict, 0-100 risk score and the reasons behind them. */
data class Assessment(val verdict: Verdict, val riskScore: Int, val reasons: List<ScanReason>)

/** A signature that matched one of the app's APK files. */
data class SignatureMatch(val apkPath: String, val signature: MalwareSignature)

/**
 * Turns scan evidence into a verdict. Deliberately simple and explainable:
 *
 * - Any known-malware digest match makes the app MALICIOUS (score from the signature severity),
 *   even if the user allow-listed it.
 * - Otherwise a few heuristics add points, for user-installed apps only (preinstalled system apps
 *   legitimately hold these permissions), and not for allow-listed apps. At
 *   [SUSPICIOUS_THRESHOLD] points or more the app is SUSPICIOUS, below it CLEAN. No single
 *   heuristic reaches the threshold on its own.
 */
object RiskAssessor {
    const val SUSPICIOUS_THRESHOLD = 50
    private const val MAX_SCORE = 100

    const val SIDELOADED_POINTS = 25
    const val SMS_POINTS = 20
    const val INSTALL_PACKAGES_POINTS = 15
    const val OVERLAY_POINTS = 15
    const val DEBUGGABLE_POINTS = 10

    /** App stores whose installs are not counted as sideloaded. */
    val TRUSTED_INSTALLERS =
        setOf(
            "com.android.vending", // Google Play
            "com.amazon.venezia", // Amazon Appstore
            "com.sec.android.app.samsungapps", // Galaxy Store
            "com.huawei.appmarket", // AppGallery
            "com.xiaomi.market" // GetApps
        )

    private val SMS_PERMISSIONS =
        setOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS"
        )

    fun assess(
        app: InstalledApp,
        matches: List<SignatureMatch>,
        hashFailures: List<String>,
        allowListed: Boolean
    ): Assessment {
        val reasons = mutableListOf<ScanReason>()

        matches.forEach { match ->
            reasons +=
                ScanReason(
                    code = Code.KNOWN_MALWARE,
                    detail =
                        "${match.signature.family} (${match.signature.severity}, source: ${match.signature.source}) " +
                            "in ${match.apkPath.substringAfterLast('/')}",
                    points = match.signature.severity.riskScore
                )
        }
        if (allowListed) {
            val detail = if (matches.isEmpty()) "Trusted by you" else "Trusted by you; ignored for known malware"
            reasons += ScanReason(Code.ALLOW_LISTED, detail)
        }
        if (!app.isSystemApp && !allowListed) {
            reasons += heuristics(app)
        }
        hashFailures.forEach { reasons += ScanReason(Code.HASH_FAILED, it) }

        return if (matches.isNotEmpty()) {
            Assessment(Verdict.MALICIOUS, matches.maxOf { it.signature.severity.riskScore }, reasons)
        } else {
            val score = reasons.sumOf { it.points }.coerceAtMost(MAX_SCORE)
            val verdict = if (score >= SUSPICIOUS_THRESHOLD) Verdict.SUSPICIOUS else Verdict.CLEAN
            Assessment(verdict, score, reasons)
        }
    }

    private fun heuristics(app: InstalledApp): List<ScanReason> = buildList {
        if (app.installerPackage !in TRUSTED_INSTALLERS) {
            add(ScanReason(Code.SIDELOADED, "Installer: ${app.installerPackage ?: "unknown"}", SIDELOADED_POINTS))
        }
        val sms = app.requestedPermissions intersect SMS_PERMISSIONS
        if (sms.isNotEmpty()) {
            add(ScanReason(Code.SMS_ACCESS, sms.sorted().joinToString { it.substringAfterLast('.') }, SMS_POINTS))
        }
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in app.requestedPermissions) {
            add(ScanReason(Code.INSTALLS_PACKAGES, "REQUEST_INSTALL_PACKAGES", INSTALL_PACKAGES_POINTS))
        }
        if ("android.permission.SYSTEM_ALERT_WINDOW" in app.requestedPermissions) {
            add(ScanReason(Code.DRAWS_OVER_APPS, "SYSTEM_ALERT_WINDOW", OVERLAY_POINTS))
        }
        if (app.isDebuggable) {
            add(ScanReason(Code.DEBUGGABLE, "android:debuggable=true", DEBUGGABLE_POINTS))
        }
    }
}
