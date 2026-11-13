package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanReason.Code
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.risk.Exemption
import com.blackshield.core.scanner.risk.RiskEngine
import com.blackshield.core.scanner.risk.RiskEvaluation
import com.blackshield.core.scanner.risk.RiskRulesSource
import java.time.Clock
import javax.inject.Inject

/** Verdict, 0-100 risk score and the reasons behind them. */
data class Assessment(val verdict: Verdict, val riskScore: Int, val reasons: List<ScanReason>)

/** A signature that matched one of the app's APK files. */
data class SignatureMatch(val apkPath: String, val signature: MalwareSignature)

/**
 * Turns scan evidence into a verdict:
 *
 * - A known-malware digest match makes the app MALICIOUS (score from the signature severity), even
 *   if the user trusts it. Heuristics are not needed then.
 * - Apps the user trusts skip heuristics.
 * - Everything else is scored by the [RiskEngine] rules; every point comes with a reason.
 *
 * What could not be analyzed is listed too (with 0 points), so a verdict never silently rests on
 * missing data.
 */
class RiskAssessor
@Inject
constructor(private val rules: RiskRulesSource, private val clock: Clock) {
    private val engine: RiskEngine by lazy { RiskEngine(rules.rules()) }

    fun assess(
        profile: AppProfile,
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
        val evaluation = if (matches.isEmpty() && !allowListed) engine.evaluate(profile, clock.millis()) else null
        evaluation?.let { reasons += reasonsFor(it) }
        profile.analysisGaps.forEach { reasons += ScanReason(Code.ANALYSIS_INCOMPLETE, it) }
        hashFailures.forEach { reasons += ScanReason(Code.HASH_FAILED, it) }

        return when {
            matches.isNotEmpty() ->
                Assessment(Verdict.MALICIOUS, matches.maxOf { it.signature.severity.riskScore }, reasons)

            evaluation != null -> Assessment(evaluation.verdict, evaluation.score, reasons)

            else -> Assessment(Verdict.CLEAN, 0, reasons)
        }
    }

    private fun reasonsFor(evaluation: RiskEvaluation): List<ScanReason> = buildList {
        when (evaluation.exemption) {
            Exemption.SYSTEM_APP -> add(ScanReason(Code.SYSTEM_APP, "Preinstalled with the system"))

            Exemption.KNOWN_GOOD -> add(
                ScanReason(Code.KNOWN_GOOD, "On the known-good list (rules ${evaluation.rulesVersion})")
            )

            null -> Unit
        }
        evaluation.findings.forEach { finding ->
            add(
                ScanReason(
                    code = Code.HEURISTIC,
                    detail = finding.title,
                    points = finding.points,
                    ruleId = finding.ruleId,
                    evidence = finding.evidence,
                    rulePoints = finding.rulePoints.takeIf { finding.capped }
                )
            )
        }
    }
}
