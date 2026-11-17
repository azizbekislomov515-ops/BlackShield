package com.blackshield.feature.home

import java.util.concurrent.TimeUnit

/** What the score is made of. Each factor's [max] adds up to 100. */
@Suppress("MagicNumber") // the weights are the definition (see SecurityScoringTest)
enum class ScoreFactor(val max: Int) {
    REAL_TIME(25),
    THREATS(25),
    RECENT_SCAN(15),
    DEFINITIONS(15),
    WEB_SHIELD(10),
    SCHEDULE(10)
}

enum class FactorState { OK, PARTIAL, MISSING }

/** One line of the explanation: what was earned for a factor, and what would fix it. */
data class ScoreItem(val factor: ScoreFactor, val earned: Int, val state: FactorState)

enum class ProtectionLevel {
    /** Score 85+ and no malware. */
    PROTECTED,

    /** Some protection is off or out of date. */
    ATTENTION,

    /** Malware is installed or waiting in a file. */
    AT_RISK
}

data class SecurityScore(val total: Int, val items: List<ScoreItem>, val level: ProtectionLevel) {
    /** The factors that cost points, worst first. */
    val improvements: List<ScoreItem> get() = items.filter { it.state != FactorState.OK }.sortedByDescending {
        it.factor.max -
            it.earned
    }
}

data class ScoreInputs(
    val realTimeProtection: Boolean,
    val webShield: Boolean,
    val definitionsUpdatedAt: Long?,
    val lastFullScanAt: Long?,
    val maliciousItems: Int,
    val suspiciousItems: Int,
    val scheduledScans: Boolean
)

/**
 * A transparent 0-100 score: every point comes from one of six facts the user can see and fix
 * (protection switches, how recent the definitions and the last scan are, unresolved threats).
 * Deterministic: the same inputs and time always give the same score.
 */
object SecurityScoring {
    private const val FRESH_SCAN_DAYS = 7L
    private const val STALE_SCAN_DAYS = 30L
    private const val FRESH_DEFINITIONS_DAYS = 3L
    private const val STALE_DEFINITIONS_DAYS = 14L
    private const val MALICIOUS_PENALTY = 15
    private const val SUSPICIOUS_PENALTY = 8
    private const val PROTECTED_THRESHOLD = 85

    fun compute(inputs: ScoreInputs, now: Long): SecurityScore {
        val items =
            listOf(
                toggle(ScoreFactor.REAL_TIME, inputs.realTimeProtection),
                threats(inputs.maliciousItems, inputs.suspiciousItems),
                age(ScoreFactor.RECENT_SCAN, inputs.lastFullScanAt, now, FRESH_SCAN_DAYS, STALE_SCAN_DAYS),
                age(
                    ScoreFactor.DEFINITIONS,
                    inputs.definitionsUpdatedAt,
                    now,
                    FRESH_DEFINITIONS_DAYS,
                    STALE_DEFINITIONS_DAYS
                ),
                toggle(ScoreFactor.WEB_SHIELD, inputs.webShield),
                toggle(ScoreFactor.SCHEDULE, inputs.scheduledScans)
            )
        val total = items.sumOf { it.earned }
        val level =
            when {
                inputs.maliciousItems > 0 -> ProtectionLevel.AT_RISK
                total >= PROTECTED_THRESHOLD -> ProtectionLevel.PROTECTED
                else -> ProtectionLevel.ATTENTION
            }
        return SecurityScore(total, items, level)
    }

    private fun toggle(factor: ScoreFactor, on: Boolean) =
        ScoreItem(factor, if (on) factor.max else 0, if (on) FactorState.OK else FactorState.MISSING)

    private fun threats(malicious: Int, suspicious: Int): ScoreItem {
        val factor = ScoreFactor.THREATS
        val earned = (factor.max - malicious * MALICIOUS_PENALTY - suspicious * SUSPICIOUS_PENALTY).coerceAtLeast(0)
        val state =
            when {
                malicious + suspicious == 0 -> FactorState.OK
                earned > 0 -> FactorState.PARTIAL
                else -> FactorState.MISSING
            }
        return ScoreItem(factor, earned, state)
    }

    /** Full points when newer than [freshDays], half when newer than [staleDays], none otherwise. */
    private fun age(factor: ScoreFactor, at: Long?, now: Long, freshDays: Long, staleDays: Long): ScoreItem {
        val days = at?.let { TimeUnit.MILLISECONDS.toDays((now - it).coerceAtLeast(0)) }
        return when {
            days == null -> ScoreItem(factor, 0, FactorState.MISSING)
            days < freshDays -> ScoreItem(factor, factor.max, FactorState.OK)
            days < staleDays -> ScoreItem(factor, factor.max / 2, FactorState.PARTIAL)
            else -> ScoreItem(factor, 0, FactorState.MISSING)
        }
    }
}
