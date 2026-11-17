package com.blackshield.feature.home

import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityScoringTest {
    private val now = TimeUnit.DAYS.toMillis(1000)

    private fun daysAgo(days: Long) = now - TimeUnit.DAYS.toMillis(days)

    private val everything =
        ScoreInputs(
            realTimeProtection = true,
            webShield = true,
            definitionsUpdatedAt = daysAgo(0),
            lastFullScanAt = daysAgo(1),
            maliciousItems = 0,
            suspiciousItems = 0,
            scheduledScans = true
        )

    @Test
    fun `factor weights add up to 100`() {
        assertEquals(100, ScoreFactor.entries.sumOf { it.max })
    }

    @Test
    fun `everything on and fresh is 100 and protected`() {
        val score = SecurityScoring.compute(everything, now)
        assertEquals(100, score.total)
        assertEquals(ProtectionLevel.PROTECTED, score.level)
        assertTrue(score.improvements.isEmpty())
    }

    @Test
    fun `nothing set up is 25 (no threats) and needs attention`() {
        val score = SecurityScoring.compute(ScoreInputs(false, false, null, null, 0, 0, false), now)
        assertEquals(25, score.total)
        assertEquals(ProtectionLevel.ATTENTION, score.level)
        // Worst first: real-time (25) before the 15-point and 10-point factors.
        assertEquals(ScoreFactor.REAL_TIME, score.improvements.first().factor)
    }

    @Test
    fun `stale scans and definitions earn half, very old ones nothing`() {
        val stale = SecurityScoring.compute(
            everything.copy(lastFullScanAt = daysAgo(10), definitionsUpdatedAt = daysAgo(5)),
            now
        )
        assertEquals(100 - 8 - 8, stale.total)
        assertEquals(FactorState.PARTIAL, stale.items.first { it.factor == ScoreFactor.RECENT_SCAN }.state)

        val old = SecurityScoring.compute(
            everything.copy(lastFullScanAt = daysAgo(60), definitionsUpdatedAt = daysAgo(30)),
            now
        )
        assertEquals(70, old.total)
    }

    @Test
    fun `any malware means at risk, whatever the score`() {
        val score = SecurityScoring.compute(everything.copy(maliciousItems = 1), now)
        assertEquals(85, score.total) // high enough for "protected", but malware overrides it
        assertEquals(ProtectionLevel.AT_RISK, score.level)
        assertEquals(listOf(ScoreFactor.THREATS), score.improvements.map { it.factor })
    }

    @Test
    fun `threat penalties never go below zero`() {
        val score = SecurityScoring.compute(everything.copy(maliciousItems = 3, suspiciousItems = 4), now)
        assertEquals(0, score.items.first { it.factor == ScoreFactor.THREATS }.earned)
        val suspicious = SecurityScoring.compute(everything.copy(suspiciousItems = 1), now)
        assertEquals(ProtectionLevel.PROTECTED, suspicious.level)
        assertEquals(92, suspicious.total)
    }
}
