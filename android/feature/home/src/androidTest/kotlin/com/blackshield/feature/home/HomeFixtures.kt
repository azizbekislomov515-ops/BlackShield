package com.blackshield.feature.home

import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.prefs.ScanFrequency
import com.blackshield.feature.webshield.WebShieldStatus
import java.util.concurrent.TimeUnit

/** Fixed dashboards. The clock is part of the state, so scores and relative times never drift. */
object HomeFixtures {
    const val NOW = 1_763_000_000_000L
    private val HOUR = TimeUnit.HOURS.toMillis(1)
    private val DAY = TimeUnit.DAYS.toMillis(1)

    private fun state(inputs: ScoreInputs, threats: Int) = HomeUiState(
        score = SecurityScoring.compute(inputs, NOW),
        lastScanAt = inputs.lastFullScanAt,
        definitionsVersion = 42,
        definitionsUpdatedAt = inputs.definitionsUpdatedAt,
        signatureCount = 18_250,
        realTimeEnabled = inputs.realTimeProtection,
        webShield = if (inputs.webShield) WebShieldStatus.On(12_400, 2, null, false) else WebShieldStatus.Off,
        scanFrequency = if (inputs.scheduledScans) ScanFrequency.WEEKLY else ScanFrequency.OFF,
        openThreats = threats,
        recent = listOf(
            HistoryEvent(
                id = 1,
                occurredAt = NOW - 2 * HOUR,
                kind = HistoryKind.SCAN_COMPLETED,
                source = ScanSource.MANUAL,
                verdict = if (threats > 0) Verdict.SUSPICIOUS else Verdict.CLEAN,
                itemsScanned = 143,
                threatsFound = threats
            ),
            HistoryEvent(
                id = 2,
                occurredAt = NOW - DAY,
                kind = HistoryKind.ITEM_CHECKED,
                source = ScanSource.REAL_TIME,
                verdict = Verdict.CLEAN,
                subject = "Notes",
                target = "com.example.notes"
            )
        ),
        now = NOW
    )

    val protectedState = state(ScoreInputs(true, true, NOW - HOUR, NOW - DAY, 0, 0, true), threats = 0)
    val attentionState = state(ScoreInputs(true, false, NOW - HOUR, NOW - 2 * HOUR, 0, 1, false), threats = 1)
    val atRiskState = state(ScoreInputs(false, false, null, null, 1, 0, false), threats = 1)
}
