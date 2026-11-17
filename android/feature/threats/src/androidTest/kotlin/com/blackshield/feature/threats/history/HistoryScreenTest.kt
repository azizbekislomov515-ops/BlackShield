package com.blackshield.feature.threats.history

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.HistoryFilter
import com.blackshield.feature.threats.R
import com.blackshield.testing.ui.Screenshots
import com.blackshield.testing.ui.checkAccessibility
import com.blackshield.testing.ui.setThemedContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HistoryScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val exports = mutableListOf<ExportFormat>()

    /** The screen with filtering done the way the view model does it, on the fixture events. */
    private fun showHistory() {
        rule.setThemedContent {
            var filter by remember { mutableStateOf(HistoryFilter()) }
            val events = HistoryFixtures.events.filter { event ->
                (filter.verdicts.isEmpty() || event.verdict in filter.verdicts) &&
                    (filter.sources.isEmpty() || event.source in filter.sources) &&
                    filter.period.days?.let { event.occurredAt >= HistoryFixtures.NOW - it * DAY } != false
            }
            HistoryScreen(
                state = HistoryUiState(filter, events, HistoryFixtures.NOW),
                onBack = {},
                onPeriod = { filter = filter.copy(period = it) },
                onVerdict = { filter = filter.copy(verdicts = filter.verdicts.toggle(it)) },
                onSource = { filter = filter.copy(sources = filter.sources.toggle(it)) },
                onClearFilters = { filter = HistoryFilter() },
                onExport = { exports += it }
            )
        }
    }

    @Test
    fun filters_narrowTheList() {
        showHistory()
        rule.onNodeWithText("Super Flashlight", substring = true).assertIsDisplayed()
        rule.onNodeWithText("Notes", substring = true).assertIsDisplayed()
        rule.checkAccessibility()

        rule.onNodeWithTag("verdict_MALICIOUS").performClick().assertIsSelected()
        rule.onNodeWithText("Notes", substring = true).assertDoesNotExist()
        rule.onNodeWithText("Super Flashlight", substring = true).assertIsDisplayed()

        rule.onNodeWithTag("source_SCHEDULED").performClick()
        rule.onNodeWithText(context.getString(R.string.history_empty)).assertIsDisplayed()

        rule.onNodeWithTag("verdict_MALICIOUS").performClick()
        rule.onNodeWithTag("source_SCHEDULED").performClick()
        rule.onNodeWithTag("period_DAY").performClick().assertIsSelected()
        rule.onNodeWithText("Old App", substring = true).assertDoesNotExist()
    }

    @Test
    fun export_offersPdfAndJson() {
        showHistory()

        rule.onNodeWithTag("export").performClick()
        rule.onNodeWithTag("exportPdf").performClick()
        rule.onNodeWithTag("export").performClick()
        rule.onNodeWithTag("exportJson").performClick()

        assertEquals(listOf(ExportFormat.PDF, ExportFormat.JSON), exports)
    }

    @Test
    fun screenshot() {
        showHistory()
        Screenshots.assertMatchesGolden(rule.onRoot(), "history")
    }

    private companion object {
        const val DAY = 86_400_000L

        fun <T> Set<T>.toggle(item: T): Set<T> = if (item in this) this - item else this + item
    }
}

object HistoryFixtures {
    const val NOW = 1_763_000_000_000L
    private const val HOUR = 3_600_000L

    val events = listOf(
        HistoryEvent(
            id = 1,
            occurredAt = NOW - HOUR,
            kind = HistoryKind.ITEM_CHECKED,
            source = ScanSource.REAL_TIME,
            verdict = Verdict.MALICIOUS,
            subject = "Super Flashlight",
            target = "com.example.flashlight",
            riskScore = 96
        ),
        HistoryEvent(
            id = 2,
            occurredAt = NOW - 3 * HOUR,
            kind = HistoryKind.SCAN_COMPLETED,
            source = ScanSource.MANUAL,
            verdict = Verdict.CLEAN,
            itemsScanned = 143
        ),
        HistoryEvent(
            id = 3,
            occurredAt = NOW - 5 * HOUR,
            kind = HistoryKind.ITEM_CHECKED,
            source = ScanSource.REAL_TIME,
            verdict = Verdict.CLEAN,
            subject = "Notes",
            target = "com.example.notes"
        ),
        HistoryEvent(
            id = 4,
            occurredAt = NOW - 10 * 24 * HOUR,
            kind = HistoryKind.ITEM_CHECKED,
            source = ScanSource.FILE,
            verdict = Verdict.SUSPICIOUS,
            subject = "Old App",
            target = "old.apk"
        )
    )
}
