package com.blackshield.feature.scan

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.testing.ui.Screenshots
import com.blackshield.testing.ui.checkAccessibility
import com.blackshield.testing.ui.setThemedContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScanScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val calls = mutableListOf<String>()

    private fun show(state: ScanUiState) {
        rule.setThemedContent {
            ScanScreen(
                state = state,
                onScanNow = { calls += "scan" },
                onPause = { calls += "pause" },
                onResume = { calls += "resume" },
                onCancel = { calls += "cancel" },
                onScanFile = { calls += "file" },
                onResultClick = { calls += "details:$it" }
            )
        }
    }

    @Test
    fun idle_offersAFullScanAndAFileScan() {
        show(ScanUiState())

        rule.onNodeWithTag("scanProgress").assertTextEquals(context.getString(R.string.scan_ready))
        rule.checkAccessibility()
        rule.onNodeWithTag("scanNow").performClick()
        rule.onNodeWithTag("scanFile").performClick()

        assertEquals(listOf("scan", "file"), calls)
    }

    @Test
    fun running_canBePausedAndCancelled() {
        show(ScanUiState(status = ScanStatus.Running(40, 120, "Camera", paused = false)))

        rule.onNodeWithTag("scanProgress").assertTextEquals(context.getString(R.string.scan_running))
        rule.onNodeWithText(context.getString(R.string.scan_pause)).performClick()
        rule.onNodeWithText(context.getString(R.string.scan_cancel)).performClick()

        assertEquals(listOf("pause", "cancel"), calls)
        rule.checkAccessibility()
    }

    @Test
    fun finished_listsFlaggedAppsWithDetails() {
        show(ScanFixtures.finished)

        rule.onNodeWithTag("scanProgress").assertTextEquals(context.getString(R.string.scan_done_threats))
        rule.onNodeWithText("Super Flashlight").performClick()

        assertEquals(listOf("details:com.example.flashlight"), calls)
        rule.checkAccessibility()
    }

    @Test
    fun screenshot_running() {
        show(ScanUiState(status = ScanStatus.Running(40, 120, "Camera", paused = false, threats = 1)))
        Screenshots.assertMatchesGolden(rule.onRoot(), "scan_running")
    }

    @Test
    fun screenshot_finished() {
        show(ScanFixtures.finished)
        Screenshots.assertMatchesGolden(rule.onRoot(), "scan_finished")
    }
}

object ScanFixtures {
    private const val NOW = 1_763_000_000_000L

    private fun result(pkg: String, label: String, verdict: Verdict, risk: Int, reason: ScanReason?) = ScanResult(
        packageName = pkg,
        appLabel = label,
        versionCode = 1,
        apkSha256 = null,
        verdict = verdict,
        riskScore = risk,
        reasons = listOfNotNull(reason),
        scannedAt = NOW
    )

    val finished = ScanUiState(
        results = listOf(
            result(
                "com.example.flashlight",
                "Super Flashlight",
                Verdict.MALICIOUS,
                96,
                ScanReason(ScanReason.Code.KNOWN_MALWARE, "Android.Banker.Gen", 100)
            ),
            result(
                "com.example.cleaner",
                "Fast Cleaner",
                Verdict.SUSPICIOUS,
                58,
                ScanReason(ScanReason.Code.HEURISTIC, "Can read your notifications", 30)
            ),
            result("com.example.notes", "Notes", Verdict.CLEAN, 0, null)
        ),
        status = ScanStatus.Finished(total = 143, malicious = 1, suspicious = 1, durationMillis = 8_400)
    )
}
