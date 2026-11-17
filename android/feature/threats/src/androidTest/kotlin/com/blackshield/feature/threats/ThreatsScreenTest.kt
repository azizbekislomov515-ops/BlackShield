package com.blackshield.feature.threats

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.FileThreatState
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
class ThreatsScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val calls = mutableListOf<String>()
    private val actions = ThreatActions(
        onAppDetails = { calls += "details:$it" },
        onUninstall = { calls += "uninstall:$it" },
        onQuarantine = { calls += "quarantine:$it" },
        onIgnore = { calls += "ignore:$it" },
        onRestore = { calls += "restore:${it.id}" },
        onDelete = { calls += "delete:${it.id}" },
        onOpenHistory = { calls += "history" }
    )

    @Test
    fun nothingToHandle_saysSo() {
        rule.setThemedContent { ThreatsScreen(ThreatsUiState(), actions) }

        rule.onNodeWithText(context.getString(R.string.threats_none)).assertIsDisplayed()
        rule.checkAccessibility()
    }

    @Test
    fun harmfulApp_isUninstalledFromItsCard() {
        rule.setThemedContent { ThreatsScreen(ThreatsFixtures.state, actions) }

        rule.onNodeWithTag("uninstall").performClick()

        assertEquals(listOf("uninstall:${ThreatsFixtures.app.packageName}"), calls)
        rule.checkAccessibility()
    }

    @Test
    fun harmfulFile_isQuarantined_andQuarantinedFilesCanBeRestoredOrDeleted() {
        rule.setThemedContent { ThreatsScreen(ThreatsFixtures.state, actions) }

        rule.onNodeWithTag("threats").performScrollToNode(hasTestTag("quarantine"))
        rule.onNodeWithTag("quarantine").performClick()
        rule.onNodeWithTag("threats").performScrollToNode(hasTestTag("restore"))
        rule.onNodeWithTag("restore").performClick()
        rule.onNodeWithTag("delete").performClick()

        assertEquals(
            listOf(
                "quarantine:${ThreatsFixtures.file.id}",
                "restore:${ThreatsFixtures.quarantined.id}",
                "delete:${ThreatsFixtures.quarantined.id}"
            ),
            calls
        )
    }

    @Test
    fun historyIsOneTapAway() {
        rule.setThemedContent { ThreatsScreen(ThreatsUiState(), actions) }

        rule.onNodeWithTag("openHistory").performClick()

        assertEquals(listOf("history"), calls)
    }

    @Test
    fun screenshot() {
        rule.setThemedContent { ThreatsScreen(ThreatsFixtures.state, actions) }
        Screenshots.assertMatchesGolden(rule.onRoot(), "threats")
    }
}

object ThreatsFixtures {
    const val NOW = 1_763_000_000_000L

    val app = ScanResult(
        packageName = "com.example.flashlight",
        appLabel = "Super Flashlight",
        versionCode = 7,
        apkSha256 = "ab".repeat(32),
        verdict = Verdict.MALICIOUS,
        riskScore = 96,
        reasons = listOf(ScanReason(ScanReason.Code.KNOWN_MALWARE, "Android.Banker.Gen", 100)),
        scannedAt = NOW
    )

    val file = FileThreat(
        id = 1,
        displayName = "free-coins.apk",
        sourcePath = "/storage/emulated/0/Download/free-coins.apk",
        sizeBytes = 2_400_000,
        verdict = Verdict.SUSPICIOUS,
        riskScore = 64,
        reasons = listOf(ScanReason(ScanReason.Code.HEURISTIC, "Reads your SMS and installs other apps", 40)),
        detectedAt = NOW
    )

    val quarantined = FileThreat(
        id = 2,
        displayName = "update.apk",
        sizeBytes = 5_100_000,
        verdict = Verdict.MALICIOUS,
        riskScore = 100,
        reasons = emptyList(),
        detectedAt = NOW - 3_600_000,
        state = FileThreatState.QUARANTINED,
        vaultFile = "2.bsq",
        quarantinedAt = NOW - 3_000_000
    )

    val state = ThreatsUiState(apps = listOf(app), files = listOf(file), vault = listOf(quarantined))
}
