package com.blackshield.app

import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkInfo
import androidx.work.WorkManager
import com.blackshield.app.di.AppEntryPoint
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.prefs.ScanSchedule
import com.blackshield.core.data.quarantine.QuarantineOutcome
import com.blackshield.core.ui.HistoryText
import com.blackshield.feature.scan.schedule.ScanScheduler
import com.blackshield.testing.ui.enableAccessibilityChecksWhereSupported
import dagger.hilt.android.EntryPointAccessors
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The main flows end to end in the real app, with accessibility checks on every screen the test touches.
 *
 * Meant for a test device or emulator: the quarantine tests clear the list of detected and quarantined files first.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class MainFlowsTest {
    @get:Rule
    val rule = createEmptyComposeRule()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val app = EntryPointAccessors.fromApplication(context.applicationContext, AppEntryPoint::class.java)
    private val vault = app.quarantineVault()
    private var scenario: ActivityScenario<MainActivity>? = null

    @After
    fun tearDown() {
        scenario?.close()
        runBlocking {
            app.appSettings().setOnboardingCompleted(true)
            app.appSettings().setScanSchedule(ScanSchedule())
            clearFileThreats()
        }
        File(context.filesDir, TEST_DIR).deleteRecursively()
    }

    @Test
    fun firstLaunch_onboardingLeadsToTheDashboard_once() {
        launch(onboarded = false)

        rule.onNodeWithTag("onboarding").assertExists()
        rule.onNodeWithTag("onboardingPrimary").performClick()
        repeat(PERMISSION_STEPS) { rule.onNodeWithTag("onboardingSkip").performClick() }
        waitForTag("home")

        assertTrue(runBlocking { app.appSettings().onboardingCompleted.first() })
        scenario?.recreate()
        waitForTag("home")
        rule.onNodeWithTag("onboarding").assertDoesNotExist()
    }

    @Test
    fun scanNow_runsAFullScan_thenThreatsHistoryAndSchedule() {
        launch(onboarded = true)
        waitForTag("home")

        rule.onNodeWithTag("homeScanNow").performClick()
        rule.waitUntil(SCAN_TIMEOUT_MILLIS) {
            val done = listOf(
                context.getString(com.blackshield.feature.scan.R.string.scan_done_clean),
                context.getString(com.blackshield.feature.scan.R.string.scan_done_threats)
            )
            done.any { rule.onAllNodes(hasTestTag("scanProgress") and hasText(it)).fetchSemanticsNodes().isNotEmpty() }
        }

        rule.onNodeWithTag("tab_THREATS").performClick()
        waitForTag("threats")
        rule.onNodeWithTag("openHistory").performClick()
        waitForTag("history")
        val scan = runBlocking { app.history().lastFullScan().first() }!!
        rule.onNodeWithText(HistoryText.title(context.resources, scan)).assertExists()
        Espresso.pressBack()
        waitForTag("threats")

        rule.onNodeWithTag("tab_SETTINGS").performClick()
        rule.onNodeWithTag("frequency_DAILY").performScrollTo().performClick()
        rule.waitUntil(TIMEOUT_MILLIS) { scheduledWork()?.periodicityInfo?.repeatIntervalMillis == DAY }
        assertTrue(scheduledWork()!!.constraints.requiresCharging())
    }

    @Test
    fun harmfulFile_isQuarantinedEncrypted_andRestoresByteForByte() {
        runBlocking { clearFileThreats() }
        val original = testApk()
        val source = File(context.filesDir, "$TEST_DIR/$FILE_NAME").apply {
            parentFile!!.mkdirs()
            writeBytes(original)
        }
        val id = runBlocking { vault.recordDetection(threat(source)) }
        launch(onboarded = true)

        rule.onNodeWithTag("tab_THREATS").performClick()
        rule.onNodeWithTag("threats").performScrollToNode(hasTestTag("quarantine"))
        rule.onNodeWithTag("quarantine").performClick()
        rule.waitUntil(TIMEOUT_MILLIS) { runBlocking { vault.quarantined().first() }.any { it.id == id } }
        rule.onNodeWithTag("threats").performScrollToNode(hasTestTag("restore"))

        assertFalse("the original is removed", source.exists())
        val locked = File(File(context.noBackupFilesDir, "quarantine"), vaultFile(id)).readBytes()
        assertFalse("the vault file is encrypted", locked.containsSequence("AndroidManifest.xml".toByteArray()))

        val restored = ByteArrayOutputStream()
        assertTrue(runBlocking { vault.restore(id, restored) })
        assertArrayEquals(original, restored.toByteArray())
        rule.waitUntil(TIMEOUT_MILLIS) { rule.onAllNodes(hasTestTag("restore")).fetchSemanticsNodes().isEmpty() }
    }

    @Test
    fun quarantinedFile_isDeletedForeverAfterConfirming() {
        runBlocking { clearFileThreats() }
        val source = File(context.filesDir, "$TEST_DIR/$FILE_NAME").apply {
            parentFile!!.mkdirs()
            writeBytes(testApk())
        }
        val id = runBlocking { vault.recordDetection(threat(source)) }
        assertEquals(QuarantineOutcome.Quarantined, runBlocking { vault.quarantine(id) })
        val locked = File(File(context.noBackupFilesDir, "quarantine"), vaultFile(id))
        launch(onboarded = true)

        rule.onNodeWithTag("tab_THREATS").performClick()
        rule.onNodeWithTag("threats").performScrollToNode(hasTestTag("delete"))
        rule.onNodeWithTag("delete").performClick()
        rule.onNodeWithTag("confirmDelete").performClick()

        rule.waitUntil(TIMEOUT_MILLIS) { runBlocking { vault.quarantined().first() }.isEmpty() }
        assertFalse("the encrypted copy is gone", locked.exists())
    }

    private fun launch(onboarded: Boolean) {
        runBlocking { app.appSettings().setOnboardingCompleted(onboarded) }
        scenario = ActivityScenario.launch(MainActivity::class.java)
        rule.enableAccessibilityChecksWhereSupported()
    }

    private fun waitForTag(tag: String) {
        rule.waitUntil(TIMEOUT_MILLIS) { rule.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun scheduledWork(): WorkInfo? = WorkManager.getInstance(context)
        .getWorkInfosForUniqueWork(ScanScheduler.WORK_NAME).get()
        .firstOrNull { it.state == WorkInfo.State.ENQUEUED }

    private fun testApk(): ByteArray = instrumentation.context.assets.open("eicar-test.apk").use { it.readBytes() }

    private fun threat(source: File) = FileThreat(
        displayName = FILE_NAME,
        sourcePath = source.absolutePath,
        sizeBytes = source.length(),
        verdict = Verdict.MALICIOUS,
        riskScore = 100,
        reasons = listOf(ScanReason(ScanReason.Code.KNOWN_MALWARE, "EICAR-Test-File", 100)),
        detectedAt = System.currentTimeMillis()
    )

    private fun vaultFile(id: Long): String =
        runBlocking { vault.quarantined().first() }.first { it.id == id }.vaultFile!!

    private suspend fun clearFileThreats() {
        vault.detected().first().forEach { vault.dismiss(it.id) }
        vault.quarantined().first().forEach { vault.delete(it.id) }
    }

    private fun ByteArray.containsSequence(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }

    private companion object {
        const val TEST_DIR = "e2e"
        const val FILE_NAME = "e2e-eicar-test.apk"
        const val PERMISSION_STEPS = 2
        const val TIMEOUT_MILLIS = 10_000L
        const val SCAN_TIMEOUT_MILLIS = 120_000L
        val DAY = TimeUnit.DAYS.toMillis(1)
    }
}
