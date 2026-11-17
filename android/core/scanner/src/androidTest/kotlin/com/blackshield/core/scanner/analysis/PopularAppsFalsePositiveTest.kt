package com.blackshield.core.scanner.analysis

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.apps.InstalledApp
import com.blackshield.core.scanner.apps.PackageManagerAppSource
import com.blackshield.core.scanner.apps.RiskAssessor
import com.blackshield.core.scanner.risk.BundledRiskRulesSource
import com.blackshield.core.scanner.yara.YaraCompileResult
import com.blackshield.core.scanner.yara.YaraScanner
import java.io.File
import java.time.Clock
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * False-positive check against the 200 popular legitimate apps in `assets/popular_apps.txt`: every one of them that is
 * installed on the device goes through the same static analysis, risk rules and bundled YARA rules as a real scan
 * (signature matches aside: those come from feeds of known malware). None may be malicious, and at most 1 % may be
 * suspicious.
 *
 * Install the apps first, from Play on a test device or with `scripts/install-popular-apps.sh <folder of APKs>`. Apps
 * installed with adb have no installer, which some rules treat as sideloading; they are assessed as if installed from
 * Play, as they would be on users' phones. Pass `-Pandroid.testInstrumentationRunnerArguments.requirePopularApps=150`
 * to fail when fewer apps are installed. Per-app results are logged under the tag "PopularApps".
 */
@RunWith(AndroidJUnit4::class)
class PopularAppsFalsePositiveTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test
    fun popularLegitimateAppsAreNotFlagged() = runTest(timeout = kotlin.time.Duration.parse("30m")) {
        val popular = instrumentation.context.assets.open("popular_apps.txt").bufferedReader().readLines()
            .map(String::trim).filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
        assertTrue("the list has 200 apps", popular.size == LIST_SIZE)
        val installed = PackageManagerAppSource(context).installedApps().filter { it.packageName in popular }
        val required = InstrumentationRegistry.getArguments().getString("requirePopularApps")?.toInt() ?: 0
        Log.i(TAG, "${installed.size} of ${popular.size} popular apps installed")
        assertTrue("only ${installed.size} popular apps installed, $required required", installed.size >= required)

        val session = PackageManagerApkAnalyzer(context).startSession()
        val assessor = RiskAssessor(BundledRiskRulesSource(context), Clock.systemUTC())
        val compiled = YaraScanner.compile(context.assets.open("yara/bundled.yar").reader().use { it.readText() })
        val yara = (compiled as YaraCompileResult.Success).scanner
        val results = installed.map { app ->
            val asUser = app.asInstalledFromPlay()
            val profile = session.analyze(asUser)
            val reports = asUser.apkPaths.map { yara.scanDetailed(File(it)) }
            val withPatterns = profile.copy(
                yaraMatches = reports.flatMap { it.matches },
                analysisGaps = profile.analysisGaps + reports.flatMap { it.problems }
            )
            val assessment = assessor.assess(withPatterns, emptyList(), emptyList(), allowListed = false)
            Log.i(
                TAG,
                "${app.packageName}: ${assessment.verdict} ${assessment.riskScore} " +
                    assessment.reasons.filter { it.points != 0 }.map { "${it.ruleId ?: it.code.name}:${it.points}" }
            )
            app.packageName to assessment
        }

        val malicious = results.filter { it.second.verdict == Verdict.MALICIOUS }.map { it.first }
        val suspicious = results.filter { it.second.verdict == Verdict.SUSPICIOUS }.map { it.first }
        Log.i(TAG, "malicious: $malicious; suspicious: $suspicious")
        assertTrue("popular apps flagged as malicious: $malicious", malicious.isEmpty())
        assertTrue(
            "too many popular apps flagged as suspicious (${suspicious.size}/${results.size}): $suspicious",
            suspicious.size * PERCENT <= results.size * MAX_SUSPICIOUS_PERCENT
        )
    }

    /** Apps pushed with adb have no installer; on users' phones these come from Play. */
    private fun InstalledApp.asInstalledFromPlay(): InstalledApp =
        if (installerPackage == null || installerPackage == SHELL) copy(installerPackage = PLAY_STORE) else this

    private companion object {
        const val TAG = "PopularApps"
        const val LIST_SIZE = 200
        const val PERCENT = 100
        const val MAX_SUSPICIOUS_PERCENT = 1
        const val SHELL = "com.android.shell"
        const val PLAY_STORE = "com.android.vending"
    }
}
