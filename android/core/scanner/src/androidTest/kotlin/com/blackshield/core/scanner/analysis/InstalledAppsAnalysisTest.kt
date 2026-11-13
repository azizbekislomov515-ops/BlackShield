package com.blackshield.core.scanner.analysis

import android.content.pm.PackageManager
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.manifest.ManifestParser
import com.blackshield.core.scanner.apps.PackageManagerAppSource
import com.blackshield.core.scanner.apps.RiskAssessor
import com.blackshield.core.scanner.risk.BundledRiskRulesSource
import java.time.Clock
import java.util.zip.ZipFile
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Static analysis over every package on the device, with the shipped rules:
 *
 * - the binary manifest parser reads every installed APK, and agrees with PackageManager on the
 *   components it finds (same fully-qualified names);
 * - no preinstalled system app is flagged.
 *
 * Results are logged under the tag "InstalledAppsAnalysis".
 */
@RunWith(AndroidJUnit4::class)
class InstalledAppsAnalysisTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun parsesEveryInstalledManifestConsistentlyWithPackageManager() = runTest {
        val apps = PackageManagerAppSource(context).installedApps()
        assertTrue("package visibility must expose the installed apps", apps.size > 50)
        val unreadable = mutableListOf<String>()
        val mismatches = mutableListOf<String>()
        var components = 0

        for (app in apps) {
            val manifest =
                runCatching {
                    ZipFile(app.apkPaths.first()).use { zip ->
                        ManifestParser.parse(zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes())
                    }
                }.getOrElse {
                    unreadable += "${app.packageName}: $it"
                    continue
                }
            assertEquals(app.packageName, manifest.packageName)
            val known = packageManagerComponents(app.packageName)
            manifest.components.filterNot { it.name in known }.forEach { mismatches += "${app.packageName}/${it.name}" }
            components += manifest.components.size
        }

        Log.i(
            TAG,
            "manifests: ${apps.size - unreadable.size}/${apps.size} parsed, $components components, " +
                "${mismatches.size} mismatches"
        )
        assertTrue("unreadable manifests: $unreadable", unreadable.isEmpty())
        assertTrue("components unknown to PackageManager: ${mismatches.take(20)}", mismatches.isEmpty())
    }

    @Test
    fun systemAppsAreNeverFlagged() = runTest {
        val apps = PackageManagerAppSource(context).installedApps()
        val session = PackageManagerApkAnalyzer(context).startSession()
        val assessor = RiskAssessor(BundledRiskRulesSource(context), Clock.systemUTC())
        val started = System.nanoTime()

        val results =
            apps.map { app ->
                val profile = session.analyze(app)
                app to assessor.assess(profile, emptyList(), emptyList(), allowListed = false)
            }

        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        val (system, user) = results.partition { (app, _) -> app.isSystemApp }
        Log.i(TAG, "analyzed ${apps.size} apps in $elapsedMs ms (${elapsedMs / apps.size.coerceAtLeast(1)} ms/app)")
        Log.i(TAG, "system apps: ${system.size}, user apps: ${user.size}")
        user.forEach { (app, assessment) ->
            Log.i(
                TAG,
                "user app ${app.packageName}: ${assessment.verdict} ${assessment.riskScore} " +
                    assessment.reasons.map { it.ruleId ?: it.code.name }
            )
        }

        val flagged = system.filter { (_, assessment) ->
            assessment.verdict != Verdict.CLEAN
        }.map { it.first.packageName }
        assertTrue("flagged system apps: $flagged", flagged.isEmpty())
        assertTrue(system.all { (_, assessment) -> assessment.reasons.any { it.code == ScanReason.Code.SYSTEM_APP } })
        assertTrue("there are preinstalled apps to check", system.size > 50)
    }

    private fun packageManagerComponents(packageName: String): Set<String> {
        val flags =
            PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or PackageManager.MATCH_DISABLED_COMPONENTS
        val info = context.packageManager.getPackageInfo(
            packageName,
            PackageManager.PackageInfoFlags.of(flags.toLong())
        )
        return buildSet {
            info.activities?.forEach { add(it.name) }
            info.services?.forEach { add(it.name) }
            info.receivers?.forEach { add(it.name) }
            info.providers?.forEach { add(it.name) }
        }
    }

    private companion object {
        const val TAG = "InstalledAppsAnalysis"
    }
}
