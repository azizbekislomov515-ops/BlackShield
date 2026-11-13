package com.blackshield.core.scanner.yara

import java.io.File
import javax.inject.Inject

/** YARA results for one app (all its APK files). */
data class PatternScanResult(
    val matches: List<YaraMatch>,
    /** What could not be scanned; reported with the verdict so nothing is silently skipped. */
    val problems: List<String> = emptyList(),
    val rulesVersion: Long? = null
)

/** Pattern-matches an app's APK files. Blocking; call it on the scan dispatcher. Faked in JVM tests. */
fun interface ApkPatternScanner {
    fun scan(apkPaths: List<String>): PatternScanResult
}

/** [ApkPatternScanner] backed by the active [YaraRules]. */
class YaraApkScanner
@Inject
constructor(private val rules: YaraRules) : ApkPatternScanner {
    override fun scan(apkPaths: List<String>): PatternScanResult = rules.withScanner { scanner, active ->
        val reports = apkPaths.map { scanner.scanDetailed(File(it)) }
        PatternScanResult(
            matches = reports.flatMap { it.matches }.distinctBy { it.namespace to it.rule },
            problems = reports.flatMap { it.problems },
            rulesVersion = active.version
        )
    } ?: PatternScanResult(emptyList(), listOf("YARA rules are not available; pattern matching was skipped"))
}
