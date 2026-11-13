package com.blackshield.core.scanner.risk

import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.AppComponent
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.analysis.LauncherState
import java.util.concurrent.TimeUnit

/**
 * One matched rule: why points were added (or removed), with the facts that triggered it.
 * [points] is what counted; it is less than [rulePoints] when the rule's group cap was reached.
 */
data class Finding(
    val ruleId: String,
    val title: String,
    val points: Int,
    val evidence: List<String>,
    val rulePoints: Int = points,
    val group: String? = null
) {
    val capped: Boolean get() = points != rulePoints
}

enum class Exemption {
    /** Preinstalled system app: heuristics are not applied. */
    SYSTEM_APP,

    /** On the rules' known-good list (package and signing certificate). */
    KNOWN_GOOD
}

data class RiskEvaluation(
    /** Sum of the findings' points, clamped to 0..100. */
    val score: Int,
    val verdict: Verdict,
    /** In rule order. Every point in [score] comes from one of these. */
    val findings: List<Finding>,
    val exemption: Exemption? = null,
    val rulesVersion: String
)

/**
 * Rule-based static risk scoring. Deterministic: the result depends only on the profile, the
 * rules and [nowMillis]; rules run in file order and evidence lists are sorted.
 */
class RiskEngine(private val rules: RiskRules) {
    fun evaluate(profile: AppProfile, nowMillis: Long): RiskEvaluation {
        exemption(profile)?.let { return RiskEvaluation(0, Verdict.CLEAN, emptyList(), it, rules.rulesVersion) }
        val facts = Facts(profile, nowMillis)
        val groupUsed = HashMap<String, Int>()
        val findings =
            rules.rules.mapNotNull { rule ->
                val evidence = facts.match(rule.condition, nested = false) ?: return@mapNotNull null
                Finding(
                    rule.id,
                    rule.title,
                    cappedPoints(rule, groupUsed),
                    evidence.distinct(),
                    rule.points,
                    rule.group
                )
            }
        val score = findings.sumOf { it.points }.coerceIn(0, MAX_SCORE)
        val verdict =
            when {
                score >= rules.thresholds.malicious -> Verdict.MALICIOUS
                score >= rules.thresholds.suspicious -> Verdict.SUSPICIOUS
                else -> Verdict.CLEAN
            }
        return RiskEvaluation(score, verdict, findings, null, rules.rulesVersion)
    }

    /** Positive points of grouped rules count until the group's cap, in rule order. */
    private fun cappedPoints(rule: Rule, used: MutableMap<String, Int>): Int {
        val group = rule.group?.takeIf { rule.points > 0 } ?: return rule.points
        val already = used.getOrDefault(group, 0)
        val applied = rule.points.coerceAtMost(rules.groupCaps.getValue(group) - already).coerceAtLeast(0)
        used[group] = already + applied
        return applied
    }

    fun installSource(profile: AppProfile): InstallSource = when {
        profile.isArchive -> InstallSource.OTHER_INSTALLER

        // a downloaded file, installed through the package installer
        profile.isSystemApp -> InstallSource.PREINSTALLED

        profile.installerPackage == RiskRules.PLAY_STORE -> InstallSource.PLAY_STORE

        profile.installerPackage in rules.trustedInstallers -> InstallSource.TRUSTED_STORE

        profile.installerPackage != null -> InstallSource.OTHER_INSTALLER

        else -> InstallSource.UNKNOWN
    }

    private fun exemption(profile: AppProfile): Exemption? = when {
        rules.exemptSystemApps && profile.isSystemApp -> Exemption.SYSTEM_APP

        rules.knownGood.any { known ->
            known.packageName == profile.packageName &&
                profile.signingCertificates.any { it.sha256 == known.certificateSha256 }
        } -> Exemption.KNOWN_GOOD

        else -> null
    }

    /** Evaluates conditions against one profile. null = no match; a list = match, with its evidence. */
    private inner class Facts(private val p: AppProfile, private val nowMillis: Long) {
        // One branch per condition type: the sealed vocabulary reads best as a single table.
        @Suppress("CyclomaticComplexMethod")
        fun match(condition: Condition, nested: Boolean): List<String>? = when (condition) {
            is Condition.All -> condition.conditions.map { match(it, nested = true) ?: return null }.flatten()

            is Condition.AnyOf ->
                condition.conditions
                    .mapNotNull { match(it, nested = true) }
                    .takeIf { it.isNotEmpty() }
                    ?.flatten()

            is Condition.Not -> if (match(condition.condition, nested = true) == null) emptyList() else null

            is Condition.RequestsPermissions -> permissions(condition)

            is Condition.DangerousPermissionsAtLeast ->
                p.dangerousPermissions
                    .takeIf { it.size >= condition.count }
                    ?.let {
                        listOf(
                            "requests ${it.size} sensitive permissions: ${summary(it.map(::shortPermission).sorted())}"
                        )
                    }

            // As a gate inside a combination the source adds nothing new: the source rule itself says it once.
            is Condition.FromSource -> installSource(p)
                .takeIf { it in condition.sources }
                ?.let { if (nested) emptyList() else listOf(describeSource(it)) }

            is Condition.ComponentWithPermission ->
                p.components
                    .filter { it.permission == condition.permission }
                    .takeIf { it.isNotEmpty() }
                    ?.let {
                        listOf("${componentRole(condition.permission)}: ${summary(it.map(::simpleName).sorted())}")
                    }

            is Condition.HandlesAction -> handles(condition.actions)

            is Condition.Launcher -> p.launcher.takeIf { it in condition.states }?.let { listOf(describeLauncher(it)) }

            is Condition.InstalledWithinDays -> installedWithin(condition.days)

            is Condition.TargetSdkBelow ->
                p.targetSdk
                    .takeIf { it in 1 until condition.sdk }
                    ?.let { listOf("targets Android SDK $it") }

            is Condition.Certificate -> certificate(condition.trait)

            is Condition.ApplicationClassIn ->
                p.applicationClass
                    ?.takeIf { it in condition.classes }
                    ?.let { listOf("application class $it") }

            is Condition.NativeLibraryMatches -> nativeLibraries(condition.patterns)

            is Condition.ObfuscatedComponents -> obfuscated(condition)

            Condition.AccessibilityEnabled -> listOf("its accessibility service is switched on").takeIf {
                p.accessibilityServiceEnabled
            }

            Condition.DeviceAdminActive -> listOf("it is an active device administrator").takeIf { p.deviceAdminActive }

            Condition.Debuggable -> listOf("it is a debuggable build").takeIf { p.isDebuggable }
        }

        private fun permissions(condition: Condition.RequestsPermissions): List<String>? {
            val wanted = condition.permissions.distinct()
            val requested = wanted.filter { it in p.requestedPermissions }.sorted()
            val matched = if (condition.requireAll) requested.size == wanted.size else requested.isNotEmpty()
            return if (matched) listOf("requests ${summary(requested.map(::shortPermission))}") else null
        }

        private fun handles(actions: List<String>): List<String>? = actions
            .distinct()
            .sorted()
            .mapNotNull { action ->
                p.components
                    .filter { component -> component.intentFilters.any { action in it.actions } }
                    .takeIf { it.isNotEmpty() }
                    ?.let {
                        "listens for ${action.substringAfterLast('.')} (${summary(it.map(::simpleName).sorted())})"
                    }
            }.takeIf { it.isNotEmpty() }

        private fun installedWithin(days: Int): List<String>? {
            val age = nowMillis - p.firstInstallTime
            val recent = p.firstInstallTime > 0 && age >= 0 && age < TimeUnit.DAYS.toMillis(days.toLong())
            return if (recent) listOf(describeAge(TimeUnit.MILLISECONDS.toDays(age))) else null
        }

        private fun describeAge(days: Long): String = when (days) {
            0L -> "installed today"
            1L -> "installed 1 day ago"
            else -> "installed $days days ago"
        }

        private fun certificate(trait: CertificateTrait): List<String>? {
            val (what, matches) =
                when (trait) {
                    CertificateTrait.DEBUG ->
                        "the Android debug certificate" to
                            p.signingCertificates.filter { it.debug }

                    CertificateTrait.AOSP_TEST_KEY ->
                        "a public AOSP test key" to
                            p.signingCertificates.filter { it.aospTestKey }
                }
            return matches
                .map { "signed with $what (SHA-256 ${it.sha256.take(CERT_PREFIX)}…)" }
                .sorted()
                .takeIf { it.isNotEmpty() }
        }

        private fun nativeLibraries(patterns: List<String>): List<String>? {
            val regexes = patterns.map(::glob)
            return p.nativeLibraries
                .filter { library -> regexes.any { it.matches(library) } }
                .sorted()
                .takeIf { it.isNotEmpty() }
                ?.let { listOf("native library ${summary(it)}") }
        }

        private fun obfuscated(condition: Condition.ObfuscatedComponents): List<String>? {
            val total = p.components.size
            val odd = p.components.map { it.name }.filter(::looksObfuscated).sorted()
            val matched = total >= condition.minComponents && odd.size.toDouble() / total >= condition.minShare
            return if (matched) {
                listOf(
                    "${odd.size} of $total components have meaningless names: ${summary(odd)}"
                )
            } else {
                null
            }
        }

        private fun describeSource(source: InstallSource): String {
            val installer = p.installerPackage?.let { rules.trustedInstallers[it] ?: WELL_KNOWN_INSTALLERS[it] ?: it }
            val via =
                p.initiatingPackage
                    ?.takeIf { it != p.installerPackage }
                    ?.let { ", started from ${WELL_KNOWN_INSTALLERS[it] ?: it}" }
                    .orEmpty()
            if (p.isArchive) return "a downloaded APK file, not installed yet"
            return when (source) {
                InstallSource.PREINSTALLED -> "preinstalled"
                InstallSource.PLAY_STORE, InstallSource.TRUSTED_STORE -> "installed by $installer"
                InstallSource.OTHER_INSTALLER -> "installed by $installer$via"
                InstallSource.UNKNOWN -> "no installer recorded (adb or unknown)$via"
            }
        }

        private fun describeLauncher(state: LauncherState): String = when (state) {
            LauncherState.HIDDEN -> "launcher activity ${summary(
                p.launcherActivities.map {
                    it.substringAfterLast('.')
                }.sorted()
            )} " +
                "is disabled"

            LauncherState.NONE_DECLARED -> "declares no launcher activity"

            LauncherState.VISIBLE -> "has a launcher icon"
        }
    }

    companion object {
        const val MAX_SCORE = 100
        private const val SUMMARY_ITEMS = 5
        private const val CERT_PREFIX = 16
        private const val SHORT_NAME = 2

        /** Installers that are not stores, named for people rather than by package. */
        private val WELL_KNOWN_INSTALLERS =
            mapOf(
                "com.google.android.packageinstaller" to "the Android package installer (a downloaded APK file)",
                "com.android.packageinstaller" to "the Android package installer (a downloaded APK file)",
                "com.android.shell" to "adb (USB debugging)"
            )

        private val COMPONENT_ROLES =
            mapOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE" to "accessibility service",
                "android.permission.BIND_DEVICE_ADMIN" to "device admin receiver",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "notification listener",
                "android.permission.BIND_VPN_SERVICE" to "VPN service"
            )

        /** R8 keeps manifest-declared class names, so very short names in the manifest are unusual. */
        fun looksObfuscated(className: String): Boolean {
            val segments = className.split('.')
            return segments.last().length <= SHORT_NAME || segments.all { it.length <= SHORT_NAME }
        }

        private fun componentRole(permission: String) =
            COMPONENT_ROLES[permission] ?: "component requiring ${shortPermission(permission)}"

        private fun shortPermission(name: String) = name.substringAfterLast('.')

        private fun simpleName(component: AppComponent) = component.name.substringAfterLast('.')

        private fun summary(items: List<String>): String = if (items.size <= SUMMARY_ITEMS) {
            items.joinToString(", ")
        } else {
            items.take(SUMMARY_ITEMS).joinToString(", ") + " and ${items.size - SUMMARY_ITEMS} more"
        }

        private fun glob(pattern: String): Regex =
            Regex(pattern.split('*').joinToString(".*") { Regex.escape(it) }, RegexOption.IGNORE_CASE)
    }
}
