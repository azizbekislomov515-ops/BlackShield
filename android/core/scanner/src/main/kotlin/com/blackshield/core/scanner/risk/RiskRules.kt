package com.blackshield.core.scanner.risk

import com.blackshield.core.scanner.analysis.LauncherState

/** Where an app came from, as judged with the rules' list of trusted installers. */
enum class InstallSource {
    /** Part of the system image. */
    PREINSTALLED,

    /** Installed by Google Play (apps there are reviewed and scanned by Play Protect). */
    PLAY_STORE,

    /** Installed by another store in [RiskRules.trustedInstallers]. */
    TRUSTED_STORE,

    /** Installed by some other app: the package installer (file manager, browser), another store. */
    OTHER_INSTALLER,

    /** No installer recorded: adb, or unknown. */
    UNKNOWN
}

enum class CertificateTrait { DEBUG, AOSP_TEST_KEY }

data class Thresholds(val suspicious: Int, val malicious: Int)

/** An app exempt from heuristics, pinned to its signing certificate so a lookalike cannot borrow it. */
data class KnownGoodApp(val packageName: String, val certificateSha256: String)

data class Rule(
    /** Stable identifier, recorded with each finding. */
    val id: String,
    /** Plain-language explanation shown to the user. */
    val title: String,
    /** Added to the score when the rule matches; negative for signs of trust. */
    val points: Int,
    val condition: Condition,
    /** Rules in a group share its points cap (see [RiskRules.groupCaps]). */
    val group: String? = null
)

/**
 * The risk engine's configuration, loaded from JSON (assets/risk/risk_rules.json, later from the
 * backend). The schema is in docs/risk-rules.md.
 */
data class RiskRules(
    val schemaVersion: Int,
    val rulesVersion: String,
    val thresholds: Thresholds,
    /** Installer package -> store name. Google Play is `com.android.vending`. */
    val trustedInstallers: Map<String, String>,
    /** Preinstalled system apps are not judged by heuristics. */
    val exemptSystemApps: Boolean,
    val knownGood: List<KnownGoodApp>,
    /**
     * Group -> the most points its rules can add together. Capability rules share one cap, so
     * capabilities alone (which legitimate automation apps also have) cannot make an app
     * malicious: that takes signs of concealment too.
     */
    val groupCaps: Map<String, Int> = emptyMap(),
    val rules: List<Rule>
) {
    companion object {
        const val SCHEMA_VERSION = 1
        const val PLAY_STORE = "com.android.vending"
    }
}

/** A rule's condition: a fixed vocabulary of facts about an [com.blackshield.core.scanner.analysis.AppProfile]. */
sealed interface Condition {
    data class All(val conditions: List<Condition>) : Condition

    data class AnyOf(val conditions: List<Condition>) : Condition

    data class Not(val condition: Condition) : Condition

    /** [requireAll]: every permission; otherwise at least one. */
    data class RequestsPermissions(val permissions: List<String>, val requireAll: Boolean) : Condition

    data class DangerousPermissionsAtLeast(val count: Int) : Condition

    data class FromSource(val sources: Set<InstallSource>) : Condition

    /** A component guarded by this permission, e.g. BIND_ACCESSIBILITY_SERVICE marks an accessibility service. */
    data class ComponentWithPermission(val permission: String) : Condition

    /** A component with an intent filter for one of these actions. */
    data class HandlesAction(val actions: List<String>) : Condition

    data class Launcher(val states: Set<LauncherState>) : Condition

    data class InstalledWithinDays(val days: Int) : Condition

    data class TargetSdkBelow(val sdk: Int) : Condition

    data class Certificate(val trait: CertificateTrait) : Condition

    data class ApplicationClassIn(val classes: List<String>) : Condition

    /** File-name patterns; `*` matches any run of characters. */
    data class NativeLibraryMatches(val patterns: List<String>) : Condition

    data class ObfuscatedComponents(val minComponents: Int, val minShare: Double) : Condition

    data object AccessibilityEnabled : Condition

    data object DeviceAdminActive : Condition

    data object Debuggable : Condition
}
