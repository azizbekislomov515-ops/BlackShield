package com.blackshield.core.scanner.analysis

import com.blackshield.core.scanner.analysis.manifest.ComponentKind
import com.blackshield.core.scanner.analysis.manifest.IntentFilterSpec
import com.blackshield.core.scanner.yara.YaraMatch

/** Whether the app shows up in the app drawer. */
enum class LauncherState {
    /** At least one launcher activity is enabled. */
    VISIBLE,

    /** No launcher activity declared at all (keyboards, plugins, widgets, wallpapers, and some malware). */
    NONE_DECLARED,

    /** Launcher activities are declared but all disabled at runtime: the icon was hidden after install. */
    HIDDEN
}

data class AppComponent(
    val kind: ComponentKind,
    val name: String,
    /** As resolved by PackageManager, including the platform's defaults. */
    val exported: Boolean,
    /** The permission a caller needs (e.g. BIND_ACCESSIBILITY_SERVICE on an accessibility service). */
    val permission: String? = null,
    /** From the manifest; empty if it could not be read. */
    val intentFilters: List<IntentFilterSpec> = emptyList()
)

data class SigningCertificate(
    /** SHA-256 of the DER-encoded certificate, lower-case hex (what `apksigner` prints). */
    val sha256: String,
    val subject: String,
    val issuer: String,
    /** Normal for Android: almost every app certificate is self-signed. Reported, not penalized. */
    val selfSigned: Boolean,
    /** The Android SDK's auto-generated debug key (CN=Android Debug). */
    val debug: Boolean,
    /** AOSP's public test/platform keys: anyone can sign with them. */
    val aospTestKey: Boolean
)

/**
 * Everything the risk engine looks at for one app, extracted by [ApkAnalyzer]. A plain value: the
 * engine's output depends only on this and the current time, so the same profile always gets the
 * same verdict.
 */
data class AppProfile(
    val packageName: String,
    val label: String,
    /** Preinstalled (FLAG_SYSTEM), including updated system apps. */
    val isSystemApp: Boolean,
    val isDebuggable: Boolean,
    /** Package that performed the install (e.g. com.android.vending); null for adb or unknown. */
    val installerPackage: String?,
    /** App that started the install (a browser or file manager when sideloading); Android 11+. */
    val initiatingPackage: String? = null,
    val targetSdk: Int,
    /** Epoch milliseconds. */
    val firstInstallTime: Long,
    val lastUpdateTime: Long = firstInstallTime,
    val requestedPermissions: Set<String> = emptySet(),
    val grantedPermissions: Set<String> = emptySet(),
    /** Requested permissions whose protection level is `dangerous` (runtime permissions). */
    val dangerousPermissions: Set<String> = emptySet(),
    val components: List<AppComponent> = emptyList(),
    val launcher: LauncherState = LauncherState.VISIBLE,
    /** Declared launcher activities, enabled or not. */
    val launcherActivities: List<String> = emptyList(),
    val signingCertificates: List<SigningCertificate> = emptyList(),
    /** `<application android:name>`, where packers put their loader. */
    val applicationClass: String? = null,
    /** File names of native libraries in the APKs (`lib/<abi>/<name>.so`). */
    val nativeLibraries: Set<String> = emptySet(),
    /** One of its accessibility services is switched on. */
    val accessibilityServiceEnabled: Boolean = false,
    /** It is an active device administrator. */
    val deviceAdminActive: Boolean = false,
    /** YARA rules that matched the APK files or the DEX code inside them. */
    val yaraMatches: List<YaraMatch> = emptyList(),
    /** What could not be read (e.g. an unparseable manifest), so missing data is never silent. */
    val analysisGaps: List<String> = emptyList(),
    /**
     * An APK file that is not installed (e.g. a fresh download). Its source counts as a downloaded
     * file; installer, install time and runtime state do not exist yet.
     */
    val isArchive: Boolean = false
)
