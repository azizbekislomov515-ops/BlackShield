package com.blackshield.core.scanner.apps

/** What the scanner needs to know about one installed package. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionCode: Long,
    /** Base APK first, then split APKs. */
    val apkPaths: List<String>,
    val isSystemApp: Boolean,
    val isDebuggable: Boolean,
    /** Package that installed this app (e.g. com.android.vending); null if unknown or adb. */
    val installerPackage: String?,
    val requestedPermissions: Set<String>
)

/** Enumerates installed packages. Backed by PackageManager; faked in tests. */
interface InstalledAppSource {
    suspend fun installedApps(): List<InstalledApp>
}
