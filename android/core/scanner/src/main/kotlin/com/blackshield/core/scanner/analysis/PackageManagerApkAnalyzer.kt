package com.blackshield.core.scanner.analysis

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.ResolveInfo
import android.os.Build
import android.view.accessibility.AccessibilityManager
import com.blackshield.core.scanner.apps.InstalledApp
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject

/**
 * [ApkAnalyzer] over PackageManager, plus reading the APK files themselves ([ApkFiles]) for what
 * PackageManager does not expose: intent filters (from the binary manifest) and native libraries.
 */
internal class PackageManagerApkAnalyzer
@Inject
constructor(@ApplicationContext private val context: Context) :
    ApkAnalyzer {
    override fun startSession(): ApkAnalyzer.Session = Session(context)

    override fun analyzeArchive(path: String): AppProfile? = Session(context).analyzeArchive(path)

    private class Session(private val context: Context) : ApkAnalyzer.Session {
        private val pm: PackageManager = context.packageManager

        // Device-wide facts, read once per scan (lazy is synchronized: workers run in parallel).
        private val declaredLaunchers: Map<String, List<String>> by lazy {
            launcherActivities(PackageManager.MATCH_DISABLED_COMPONENTS)
        }
        private val enabledLaunchers: Set<String> by lazy { launcherActivities(0).keys }
        private val accessibilityEnabled: Set<String> by lazy {
            context
                .getSystemService(AccessibilityManager::class.java)
                ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .orEmpty()
                .mapNotNullTo(HashSet()) { it.resolveInfo?.serviceInfo?.packageName }
        }
        private val activeAdmins: Set<String> by lazy {
            context
                .getSystemService(DevicePolicyManager::class.java)
                ?.activeAdmins
                .orEmpty()
                .mapTo(HashSet()) { it.packageName }
        }
        private val dangerous = ConcurrentHashMap<String, Boolean>()

        override suspend fun analyze(app: InstalledApp): AppProfile {
            val gaps = mutableListOf<String>()
            val info = packageInfo(app.packageName, gaps)
            val appInfo = info?.applicationInfo
            val base = ApkFiles.read(app.apkPaths.first(), withManifest = true, gaps)
            val manifest = base.manifest
            val libraries =
                base.libraries +
                    app.apkPaths.drop(1).flatMap { ApkFiles.read(it, withManifest = false, gaps).libraries }
            val filters = manifest?.components?.associate { it.name to it.intentFilters }.orEmpty()
            val requested = info?.requestedPermissions?.toSet() ?: app.requestedPermissions
            val launchers = declaredLaunchers[app.packageName].orEmpty()
            return AppProfile(
                packageName = app.packageName,
                label = app.label,
                isSystemApp = app.isSystemApp,
                isDebuggable = app.isDebuggable,
                installerPackage = app.installerPackage,
                initiatingPackage = initiatingPackage(app.packageName),
                targetSdk = appInfo?.targetSdkVersion ?: manifest?.targetSdk ?: 0,
                firstInstallTime = info?.firstInstallTime ?: 0,
                lastUpdateTime = info?.lastUpdateTime ?: 0,
                requestedPermissions = requested,
                grantedPermissions = info?.grantedPermissions().orEmpty(),
                dangerousPermissions = requested.filterTo(HashSet(), ::isDangerous),
                components = info?.components(filters).orEmpty(),
                launcher =
                    when {
                        app.packageName in enabledLaunchers -> LauncherState.VISIBLE
                        launchers.isNotEmpty() -> LauncherState.HIDDEN
                        else -> LauncherState.NONE_DECLARED
                    },
                launcherActivities = launchers,
                signingCertificates = info?.signingCertificates().orEmpty(),
                applicationClass = appInfo?.className ?: manifest?.applicationClass,
                nativeLibraries = libraries.toSet(),
                accessibilityServiceEnabled = app.packageName in accessibilityEnabled,
                deviceAdminActive = app.packageName in activeAdmins,
                analysisGaps = gaps
            )
        }

        fun analyzeArchive(path: String): AppProfile? {
            val flags = PackageManager.GET_PERMISSIONS or SIGNING_FLAG or COMPONENT_FLAGS
            val info =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageArchiveInfo(path, flags)
                } ?: return null
            val appInfo = info.applicationInfo?.apply {
                // Needed to load the label and icon of an uninstalled APK.
                sourceDir = path
                publicSourceDir = path
            }
            val gaps = mutableListOf<String>()
            val apk = ApkFiles.read(path, withManifest = true, gaps)
            val manifest = apk.manifest
            val launchers = manifest?.components?.filter { it.isLauncher && it.enabled != false }.orEmpty()
            val requested = info.requestedPermissions?.toSet().orEmpty()
            return AppProfile(
                packageName = info.packageName,
                label = appInfo?.loadLabel(pm)?.toString() ?: info.packageName,
                isSystemApp = false,
                isDebuggable = appInfo?.let { it.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 } ?: false,
                installerPackage = null,
                targetSdk = appInfo?.targetSdkVersion ?: manifest?.targetSdk ?: 0,
                firstInstallTime = 0,
                requestedPermissions = requested,
                dangerousPermissions = requested.filterTo(HashSet(), ::isDangerous),
                components = info.components(manifest?.components?.associate { it.name to it.intentFilters }.orEmpty()),
                // A file cannot have hidden its icon yet; without a readable manifest, do not guess "none".
                launcher =
                    if (launchers.isNotEmpty() ||
                        manifest == null
                    ) {
                        LauncherState.VISIBLE
                    } else {
                        LauncherState.NONE_DECLARED
                    },
                launcherActivities = launchers.map { it.name },
                signingCertificates = info.signingCertificates(),
                applicationClass = appInfo?.className ?: manifest?.applicationClass,
                nativeLibraries = apk.libraries.toSet(),
                analysisGaps = gaps,
                isArchive = true
            )
        }

        private fun packageInfo(packageName: String, gaps: MutableList<String>): PackageInfo? {
            val base = PackageManager.GET_PERMISSIONS or PackageManager.MATCH_DISABLED_COMPONENTS or SIGNING_FLAG
            return try {
                getPackageInfo(packageName, base or COMPONENT_FLAGS)
            } catch (ignored: PackageManager.NameNotFoundException) {
                gaps += "package details unavailable (uninstalled during the scan?)"
                null
            } catch (
                @Suppress("TooGenericExceptionCaught") tooLarge: RuntimeException
            ) {
                // Huge apps can exceed the Binder transaction limit; read component kinds one by one.
                gaps += "component list read in parts (${tooLarge.javaClass.simpleName})"
                runCatching { getPackageInfo(packageName, base) }.getOrNull()?.also { info ->
                    for (flag in COMPONENT_FLAG_LIST) {
                        runCatching { getPackageInfo(packageName, base or flag) }
                            .onSuccess { part -> info.mergeComponentsFrom(part) }
                            .onFailure { gaps += "some components could not be read" }
                    }
                }
            }
        }

        private fun getPackageInfo(packageName: String, flags: Int): PackageInfo =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }

        private fun isDangerous(permission: String): Boolean = dangerous.getOrPut(permission) {
            try {
                val info = pm.getPermissionInfo(permission, 0)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    info.protection == PermissionInfo.PROTECTION_DANGEROUS
                } else {
                    @Suppress("DEPRECATION")
                    info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE == PermissionInfo.PROTECTION_DANGEROUS
                }
            } catch (ignored: PackageManager.NameNotFoundException) {
                false // declared by an app that is not installed: nothing can grant it
            }
        }

        private fun initiatingPackage(packageName: String): String? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                runCatching { pm.getInstallSourceInfo(packageName).initiatingPackageName }.getOrNull()
            } else {
                null
            }

        /** Package name -> launcher activity names, across all visible packages, in one query. */
        private fun launcherActivities(flags: Int): Map<String, List<String>> {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val matches: List<ResolveInfo> =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.queryIntentActivities(intent, flags)
                }
            return matches.mapNotNull { it.activityInfo }.groupBy({ it.packageName }, { it.name })
        }
    }

    private companion object {
        val COMPONENT_FLAG_LIST =
            listOf(
                PackageManager.GET_ACTIVITIES,
                PackageManager.GET_SERVICES,
                PackageManager.GET_RECEIVERS,
                PackageManager.GET_PROVIDERS
            )
        val COMPONENT_FLAGS = COMPONENT_FLAG_LIST.reduce(Int::or)

        @Suppress("DEPRECATION")
        val SIGNING_FLAG =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                PackageManager.GET_SIGNATURES
            }
    }
}
