package com.blackshield.core.scanner.apps

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Lists every installed package. Requires QUERY_ALL_PACKAGES on Android 11+ (declared in this
 * module's manifest; see docs/permissions.md), otherwise package visibility hides most apps.
 */
internal class PackageManagerAppSource
@Inject
constructor(@ApplicationContext private val context: Context) :
    InstalledAppSource {
    override suspend fun installedApps(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        installedPackages(pm).mapNotNull { info -> info.toInstalledApp(pm) }
    }

    override suspend fun installedApp(packageName: String): InstalledApp? = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        try {
            val info =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                    )
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                }
            info.toInstalledApp(pm)
        } catch (ignored: PackageManager.NameNotFoundException) {
            null // uninstalled again before we got to it
        }
    }

    private fun installedPackages(pm: PackageManager): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

    private fun PackageInfo.toInstalledApp(pm: PackageManager): InstalledApp? {
        val app = applicationInfo
        val baseApk = app?.sourceDir ?: return null
        return InstalledApp(
            packageName = packageName,
            label = app.loadLabel(pm).toString(),
            versionCode = longVersionCodeCompat(),
            apkPaths = listOf(baseApk) + app.splitSourceDirs.orEmpty(),
            isSystemApp =
                app.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
            isDebuggable = app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            installerPackage = installerOf(pm, packageName),
            requestedPermissions = requestedPermissions?.toSet().orEmpty()
        )
    }

    private fun PackageInfo.longVersionCodeCompat(): Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        longVersionCode
    } else {
        @Suppress("DEPRECATION")
        versionCode.toLong()
    }

    private fun installerOf(pm: PackageManager, packageName: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    }.getOrNull()
}
