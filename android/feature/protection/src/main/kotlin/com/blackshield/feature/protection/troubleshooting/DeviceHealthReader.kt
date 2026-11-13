package com.blackshield.feature.protection.troubleshooting

import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.feature.protection.DeviceGrants
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.protection.ProtectionNotifications
import com.blackshield.feature.protection.logic.WatchPlanner
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import kotlinx.coroutines.flow.first

/** Reads [DeviceHealth] from the system. All reads are cheap, one-shot calls: run on resume, not polled. */
class DeviceHealthReader
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val preferences: UserPreferencesRepository,
    private val notifications: ProtectionNotifications,
    private val controller: ProtectionController
) {
    suspend fun read(): DeviceHealth {
        val power = context.getSystemService(PowerManager::class.java)
        val activities = context.getSystemService(ActivityManager::class.java)
        return DeviceHealth(
            protectionEnabled = preferences.realTimeProtectionEnabled.first(),
            serviceRunning = controller.isRunning.value,
            notificationsAllowed = notifications.canPost(),
            threatChannelEnabled = notifications.threatChannelEnabled(),
            ignoringBatteryOptimizations = power?.isIgnoringBatteryOptimizations(context.packageName) ?: true,
            backgroundRestricted =
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && activities?.isBackgroundRestricted == true,
            standbyBucket = standbyBucket(),
            downloadsWatch =
                WatchPlanner
                    .plan(
                        sdkInt = Build.VERSION.SDK_INT,
                        watchDownloads = preferences.watchDownloads.first(),
                        hasAllFilesAccess = DeviceGrants.hasAllFilesAccess(),
                        hasLegacyRead = DeviceGrants.hasLegacyRead(context),
                        folders = emptySet()
                    ).downloads,
            oem = TroubleshootingChecks.oemOf(Build.MANUFACTURER)
        )
    }

    private fun standbyBucket(): StandbyBucket? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return context.getSystemService(UsageStatsManager::class.java)?.appStandbyBucket?.let(::bucketOf)
    }

    private fun bucketOf(bucket: Int): StandbyBucket = when {
        bucket <= UsageStatsManager.STANDBY_BUCKET_ACTIVE -> StandbyBucket.ACTIVE
        bucket <= UsageStatsManager.STANDBY_BUCKET_WORKING_SET -> StandbyBucket.WORKING_SET
        bucket <= UsageStatsManager.STANDBY_BUCKET_FREQUENT -> StandbyBucket.FREQUENT
        bucket <= UsageStatsManager.STANDBY_BUCKET_RARE -> StandbyBucket.RARE
        else -> StandbyBucket.RESTRICTED // STANDBY_BUCKET_RESTRICTED (Android 11+) and anything stricter
    }

    /** The system screen that fixes [action], or null when it is handled in-app. */
    fun intentFor(action: FixAction, oem: Oem): Intent? {
        val pkg = Uri.fromParts("package", context.packageName, null)
        return when (action) {
            FixAction.ENABLE_PROTECTION, FixAction.RESTART_PROTECTION -> null

            FixAction.NOTIFICATION_SETTINGS ->
                Intent(
                    Settings.ACTION_APP_NOTIFICATION_SETTINGS
                ).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)

            FixAction.THREAT_CHANNEL_SETTINGS ->
                Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                    .putExtra(Settings.EXTRA_CHANNEL_ID, ProtectionNotifications.THREAT_CHANNEL)

            // The list screen needs no special permission (unlike ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            // which Google Play restricts); the user picks BlackShield and chooses "Not optimized".
            FixAction.BATTERY_OPTIMIZATION_SETTINGS -> Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

            FixAction.APP_DETAILS -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg)

            FixAction.ALL_FILES_ACCESS ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkg)
                } else {
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg)
                }

            FixAction.OEM_SETTINGS -> oemIntent(oem) ?: Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg)
        }?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    /** Vendor auto-start / battery screens; used only if this device actually has them. */
    private fun oemIntent(oem: Oem): Intent? = OEM_SCREENS[oem]
        .orEmpty()
        .map { Intent().setComponent(it) }
        .firstOrNull { intent ->
            context.packageManager.resolveActivity(intent, 0)?.activityInfo?.exported == true
        }

    private companion object {
        val OEM_SCREENS =
            mapOf(
                Oem.XIAOMI to
                    listOf(
                        ComponentName(
                            "com.miui.securitycenter",
                            "com.miui.permcenter.autostart.AutoStartManagementActivity"
                        )
                    ),
                Oem.HUAWEI to
                    listOf(
                        ComponentName(
                            "com.huawei.systemmanager",
                            "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"
                        ),
                        ComponentName(
                            "com.huawei.systemmanager",
                            "com.huawei.systemmanager.optimize.process.ProtectActivity"
                        )
                    ),
                Oem.SAMSUNG to
                    listOf(
                        ComponentName("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity")
                    ),
                Oem.ONEPLUS to
                    listOf(
                        ComponentName(
                            "com.oneplus.security",
                            "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity"
                        )
                    ),
                Oem.OPPO to
                    listOf(
                        ComponentName(
                            "com.coloros.safecenter",
                            "com.coloros.safecenter.permission.startup.StartupAppListActivity"
                        )
                    ),
                Oem.VIVO to
                    listOf(
                        ComponentName(
                            "com.vivo.permissionmanager",
                            "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"
                        )
                    )
            )
    }
}
