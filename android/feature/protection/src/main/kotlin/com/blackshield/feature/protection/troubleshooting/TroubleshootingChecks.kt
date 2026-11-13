package com.blackshield.feature.protection.troubleshooting

import com.blackshield.feature.protection.logic.DownloadsWatch

/** App standby buckets (UsageStatsManager), from most to least favourable. */
enum class StandbyBucket { ACTIVE, WORKING_SET, FREQUENT, RARE, RESTRICTED }

/** Manufacturers whose own task killers stop background services beyond what Android does. */
enum class Oem { XIAOMI, HUAWEI, SAMSUNG, ONEPLUS, OPPO, VIVO, OTHER }

/** A snapshot of what affects real-time protection on this device. Read by [DeviceHealthReader]. */
data class DeviceHealth(
    val protectionEnabled: Boolean,
    val serviceRunning: Boolean,
    /** POST_NOTIFICATIONS granted and the app's notifications not switched off. */
    val notificationsAllowed: Boolean,
    val threatChannelEnabled: Boolean,
    val ignoringBatteryOptimizations: Boolean,
    /** "Restricted" background usage (Android 9+): the system stops the service. */
    val backgroundRestricted: Boolean,
    val standbyBucket: StandbyBucket?,
    val downloadsWatch: DownloadsWatch,
    val oem: Oem
)

enum class Severity { CRITICAL, WARNING, INFO }

enum class FixAction {
    ENABLE_PROTECTION,
    RESTART_PROTECTION,
    NOTIFICATION_SETTINGS,
    THREAT_CHANNEL_SETTINGS,
    BATTERY_OPTIMIZATION_SETTINGS,
    APP_DETAILS,
    ALL_FILES_ACCESS,
    OEM_SETTINGS
}

enum class IssueKind {
    PROTECTION_OFF,
    SERVICE_NOT_RUNNING,
    NOTIFICATIONS_BLOCKED,
    THREAT_ALERTS_BLOCKED,
    BACKGROUND_RESTRICTED,
    BATTERY_OPTIMIZED,
    RARELY_USED_BUCKET,
    DOWNLOADS_ACCESS_MISSING,
    OEM_TASK_KILLER
}

data class Issue(val kind: IssueKind, val severity: Severity, val fix: FixAction)

object TroubleshootingChecks {
    /** Every problem found, most severe first. Empty means protection should keep working. */
    fun evaluate(health: DeviceHealth): List<Issue> {
        if (!health.protectionEnabled) {
            return listOf(Issue(IssueKind.PROTECTION_OFF, Severity.CRITICAL, FixAction.ENABLE_PROTECTION))
        }
        return buildList {
            if (!health.serviceRunning) {
                add(Issue(IssueKind.SERVICE_NOT_RUNNING, Severity.CRITICAL, FixAction.RESTART_PROTECTION))
            }
            if (!health.notificationsAllowed) {
                add(Issue(IssueKind.NOTIFICATIONS_BLOCKED, Severity.CRITICAL, FixAction.NOTIFICATION_SETTINGS))
            } else if (!health.threatChannelEnabled) {
                add(Issue(IssueKind.THREAT_ALERTS_BLOCKED, Severity.CRITICAL, FixAction.THREAT_CHANNEL_SETTINGS))
            }
            if (health.backgroundRestricted) {
                add(Issue(IssueKind.BACKGROUND_RESTRICTED, Severity.CRITICAL, FixAction.APP_DETAILS))
            }
            if (!health.ignoringBatteryOptimizations) {
                add(Issue(IssueKind.BATTERY_OPTIMIZED, Severity.WARNING, FixAction.BATTERY_OPTIMIZATION_SETTINGS))
            }
            if (health.standbyBucket == StandbyBucket.RARE || health.standbyBucket == StandbyBucket.RESTRICTED) {
                add(Issue(IssueKind.RARELY_USED_BUCKET, Severity.WARNING, FixAction.APP_DETAILS))
            }
            if (health.downloadsWatch == DownloadsWatch.MISSING_PERMISSION) {
                add(Issue(IssueKind.DOWNLOADS_ACCESS_MISSING, Severity.WARNING, FixAction.ALL_FILES_ACCESS))
            }
            if (health.oem != Oem.OTHER) {
                add(Issue(IssueKind.OEM_TASK_KILLER, Severity.INFO, FixAction.OEM_SETTINGS))
            }
        }.sortedBy { it.severity }
    }

    fun oemOf(manufacturer: String): Oem = when (manufacturer.trim().lowercase()) {
        "xiaomi", "redmi", "poco" -> Oem.XIAOMI
        "huawei", "honor" -> Oem.HUAWEI
        "samsung" -> Oem.SAMSUNG
        "oneplus" -> Oem.ONEPLUS
        "oppo", "realme" -> Oem.OPPO
        "vivo", "iqoo" -> Oem.VIVO
        else -> Oem.OTHER
    }
}
