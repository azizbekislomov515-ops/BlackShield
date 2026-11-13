package com.blackshield.feature.protection.troubleshooting

import com.blackshield.feature.protection.logic.DownloadsWatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TroubleshootingChecksTest {
    private val healthy =
        DeviceHealth(
            protectionEnabled = true,
            serviceRunning = true,
            notificationsAllowed = true,
            threatChannelEnabled = true,
            ignoringBatteryOptimizations = true,
            backgroundRestricted = false,
            standbyBucket = StandbyBucket.ACTIVE,
            downloadsWatch = DownloadsWatch.MEDIA_STORE,
            oem = Oem.OTHER
        )

    private fun kinds(health: DeviceHealth) = TroubleshootingChecks.evaluate(health).map { it.kind }

    @Test
    fun `a healthy device has no issues`() {
        assertTrue(TroubleshootingChecks.evaluate(healthy).isEmpty())
    }

    @Test
    fun `protection off is the only thing reported when it is off`() {
        val issues = TroubleshootingChecks.evaluate(
            healthy.copy(protectionEnabled = false, ignoringBatteryOptimizations = false)
        )

        assertEquals(listOf(Issue(IssueKind.PROTECTION_OFF, Severity.CRITICAL, FixAction.ENABLE_PROTECTION)), issues)
    }

    @Test
    fun `aggressive battery settings are detected with the right fix`() {
        val issues =
            TroubleshootingChecks.evaluate(
                healthy.copy(
                    ignoringBatteryOptimizations = false,
                    backgroundRestricted = true,
                    standbyBucket = StandbyBucket.RESTRICTED
                )
            )

        assertEquals(
            listOf(IssueKind.BACKGROUND_RESTRICTED, IssueKind.BATTERY_OPTIMIZED, IssueKind.RARELY_USED_BUCKET),
            issues.map { it.kind }
        )
        assertEquals(
            FixAction.BATTERY_OPTIMIZATION_SETTINGS,
            issues.single {
                it.kind == IssueKind.BATTERY_OPTIMIZED
            }.fix
        )
        assertEquals(Severity.CRITICAL, issues.first().severity)
    }

    @Test
    fun `notification problems are critical, and the channel only matters when notifications are allowed`() {
        assertEquals(
            listOf(IssueKind.NOTIFICATIONS_BLOCKED),
            kinds(healthy.copy(notificationsAllowed = false, threatChannelEnabled = false))
        )
        assertEquals(listOf(IssueKind.THREAT_ALERTS_BLOCKED), kinds(healthy.copy(threatChannelEnabled = false)))
    }

    @Test
    fun `a stopped service, missing downloads access and OEM killers are reported, most severe first`() {
        val issues =
            TroubleshootingChecks.evaluate(
                healthy.copy(
                    serviceRunning = false,
                    downloadsWatch = DownloadsWatch.MISSING_PERMISSION,
                    oem = Oem.XIAOMI
                )
            )

        assertEquals(
            listOf(IssueKind.SERVICE_NOT_RUNNING, IssueKind.DOWNLOADS_ACCESS_MISSING, IssueKind.OEM_TASK_KILLER),
            issues.map {
                it.kind
            }
        )
        assertEquals(listOf(Severity.CRITICAL, Severity.WARNING, Severity.INFO), issues.map { it.severity })
    }

    @Test
    fun `manufacturer names map to OEM guidance`() {
        assertEquals(Oem.XIAOMI, TroubleshootingChecks.oemOf("Xiaomi"))
        assertEquals(Oem.XIAOMI, TroubleshootingChecks.oemOf(" POCO "))
        assertEquals(Oem.HUAWEI, TroubleshootingChecks.oemOf("HONOR"))
        assertEquals(Oem.SAMSUNG, TroubleshootingChecks.oemOf("samsung"))
        assertEquals(Oem.OPPO, TroubleshootingChecks.oemOf("realme"))
        assertEquals(Oem.OTHER, TroubleshootingChecks.oemOf("Google"))
    }
}
