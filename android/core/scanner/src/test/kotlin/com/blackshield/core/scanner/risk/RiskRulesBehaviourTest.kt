package com.blackshield.core.scanner.risk

import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.risk.TestProfiles.BIND_DEVICE_ADMIN
import com.blackshield.core.scanner.risk.TestProfiles.DANGEROUS_12
import com.blackshield.core.scanner.risk.TestProfiles.INSTALL_PACKAGES
import com.blackshield.core.scanner.risk.TestProfiles.NOW
import com.blackshield.core.scanner.risk.TestProfiles.OVERLAY
import com.blackshield.core.scanner.risk.TestProfiles.PACKAGE_INSTALLER
import com.blackshield.core.scanner.risk.TestProfiles.READ_SMS
import com.blackshield.core.scanner.risk.TestProfiles.RECEIVE_SMS
import com.blackshield.core.scanner.risk.TestProfiles.SEND_SMS
import com.blackshield.core.scanner.risk.TestProfiles.accessibilityService
import com.blackshield.core.scanner.risk.TestProfiles.activity
import com.blackshield.core.scanner.risk.TestProfiles.aospTestKeyCert
import com.blackshield.core.scanner.risk.TestProfiles.debugCert
import com.blackshield.core.scanner.risk.TestProfiles.deviceAdminReceiver
import com.blackshield.core.scanner.risk.TestProfiles.profile
import com.blackshield.core.scanner.risk.TestProfiles.service
import com.blackshield.core.scanner.risk.TestProfiles.smsReceiver
import com.blackshield.core.scanner.yara.YaraMatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One test per shipped rule: it fires (with the expected evidence) on the signal it describes and
 * stays quiet on the near misses. [`every shipped rule is covered by a trigger`] fails when a rule
 * is added to risk_rules.json without being added here.
 */
class RiskRulesBehaviourTest {
    private val engine = TestProfiles.engine()

    private fun finding(profile: AppProfile, ruleId: String): Finding? =
        engine.evaluate(profile, NOW).findings.firstOrNull { it.ruleId == ruleId }

    private fun assertFires(ruleId: String, profile: AppProfile, vararg evidence: String): Finding {
        val finding = finding(profile, ruleId)
        checkNotNull(finding) {
            "$ruleId did not fire; findings: ${engine.evaluate(profile, NOW).findings.map { it.ruleId }}"
        }
        evidence.forEach { expected ->
            assertTrue(
                "$ruleId evidence ${finding.evidence} should mention '$expected'",
                finding.evidence.any {
                    expected in
                        it
                }
            )
        }
        assertTrue("$ruleId must explain itself", finding.evidence.isNotEmpty() && finding.title.isNotBlank())
        return finding
    }

    private fun assertQuiet(ruleId: String, profile: AppProfile) {
        assertNull("$ruleId should not fire", finding(profile, ruleId))
    }

    private val sideloaded = profile(installer = PACKAGE_INSTALLER, initiating = "com.android.chrome")

    @Test
    fun `installed_from_play takes points off`() {
        assertEquals(-20, assertFires("installed_from_play", profile(), "installed by Google Play").points)
        assertQuiet("installed_from_play", sideloaded)
    }

    @Test
    fun `installed_from_known_store takes points off`() {
        assertEquals(
            -10,
            assertFires("installed_from_known_store", profile(installer = "org.fdroid.fdroid"), "F-Droid").points
        )
        assertQuiet("installed_from_known_store", profile())
    }

    @Test
    fun `unknown_source covers other installers and missing installers`() {
        assertFires(
            "unknown_source",
            sideloaded,
            "installed by the Android package installer (a downloaded APK file), started from com.android.chrome"
        )
        assertFires("unknown_source", profile(installer = null), "no installer recorded")
        assertQuiet("unknown_source", profile())
        assertQuiet("unknown_source", profile(installer = "com.amazon.venezia"))
    }

    @Test
    fun `banking_trojan_capabilities needs SMS, an accessibility service and overlay together`() {
        val all =
            profile(
                permissions = setOf(RECEIVE_SMS, OVERLAY),
                components = listOf(activity("x.Main"), accessibilityService("com.evil.Watcher"))
            )
        assertFires(
            "banking_trojan_capabilities",
            all,
            "requests RECEIVE_SMS",
            "accessibility service: Watcher",
            "SYSTEM_ALERT_WINDOW"
        )

        assertQuiet("banking_trojan_capabilities", all.copy(requestedPermissions = setOf(OVERLAY)))
        assertQuiet("banking_trojan_capabilities", all.copy(requestedPermissions = setOf(RECEIVE_SMS)))
        assertQuiet("banking_trojan_capabilities", all.copy(components = listOf(activity("x.Main"))))
    }

    @Test
    fun `device_admin_unknown_source needs device admin and an unknown origin`() {
        val admin = sideloaded.copy(components = listOf(activity("x.Main"), deviceAdminReceiver("com.evil.Admin")))
        assertFires("device_admin_unknown_source", admin, "device admin receiver: Admin")
        assertFires(
            "device_admin_unknown_source",
            sideloaded.copy(requestedPermissions = setOf(BIND_DEVICE_ADMIN)),
            "BIND_DEVICE_ADMIN"
        )

        assertQuiet("device_admin_unknown_source", admin.copy(installerPackage = TestProfiles.PLAY))
        assertQuiet("device_admin_unknown_source", sideloaded)
    }

    @Test
    fun `installs_other_apps_unknown_source`() {
        assertFires(
            "installs_other_apps_unknown_source",
            sideloaded.copy(requestedPermissions = setOf(INSTALL_PACKAGES))
        )
        assertQuiet("installs_other_apps_unknown_source", profile(permissions = setOf(INSTALL_PACKAGES)))
    }

    @Test
    fun `many_sensitive_permissions_unknown_source counts dangerous permissions`() {
        val many = sideloaded.copy(requestedPermissions = DANGEROUS_12, dangerousPermissions = DANGEROUS_12)
        assertFires(
            "many_sensitive_permissions_unknown_source",
            many,
            "requests 12 sensitive permissions",
            "and 7 more"
        )

        val nine = DANGEROUS_12.take(9).toSet()
        assertQuiet("many_sensitive_permissions_unknown_source", many.copy(dangerousPermissions = nine))
        assertQuiet("many_sensitive_permissions_unknown_source", many.copy(installerPackage = TestProfiles.PLAY))
    }

    @Test
    fun `reads_sms_unknown_source by permission or by an SMS receiver`() {
        assertFires(
            "reads_sms_unknown_source",
            sideloaded.copy(requestedPermissions = setOf(READ_SMS)),
            "requests READ_SMS"
        )
        assertFires(
            "reads_sms_unknown_source",
            sideloaded.copy(components = listOf(activity("x.Main"), smsReceiver("a.b"))),
            "listens for SMS_RECEIVED (b)"
        )
        assertQuiet("reads_sms_unknown_source", sideloaded.copy(requestedPermissions = setOf(SEND_SMS)))
        assertQuiet("reads_sms_unknown_source", profile(permissions = setOf(READ_SMS)))
    }

    @Test
    fun `accessibility_enabled_unknown_source`() {
        assertFires(
            "accessibility_enabled_unknown_source",
            sideloaded.copy(accessibilityServiceEnabled = true),
            "switched on"
        )
        assertQuiet("accessibility_enabled_unknown_source", profile(accessibilityEnabled = true))
    }

    @Test
    fun `device_admin_active_unknown_source`() {
        assertFires(
            "device_admin_active_unknown_source",
            sideloaded.copy(deviceAdminActive = true),
            "active device administrator"
        )
        assertQuiet("device_admin_active_unknown_source", profile(deviceAdminActive = true))
    }

    @Test
    fun `hidden_launcher_icon fires whatever the source`() {
        val hidden =
            profile(launcher = LauncherState.HIDDEN, launcherActivities = listOf("com.example.app.MainActivity"))
        assertFires("hidden_launcher_icon", hidden, "launcher activity MainActivity is disabled")
        assertQuiet(
            "hidden_launcher_icon",
            profile(launcher = LauncherState.NONE_DECLARED, launcherActivities = emptyList())
        )
    }

    @Test
    fun `no_launcher_icon_unknown_source spares store apps such as keyboards`() {
        val none = sideloaded.copy(launcher = LauncherState.NONE_DECLARED, launcherActivities = emptyList())
        assertFires("no_launcher_icon_unknown_source", none, "declares no launcher activity")
        assertQuiet("no_launcher_icon_unknown_source", none.copy(installerPackage = TestProfiles.PLAY))
    }

    @Test
    fun `packed detects packer loaders and libraries`() {
        assertFires("packed", profile(applicationClass = "com.stub.StubApp"), "application class com.stub.StubApp")
        assertFires(
            "packed",
            profile(nativeLibraries = setOf("libjiagu_x86.so", "libc++_shared.so")),
            "native library libjiagu_x86.so"
        )
        assertFires("packed", profile(nativeLibraries = setOf("libDEXHELPER.so")), "libDEXHELPER.so")
        assertQuiet("packed", profile(applicationClass = "com.example.App", nativeLibraries = setOf("libsqlite.so")))
    }

    @Test
    fun `obfuscated_component_names needs a majority of short names`() {
        val odd = profile(components = listOf(activity("com.x.Main"), service("a.b"), service("a.c"), service("q.r.s")))
        assertFires("obfuscated_component_names", odd, "3 of 4 components have meaningless names", "a.b")

        val few = profile(components = listOf(activity("com.x.Main"), service("a.b"), service("com.x.SyncService")))
        assertQuiet("obfuscated_component_names", few)
        assertQuiet("obfuscated_component_names", profile(components = listOf(service("a.b"), service("a.c"))))
    }

    @Test
    fun `aosp_test_key`() {
        assertFires("aosp_test_key", profile(certificates = listOf(aospTestKeyCert())), "public AOSP test key")
        assertQuiet("aosp_test_key", profile(certificates = listOf(debugCert())))
    }

    @Test
    fun `legacy_target_sdk_unknown_source`() {
        assertFires("legacy_target_sdk_unknown_source", sideloaded.copy(targetSdk = 22), "targets Android SDK 22")
        assertQuiet("legacy_target_sdk_unknown_source", sideloaded.copy(targetSdk = 23))
        assertQuiet("legacy_target_sdk_unknown_source", sideloaded.copy(targetSdk = 0)) // unknown, not "old"
        assertQuiet("legacy_target_sdk_unknown_source", profile(targetSdk = 22))
    }

    @Test
    fun `development_build_unknown_source`() {
        assertFires(
            "development_build_unknown_source",
            sideloaded.copy(signingCertificates = listOf(debugCert())),
            "debug certificate"
        )
        assertFires("development_build_unknown_source", sideloaded.copy(isDebuggable = true), "debuggable build")
        assertQuiet("development_build_unknown_source", sideloaded)
        assertQuiet("development_build_unknown_source", profile(certificates = listOf(debugCert())))
    }

    @Test
    fun `recently_sideloaded`() {
        val today = sideloaded.copy(firstInstallTime = NOW - TimeUnit.HOURS.toMillis(5))
        assertFires("recently_sideloaded", today, "installed today")
        assertFires(
            "recently_sideloaded",
            sideloaded.copy(firstInstallTime = NOW - TimeUnit.DAYS.toMillis(2)),
            "installed 2 days ago"
        )
        assertQuiet(
            "recently_sideloaded",
            sideloaded.copy(
                firstInstallTime =
                    NOW - TimeUnit.DAYS.toMillis(3)
            )
        )
        assertQuiet("recently_sideloaded", sideloaded.copy(firstInstallTime = 0))
        // adb (no installer): developers, not drive-by infection.
        assertQuiet("recently_sideloaded", today.copy(installerPackage = null))
        assertQuiet("recently_sideloaded", today.copy(installerPackage = TestProfiles.PLAY))
    }

    private fun yara(severity: String?, rule: String = "Rule_$severity") = YaraMatch(
        rule = rule,
        meta = listOfNotNull(severity?.let { "severity" to it }, "description" to "why it matters").toMap(),
        location = "base.apk!classes.dex"
    )

    @Test
    fun `yara matches score by severity`() {
        val critical =
            assertFires(
                "yara_critical",
                profile().copy(yaraMatches = listOf(yara("critical"))),
                "YARA rule Rule_critical matched in base.apk!classes.dex: why it matters"
            )
        assertEquals(100, critical.points)
        assertEquals(50, assertFires("yara_high", profile().copy(yaraMatches = listOf(yara("HIGH")))).points)
        assertEquals(25, assertFires("yara_medium", profile().copy(yaraMatches = listOf(yara("medium")))).points)
        assertEquals(10, assertFires("yara_low", profile().copy(yaraMatches = listOf(yara("low")))).points)
        // No (or an unknown) severity counts as medium.
        assertFires("yara_medium", profile().copy(yaraMatches = listOf(yara(null, rule = "Untagged"))), "Untagged")
        assertFires("yara_medium", profile().copy(yaraMatches = listOf(yara("severe"))))
        assertQuiet("yara_high", profile().copy(yaraMatches = listOf(yara("medium"))))
        assertQuiet("yara_critical", profile())
    }

    @Test
    fun `a critical yara match is malicious even from Google Play, but system and known-good apps are exempt`() {
        val fromPlay = profile().copy(yaraMatches = listOf(yara("critical")))
        assertEquals(Verdict.MALICIOUS, engine.evaluate(fromPlay, NOW).verdict)

        val system = fromPlay.copy(isSystemApp = true)
        assertEquals(Exemption.SYSTEM_APP, engine.evaluate(system, NOW).exemption)
    }

    @Test
    fun `a high yara match from an unknown source with spying capabilities is malicious`() {
        val evaluation =
            engine.evaluate(
                sideloaded.copy(
                    yaraMatches = listOf(yara("high")),
                    requestedPermissions = setOf(READ_SMS),
                    components = listOf(smsReceiver("x.Sms"))
                ),
                NOW
            )
        assertEquals(Verdict.MALICIOUS, evaluation.verdict)
        assertTrue(evaluation.findings.any { it.ruleId == "yara_high" })
    }

    @Test
    fun `every shipped rule is covered by a trigger`() {
        val triggers =
            listOf(
                profile(),
                profile(installer = "org.fdroid.fdroid"),
                sideloaded.copy(
                    requestedPermissions = DANGEROUS_12 + setOf(READ_SMS, OVERLAY, INSTALL_PACKAGES),
                    dangerousPermissions = DANGEROUS_12,
                    components = listOf(
                        accessibilityService("x.Svc"),
                        deviceAdminReceiver("x.Admin"),
                        service("a.b"),
                        service("a.c"),
                        service("b.d")
                    ),
                    accessibilityServiceEnabled = true,
                    deviceAdminActive = true,
                    targetSdk = 22,
                    isDebuggable = true,
                    firstInstallTime = NOW,
                    applicationClass = "com.stub.StubApp",
                    signingCertificates = listOf(aospTestKeyCert())
                ),
                sideloaded.copy(launcher = LauncherState.HIDDEN),
                sideloaded.copy(launcher = LauncherState.NONE_DECLARED),
                sideloaded.copy(yaraMatches = listOf("critical", "high", "medium", "low").map(::yara))
            )
        val fired = triggers.flatMap { p -> engine.evaluate(p, NOW).findings.map { it.ruleId } }.toSet()

        assertEquals(TestProfiles.SHIPPED_RULES.rules.map { it.id }.toSet(), fired)
    }

    @Test
    fun `the install source is explained once, not repeated under every rule it gates`() {
        val many =
            sideloaded.copy(
                requestedPermissions = setOf(READ_SMS, INSTALL_PACKAGES),
                isDebuggable = true,
                initiatingPackage = "com.android.shell"
            )

        val findings = engine.evaluate(many, NOW).findings
        val mentions = findings.flatMap { it.evidence }.filter { "installed by" in it }

        assertTrue(findings.size >= 4)
        assertEquals(
            listOf(
                "installed by the Android package installer (a downloaded APK file), started from adb (USB debugging)"
            ),
            mentions
        )
        assertEquals("unknown_source", findings.single { f -> f.evidence.any { "installed by" in it } }.ruleId)
    }

    @Test
    fun `quiet profiles produce no findings beyond the source`() {
        assertEquals(listOf("installed_from_play"), engine.evaluate(profile(), NOW).findings.map { it.ruleId })
        assertFalse(engine.evaluate(profile(), NOW).findings.any { it.points > 0 })
    }
}
