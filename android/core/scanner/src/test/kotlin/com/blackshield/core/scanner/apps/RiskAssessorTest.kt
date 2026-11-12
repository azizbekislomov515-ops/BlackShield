package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason.Code
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskAssessorTest {
    @Test
    fun `play store app with ordinary permissions is clean with no findings`() {
        val assessment = RiskAssessor.assess(app(installer = "com.android.vending"), emptyList(), emptyList(), false)

        assertEquals(Assessment(Verdict.CLEAN, 0, emptyList()), assessment)
    }

    @Test
    fun `sideloading alone is not enough to be suspicious`() {
        val assessment = RiskAssessor.assess(app(installer = null), emptyList(), emptyList(), false)

        assertEquals(Verdict.CLEAN, assessment.verdict)
        assertEquals(RiskAssessor.SIDELOADED_POINTS, assessment.riskScore)
        assertEquals(listOf(Code.SIDELOADED), assessment.reasons.map { it.code })
    }

    @Test
    fun `sideloaded app reading SMS and drawing over apps is suspicious`() {
        val app =
            app(
                installer = "com.example.browser",
                permissions = setOf("android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW")
            )

        val assessment = RiskAssessor.assess(app, emptyList(), emptyList(), false)

        assertEquals(Verdict.SUSPICIOUS, assessment.verdict)
        assertEquals(60, assessment.riskScore)
        assertEquals(listOf(Code.SIDELOADED, Code.SMS_ACCESS, Code.DRAWS_OVER_APPS), assessment.reasons.map { it.code })
    }

    @Test
    fun `score is capped at 100`() {
        val app =
            app(
                installer = null,
                debuggable = true,
                permissions =
                    setOf(
                        "android.permission.SEND_SMS",
                        "android.permission.REQUEST_INSTALL_PACKAGES",
                        "android.permission.SYSTEM_ALERT_WINDOW"
                    )
            )

        assertEquals(85, RiskAssessor.assess(app, emptyList(), emptyList(), false).riskScore)
    }

    @Test
    fun `system apps are not judged by permission heuristics`() {
        val app = app(installer = null, system = true, permissions = setOf("android.permission.READ_SMS"))

        assertEquals(
            Assessment(Verdict.CLEAN, 0, emptyList()),
            RiskAssessor.assess(app, emptyList(), emptyList(), false)
        )
    }

    @Test
    fun `known malware is malicious with the severity score, even when allow-listed`() {
        val match = SignatureMatch("/data/app/x/split_config.apk", signature(Severity.MEDIUM))

        val assessment = RiskAssessor.assess(app(installer = null), listOf(match), emptyList(), allowListed = true)

        assertEquals(Verdict.MALICIOUS, assessment.verdict)
        assertEquals(Severity.MEDIUM.riskScore, assessment.riskScore)
        assertEquals(listOf(Code.KNOWN_MALWARE, Code.ALLOW_LISTED), assessment.reasons.map { it.code })
        assertTrue(assessment.reasons.first().detail.contains("split_config.apk"))
    }

    @Test
    fun `allow-listed apps skip heuristics`() {
        val app =
            app(
                installer = null,
                permissions = setOf("android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW")
            )

        val assessment = RiskAssessor.assess(app, emptyList(), emptyList(), allowListed = true)

        assertEquals(Verdict.CLEAN, assessment.verdict)
        assertEquals(0, assessment.riskScore)
        assertEquals(listOf(Code.ALLOW_LISTED), assessment.reasons.map { it.code })
    }

    private fun app(
        installer: String?,
        permissions: Set<String> = setOf("android.permission.INTERNET"),
        system: Boolean = false,
        debuggable: Boolean = false
    ) = InstalledApp(
        packageName = "com.example.app",
        label = "Example",
        versionCode = 1,
        apkPaths = listOf("/data/app/x/base.apk"),
        isSystemApp = system,
        isDebuggable = debuggable,
        installerPackage = installer,
        requestedPermissions = permissions
    )

    private fun signature(severity: Severity) =
        MalwareSignature("ab".repeat(32), SignatureAlgorithm.SHA256, "Test.Trojan", "unit-test", severity, 0)
}
