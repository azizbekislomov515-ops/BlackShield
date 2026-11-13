package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason.Code
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.risk.RiskRulesSource
import com.blackshield.core.scanner.risk.TestProfiles
import com.blackshield.core.scanner.risk.TestProfiles.OVERLAY
import com.blackshield.core.scanner.risk.TestProfiles.PACKAGE_INSTALLER
import com.blackshield.core.scanner.risk.TestProfiles.RECEIVE_SMS
import com.blackshield.core.scanner.risk.TestProfiles.accessibilityService
import com.blackshield.core.scanner.risk.TestProfiles.activity
import com.blackshield.core.scanner.risk.TestProfiles.profile
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskAssessorTest {
    private val assessor =
        RiskAssessor(
            RiskRulesSource {
                TestProfiles.SHIPPED_RULES
            },
            Clock.fixed(Instant.ofEpochMilli(TestProfiles.NOW), ZoneOffset.UTC)
        )

    private val banker =
        profile(
            installer = PACKAGE_INSTALLER,
            permissions = setOf(RECEIVE_SMS, OVERLAY),
            components = listOf(activity("com.x.Main"), accessibilityService("com.x.Svc")),
            launcher = LauncherState.HIDDEN
        )

    @Test
    fun `play store app with ordinary permissions is clean and says why`() {
        val assessment = assessor.assess(profile(), emptyList(), emptyList(), allowListed = false)

        assertEquals(Verdict.CLEAN, assessment.verdict)
        assertEquals(0, assessment.riskScore)
        val reason = assessment.reasons.single()
        assertEquals(Code.HEURISTIC, reason.code)
        assertEquals("installed_from_play", reason.ruleId)
        assertEquals(-20, reason.points)
    }

    @Test
    fun `heuristic findings become reasons with titles, evidence and points`() {
        val assessment = assessor.assess(banker, emptyList(), emptyList(), allowListed = false)

        assertEquals(Verdict.MALICIOUS, assessment.verdict)
        assertEquals(
            listOf("unknown_source", "banking_trojan_capabilities", "reads_sms_unknown_source", "hidden_launcher_icon"),
            assessment.reasons.map {
                it.ruleId
            }
        )
        assertTrue(
            assessment.reasons.all {
                it.code == Code.HEURISTIC && it.detail.isNotBlank() &&
                    it.evidence.isNotEmpty()
            }
        )
        assertEquals(assessment.riskScore, assessment.reasons.sumOf { it.points })
    }

    @Test
    fun `capped findings keep the rule's full points for display`() {
        val capped =
            banker.copy(
                launcher = LauncherState.VISIBLE,
                accessibilityServiceEnabled = true,
                deviceAdminActive = true
            )

        val reasons = assessor.assess(capped, emptyList(), emptyList(), allowListed = false).reasons

        val enabled = reasons.single { it.ruleId == "accessibility_enabled_unknown_source" }
        assertEquals(0, enabled.points) // 35 + 15 already used the capability cap of 50
        assertEquals(15, enabled.rulePoints)
        assertEquals(null, reasons.single { it.ruleId == "banking_trojan_capabilities" }.rulePoints)
    }

    @Test
    fun `known malware is malicious with the severity score and skips heuristics, even when trusted`() {
        val match = SignatureMatch("/data/app/x/base.apk", signature(Severity.CRITICAL))

        val assessment = assessor.assess(banker, listOf(match), emptyList(), allowListed = true)

        assertEquals(Verdict.MALICIOUS, assessment.verdict)
        assertEquals(100, assessment.riskScore)
        assertEquals(listOf(Code.KNOWN_MALWARE, Code.ALLOW_LISTED), assessment.reasons.map { it.code })
        assertTrue(assessment.reasons.first().detail.contains("base.apk"))
    }

    @Test
    fun `apps trusted by the user skip heuristics`() {
        val assessment = assessor.assess(banker, emptyList(), emptyList(), allowListed = true)

        assertEquals(Verdict.CLEAN, assessment.verdict)
        assertEquals(listOf(Code.ALLOW_LISTED), assessment.reasons.map { it.code })
    }

    @Test
    fun `system apps are clean with the exemption explained`() {
        val assessment = assessor.assess(banker.copy(isSystemApp = true), emptyList(), emptyList(), allowListed = false)

        assertEquals(Verdict.CLEAN, assessment.verdict)
        assertEquals(listOf(Code.SYSTEM_APP), assessment.reasons.map { it.code })
    }

    @Test
    fun `analysis gaps and hash failures are reported without points`() {
        val assessment =
            assessor.assess(
                profile().copy(analysisGaps = listOf("manifest unreadable: bad chunk")),
                emptyList(),
                listOf("split.apk: permission denied"),
                false
            )

        assertEquals(
            listOf(Code.HEURISTIC, Code.ANALYSIS_INCOMPLETE, Code.HASH_FAILED),
            assessment.reasons.map { it.code }
        )
        assertTrue(assessment.reasons.drop(1).all { it.points == 0 })
    }

    private fun signature(severity: Severity) =
        MalwareSignature("a".repeat(64), SignatureAlgorithm.SHA256, "Test.Banker", "unit-test", severity, 0)
}
