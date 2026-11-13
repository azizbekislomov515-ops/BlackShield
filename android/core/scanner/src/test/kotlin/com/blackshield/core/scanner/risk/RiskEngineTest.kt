package com.blackshield.core.scanner.risk

import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.risk.TestProfiles.NOW
import com.blackshield.core.scanner.risk.TestProfiles.OVERLAY
import com.blackshield.core.scanner.risk.TestProfiles.PACKAGE_INSTALLER
import com.blackshield.core.scanner.risk.TestProfiles.READ_SMS
import com.blackshield.core.scanner.risk.TestProfiles.RECEIVE_SMS
import com.blackshield.core.scanner.risk.TestProfiles.accessibilityService
import com.blackshield.core.scanner.risk.TestProfiles.activity
import com.blackshield.core.scanner.risk.TestProfiles.profile
import com.blackshield.core.scanner.risk.TestProfiles.releaseCert
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Engine mechanics: scoring, verdict thresholds, caps, exemptions, determinism. Uses small inline rules. */
class RiskEngineTest {
    private fun rules(json: String) = RiskRulesParser.parse(json)

    private fun rulesWith(
        thresholds: String = """{"suspicious": 40, "malicious": 75}""",
        rules: String,
        extra: String = ""
    ) = rules(
        """{"schemaVersion":1,"rulesVersion":"t","thresholds":$thresholds,"trustedInstallers":{"com.android.vending":"Google Play"},
           $extra "rules":[$rules]}"""
    )

    private fun rule(id: String, points: Int, condition: String, group: String? = null) =
        """{"id":"$id","title":"$id","points":$points,${group?.let {
            "\"group\":\"$it\","
        }.orEmpty()}"when":$condition}"""

    @Test
    fun `score is the sum of matched rules, mapped to verdicts by thresholds`() {
        val engine =
            RiskEngine(
                rulesWith(
                    rules =
                        listOf(
                            rule("a", 20, """{"debuggable":true}"""),
                            rule("b", 20, """{"requestsPermission":"$OVERLAY"}"""),
                            rule("c", 40, """{"requestsPermission":"$READ_SMS"}""")
                        ).joinToString(",")
                )
            )

        fun verdict(vararg permissions: String, debuggable: Boolean = false) =
            engine.evaluate(profile(permissions = permissions.toSet(), debuggable = debuggable), NOW)

        assertEquals(Verdict.CLEAN to 0, verdict().let { it.verdict to it.score })
        assertEquals(Verdict.CLEAN to 20, verdict(OVERLAY).let { it.verdict to it.score })
        // Exactly on the threshold.
        assertEquals(Verdict.SUSPICIOUS to 40, verdict(OVERLAY, debuggable = true).let { it.verdict to it.score })
        assertEquals(Verdict.SUSPICIOUS to 60, verdict(READ_SMS, OVERLAY).let { it.verdict to it.score })
        assertEquals(
            Verdict.MALICIOUS to 80,
            verdict(READ_SMS, OVERLAY, debuggable = true).let {
                it.verdict to it.score
            }
        )
    }

    @Test
    fun `negative points are explained and the score never drops below zero`() {
        val engine =
            RiskEngine(
                rulesWith(
                    rules = rule("trusted", -20, """{"installSource":"PLAY_STORE"}""") + "," +
                        rule("overlay", 10, """{"requestsPermission":"$OVERLAY"}""")
                )
            )

        val result = engine.evaluate(profile(permissions = setOf(OVERLAY)), NOW)

        assertEquals(0, result.score)
        assertEquals(listOf("trusted" to -20, "overlay" to 10), result.findings.map { it.ruleId to it.points })
    }

    @Test
    fun `scores above 100 are capped`() {
        val engine =
            RiskEngine(rulesWith(rules = (1..3).joinToString(",") { rule("r$it", 60, """{"debuggable":true}""") }))

        assertEquals(100, engine.evaluate(profile(debuggable = true), NOW).score)
    }

    @Test
    fun `group caps limit grouped rules in rule order and say so`() {
        val engine =
            RiskEngine(
                rulesWith(
                    extra = """"groups":{"cap":{"maxPoints":50}},""",
                    rules =
                        listOf(
                            rule("first", 35, """{"debuggable":true}""", group = "cap"),
                            rule("second", 30, """{"requestsPermission":"$OVERLAY"}""", group = "cap"),
                            rule("third", 10, """{"requestsPermission":"$READ_SMS"}""", group = "cap"),
                            rule("ungrouped", 10, """{"requestsPermission":"$READ_SMS"}""")
                        ).joinToString(",")
                )
            )

        val result = engine.evaluate(profile(permissions = setOf(OVERLAY, READ_SMS), debuggable = true), NOW)

        assertEquals(
            listOf("first" to 35, "second" to 15, "third" to 0, "ungrouped" to 10),
            result.findings.map { it.ruleId to it.points }
        )
        assertEquals(listOf(false, true, true, false), result.findings.map { it.capped })
        assertEquals(30, result.findings[1].rulePoints)
        assertEquals("every point is accounted for", result.score, result.findings.sumOf { it.points })
    }

    @Test
    fun `system apps are exempt, with the exemption recorded`() {
        val result = TestProfiles.engine().evaluate(maliciousLooking().copy(isSystemApp = true), NOW)

        assertEquals(Exemption.SYSTEM_APP, result.exemption)
        assertEquals(Verdict.CLEAN, result.verdict)
        assertTrue(result.findings.isEmpty())
    }

    @Test
    fun `known-good apps are exempt only with the pinned certificate`() {
        val cert = releaseCert('c')
        val engine =
            RiskEngine(
                rulesWith(
                    extra =
                        """"allowlist":{"systemApps":true,"apps":""" +
                            """[{"package":"org.good","certSha256":"${cert.sha256}"}]},""",
                    rules = rule("d", 50, """{"debuggable":true}""")
                )
            )

        val genuine = profile(packageName = "org.good", debuggable = true, certificates = listOf(cert))
        val lookalike = genuine.copy(signingCertificates = listOf(releaseCert('f')))

        assertEquals(Exemption.KNOWN_GOOD, engine.evaluate(genuine, NOW).exemption)
        assertEquals(Verdict.SUSPICIOUS, engine.evaluate(lookalike, NOW).verdict)
    }

    @Test
    fun `install source classification`() {
        val engine = TestProfiles.engine()

        assertEquals(InstallSource.PLAY_STORE, engine.installSource(profile()))
        assertEquals(
            InstallSource.TRUSTED_STORE,
            engine.installSource(profile(installer = "com.sec.android.app.samsungapps"))
        )
        assertEquals(InstallSource.OTHER_INSTALLER, engine.installSource(profile(installer = PACKAGE_INSTALLER)))
        assertEquals(InstallSource.UNKNOWN, engine.installSource(profile(installer = null)))
        assertEquals(InstallSource.PREINSTALLED, engine.installSource(profile(installer = null, system = true)))
    }

    @Test
    fun `a downloaded APK that is not installed counts as a sideloaded file`() {
        val engine = TestProfiles.engine()
        val archive = profile(
            installer = null,
            installedAt = 0
        ).copy(isArchive = true, requestedPermissions = setOf(READ_SMS))

        val result = engine.evaluate(archive, NOW)

        assertEquals(InstallSource.OTHER_INSTALLER, engine.installSource(archive))
        assertEquals(
            listOf("a downloaded APK file, not installed yet"),
            result.findings.single { it.ruleId == "unknown_source" }.evidence
        )
        assertTrue("no install time yet", result.findings.none { it.ruleId == "recently_sideloaded" })
        assertTrue(result.findings.any { it.ruleId == "reads_sms_unknown_source" })
    }

    @Test
    fun `evaluation is deterministic regardless of collection order`() {
        val base = maliciousLooking()
        val shuffled =
            base.copy(
                requestedPermissions = base.requestedPermissions.reversed().toCollection(LinkedHashSet()),
                dangerousPermissions = base.dangerousPermissions.reversed().toCollection(LinkedHashSet()),
                components = base.components.reversed(),
                nativeLibraries = base.nativeLibraries.reversed().toCollection(LinkedHashSet())
            )
        val engine = TestProfiles.engine()

        val first = engine.evaluate(base, NOW)
        assertEquals(first, engine.evaluate(shuffled, NOW))
        assertEquals(
            first,
            TestProfiles.engine(RiskRulesParser.parse(TestProfiles.SHIPPED_RULES_JSON)).evaluate(base, NOW)
        )
    }

    @Test
    fun `every point of the score comes from a listed finding`() {
        val result = TestProfiles.engine().evaluate(maliciousLooking(), NOW)

        assertTrue(result.findings.all { it.evidence.isNotEmpty() && it.title.isNotBlank() })
        assertEquals(result.score, result.findings.sumOf { it.points }.coerceIn(0, 100))
    }

    @Test
    fun `glob patterns are literal apart from the star`() {
        val engine = RiskEngine(rulesWith(rules = rule("lib", 10, """{"nativeLibraryMatches":["lib.x*.so"]}""")))

        assertEquals(1, engine.evaluate(profile(nativeLibraries = setOf("lib.x-1.so")), NOW).findings.size)
        // '.' is not a wildcard.
        assertEquals(0, engine.evaluate(profile(nativeLibraries = setOf("libax1.so")), NOW).findings.size)
    }

    @Test
    fun `obfuscated names are short simple names or all-short paths`() {
        assertTrue(RiskEngine.looksObfuscated("a.b"))
        assertTrue(RiskEngine.looksObfuscated("com.example.a"))
        assertTrue(RiskEngine.looksObfuscated("ab.cd.ef"))
        assertTrue(!RiskEngine.looksObfuscated("com.example.MainActivity"))
        assertTrue(!RiskEngine.looksObfuscated("io.ab.Sync"))
    }

    private fun maliciousLooking() = profile(
        installer = PACKAGE_INSTALLER,
        permissions = setOf(RECEIVE_SMS, READ_SMS, OVERLAY),
        components = listOf(activity("com.evil.Main"), accessibilityService("com.evil.Watcher")),
        launcher = LauncherState.HIDDEN,
        nativeLibraries = setOf("libjiagu.so", "libmain.so"),
        installedAt = NOW
    )
}
