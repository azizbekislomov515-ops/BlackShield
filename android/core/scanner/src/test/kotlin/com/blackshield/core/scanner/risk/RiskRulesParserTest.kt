package com.blackshield.core.scanner.risk

import com.blackshield.core.scanner.analysis.LauncherState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskRulesParserTest {
    private fun doc(rules: String, extra: String = "", thresholds: String = """{"suspicious":40,"malicious":75}""") =
        """{"schemaVersion":1,"rulesVersion":"t","thresholds":$thresholds,""" +
            """"trustedInstallers":{},$extra"rules":[$rules]}"""

    private fun rule(condition: String, id: String = "r", points: Int = 10, extraKeys: String = "") =
        """{"id":"$id","title":"Title","points":$points,$extraKeys"when":$condition}"""

    private fun rejects(json: String, messagePart: String) {
        val error = assertThrows(RiskRulesException::class.java) { RiskRulesParser.parse(json) }
        assertTrue("'${error.message}' should mention '$messagePart'", error.message.orEmpty().contains(messagePart))
    }

    @Test
    fun `the shipped rules file is valid`() {
        val rules = TestProfiles.SHIPPED_RULES

        assertEquals(RiskRules.SCHEMA_VERSION, rules.schemaVersion)
        assertEquals(Thresholds(suspicious = 40, malicious = 75), rules.thresholds)
        assertEquals("Google Play", rules.trustedInstallers[RiskRules.PLAY_STORE])
        assertTrue(rules.exemptSystemApps)
        assertEquals(mapOf("capability" to 50), rules.groupCaps)
        assertTrue(rules.rules.size >= 15)
        assertTrue("titles are sentences, not codes", rules.rules.all { it.title.contains(' ') })
    }

    @Test
    fun `parses every condition type and resolves list references`() {
        val conditions =
            """{"all":[
                {"any":[{"requestsPermission":"p.A"},{"requestsAllPermissions":["p.A","p.B"]},{"requestsAnyPermission":"@perms"}]},
                {"not":{"dangerousPermissionsAtLeast":3}},
                {"installSource":["UNKNOWN","OTHER_INSTALLER"]},
                {"componentWithPermission":"p.BIND"},
                {"handlesAction":["a.X"]},
                {"launcher":["HIDDEN","NONE_DECLARED"]},
                {"installedWithinDays":3},
                {"targetSdkBelow":23},
                {"certificate":"DEBUG"},
                {"applicationClassIn":"@classes"},
                {"nativeLibraryMatches":["lib*.so"]},
                {"obfuscatedComponents":{"minComponents":3,"minShare":0.5}},
                {"accessibilityEnabled":true},
                {"deviceAdminActive":true},
                {"debuggable":true}
            ]}"""
        val rules = RiskRulesParser.parse(
            doc(rule(conditions), extra = """"lists":{"perms":["p.C","p.D"],"classes":["c.Stub"]},""")
        )

        val all = rules.rules.single().condition as Condition.All
        assertEquals(15, all.conditions.size)
        val any = all.conditions[0] as Condition.AnyOf
        assertEquals(Condition.RequestsPermissions(listOf("p.C", "p.D"), requireAll = false), any.conditions[2])
        assertEquals(Condition.Launcher(setOf(LauncherState.HIDDEN, LauncherState.NONE_DECLARED)), all.conditions[5])
        assertEquals(Condition.ApplicationClassIn(listOf("c.Stub")), all.conditions[9])
        assertEquals(Condition.ObfuscatedComponents(3, 0.5), all.conditions[11])
    }

    @Test
    fun `rejects structural mistakes`() {
        rejects("not json", "not valid JSON")
        rejects("[]", "top level must be an object")
        rejects(
            doc(rule("""{"debuggable":true}""")).replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            "unsupported schemaVersion 2"
        )
        rejects(
            doc(rule("""{"debuggable":true}""")).replace("{\"schemaVersion\"", "{\"surprise\":1,\"schemaVersion\""),
            "unknown key 'surprise'"
        )
        rejects(doc(rule("""{"debuggable":true}""", extraKeys = """"weight":3,""")), "unknown key 'weight'")
        rejects(doc(rule("""{"debuggable":true}""") + "," + rule("""{"debuggable":true}""")), "duplicate rule id 'r'")
        rejects(doc(rule("""{"debuggable":true}""", id = "Bad Id")), "id must match")
        rejects(doc(rule("""{"debuggable":true}""", points = 150)), "points must be within")
        rejects(
            doc(rule("""{"debuggable":true}"""), thresholds = """{"suspicious":80,"malicious":40}"""),
            "thresholds must satisfy"
        )
        rejects(doc(rule("""{"debuggable":true}""", extraKeys = """"group":"nope",""")), "unknown group 'nope'")
    }

    @Test
    fun `rejects conditions it does not understand`() {
        rejects(doc(rule("""{"usesBlockchain":true}""")), "unknown condition 'usesBlockchain'")
        rejects(doc(rule("""{"debuggable":true,"targetSdkBelow":23}""")), "exactly one key")
        rejects(doc(rule("""{"all":[]}""")), "is empty")
        rejects(doc(rule("""{"requestsAnyPermission":"@missing"}""")), "unknown list '@missing'")
        rejects(doc(rule("""{"installSource":"MARS"}""")), "unknown value 'MARS'")
        rejects(doc(rule("""{"debuggable":false}""")), "must be true")
        rejects(doc(rule("""{"targetSdkBelow":"23"}""")), "positive integer")
        rejects(doc(rule("""{"obfuscatedComponents":{"minComponents":3,"minShare":1.5}}""")), "minShare")
        val deep = (1..20).fold("""{"debuggable":true}""") { inner, _ -> """{"not":$inner}""" }
        rejects(doc(rule(deep)), "nested deeper")
    }

    @Test
    fun `a broken update falls back to the bundled rules`() {
        var rejected: RiskRulesException? = null

        val rules = RiskRulesLoader.load(
            override = """{"schemaVersion":99}""",
            bundled = TestProfiles.SHIPPED_RULES_JSON
        ) {
            rejected =
                it
        }

        assertEquals(TestProfiles.SHIPPED_RULES, rules)
        assertTrue(rejected != null)
    }

    @Test
    fun `a valid update replaces the bundled rules`() {
        val update = doc(rule("""{"debuggable":true}""", id = "only_rule"))

        assertEquals(
            listOf("only_rule"),
            RiskRulesLoader.load(update, TestProfiles.SHIPPED_RULES_JSON).rules.map {
                it.id
            }
        )
    }
}
