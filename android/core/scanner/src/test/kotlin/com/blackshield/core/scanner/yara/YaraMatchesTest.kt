package com.blackshield.core.scanner.yara

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class YaraMatchesTest {
    @Test
    fun `decodes rules with tags and metadata`() {
        val flat =
            arrayOf(
                "first", "default", "2", "t1", "t2", "2", "severity", "1", "high", "score", "0", "7",
                "second", "ns", "0", "0"
            )
        val matches = YaraMatches.parse(flat, "base.apk!classes.dex")
        assertEquals(
            listOf(
                YaraMatch(
                    "first",
                    "default",
                    listOf("t1", "t2"),
                    mapOf("severity" to "high", "score" to "7"),
                    "base.apk!classes.dex"
                ),
                YaraMatch("second", "ns", emptyList(), emptyMap(), "base.apk!classes.dex")
            ),
            matches
        )
        assertEquals(YaraSeverity.HIGH, matches[0].severity)
        assertEquals(YaraSeverity.MEDIUM, matches[1].severity)
    }

    @Test
    fun `malformed input ends the list instead of throwing`() {
        assertTrue(YaraMatches.parse(arrayOf("a", "b"), "x").isEmpty())
        assertTrue(YaraMatches.parse(arrayOf("a", "b", "-1", "0"), "x").isEmpty())
        assertTrue(YaraMatches.parse(arrayOf("a", "b", "5", "t"), "x").isEmpty())
        assertTrue(YaraMatches.parse(arrayOf("a", "b", "0", "2", "k", "1"), "x").isEmpty())
        assertEquals(1, YaraMatches.parse(arrayOf("a", "b", "0", "0", "trailing"), "x").size)
    }

    @Test
    fun `severity parsing is lenient`() {
        assertEquals(YaraSeverity.CRITICAL, YaraSeverity.of(" Critical "))
        assertEquals(YaraSeverity.MEDIUM, YaraSeverity.of("bad"))
        assertEquals(YaraSeverity.MEDIUM, YaraSeverity.of(null))
    }

    @Test
    fun `bundled rules follow the conventions`() {
        val source = File("src/main/assets/yara/bundled.yar").readText()
        assertTrue("bundled rules need a version header", YaraRules.bundledVersion(source) > 0)
        val rules = Regex(
            """(?m)^(private\s+)?rule\s+(\w+)[^{]*\{(.*?)^\}""",
            RegexOption.DOT_MATCHES_ALL
        ).findAll(source).toList()
        assertTrue(rules.size >= 5)
        assertEquals("rule names must be unique", rules.size, rules.map { it.groupValues[2] }.toSet().size)
        for (rule in rules.filter { it.groupValues[1].isBlank() }) {
            val name = rule.groupValues[2]
            val body = rule.groupValues[3]
            val severity = Regex("""severity\s*=\s*"(\w+)"""").find(body)?.groupValues?.get(1)
            assertTrue("$name: severity '$severity'", severity in YaraSeverity.entries.map { it.name.lowercase() })
            assertTrue("$name needs a description", Regex("""description\s*=\s*"[^"]{10,}"""").containsMatchIn(body))
        }
        Regex("""(?m)^import\s+"(\w+)"""").findAll(source).forEach {
            assertTrue("module ${it.groupValues[1]} is not built in", it.groupValues[1] in setOf("dex", "math"))
        }
        assertTrue("no include directives", !Regex("""(?m)^\s*include\s""").containsMatchIn(source))
    }
}
