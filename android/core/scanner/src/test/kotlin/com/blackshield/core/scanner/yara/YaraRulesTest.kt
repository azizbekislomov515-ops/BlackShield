package com.blackshield.core.scanner.yara

import com.blackshield.core.scanner.yara.RulesetSigning.bundle
import com.blackshield.core.scanner.yara.RulesetSigning.keySpec
import com.blackshield.core.scanner.yara.RulesetSigning.newKeyPair
import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The rules lifecycle with a fake native engine: which ruleset is active, and when an update is refused. */
class YaraRulesTest {
    private val directory: File = Files.createTempDirectory("yara-rules").toFile()
    private val keys = newKeyPair()
    private val verifier = RulesetVerifier(RulesetVerifier.parseKeys(keySpec("k1", keys)))
    private val bridge = FakeBridge()
    private var bundled = "// blackshield-yara-rules version: 3\nrule bundled { condition: true }"

    private fun rules() = YaraRules(directory, { bundled }, verifier) { source ->
        YaraScanner.compile(bridge, source, YaraLimits())
    }

    private fun update(version: Long, body: String = "rule update_$version { condition: true }") =
        bundle(keys, version, body)

    @After
    fun cleanUp() {
        directory.deleteRecursively()
    }

    @Test
    fun `uses the bundled rules until an update arrives`() {
        val active = rules().active()
        assertEquals(3L, active.version)
        assertEquals(ActiveRuleset.Source.BUNDLED, active.source)
        assertEquals(1, active.ruleCount)
        assertNull(active.rejectedUpdate)
    }

    @Test
    fun `a newer signed update takes effect at once and survives a restart`() {
        val rules = rules()
        assertEquals(3L, rules.activeVersion())
        assertEquals(RulesInstallResult.Installed(5), rules.install(update(5)))
        assertEquals(5L, rules.activeVersion())
        assertEquals(ActiveRuleset.Source.UPDATE, rules.active().source)
        assertEquals(
            "rule update_5 { condition: true }",
            rules.withScanner { _, _ ->
                checkNotNull(bridge.lastCompiled)
            }
        )

        // A new process (or reload) verifies the stored file again and keeps using it.
        val restarted = rules()
        assertEquals(5L, restarted.activeVersion())
        assertEquals(ActiveRuleset.Source.UPDATE, restarted.active().source)
    }

    @Test
    fun `older or equal versions are refused, so rules cannot be rolled back`() {
        val rules = rules()
        assertEquals(RulesInstallResult.NotNewer(3, 3), rules.install(update(3)))
        assertEquals(RulesInstallResult.NotNewer(2, 3), rules.install(update(2)))
        rules.install(update(6))
        assertEquals(RulesInstallResult.NotNewer(5, 6), rules.install(update(5)))
        assertEquals(6L, rules.activeVersion())
    }

    @Test
    fun `tampered or unsigned updates are refused and change nothing`() {
        val rules = rules()
        val tampered = update(5).replace("condition: true", "condition: false")
        assertTrue(rules.install(tampered) is RulesInstallResult.Rejected)
        assertTrue(rules.install(bundle(newKeyPair(), 5, "rule x { condition: true }")) is RulesInstallResult.Rejected)
        assertTrue(rules.install("{}") is RulesInstallResult.Rejected)
        assertEquals(3L, rules.activeVersion())
        assertFalse(File(directory, YaraRules.UPDATE_FILE).exists())
    }

    @Test
    fun `a stored update changed on disk is rejected, deleted, and the bundled rules are used`() {
        rules().install(update(5))
        val stored = File(directory, YaraRules.UPDATE_FILE)
        stored.writeText(stored.readText().replace("condition: true", "condition: false"))

        val restarted = rules()
        val active = restarted.active()
        assertEquals(ActiveRuleset.Source.BUNDLED, active.source)
        assertEquals(3L, active.version)
        assertTrue(active.rejectedUpdate.orEmpty().contains("do not match"))
        assertFalse(stored.exists())
        // The next sync can install a valid update again.
        assertEquals(RulesInstallResult.Installed(5), restarted.install(update(5)))
    }

    @Test
    fun `an update that does not compile is refused and the working rules stay`() {
        val rules = rules()
        val result = rules.install(update(5, "rule broken { condition: and }"))
        assertTrue(result is RulesInstallResult.Rejected)
        assertTrue((result as RulesInstallResult.Rejected).reason.contains("do not compile"))
        assertEquals(3L, rules.activeVersion())
        assertNotNull(rules.withScanner { scanner, _ -> scanner.ruleCount })
    }

    @Test
    fun `newer bundled rules from an app update win over an older stored update`() {
        rules().install(update(5))
        bundled = "// blackshield-yara-rules version: 9\nrule bundled_v9 { condition: true }"
        val active = rules().active()
        assertEquals(9L, active.version)
        assertEquals(ActiveRuleset.Source.BUNDLED, active.source)
    }

    @Test
    fun `replaced rules are released once in-flight scans finish`() {
        val rules = rules()
        rules.withScanner { scanner, _ ->
            val oldHandle = bridge.handles.single()
            rules.install(update(5)) // replaced while this scan holds the old rules
            assertFalse(oldHandle in bridge.released)
            assertTrue(scanner.scan(File("x")).isEmpty())
            oldHandle
        }.let { oldHandle -> assertTrue(oldHandle in bridge.released) }
    }

    @Test
    fun `bundled version header`() {
        assertEquals(12L, YaraRules.bundledVersion("// a comment\n// blackshield-yara-rules version: 12\nrule x {}"))
        assertEquals(0L, YaraRules.bundledVersion("rule x { condition: true }"))
    }

    /** Compiles anything without "and }" in it; every scan finds nothing. */
    private class FakeBridge : YaraBridge {
        val handles = mutableListOf<Long>()
        val released = mutableSetOf<Long>()
        var lastCompiled: String? = null

        override fun compile(source: ByteArray, result: LongArray): Array<String> {
            val text = String(source)
            if ("and }" in text) {
                result[YaraBridge.RESULT_STATUS] = YaraStatus.COMPILE_ERROR.ordinal.toLong()
                return arrayOf("line 1: syntax error")
            }
            lastCompiled = text
            val handle = handles.size + 1L
            handles += handle
            result[YaraBridge.RESULT_STATUS] = 0
            result[YaraBridge.RESULT_HANDLE] = handle
            return emptyArray()
        }

        override fun scanFile(handle: Long, path: String, timeoutMillis: Int, result: LongArray): Array<String>? {
            check(handle !in released) { "scan after release" }
            return emptyArray()
        }

        override fun scanBuffer(
            handle: Long,
            buffer: ByteBuffer,
            length: Int,
            timeoutMillis: Int,
            result: LongArray
        ): Array<String> = emptyArray()

        override fun ruleCount(handle: Long): Int = 1

        override fun release(handle: Long) {
            check(released.add(handle)) { "released twice" }
        }
    }
}
