package com.blackshield.core.scanner.yara

import com.blackshield.core.scanner.yara.RulesetSigning.bundle
import com.blackshield.core.scanner.yara.RulesetSigning.keySpec
import com.blackshield.core.scanner.yara.RulesetSigning.newKeyPair
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RulesetVerifierTest {
    private val keys = newKeyPair()
    private val verifier = RulesetVerifier(RulesetVerifier.parseKeys(keySpec("k1", keys)))
    private val rules = "rule a { condition: true }"

    private fun assertRejected(json: String, reason: String) {
        val e = assertThrows(RulesetRejectedException::class.java) { verifier.verify(json) }
        assertTrue("'${e.message}' should mention '$reason'", e.message.orEmpty().contains(reason))
    }

    @Test
    fun `accepts a correctly signed ruleset`() {
        val verified = verifier.verify(bundle(keys, 7, rules))
        assertEquals(7L, verified.version)
        assertEquals("k1", verified.keyId)
        assertEquals(rules, verified.rules)
        assertEquals(RulesetVerifier.sha256Hex(rules.toByteArray()), verified.sha256)
    }

    @Test
    fun `rejects changed rules`() {
        val signed = bundle(keys, 7, rules)
        assertRejected(signed.replace("condition: true", "condition: false"), "do not match")
    }

    @Test
    fun `rejects a changed version or digest`() {
        assertRejected(bundle(keys, 8, rules, signedVersion = 7), "signature does not verify")
        val otherDigest = RulesetVerifier.sha256Hex("other".toByteArray())
        assertRejected(bundle(keys, 7, rules, declaredSha256 = otherDigest), "signature does not verify")
    }

    @Test
    fun `rejects a valid signature over another text`() {
        // Signed digest and declared digest agree, but the rules are different.
        val otherDigest = RulesetVerifier.sha256Hex("other".toByteArray())
        assertRejected(bundle(keys, 7, rules, signedSha256 = otherDigest), "do not match")
    }

    @Test
    fun `rejects other keys, unknown key ids and broken signatures`() {
        assertRejected(bundle(newKeyPair(), 7, rules), "signature does not verify")
        assertRejected(bundle(keys, 7, rules, keyId = "k2"), "unknown key 'k2'")
        assertRejected(bundle(keys, 7, rules, signature = "AAAA"), "signature does not verify")
        assertRejected(bundle(keys, 7, rules, signature = "not base64!"), "signature must be base64")
    }

    @Test
    fun `without trusted keys nothing is accepted`() {
        val e =
            assertThrows(RulesetRejectedException::class.java) {
                RulesetVerifier(emptyMap()).verify(bundle(keys, 7, rules))
            }
        assertTrue(e.message.orEmpty().contains("unknown key"))
    }

    @Test
    fun `rejects malformed documents`() {
        assertRejected("not json", "not valid JSON")
        assertRejected("[1, 2]", "not a JSON object")
        assertRejected("""{"version": "7"}""", "version must be a positive integer")
        assertRejected("""{"version": 0}""", "version must be a positive integer")
        assertRejected("""{"version": 1, "sha256": "abc"}""", "sha256 must be 64 hex digits")
        assertRejected(bundle(keys, 7, ""), "rules are missing")
    }

    @Test
    fun `accepts a ruleset signed by the Python backend, including non-ASCII rules`() {
        val fixture = checkNotNull(javaClass.getResource("/yara/python_signed_ruleset.json")).readText()
        val obj = Json.parseToJsonElement(fixture).jsonObject
        val python = RulesetVerifier(RulesetVerifier.parseKeys(obj.getValue("public_key").jsonPrimitive.content))
        val bundle = obj.getValue("bundle").jsonPrimitive.content

        val verified = python.verify(bundle)
        assertEquals(42L, verified.version)
        assertEquals("py1", verified.keyId)
        assertTrue(verified.rules.contains("café ✓"))
        // ...and the same bytes are refused with this test's key.
        assertThrows(RulesetRejectedException::class.java) { verifier.verify(bundle) }
    }

    @Test
    fun `parses key lists and skips malformed entries`() {
        val second = newKeyPair()
        val parsed = RulesetVerifier.parseKeys(" ${keySpec("k1", keys)} , ,garbage, k3:@@@, ${keySpec("k2", second)}")
        assertEquals(setOf("k1", "k2"), parsed.keys)
        assertEquals(second.public, parsed["k2"])
        assertTrue(RulesetVerifier.parseKeys("").isEmpty())
    }
}
