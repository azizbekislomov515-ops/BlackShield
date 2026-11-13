package com.blackshield.core.scanner.yara

import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/** A ruleset whose signature, digest and version have been checked. */
data class VerifiedRuleset(val version: Long, val sha256: String, val keyId: String, val rules: String)

class RulesetRejectedException(message: String) : Exception(message)

/**
 * Checks a signed YARA ruleset as served by `GET /v1/rules` (docs/sync-protocol.md):
 *
 * ```json
 * {"version": 7, "sha256": "<hex of the UTF-8 rules>", "key_id": "k1", "signature": "<base64>", "rules": "..."}
 * ```
 *
 * The signature is ECDSA P-256 with SHA-256 (DER) over `blackshield-yara-rules\n<version>\n<sha256>`,
 * made by the backend's offline signing key. The rules text must hash to `sha256`, so changing
 * any byte of the rules, the version or the digest invalidates the signature. Unknown key ids
 * are rejected: with no trusted keys configured, no update is ever accepted.
 */
class RulesetVerifier(private val trustedKeys: Map<String, PublicKey>) {
    fun verify(json: String): VerifiedRuleset {
        val obj =
            try {
                Json.parseToJsonElement(json).jsonObject
            } catch (e: SerializationException) {
                reject("not valid JSON (${e.javaClass.simpleName})")
            } catch (e: IllegalArgumentException) {
                reject("not a JSON object (${e.javaClass.simpleName})")
            }
        val version = obj.long("version")?.takeIf { it > 0 } ?: reject("version must be a positive integer")
        val sha256 =
            obj.text("sha256")?.lowercase()?.takeIf { HEX_SHA256.matches(it) } ?: reject("sha256 must be 64 hex digits")
        val keyId = obj.text("key_id") ?: reject("key_id is missing")
        val signature = obj.text("signature")?.let(::decodeBase64) ?: reject("signature must be base64")
        val rules = obj.text("rules")?.takeIf { it.isNotEmpty() } ?: reject("rules are missing")
        val key = trustedKeys[keyId] ?: reject("signed with unknown key '$keyId'")

        if (!signatureValid(key, message(version, sha256), signature)) reject("signature does not verify")
        // The signature covers the digest; the digest must also cover the text, or a valid
        // signature could be paired with different rules.
        if (sha256Hex(rules.toByteArray(Charsets.UTF_8)) != sha256) reject("rules do not match their signed digest")
        return VerifiedRuleset(version, sha256, keyId, rules)
    }

    private fun signatureValid(key: PublicKey, message: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(key)
            update(message)
            verify(signature)
        }
    } catch (_: GeneralSecurityException) {
        false // Malformed DER signatures throw SignatureException.
    }

    companion object {
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private val HEX_SHA256 = Regex("[0-9a-f]{64}")

        /** The exact bytes the backend signs. */
        fun message(version: Long, sha256: String): ByteArray =
            "blackshield-yara-rules\n$version\n$sha256".toByteArray(Charsets.UTF_8)

        fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        /**
         * Trusted keys from `keyId:base64(SubjectPublicKeyInfo DER)` entries separated by commas
         * (what `blackshield-signatures rules-keygen` prints). Malformed entries are skipped.
         */
        fun parseKeys(spec: String): Map<String, PublicKey> {
            val factory = KeyFactory.getInstance("EC")
            return spec
                .split(',')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .mapNotNull { entry ->
                    val keyId = entry.substringBefore(':', "").trim()
                    val der = decodeBase64(entry.substringAfter(':', "").trim())
                    if (keyId.isEmpty() || der == null) return@mapNotNull null
                    try {
                        keyId to factory.generatePublic(X509EncodedKeySpec(der))
                    } catch (_: GeneralSecurityException) {
                        null
                    }
                }.toMap()
        }

        private fun decodeBase64(value: String): ByteArray? = try {
            Base64.getDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            null
        }

        private fun reject(reason: String): Nothing = throw RulesetRejectedException(reason)

        private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf {
            it.isString
        }?.content

        private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf {
            !it.isString
        }?.longOrNull
    }
}
