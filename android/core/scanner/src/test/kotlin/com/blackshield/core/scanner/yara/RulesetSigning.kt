package com.blackshield.core.scanner.yara

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Signs rulesets exactly like the backend (app/rules_signing.py), for tests. */
internal object RulesetSigning {
    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    fun keySpec(keyId: String, keys: KeyPair): String =
        "$keyId:" + Base64.getEncoder().encodeToString(keys.public.encoded)

    fun sign(keys: KeyPair, version: Long, sha256: String): String = Signature
        .getInstance(RulesetVerifier.SIGNATURE_ALGORITHM)
        .run {
            initSign(keys.private)
            update(RulesetVerifier.message(version, sha256))
            Base64.getEncoder().encodeToString(sign())
        }

    /** A signed bundle; the overrides produce tampered variants. */
    @Suppress("LongParameterList") // Each override is one way to tamper with a bundle.
    fun bundle(
        keys: KeyPair,
        version: Long,
        rules: String,
        keyId: String = "k1",
        signedVersion: Long = version,
        signedSha256: String = RulesetVerifier.sha256Hex(rules.toByteArray()),
        declaredSha256: String = signedSha256,
        signature: String? = null
    ): String = buildJsonObject {
        put("version", version)
        put("sha256", declaredSha256)
        put("key_id", keyId)
        put("signature", JsonPrimitive(signature ?: sign(keys, signedVersion, signedSha256)))
        put("rules", rules)
        put("published_at", "2026-11-13T00:00:00Z")
    }.toString()
}
