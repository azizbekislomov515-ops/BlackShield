package com.blackshield.core.scanner.analysis

import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/** Classifies an APK signing certificate. Pure JVM code: unit-tested without a device. */
object SigningCertificates {
    private const val EMAIL_OID = "1.2.840.113549.1.9.1"
    private val NAME_OIDS = mapOf(EMAIL_OID to "EMAILADDRESS")

    /** RDNs of the AOSP test keys (build/target/product/security: testkey, platform, shared, media). */
    private val AOSP_TEST_KEY_RDNS =
        setOf(
            "EMAILADDRESS=android@android.com",
            "CN=Android",
            "OU=Android",
            "O=Android",
            "L=Mountain View",
            "ST=California",
            "C=US"
        )

    fun describe(der: ByteArray): SigningCertificate {
        val sha256 = MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
        val cert =
            try {
                CertificateFactory.getInstance(
                    "X.509"
                ).generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            } catch (ignored: GeneralSecurityException) {
                // Not an X.509 certificate: the fingerprint is still useful (e.g. for known-good pins).
                return SigningCertificate(sha256, "", "", selfSigned = false, debug = false, aospTestKey = false)
            }
        val subject = name(cert.subjectX500Principal)
        val issuer = name(cert.issuerX500Principal)
        return SigningCertificate(
            sha256 = sha256,
            subject = subject,
            issuer = issuer,
            selfSigned = subject == issuer && verifiesItself(cert),
            debug = isDebugSubject(subject),
            aospTestKey = isAospTestKeySubject(subject)
        )
    }

    /** The SDK's debug keystore uses `CN=Android Debug, O=Android, C=US`. */
    fun isDebugSubject(subject: String): Boolean =
        rdns(subject).any { it.equals("CN=Android Debug", ignoreCase = true) }

    fun isAospTestKeySubject(subject: String): Boolean = rdns(subject).map { it.trim() }.toSet() == AOSP_TEST_KEY_RDNS

    private fun name(principal: X500Principal): String = principal.getName(X500Principal.RFC1779, NAME_OIDS)

    private fun rdns(dn: String): List<String> = dn.split(',').map { it.trim() }.filter { it.isNotEmpty() }

    private fun verifiesItself(cert: X509Certificate): Boolean = try {
        cert.verify(cert.publicKey)
        true
    } catch (ignored: GeneralSecurityException) {
        false // signed by another key
    }
}
