package com.blackshield.core.scanner.analysis

import java.security.MessageDigest
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SigningCertificatesTest {
    @Test
    fun `debug keystore certificate`() {
        val der = HeldCertificate.Builder().commonName("Android Debug").build().certificate.encoded

        val cert = SigningCertificates.describe(der)

        assertTrue(cert.debug)
        assertTrue("debug keys are self-signed", cert.selfSigned)
        assertFalse(cert.aospTestKey)
        assertEquals(sha256(der), cert.sha256)
        assertTrue(cert.subject.contains("CN=Android Debug"))
    }

    @Test
    fun `release certificate signed by another key is not self-signed`() {
        val ca = HeldCertificate.Builder().commonName("Example CA").certificateAuthority(0).build()
        val der = HeldCertificate.Builder().commonName("Example Release").signedBy(ca).build().certificate.encoded

        val cert = SigningCertificates.describe(der)

        assertFalse(cert.selfSigned)
        assertFalse(cert.debug)
        assertTrue(cert.issuer.contains("CN=Example CA"))
    }

    @Test
    fun `AOSP test key subject is recognised exactly`() {
        val aosp =
            "EMAILADDRESS=android@android.com, CN=Android, OU=Android, O=Android, " +
                "L=Mountain View, ST=California, C=US"

        assertTrue(SigningCertificates.isAospTestKeySubject(aosp))
        assertFalse(SigningCertificates.isAospTestKeySubject("CN=Android, OU=Android, O=Android, C=US"))
        assertFalse(SigningCertificates.isAospTestKeySubject("$aosp, OU=Acme"))
    }

    @Test
    fun `debug subject needs the exact common name`() {
        assertTrue(SigningCertificates.isDebugSubject("CN=Android Debug, O=Android, C=US"))
        assertFalse(SigningCertificates.isDebugSubject("CN=Android Debugger Pro, O=Acme"))
    }

    @Test
    fun `unparseable bytes still get a fingerprint`() {
        val cert = SigningCertificates.describe(byteArrayOf(1, 2, 3))

        assertEquals(sha256(byteArrayOf(1, 2, 3)), cert.sha256)
        assertFalse(cert.selfSigned || cert.debug || cert.aospTestKey)
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
        "%02x".format(it)
    }
}
