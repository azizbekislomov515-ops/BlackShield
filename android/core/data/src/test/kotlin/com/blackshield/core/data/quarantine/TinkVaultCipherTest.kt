package com.blackshield.core.data.quarantine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

/** The quarantine format: streaming, authenticated, bound to its vault entry. */
class TinkVaultCipherTest {
    private val cipher = TinkVaultCipher.inMemory()
    private val aad = QuarantineVault.aad("entry-1.bsq")

    private fun encrypt(plain: ByteArray, associated: ByteArray = aad): ByteArray = ByteArrayOutputStream().also {
        assertEquals(plain.size.toLong(), cipher.encrypt(ByteArrayInputStream(plain), it, associated))
    }.toByteArray()

    private fun decrypt(encrypted: ByteArray, associated: ByteArray = aad): ByteArray =
        cipher.decrypt(ByteArrayInputStream(encrypted), associated).use { it.readBytes() }

    @Test
    fun `round trips small, empty and multi-segment files`() {
        val random = Random(7)
        for (size in listOf(0, 1, 4096, 3 * 1024 * 1024 + 17)) {
            val plain = ByteArray(size).also(random::nextBytes)
            val encrypted = encrypt(plain)
            assertArrayEquals("size $size", plain, decrypt(encrypted))
        }
    }

    @Test
    fun `the ciphertext reveals nothing of an APK`() {
        val plain = ("PK\u0003\u0004" + "classes.dex".repeat(1000)).toByteArray()
        val encrypted = encrypt(plain)
        assertFalse(String(encrypted, Charsets.ISO_8859_1).contains("classes.dex"))
        assertFalse(encrypted.copyOf(4).contentEquals(byteArrayOf(0x50, 0x4B, 3, 4)))
    }

    @Test
    fun `a changed byte, another entry's name or a truncated file fail to decrypt`() {
        val plain = ByteArray(200_000) { it.toByte() }
        val encrypted = encrypt(plain)

        val flipped = encrypted.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        assertThrows(IOException::class.java) { decrypt(flipped) }
        assertThrows(IOException::class.java) { decrypt(encrypted, QuarantineVault.aad("entry-2.bsq")) }
        assertThrows(IOException::class.java) { decrypt(encrypted.copyOf(encrypted.size - 10)) }
    }

    @Test
    fun `another key cannot decrypt`() {
        val encrypted = encrypt(ByteArray(1000))
        assertThrows(IOException::class.java) {
            TinkVaultCipher.inMemory().decrypt(ByteArrayInputStream(encrypted), aad).use { it.readBytes() }
        }
    }
}
