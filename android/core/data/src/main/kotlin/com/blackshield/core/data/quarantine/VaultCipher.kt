package com.blackshield.core.data.quarantine

import android.content.Context
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import java.io.InputStream
import java.io.OutputStream

/**
 * Authenticated streaming encryption for quarantined files. [associatedData] binds a ciphertext to
 * its vault entry: a file renamed or swapped with another entry's fails to decrypt.
 */
interface VaultCipher {
    /** Encrypts everything from [plaintext] into [ciphertext]; both stay open. Returns bytes read. */
    fun encrypt(plaintext: InputStream, ciphertext: OutputStream, associatedData: ByteArray): Long

    /** A stream of the decrypted content. Reading throws IOException if anything was changed. */
    fun decrypt(ciphertext: InputStream, associatedData: ByteArray): InputStream
}

/**
 * [VaultCipher] with Tink's AES256-GCM-HKDF streaming AEAD (1 MiB segments: constant memory for
 * any file size; every segment authenticated, truncation and reordering detected).
 *
 * The keyset lives in SharedPreferences, encrypted by an AES-256-GCM key in the Android Keystore
 * that never leaves it (hardware-backed where available). This is the approach Google recommends
 * in place of the deprecated Jetpack Security (EncryptedFile). Without the Keystore key, which is
 * not backed up and dies with the app, the vault cannot be decrypted.
 */
class TinkVaultCipher internal constructor(private val primitive: StreamingAead) : VaultCipher {
    override fun encrypt(plaintext: InputStream, ciphertext: OutputStream, associatedData: ByteArray): Long {
        var total = 0L
        primitive.newEncryptingStream(NonClosingOutputStream(ciphertext), associatedData).use { encrypted ->
            val buffer = ByteArray(BUFFER)
            while (true) {
                val read = plaintext.read(buffer)
                if (read < 0) break
                encrypted.write(buffer, 0, read)
                total += read
            }
        }
        return total
    }

    override fun decrypt(ciphertext: InputStream, associatedData: ByteArray): InputStream =
        primitive.newDecryptingStream(ciphertext, associatedData)

    companion object {
        private const val BUFFER = 64 * 1024
        const val KEY_TEMPLATE = "AES256_GCM_HKDF_1MB"
        private const val KEYSET_NAME = "quarantine_keyset"
        private const val PREFERENCES = "quarantine_keys"
        private const val MASTER_KEY_URI = "android-keystore://blackshield_quarantine_master"

        /** Creates (first use) or loads the Keystore-protected keyset. Blocking; call off the main thread. */
        fun create(context: Context): TinkVaultCipher {
            StreamingAeadConfig.register()
            val handle: KeysetHandle =
                AndroidKeysetManager
                    .Builder()
                    .withSharedPref(context, KEYSET_NAME, PREFERENCES)
                    .withKeyTemplate(KeyTemplates.get(KEY_TEMPLATE))
                    .withMasterKeyUri(MASTER_KEY_URI)
                    .build()
                    .keysetHandle
            return TinkVaultCipher(handle.getPrimitive(RegistryConfiguration.get(), StreamingAead::class.java))
        }

        /** For tests: an in-memory key, no Keystore. */
        fun inMemory(): TinkVaultCipher {
            StreamingAeadConfig.register()
            val handle = KeysetHandle.generateNew(KeyTemplates.get(KEY_TEMPLATE))
            return TinkVaultCipher(handle.getPrimitive(RegistryConfiguration.get(), StreamingAead::class.java))
        }
    }
}

/** Tink closes the stream it wraps; the caller owns [out]. */
private class NonClosingOutputStream(private val out: OutputStream) : OutputStream() {
    override fun write(b: Int) = out.write(b)

    override fun write(b: ByteArray, off: Int, len: Int) = out.write(b, off, len)

    override fun flush() = out.flush()

    override fun close() = out.flush()
}
