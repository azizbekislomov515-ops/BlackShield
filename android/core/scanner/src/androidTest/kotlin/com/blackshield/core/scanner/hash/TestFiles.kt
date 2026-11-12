package com.blackshield.core.scanner.hash

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest

/** Shared helpers for the instrumented hash tests. */
internal object TestFiles {
    const val MIB = 1024L * 1024L

    /** Pattern byte `i % 251`, identical to the native GoogleTest suite. */
    private val chunk: ByteArray = ByteArray((1024 * 1024 / 251) * 251) { (it % 251).toByte() }

    val dir: File
        get() = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir

    fun write(name: String, content: ByteArray): File = File(dir, name).apply { writeBytes(content) }

    /**
     * Streams [size] pattern bytes to a file and returns it together with the digests computed by
     * `java.security.MessageDigest` (Conscrypt/BoringSSL) over the same bytes: an independent oracle.
     */
    fun writePattern(
        name: String,
        size: Long,
        algorithms: Collection<HashAlgorithm> = HashAlgorithm.entries
    ): Pair<File, Map<HashAlgorithm, String>> {
        val digests = algorithms.associateWith { MessageDigest.getInstance(it.jcaName) }
        val file = File(dir, name)
        file.outputStream().buffered(chunk.size).use { out ->
            var written = 0L
            while (written < size) {
                val n = minOf(chunk.size.toLong(), size - written).toInt()
                out.write(chunk, 0, n)
                digests.values.forEach { it.update(chunk, 0, n) }
                written += n
            }
        }
        return file to digests.mapValues { (_, md) -> md.digest().toHex() }
    }

    fun digest(algorithm: HashAlgorithm, bytes: ByteArray): String =
        MessageDigest.getInstance(algorithm.jcaName).digest(bytes).toHex()

    /** Resident set size of this process in KiB, from /proc/self/status. */
    fun rssKib(): Long = File("/proc/self/status")
        .readLines()
        .first { it.startsWith("VmRSS:") }
        .removePrefix("VmRSS:")
        .trim()
        .removeSuffix("kB")
        .trim()
        .toLong()

    private val HashAlgorithm.jcaName: String
        get() =
            when (this) {
                HashAlgorithm.MD5 -> "MD5"
                HashAlgorithm.SHA1 -> "SHA-1"
                HashAlgorithm.SHA256 -> "SHA-256"
            }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
