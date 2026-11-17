package com.blackshield.core.scanner.fuzz

import com.blackshield.core.scanner.analysis.ApkFiles
import com.blackshield.core.scanner.analysis.SigningCertificates
import com.blackshield.core.scanner.analysis.manifest.ManifestParseException
import com.blackshield.core.scanner.analysis.manifest.ManifestParser
import com.blackshield.core.scanner.yara.DexEntries
import com.blackshield.core.scanner.yara.YaraLimits
import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Fuzz tests for the parsers that read untrusted APKs on the JVM side. Each parser must either succeed or fail in
 * the way it documents; any other exception (index out of bounds, buffer underflow, out of memory...) is a bug.
 *
 * Plain `testDebugUnitTest` replays the seeds in `src/test/resources/.../ParserFuzzTestInputs/<test>/` and every
 * crash reproducer saved there. `JAZZER_FUZZ=1 ./gradlew :core:scanner:testDebugUnitTest --tests '*ParserFuzzTest*'`
 * fuzzes for each test's maxDuration (see docs/testing.md).
 */
class ParserFuzzTest {
    /**
     * Binary AndroidManifest.xml: a deliberate ManifestParseException is the only allowed failure. The parser also
     * wraps unexpected runtime exceptions (a safety net for scans); here those still count as bugs.
     */
    @FuzzTest(maxDuration = "5m")
    fun manifest(data: ByteArray) {
        try {
            ManifestParser.parse(data)
        } catch (rejected: ManifestParseException) {
            rejected.cause?.let { throw it }
        }
    }

    /** The ZIP directory pass and the manifest inside it: reports problems as gaps, never throws. */
    @FuzzTest(maxDuration = "5m")
    fun apkContents(data: FuzzedDataProvider) {
        withApk(data) { apk ->
            val gaps = mutableListOf<String>()
            ApkFiles.read(apk.path, withManifest = true, gaps = gaps)
        }
    }

    /** DEX entries streamed out of the ZIP for YARA: size limits hold and nothing throws. */
    @FuzzTest(maxDuration = "5m")
    fun dexEntries(data: FuzzedDataProvider) {
        val limits = YaraLimits(maxDexBytes = MAX_DEX_BYTES, maxDexEntries = MAX_DEX_ENTRIES)
        withApk(data) { apk ->
            val problems = mutableListOf<String>()
            var entries = 0
            DexEntries(limits).forEach(apk, problems) { _, _, length ->
                entries++
                check(length in 0..MAX_DEX_BYTES) { "DEX entry of $length bytes passed the $MAX_DEX_BYTES limit" }
            }
            check(entries <= MAX_DEX_ENTRIES) { "$entries DEX entries passed the $MAX_DEX_ENTRIES limit" }
        }
    }

    /** Signing certificates from the APK signature block: any bytes give a description, never an exception. */
    @FuzzTest(maxDuration = "2m")
    fun certificate(data: ByteArray) {
        SigningCertificates.describe(data)
    }

    /**
     * Raw bytes rarely form a ZIP, so half the inputs are turned into a structurally valid APK (fuzzed manifest,
     * DEX files and names, stored or deflated) and then optionally corrupted; the other half are used as they are.
     */
    private fun withApk(data: FuzzedDataProvider, block: (File) -> Unit) {
        val bytes = if (data.consumeBoolean()) buildApk(data) else data.consumeRemainingAsBytes()
        val file = File.createTempFile("fuzz", ".apk")
        try {
            file.writeBytes(bytes)
            block(file)
        } finally {
            file.delete()
        }
    }

    private fun buildApk(data: FuzzedDataProvider): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            repeat(data.consumeInt(1, MAX_ZIP_ENTRIES)) {
                val name = when (data.consumeInt(0, 3)) {
                    0 -> "AndroidManifest.xml"
                    1 -> "classes${data.consumeInt(0, 3).takeIf { it > 1 } ?: ""}.dex"
                    2 -> "lib/${data.consumeString(12)}/lib${data.consumeString(12)}.so"
                    else -> data.consumeString(64).ifEmpty { "x" }
                }
                val content = data.consumeBytes(data.consumeInt(0, MAX_ENTRY_BYTES))
                val entry = ZipEntry(name)
                if (data.consumeBoolean()) {
                    entry.method = ZipEntry.STORED
                    entry.size = content.size.toLong()
                    entry.crc = CRC32().apply { update(content) }.value
                }
                runCatching {
                    zip.putNextEntry(entry)
                    zip.write(content)
                    zip.closeEntry()
                }
            }
        }
        val apk = out.toByteArray()
        // Flip a few bytes: headers that lie about sizes, offsets and names.
        repeat(data.consumeInt(0, MAX_CORRUPTIONS)) {
            if (apk.isNotEmpty()) apk[data.consumeInt(0, apk.size - 1)] = data.consumeByte()
        }
        return apk
    }

    private companion object {
        const val MAX_DEX_BYTES = 256 * 1024
        const val MAX_DEX_ENTRIES = 4
        const val MAX_ZIP_ENTRIES = 6
        const val MAX_ENTRY_BYTES = 64 * 1024
        const val MAX_CORRUPTIONS = 8
    }
}
