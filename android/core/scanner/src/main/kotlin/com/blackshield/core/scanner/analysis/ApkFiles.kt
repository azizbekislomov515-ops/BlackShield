package com.blackshield.core.scanner.analysis

import com.blackshield.core.scanner.analysis.manifest.ManifestInfo
import com.blackshield.core.scanner.analysis.manifest.ManifestParseException
import com.blackshield.core.scanner.analysis.manifest.ManifestParser
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipFile

/** What is read from an APK file itself. */
internal class ApkContents(val manifest: ManifestInfo?, val libraries: List<String>)

/** Reads APK files directly. Failures become entries in `gaps`, never exceptions. */
internal object ApkFiles {
    private const val MANIFEST_ENTRY = "AndroidManifest.xml"
    private const val MAX_MANIFEST_BYTES = 4 * 1024 * 1024
    private const val BUFFER_BYTES = 16 * 1024

    /** One pass over the zip directory: native library names, plus the manifest when [withManifest]. */
    fun read(apkPath: String, withManifest: Boolean, gaps: MutableList<String>): ApkContents {
        val file = apkPath.substringAfterLast('/')
        return try {
            ZipFile(apkPath).use { zip ->
                val libraries =
                    zip
                        .entries()
                        .asSequence()
                        .map { it.name }
                        .filter { it.startsWith("lib/") && it.endsWith(".so") }
                        .map { it.substringAfterLast('/') }
                        .toList()
                ApkContents(if (withManifest) manifest(zip, gaps) else null, libraries)
            }
        } catch (e: IOException) {
            gaps += "$file unreadable (${e.javaClass.simpleName})"
            ApkContents(null, emptyList())
        } catch (e: SecurityException) {
            gaps += "$file not readable (${e.javaClass.simpleName})"
            ApkContents(null, emptyList())
        }
    }

    private fun manifest(zip: ZipFile, gaps: MutableList<String>): ManifestInfo? = try {
        val entry = zip.getEntry(MANIFEST_ENTRY) ?: throw ManifestParseException("no AndroidManifest.xml")
        ManifestParser.parse(zip.getInputStream(entry).use { it.readAtMost(MAX_MANIFEST_BYTES) })
    } catch (e: ManifestParseException) {
        gaps += "manifest unreadable: ${e.message}"
        null
    } catch (e: IOException) {
        gaps += "manifest unreadable (${e.javaClass.simpleName})"
        null
    }

    private fun InputStream.readAtMost(limit: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER_BYTES)
        while (true) {
            val read = read(buffer)
            if (read == -1) break
            if (out.size() + read > limit) throw ManifestParseException("manifest larger than $limit bytes")
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
