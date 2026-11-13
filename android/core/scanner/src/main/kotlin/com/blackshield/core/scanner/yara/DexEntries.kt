package com.blackshield.core.scanner.yara

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Streams the DEX files out of an APK one at a time into a reused direct buffer, so the archive is
 * never extracted to disk and at most one DEX file is in memory. The `classesN.dex` files come
 * first, then any other `*.dex` entry (code hidden in assets, loaded at runtime).
 *
 * Sizes come from the ZIP central directory and are enforced while inflating, so an entry that
 * lies about its size (a zip bomb) is cut off instead of exhausting memory.
 */
internal class DexEntries(private val limits: YaraLimits) {
    fun forEach(
        file: File,
        problems: MutableList<String>,
        scan: (name: String, buffer: ByteBuffer, length: Int) -> Unit
    ) {
        try {
            ZipFile(file).use { zip -> scanAll(zip, problems, scan) }
        } catch (e: IOException) {
            problems += "DEX files in ${file.name} could not be read (${e.javaClass.simpleName})"
        } catch (e: SecurityException) {
            problems += "DEX files in ${file.name} could not be read (${e.javaClass.simpleName})"
        }
    }

    private fun scanAll(zip: ZipFile, problems: MutableList<String>, scan: (String, ByteBuffer, Int) -> Unit) {
        val dexFiles =
            zip
                .entries()
                .asSequence()
                .filter { !it.isDirectory && it.name.endsWith(DEX_SUFFIX, ignoreCase = true) }
                .sortedWith(
                    compareBy<ZipEntry> {
                        !PRIMARY_DEX.matches(it.name)
                    }.thenBy { it.name.length }.thenBy { it.name }
                )
                .toList()
        if (dexFiles.size > limits.maxDexEntries) {
            problems += "only the first ${limits.maxDexEntries} of ${dexFiles.size} DEX files were scanned"
        }
        var buffer: ByteBuffer? = null
        for (entry in dexFiles.take(limits.maxDexEntries)) {
            buffer = scanEntry(zip, entry, buffer, problems, scan)
        }
    }

    /** Scans one entry; returns the buffer to reuse for the next one. */
    private fun scanEntry(
        zip: ZipFile,
        entry: ZipEntry,
        buffer: ByteBuffer?,
        problems: MutableList<String>,
        scan: (String, ByteBuffer, Int) -> Unit
    ): ByteBuffer? {
        val declared = entry.size
        val target =
            if (declared in 0..limits.maxDexBytes.toLong()) {
                buffer?.takeIf { it.capacity() >= declared } ?: allocate(declared.toInt(), entry, problems)
            } else {
                problems += "${entry.name} is too large to scan (${declared / MIB} MiB)"
                null
            }
        target?.let {
            it.clear()
            val length = zip.getInputStream(entry).use { input -> readExactly(input, it, declared.toInt()) }
            if (length != null) {
                scan(entry.name, it, length)
            } else {
                problems += "${entry.name} is larger than its declared size; not scanned"
            }
        }
        return target ?: buffer
    }

    private fun allocate(size: Int, entry: ZipEntry, problems: MutableList<String>): ByteBuffer? = try {
        ByteBuffer.allocateDirect(maxOf(size, MIN_BUFFER))
    } catch (_: OutOfMemoryError) {
        problems += "not enough memory to scan ${entry.name} (${size / MIB} MiB)"
        null
    }

    /** Inflates exactly [size] bytes into [buffer]; null if the stream holds more (or fewer) bytes. */
    private fun readExactly(input: InputStream, buffer: ByteBuffer, size: Int): Int? {
        val chunk = ByteArray(CHUNK)
        var total = 0
        while (total < size) {
            val read = input.read(chunk, 0, minOf(chunk.size, size - total))
            if (read < 0) return null
            buffer.put(chunk, 0, read)
            total += read
        }
        return if (input.read() == -1) total else null
    }

    private companion object {
        const val DEX_SUFFIX = ".dex"
        const val MIB = 1024 * 1024
        const val CHUNK = 64 * 1024
        const val MIN_BUFFER = 1024 * 1024
        val PRIMARY_DEX = Regex("classes\\d*\\.dex")
    }
}
