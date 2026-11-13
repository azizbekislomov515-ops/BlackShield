package com.blackshield.core.scanner.yara

import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Limits for one [YaraScanner.scanDetailed] call. */
data class YaraLimits(
    /** Per libyara call: the whole file, then each DEX file. */
    val timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    /** DEX files are inflated into memory one at a time, up to this size. */
    val maxDexBytes: Int = DEFAULT_MAX_DEX_BYTES,
    val maxDexEntries: Int = DEFAULT_MAX_DEX_ENTRIES
) {
    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 10_000
        const val DEFAULT_MAX_DEX_BYTES = 64 * 1024 * 1024
        const val DEFAULT_MAX_DEX_ENTRIES = 64
    }
}

sealed interface YaraCompileResult {
    data class Success(val scanner: YaraScanner) : YaraCompileResult

    data class Failure(val status: YaraStatus, val errors: List<String>) : YaraCompileResult
}

/**
 * A compiled YARA ruleset. Compile once ([compile]) and share: scans may run on any number of
 * threads at once. [close] releases the native rules after the last in-flight scan finishes.
 *
 * Files are scanned as they are on disk; APKs (ZIP archives) additionally have each DEX file
 * inflated into memory and scanned, since DEX code is normally stored compressed. The archive is
 * never extracted to disk.
 */
class YaraScanner internal constructor(
    private val bridge: YaraBridge,
    private val handle: Long,
    private val limits: YaraLimits = YaraLimits()
) : Closeable {
    // One reference for the owner plus one per in-flight scan; the native rules go with the last.
    private val references = AtomicInteger(1)
    private val closed = AtomicBoolean(false)

    val ruleCount: Int by lazy { borrow { bridge.ruleCount(handle) } ?: 0 }

    /** The rules that matched [file]. Problems (timeouts, unreadable entries) are dropped; see [scanDetailed]. */
    fun scan(file: File): List<YaraMatch> = scanDetailed(file).matches

    fun scanDetailed(file: File): YaraScanReport = borrow {
        val matches = mutableListOf<YaraMatch>()
        val problems = mutableListOf<String>()
        val result = LongArray(YaraBridge.RESULT_SIZE)
        val flat = bridge.scanFile(handle, file.absolutePath, limits.timeoutMillis, result)
        collect(flat, result, file.name, matches, problems)
        if (isZip(file)) {
            DexEntries(limits).forEach(file, problems) { name, buffer, length ->
                val dexResult = LongArray(YaraBridge.RESULT_SIZE)
                collect(
                    bridge.scanBuffer(handle, buffer, length, limits.timeoutMillis, dexResult),
                    dexResult,
                    "${file.name}!$name",
                    matches,
                    problems
                )
            }
        }
        YaraScanReport(distinct(matches), problems)
    } ?: YaraScanReport(emptyList(), listOf(RULES_UNLOADED))

    /** Scans the first [length] bytes of a direct [buffer], e.g. a DEX file streamed from an archive. */
    fun scanBuffer(buffer: ByteBuffer, length: Int, location: String): YaraScanReport {
        require(buffer.isDirect) { "buffer must be direct" }
        return borrow {
            val matches = mutableListOf<YaraMatch>()
            val problems = mutableListOf<String>()
            val result = LongArray(YaraBridge.RESULT_SIZE)
            collect(
                bridge.scanBuffer(handle, buffer, length, limits.timeoutMillis, result),
                result,
                location,
                matches,
                problems
            )
            YaraScanReport(matches, problems)
        } ?: YaraScanReport(emptyList(), listOf(RULES_UNLOADED))
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) dropReference()
    }

    /** Runs [block] with the native rules guaranteed alive; null once closed. */
    internal fun <T : Any> borrow(block: () -> T): T? {
        while (true) {
            val current = references.get()
            if (current == 0) return null
            if (references.compareAndSet(current, current + 1)) break
        }
        return try {
            block()
        } finally {
            dropReference()
        }
    }

    private fun dropReference() {
        if (references.decrementAndGet() == 0) bridge.release(handle)
    }

    private fun collect(
        flat: Array<String>?,
        result: LongArray,
        location: String,
        matches: MutableList<YaraMatch>,
        problems: MutableList<String>
    ) {
        flat?.let { matches += YaraMatches.parse(it, location) }
        val status = if (flat == null) YaraStatus.INTERNAL_ERROR else YaraStatus.of(result[YaraBridge.RESULT_STATUS])
        when (status) {
            YaraStatus.OK -> Unit
            YaraStatus.TIMEOUT -> problems += "YARA scan of $location stopped after ${limits.timeoutMillis} ms"
            YaraStatus.FILE_ERROR -> problems += "YARA could not read $location"
            else -> problems += "YARA scan of $location failed ($status, error ${result[YaraBridge.RESULT_YARA_ERROR]})"
        }
    }

    companion object {
        private const val RULES_UNLOADED = "YARA rules were unloaded during the scan"
        private val ZIP_MAGIC = byteArrayOf(0x50, 0x4B, 0x03, 0x04)

        /** Compiles [source] (YARA rule text). Identical sources share one native ruleset. */
        fun compile(source: String, limits: YaraLimits = YaraLimits()): YaraCompileResult =
            compile(NativeYaraBridge, source, limits)

        internal fun compile(bridge: YaraBridge, source: String, limits: YaraLimits): YaraCompileResult {
            val result = LongArray(YaraBridge.RESULT_SIZE)
            val errors = bridge.compile(source.toByteArray(Charsets.UTF_8), result)
            val status = if (errors ==
                null
            ) {
                YaraStatus.INTERNAL_ERROR
            } else {
                YaraStatus.of(result[YaraBridge.RESULT_STATUS])
            }
            val handle = result[YaraBridge.RESULT_HANDLE]
            return if (status == YaraStatus.OK && handle != 0L) {
                YaraCompileResult.Success(YaraScanner(bridge, handle, limits))
            } else {
                YaraCompileResult.Failure(status, errors?.toList().orEmpty())
            }
        }

        /** One entry per rule: the first location it matched in. */
        private fun distinct(matches: List<YaraMatch>): List<YaraMatch> = matches.distinctBy { it.namespace to it.rule }

        private fun isZip(file: File): Boolean = try {
            RandomAccessFile(file, "r").use { raf ->
                val head = ByteArray(ZIP_MAGIC.size)
                raf.length() >= head.size && raf.read(head) == head.size && head.contentEquals(ZIP_MAGIC)
            }
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }
}
