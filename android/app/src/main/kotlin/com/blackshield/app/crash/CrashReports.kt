package com.blackshield.app.crash

import android.content.Context
import android.os.Build
import com.blackshield.app.BuildConfig
import com.blackshield.core.network.model.CrashReportRequest
import java.io.File
import java.time.Instant
import kotlinx.serialization.json.Json

/**
 * Crash reports that respect the privacy setting.
 *
 * Nothing is written, kept or sent unless the user turned crash reports on ([enabled]). A report holds the app
 * version, the Android SDK level, the exception class names and the stack frames of the root cause: no exception
 * messages (they can contain file names or other data), no device or user identifier. Reports wait in app-private
 * storage until [CrashUploadWorker] sends them; turning the setting off deletes them.
 */
object CrashReports {
    /** Mirrors the setting, so the crash handler never has to read storage while the process is dying. */
    @Volatile
    var enabled: Boolean = false

    private val json = Json { explicitNulls = false }

    fun install(context: Context) {
        val directory = directory(context)
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            if (enabled) {
                runCatching { save(directory, report(throwable, System.currentTimeMillis())) }
            }
            previous?.uncaughtException(thread, throwable)
        }
    }

    fun pending(context: Context): List<File> =
        directory(context).listFiles { file -> file.name.endsWith(SUFFIX) }.orEmpty().sortedBy { it.name }

    fun read(file: File): CrashReportRequest? =
        runCatching { json.decodeFromString(CrashReportRequest.serializer(), file.readText()) }.getOrNull()

    fun deleteAll(context: Context) {
        pending(context).forEach { it.delete() }
    }

    /** The report for [throwable]: class names and sanitized frames only. */
    fun report(throwable: Throwable, at: Long): CrashReportRequest {
        val chain = generateSequence(throwable) { it.cause.takeIf { cause -> cause !== it } }.take(MAX_CAUSES).toList()
        val frames = chain.last().stackTrace.take(MAX_FRAMES).map(::frame)
        return CrashReportRequest(
            appVersion = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            androidSdk = Build.VERSION.SDK_INT,
            occurredAt = Instant.ofEpochMilli(at).toString(),
            exceptions = chain.map { clean(it.javaClass.name, CLASS_CHARS).ifEmpty { "unknown" } },
            frames = frames.ifEmpty { listOf("unknown(Unknown Source)") }
        )
    }

    /** "class.method(File.kt:12)", limited to the characters the backend accepts. */
    internal fun frame(element: StackTraceElement): String {
        val method = clean("${element.className}.${element.methodName}", NAME_CHARS).ifEmpty { "unknown" }
        val location = when {
            element.isNativeMethod -> "Native Method"

            element.fileName == null -> "Unknown Source"

            else -> clean(element.fileName, FILE_CHARS).ifEmpty { "Unknown Source" } +
                (if (element.lineNumber >= 0) ":${element.lineNumber}" else "")
        }
        return "$method($location)"
    }

    private fun clean(value: String, allowed: Regex): String = value.filter {
        allowed.matches(it.toString())
    }.take(MAX_PART)

    private fun save(directory: File, report: CrashReportRequest) {
        directory.mkdirs()
        val existing = directory.listFiles { file -> file.name.endsWith(SUFFIX) }.orEmpty().sortedBy { it.name }
        existing.dropLast(MAX_PENDING - 1).forEach { it.delete() }
        File(directory, "${System.currentTimeMillis()}$SUFFIX")
            .writeText(json.encodeToString(CrashReportRequest.serializer(), report))
    }

    private fun directory(context: Context) = File(context.noBackupFilesDir, "crash-reports")

    private const val SUFFIX = ".json"
    private const val MAX_PENDING = 5
    private const val MAX_CAUSES = 8
    private const val MAX_FRAMES = 64
    private const val MAX_PART = 200
    private val CLASS_CHARS = Regex("[A-Za-z0-9_$.]")
    private val NAME_CHARS = Regex("[A-Za-z0-9_$.<>-]")
    private val FILE_CHARS = Regex("[A-Za-z0-9_$. -]")
}
