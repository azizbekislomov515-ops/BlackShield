package com.blackshield.core.scanner.files

import android.content.Context
import androidx.core.net.toUri
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.SignatureRepository
import com.blackshield.core.scanner.analysis.ApkAnalyzer
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.apps.RiskAssessor
import com.blackshield.core.scanner.apps.SignatureMatch
import com.blackshield.core.scanner.di.ScanDispatcher
import com.blackshield.core.scanner.hash.FileHasher
import com.blackshield.core.scanner.hash.HashAlgorithm
import com.blackshield.core.scanner.hash.HashResult
import com.blackshield.core.scanner.yara.ApkPatternScanner
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.IOException
import java.time.Clock
import javax.inject.Inject
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext

/** An APK file found on shared storage, not installed. Exactly one of [path] and [uri] is set. */
data class ApkCandidate(
    val displayName: String,
    /** Absolute path, when the file is directly readable (FileObserver, All files access). */
    val path: String? = null,
    /** content:// URI, when the file is only reachable through a provider (SAF). */
    val uri: String? = null,
    val size: Long,
    val lastModified: Long
) {
    /** Identifies this version of the file: a rewrite changes size or time. */
    val key: String get() = "${path ?: uri}|$size|$lastModified"
}

/** The scan result for a file. [packageName] is null when the file is not a parseable APK. */
data class FileScanResult(
    val candidate: ApkCandidate,
    val packageName: String?,
    val appLabel: String?,
    val versionCode: Long?,
    val sha256: String?,
    val verdict: Verdict,
    val riskScore: Int,
    val reasons: List<ScanReason>,
    val scannedAt: Long
) {
    /** For the shared result details UI. Not stored: files are not installed apps. */
    fun asScanResult(): ScanResult = ScanResult(
        packageName = packageName ?: candidate.displayName,
        appLabel = appLabel?.let { "$it (${candidate.displayName})" } ?: candidate.displayName,
        versionCode = versionCode ?: 0,
        apkSha256 = sha256,
        verdict = verdict,
        riskScore = riskScore,
        reasons = reasons,
        scannedAt = scannedAt
    )
}

/**
 * Scans an APK file before it is installed: the same hashing, signature lookup, static analysis
 * and risk rules as for installed apps. Files reachable only by URI are copied to a private cache
 * file first (PackageManager parses archives by path) and deleted afterwards.
 */
class ApkFileScanner
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val hasher: FileHasher,
    private val signatures: SignatureRepository,
    private val allowList: AllowListRepository,
    private val analyzer: ApkAnalyzer,
    private val assessor: RiskAssessor,
    private val patterns: ApkPatternScanner,
    @param:ScanDispatcher private val dispatcher: CoroutineDispatcher,
    private val clock: Clock
) {
    suspend fun scan(candidate: ApkCandidate): FileScanResult = withContext(dispatcher) {
        val gaps = mutableListOf<String>()
        val local = localCopy(candidate, gaps)
        try {
            local?.let { scanPath(candidate, it.path, gaps) } ?: unreadable(candidate, gaps)
        } finally {
            local?.takeIf { it.temporary }?.file?.delete()
        }
    }

    private suspend fun scanPath(candidate: ApkCandidate, path: String, gaps: MutableList<String>): FileScanResult {
        val algorithms = signatures.algorithmsInUse().map(::toHashAlgorithm).toSet() + HashAlgorithm.SHA256
        val digests = LinkedHashMap<HashAlgorithm, String>()
        val failures = mutableListOf<String>()
        for (algorithm in algorithms) {
            when (val hash = hasher.hashFile(path, algorithm)) {
                is HashResult.Success -> digests[algorithm] = hash.hexDigest
                else -> failures += "${candidate.displayName} ($algorithm): ${hash.javaClass.simpleName}"
            }
        }
        val matches = signatures.findMatches(digests.values).values.map { SignatureMatch(candidate.displayName, it) }
        val profile = analyzer.analyzeArchive(path)
        if (profile == null) gaps += "not a valid APK, only its hash was checked"
        val trusted = profile != null && profile.packageName in allowList.allowedPackages()
        // Pattern matching works on any file, parseable APK or not.
        val found = if (trusted || matches.isNotEmpty()) null else patterns.scan(listOf(path))
        val subject =
            (profile ?: placeholderProfile(candidate)).let {
                it.copy(
                    yaraMatches = found?.matches.orEmpty(),
                    analysisGaps = it.analysisGaps + gaps + found?.problems.orEmpty()
                )
            }
        val assessment = assessor.assess(subject, matches, failures, allowListed = trusted)
        return FileScanResult(
            candidate = candidate,
            packageName = profile?.packageName,
            appLabel = profile?.label,
            versionCode = null,
            sha256 = digests[HashAlgorithm.SHA256],
            verdict = assessment.verdict,
            riskScore = assessment.riskScore,
            reasons = assessment.reasons,
            scannedAt = clock.millis()
        )
    }

    private fun unreadable(candidate: ApkCandidate, gaps: List<String>) = FileScanResult(
        candidate = candidate,
        packageName = null,
        appLabel = null,
        versionCode = null,
        sha256 = null,
        verdict = Verdict.CLEAN,
        riskScore = 0,
        reasons = gaps.map { ScanReason(ScanReason.Code.ANALYSIS_INCOMPLETE, it) },
        scannedAt = clock.millis()
    )

    private class LocalFile(val file: File, val temporary: Boolean) {
        val path: String get() = file.absolutePath
    }

    private fun localCopy(candidate: ApkCandidate, gaps: MutableList<String>): LocalFile? = when {
        candidate.path != null -> directFile(candidate, candidate.path, gaps)
        candidate.uri != null -> copyOf(candidate, candidate.uri, gaps)
        else -> null
    }

    private fun directFile(candidate: ApkCandidate, path: String, gaps: MutableList<String>): LocalFile? {
        val file = File(path)
        if (!file.canRead()) gaps += "${candidate.displayName} is not readable"
        return file.takeIf { it.canRead() }?.let { LocalFile(it, temporary = false) }
    }

    private fun copyOf(candidate: ApkCandidate, uri: String, gaps: MutableList<String>): LocalFile? {
        if (candidate.size > MAX_COPY_BYTES) {
            gaps += "${candidate.displayName} is too large to analyze (${candidate.size / MIB} MiB)"
            return null
        }
        val directory = File(context.cacheDir, CACHE_DIRECTORY).apply { mkdirs() }
        val copy = File.createTempFile("scan-", ".apk", directory)
        val problem =
            try {
                val input = context.contentResolver.openInputStream(uri.toUri()) ?: throw IOException("no stream")
                input.use { source -> copy.outputStream().use { source.copyTo(it) } }
                null
            } catch (e: IOException) {
                "${candidate.displayName} could not be read (${e.javaClass.simpleName})"
            } catch (e: SecurityException) {
                "access to ${candidate.displayName} was revoked (${e.javaClass.simpleName})"
            }
        if (problem != null) {
            copy.delete()
            gaps += problem
        }
        return if (problem == null) LocalFile(copy, temporary = true) else null
    }

    private fun placeholderProfile(candidate: ApkCandidate) = AppProfile(
        packageName = candidate.displayName,
        label = candidate.displayName,
        isSystemApp = false,
        isDebuggable = false,
        installerPackage = null,
        targetSdk = 0,
        firstInstallTime = 0,
        isArchive = true
    )

    private fun toHashAlgorithm(algorithm: SignatureAlgorithm): HashAlgorithm = when (algorithm) {
        SignatureAlgorithm.MD5 -> HashAlgorithm.MD5
        SignatureAlgorithm.SHA1 -> HashAlgorithm.SHA1
        SignatureAlgorithm.SHA256 -> HashAlgorithm.SHA256
    }

    private companion object {
        const val CACHE_DIRECTORY = "apk-scan"
        const val MIB = 1024 * 1024
        const val MAX_COPY_BYTES = 1024L * MIB
    }
}
