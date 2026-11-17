package com.blackshield.app.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.blackshield.app.BuildConfig
import java.security.MessageDigest

/** Why a release build does not trust itself. */
enum class IntegrityProblem {
    /** A release build is debuggable: it was rebuilt or repackaged. */
    DEBUGGABLE,

    /** Signed by a key other than BlackShield's release (or Play app signing) key. */
    UNKNOWN_SIGNER
}

/**
 * Local tamper checks for release builds. They stop a casually repackaged copy from posing as BlackShield, not a
 * determined attacker who can patch the checks out; the backend must not rely on them (see docs/attestation.md).
 */
object AppIntegrity {
    fun problems(context: Context): Set<IntegrityProblem> {
        if (BuildConfig.DEBUG) return emptySet()
        val problems = mutableSetOf<IntegrityProblem>()
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            problems += IntegrityProblem.DEBUGGABLE
        }
        val trusted = trustedCertificates()
        // An empty list means the build was made without the release certificate configured: nothing to compare.
        if (trusted.isNotEmpty() && signerDigests(context).none { it in trusted }) {
            problems += IntegrityProblem.UNKNOWN_SIGNER
        }
        return problems
    }

    /** SHA-256 digests of the certificates allowed to sign release builds (Gradle `blackshield.releaseCertSha256`). */
    internal fun trustedCertificates(): Set<String> =
        BuildConfig.RELEASE_CERT_SHA256.split(',').map(::normalize).filter { it.isNotEmpty() }.toSet()

    internal fun normalize(digest: String): String = digest.replace(":", "").trim().lowercase()

    private fun signerDigests(context: Context): List<String> = signatures(context).map { signature ->
        MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun signatures(context: Context): List<Signature> {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return emptyList()
            // With key rotation, any certificate in the lineage is ours.
            (if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory).toList()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures?.toList().orEmpty()
        }
    }
}
