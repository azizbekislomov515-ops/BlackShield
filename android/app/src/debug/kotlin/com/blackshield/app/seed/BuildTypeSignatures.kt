package com.blackshield.app.seed

import com.blackshield.app.BuildConfig
import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm

/** Debug-only test signatures. None of them is real malware. */
internal object BuildTypeSignatures {
    private const val SOURCE = "debug-seed"

    /** SHA-256 of the standard 68-byte EICAR anti-malware test file (eicar.org). */
    const val EICAR_TEST_FILE_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    fun signatures(now: Long): List<MalwareSignature> = listOf(
        MalwareSignature(
            hash = EICAR_TEST_FILE_SHA256,
            algorithm = SignatureAlgorithm.SHA256,
            family = "EICAR-Test-File",
            source = SOURCE,
            severity = Severity.HIGH,
            addedAt = now
        ),
        // The harmless :testing:eicar-apk app; install it to see a MALICIOUS verdict.
        MalwareSignature(
            hash = BuildConfig.EICAR_TEST_APK_SHA256,
            algorithm = SignatureAlgorithm.SHA256,
            family = "BlackShield-EICAR-Test-APK",
            source = SOURCE,
            severity = Severity.CRITICAL,
            addedAt = now
        )
    )
}
