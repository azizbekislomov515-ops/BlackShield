package com.blackshield.feature.protection

import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.files.ApkCandidate
import com.blackshield.core.scanner.files.FileScanResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FileResultCodecTest {
    @Test
    fun `a file result survives the round trip through the notification intent`() {
        val result =
            FileScanResult(
                candidate = ApkCandidate(
                    "flashlight.apk",
                    path = "/storage/emulated/0/Download/flashlight.apk",
                    size = 10,
                    lastModified = 1
                ),
                packageName = "com.flashlight",
                appLabel = "Flashlight",
                versionCode = null,
                sha256 = "a".repeat(64),
                verdict = Verdict.MALICIOUS,
                riskScore = 95,
                reasons =
                    listOf(
                        ScanReason(
                            ScanReason.Code.HEURISTIC,
                            "Hides its icon",
                            30,
                            "hidden_launcher_icon",
                            listOf("launcher activity Main is disabled")
                        ),
                        ScanReason(ScanReason.Code.HEURISTIC, "Capped", 0, "x", rulePoints = 15)
                    ),
                scannedAt = 1_700_000_000_000
            )

        val decoded = FileResultCodec.decode(FileResultCodec.encode(result))

        assertEquals(result.asScanResult().copy(versionCode = 0), decoded)
        assertEquals("Flashlight (flashlight.apk)", decoded?.appLabel)
    }

    @Test
    fun `anything else decodes to null`() {
        assertNull(FileResultCodec.decode(null))
        assertNull(FileResultCodec.decode("not json"))
        assertNull(FileResultCodec.decode("""{"package":"x"}"""))
    }
}
