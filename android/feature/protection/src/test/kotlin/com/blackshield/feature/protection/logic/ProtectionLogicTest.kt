package com.blackshield.feature.protection.logic

import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionLogicTest {
    // --- AlertPolicy ---------------------------------------------------------------------------

    @Test
    fun `alerts on suspicious and malicious, never on clean`() {
        assertFalse(AlertPolicy.shouldAlert(Verdict.CLEAN, "a", emptySet()))
        assertTrue(AlertPolicy.shouldAlert(Verdict.SUSPICIOUS, "a", emptySet()))
        assertTrue(AlertPolicy.shouldAlert(Verdict.MALICIOUS, "a", emptySet()))
    }

    @Test
    fun `ignored APKs stay quiet, but only that exact APK`() {
        assertFalse(AlertPolicy.shouldAlert(Verdict.MALICIOUS, "aaa", setOf("aaa")))
        assertTrue("an update has a new hash", AlertPolicy.shouldAlert(Verdict.MALICIOUS, "bbb", setOf("aaa")))
        assertTrue(
            "no hash: cannot be matched to an ignore",
            AlertPolicy.shouldAlert(Verdict.SUSPICIOUS, null, setOf("aaa"))
        )
    }

    @Test
    fun `alert reasons put known malware first, then the strongest findings, and drop trust entries`() {
        val reasons =
            listOf(
                ScanReason(ScanReason.Code.HEURISTIC, "Installed from Google Play", -20),
                ScanReason(ScanReason.Code.HEURISTIC, "Small finding", 5),
                ScanReason(ScanReason.Code.HEURISTIC, "Big finding", 35),
                ScanReason(ScanReason.Code.KNOWN_MALWARE, "Hydra (HIGH)", 90),
                ScanReason(ScanReason.Code.ANALYSIS_INCOMPLETE, "manifest unreadable"),
                ScanReason(ScanReason.Code.HEURISTIC, "Medium finding", 15)
            )

        assertEquals(
            listOf("Known malware: Hydra (HIGH)", "Big finding", "Medium finding"),
            ThreatAlert.topReasons(reasons)
        )
    }

    // --- WatchPlanner ----------------------------------------------------------------------------

    @Test
    fun `downloads use FileObserver up to Android 10 and MediaStore from Android 11`() {
        assertEquals(DownloadsWatch.FILE_OBSERVER, plan(sdk = 29, legacyRead = true).downloads)
        assertEquals(DownloadsWatch.MEDIA_STORE, plan(sdk = 30, allFiles = true).downloads)
        assertEquals(DownloadsWatch.MEDIA_STORE, plan(sdk = 37, allFiles = true).downloads)
    }

    @Test
    fun `missing storage access is reported instead of silently watching nothing`() {
        assertEquals(DownloadsWatch.MISSING_PERMISSION, plan(sdk = 29).downloads)
        // READ_EXTERNAL_STORAGE only covers media on Android 11+.
        assertEquals(DownloadsWatch.MISSING_PERMISSION, plan(sdk = 33, legacyRead = true).downloads)
        assertEquals(DownloadsWatch.MISSING_PERMISSION, plan(sdk = 28, allFiles = true).downloads)
    }

    @Test
    fun `downloads off means no watcher, and picked folders are watched regardless of storage permissions`() {
        val off = WatchPlanner.plan(
            37,
            watchDownloads = false,
            hasAllFilesAccess = true,
            hasLegacyRead = true,
            folders = setOf("b", "a")
        )

        assertEquals(DownloadsWatch.OFF, off.downloads)
        assertEquals(listOf("a", "b"), off.folders)
    }

    private fun plan(sdk: Int, allFiles: Boolean = false, legacyRead: Boolean = false) = WatchPlanner.plan(
        sdk,
        watchDownloads = true,
        hasAllFilesAccess = allFiles,
        hasLegacyRead = legacyRead,
        folders = emptySet()
    )

    // --- ApkNames ---------------------------------------------------------------------------------

    @Test
    fun `recognises APKs by MIME type or extension`() {
        assertTrue(ApkNames.isApk("game.APK", null))
        assertTrue(ApkNames.isApk("download", ApkNames.APK_MIME))
        assertFalse(ApkNames.isApk("game.apk.part", null))
        assertFalse(ApkNames.isApk("photo.jpg", "image/jpeg"))
        assertFalse(ApkNames.isApk(null, null))
    }

    // --- PackageCatchUp ---------------------------------------------------------------------------

    @Test
    fun `catch-up resumes from the stored sequence in the same boot`() {
        assertEquals(
            42,
            PackageCatchUp.startSequence(PackageCatchUp.Cursor(bootCount = 7, sequence = 42), currentBootCount = 7)
        )
    }

    @Test
    fun `after a reboot catch-up starts from zero because sequence numbers restart`() {
        assertEquals(
            0,
            PackageCatchUp.startSequence(PackageCatchUp.Cursor(bootCount = 7, sequence = 42), currentBootCount = 8)
        )
    }

    @Test
    fun `the very first start has nothing to catch up on`() {
        assertNull(PackageCatchUp.startSequence(null, currentBootCount = 3))
    }
}
