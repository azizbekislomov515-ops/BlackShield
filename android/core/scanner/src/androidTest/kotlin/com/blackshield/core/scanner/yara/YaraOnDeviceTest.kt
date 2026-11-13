package com.blackshield.core.scanner.yara

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Random
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real engine on a device: bundled rules, a real APK (:testing:yara-test-apk, whose DEX files
 * are stored compressed), scan time on a 50 MB APK, and signed rule updates end to end.
 */
@RunWith(AndroidJUnit4::class)
class YaraOnDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().context
    private val work = File(context.cacheDir, "yara-test").apply { mkdirs() }
    private lateinit var scanner: YaraScanner

    private val bundledRules: String by lazy { context.assets.open("yara/bundled.yar").reader().use { it.readText() } }

    private val testApk: File by lazy {
        File(work, "yara-test.apk").also { file ->
            context.assets.open("yara-test.apk").use { input -> file.outputStream().use { input.copyTo(it) } }
        }
    }

    @Before
    fun setUp() {
        scanner = (YaraScanner.compile(bundledRules) as YaraCompileResult.Success).scanner
    }

    @After
    fun tearDown() {
        scanner.close()
        work.deleteRecursively()
    }

    @Test
    fun bundledRulesCompileOnTheDevice() {
        // Six public rules plus the private is_dex helper.
        assertEquals(7, scanner.ruleCount)
    }

    @Test
    fun findsTheMarkerInsideTheCompressedDexOfARealApk() {
        // Preconditions: the marker is only reachable by inflating the DEX, not in the raw APK bytes.
        ZipFile(testApk).use { zip -> assertEquals(ZipEntry.DEFLATED, zip.getEntry("classes.dex").method) }
        assertFalse(String(testApk.readBytes(), Charsets.ISO_8859_1).contains(MARKER))

        val report = scanner.scanDetailed(testApk)

        assertEquals(emptyList<String>(), report.problems)
        val match = report.matches.single()
        assertEquals("BlackShield_Test_File", match.rule)
        assertEquals(YaraSeverity.CRITICAL, match.severity)
        assertTrue(match.location, match.location.startsWith("yara-test.apk!classes"))
        assertNotNull(match.description)
    }

    @Test
    fun cleanArchivesAndFilesHaveNoMatches() {
        val apk = syntheticApk("clean.apk", dexCopies = 2, randomMegabytes = 2)
        assertEquals(YaraScanReport(emptyList()), scanner.scanDetailed(apk))
        val text = File(work, "notes.txt").apply { writeText("nothing to see here") }
        assertEquals(YaraScanReport(emptyList()), scanner.scanDetailed(text))
    }

    @Test
    fun aFiftyMegabyteApkScansInAFewSeconds() {
        val apk = syntheticApk("large.apk", dexCopies = 8, randomMegabytes = 45, markerInLastDex = true)
        assertTrue("APK is ${apk.length() / MIB} MiB", apk.length() >= 50 * MIB)

        val start = System.nanoTime()
        val report = scanner.scanDetailed(apk)
        val millis = (System.nanoTime() - start) / 1_000_000

        Log.i(TAG, "scanned ${apk.length() / MIB} MiB APK (${dexBytes(apk) / MIB} MiB of DEX) in $millis ms")
        assertEquals(emptyList<String>(), report.problems)
        assertEquals(listOf("BlackShield_Test_File"), report.matches.map { it.rule })
        assertTrue("took $millis ms", millis < 5_000)
    }

    @Test
    fun theLargestInstalledApkScansInAFewSeconds() {
        val apk =
            context.packageManager
                .getInstalledApplications(0)
                .mapNotNull { info -> info.sourceDir?.let(::File)?.takeIf { it.canRead() } }
                .maxBy { it.length() }
        val start = System.nanoTime()
        val report = scanner.scanDetailed(apk)
        val millis = (System.nanoTime() - start) / 1_000_000
        Log.i(
            TAG,
            "scanned ${apk.path} (${apk.length() / MIB} MiB, ${dexBytes(apk) / MIB} MiB of DEX) in $millis ms: $report"
        )
        assertTrue("took $millis ms", millis < 15_000)
    }

    @Test
    fun aSignedUpdateTakesEffectAtOnceAndATamperedFileIsRejected() {
        val keys = newKeyPair()
        val directory = File(work, "rules")
        fun rules() = YaraRules(
            directory,
            { bundledRules },
            RulesetVerifier(mapOf("k1" to keys.public)),
            compiler = { source -> YaraScanner.compile(source) }
        )

        val rules = rules()
        assertFalse(probeMatched(rules))

        val version = YaraRules.bundledVersion(bundledRules) + 1
        val updated = bundledRules + PROBE_RULE
        assertEquals(RulesInstallResult.Installed(version), rules.install(signed(keys, version, updated)))
        assertTrue("the update applies to the next scan, no restart", probeMatched(rules))
        assertTrue("a restart keeps the verified update", probeMatched(rules()))

        // Someone edits the stored rules on disk: the next load rejects them and falls back.
        val stored = File(directory, YaraRules.UPDATE_FILE)
        stored.writeText(stored.readText().replace(PROBE, "SOMETHING-ELSE"))
        val restarted = rules()
        assertEquals(ActiveRuleset.Source.BUNDLED, restarted.active().source)
        assertTrue(restarted.active().rejectedUpdate.orEmpty().contains("rejected"))
        assertFalse(probeMatched(restarted))
        assertFalse(stored.exists())

        // A rolled-back (older) or foreign-signed ruleset is refused.
        assertTrue(restarted.install(signed(keys, 1, updated)) is RulesInstallResult.NotNewer)
        assertTrue(restarted.install(signed(newKeyPair(), version, updated)) is RulesInstallResult.Rejected)
    }

    private fun probeMatched(rules: YaraRules): Boolean = checkNotNull(
        rules.withScanner { scanner, _ ->
            scanner.scan(testApk).any { it.rule == "BlackShield_Update_Probe" }
        }
    )

    /** An APK-shaped ZIP: the test APK's real DEX code repeated, plus stored random assets (like media). */
    private fun syntheticApk(
        name: String,
        dexCopies: Int,
        randomMegabytes: Int,
        markerInLastDex: Boolean = false
    ): File {
        val dexFiles =
            ZipFile(testApk).use { zip ->
                zip.entries().asSequence().filter {
                    it.name.endsWith(".dex")
                }.map { zip.getInputStream(it).readBytes() }.toList()
            }
        // The app's own code (with the marker) is a small DEX; the libraries make the big one.
        val markerDex = dexFiles.first { latin1(it).contains(MARKER) }
        val cleanDex = dexFiles.maxBy {
            it.size
        }.let { latin1(it).replace(MARKER, "x".repeat(MARKER.length)).toByteArray(Charsets.ISO_8859_1) }
        val random = Random(42)
        val file = File(work, name)
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(ByteArray(2048))
            for (i in 1..dexCopies) {
                zip.putNextEntry(ZipEntry(if (i == 1) "classes.dex" else "classes$i.dex"))
                zip.write(if (markerInLastDex && i == dexCopies) markerDex else cleanDex)
            }
            val blob = ByteArray(MIB.toInt()).also(random::nextBytes)
            val crc = CRC32().apply { repeat(randomMegabytes) { update(blob) } }
            zip.putNextEntry(
                ZipEntry("assets/media.bin").apply {
                    method = ZipEntry.STORED
                    size = randomMegabytes * MIB
                    compressedSize = size
                    this.crc = crc.value
                }
            )
            repeat(randomMegabytes) { zip.write(blob) }
            zip.closeEntry()
        }
        return file
    }

    private fun latin1(bytes: ByteArray) = String(bytes, Charsets.ISO_8859_1)

    private fun dexBytes(apk: File): Long = ZipFile(apk).use { zip ->
        zip.entries().asSequence().filter { it.name.endsWith(".dex") }.sumOf { it.size }
    }

    private fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun signed(keys: KeyPair, version: Long, rules: String): String {
        val sha256 = RulesetVerifier.sha256Hex(rules.toByteArray())
        val signature =
            Signature.getInstance(RulesetVerifier.SIGNATURE_ALGORITHM).run {
                initSign(keys.private)
                update(RulesetVerifier.message(version, sha256))
                Base64.getEncoder().encodeToString(sign())
            }
        return buildJsonObject {
            put("version", version)
            put("sha256", sha256)
            put("key_id", "k1")
            put("signature", JsonPrimitive(signature))
            put("rules", rules)
        }.toString()
    }

    private companion object {
        const val TAG = "YaraOnDeviceTest"
        const val MIB = 1024L * 1024L
        const val MARKER = "X5O-BLACKSHIELD-YARA-TEST-FILE-1d8e"
        const val PROBE = "BLACKSHIELD-YARA-UPDATE-PROBE-5c21"
        val PROBE_RULE =
            """

            rule BlackShield_Update_Probe
            {
                meta:
                    severity = "low"
                    description = "Delivered by a rule update in a test"
                strings:
                    ${'$'}probe = "$PROBE"
                condition:
                    ${'$'}probe
            }
            """.trimIndent()
    }
}
