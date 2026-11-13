package com.blackshield.core.sync

import com.blackshield.core.network.BlackShieldHttp
import com.blackshield.core.network.NetworkConfig
import com.blackshield.core.scanner.yara.RulesInstallResult
import com.blackshield.core.scanner.yara.YaraRulesInstaller
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** The rules sync against a scripted backend; signature checks are the installer's job (tested in core:scanner). */
class YaraRulesSyncEngineTest {
    private val server = MockWebServer()
    private val installer = FakeInstaller(activeVersion = 3)

    @Before
    fun setUp() {
        server.start()
    }

    @After
    fun tearDown() {
        server.close()
    }

    private fun engine() = YaraRulesSyncEngine(
        BlackShieldHttp.createApi(NetworkConfig(baseUrl = server.url("/"), apiKey = "test-key")),
        installer
    )

    private fun json(body: String, code: Int = 200) = MockResponse
        .Builder()
        .code(code)
        .addHeader("Content-Type", "application/json")
        .body(body)
        .build()

    @Test
    fun `sends the version in use and treats 304 as up to date`() = runTest {
        server.enqueue(MockResponse.Builder().code(304).build())

        assertEquals(RulesSyncResult.Success(RulesSyncOutcome.UpToDate(3)), engine().sync())
        val request = server.takeRequest()
        assertEquals("/v1/rules", request.url.encodedPath)
        assertEquals("\"rules-3\"", request.headers["If-None-Match"])
        assertEquals("test-key", request.headers["X-API-Key"])
        assertTrue(installer.installed.isEmpty())
    }

    @Test
    fun `a new ruleset is handed to the installer`() = runTest {
        server.enqueue(json("""{"version": 4, "rules": "..."}"""))
        installer.next = RulesInstallResult.Installed(4)

        assertEquals(RulesSyncResult.Success(RulesSyncOutcome.Updated(3, 4)), engine().sync())
        assertEquals(listOf("""{"version": 4, "rules": "..."}"""), installer.installed)
    }

    @Test
    fun `refused and older rulesets change nothing and are not retried`() = runTest {
        server.enqueue(json("{}"))
        installer.next = RulesInstallResult.Rejected("signature does not verify")
        assertEquals(RulesSyncResult.Success(RulesSyncOutcome.Refused("signature does not verify")), engine().sync())

        server.enqueue(json("{}"))
        installer.next = RulesInstallResult.NotNewer(version = 2, activeVersion = 3)
        assertEquals(RulesSyncResult.Success(RulesSyncOutcome.UpToDate(3)), engine().sync())
    }

    @Test
    fun `nothing published yet is not an error`() = runTest {
        server.enqueue(json("""{"detail": "no rules published"}""", code = 404))
        assertEquals(RulesSyncResult.Success(RulesSyncOutcome.NonePublished), engine().sync())
    }

    @Test
    fun `server and auth errors are classified like signature sync errors`() = runTest {
        server.enqueue(json("{}", code = 503))
        assertEquals(SyncErrorKind.SERVER, (engine().sync() as RulesSyncResult.Failure).error)
        server.enqueue(json("{}", code = 401))
        assertEquals(SyncErrorKind.UNAUTHORIZED, (engine().sync() as RulesSyncResult.Failure).error)
        assertTrue(installer.installed.isEmpty())
    }

    @Test
    fun `an oversized response is refused before it reaches the installer`() = runTest {
        server.enqueue(json("x".repeat(YaraRulesSyncEngine.MAX_BODY_BYTES + 1)))
        assertEquals(SyncErrorKind.CORRUPT_DATA, (engine().sync() as RulesSyncResult.Failure).error)
        assertTrue(installer.installed.isEmpty())
    }

    @Test
    fun `worker result combines both syncs`() {
        assertEquals(androidx.work.ListenableWorker.Result.success(), SignatureSyncWorker.resultFor(emptyList(), 0))
        assertEquals(
            androidx.work.ListenableWorker.Result.retry(),
            SignatureSyncWorker.resultFor(listOf(SyncErrorKind.CERTIFICATE, SyncErrorKind.NETWORK), 0)
        )
        assertEquals(
            androidx.work.ListenableWorker.Result.failure(),
            SignatureSyncWorker.resultFor(listOf(SyncErrorKind.UNAUTHORIZED), 0)
        )
    }

    private class FakeInstaller(private var activeVersion: Long) : YaraRulesInstaller {
        val installed = mutableListOf<String>()
        var next: RulesInstallResult = RulesInstallResult.Rejected("unexpected")

        override fun activeVersion(): Long = activeVersion

        override fun install(signedJson: String): RulesInstallResult {
            installed += signedJson
            (next as? RulesInstallResult.Installed)?.let { activeVersion = it.version }
            return next
        }
    }
}
