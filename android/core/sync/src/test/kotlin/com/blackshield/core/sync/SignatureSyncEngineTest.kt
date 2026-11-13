package com.blackshield.core.sync

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.network.BlackShieldHttp
import com.blackshield.core.network.NetworkConfig
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import mockwebserver3.SocketEffect
import okio.Buffer
import okio.GzipSink
import okio.buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Sync protocol behaviour against a scripted backend (MockWebServer), real Retrofit/OkHttp stack. */
class SignatureSyncEngineTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val server = MockWebServer()
    private val store = FakeSyncStore()
    private lateinit var state: SyncStateRepository
    private lateinit var workDirectory: File

    @Before
    fun setUp() {
        server.start()
        workDirectory = temp.newFolder("work")
        state = SyncStateRepository(InMemoryPreferencesDataStore())
    }

    @After
    fun tearDown() {
        server.close()
    }

    // --- First launch / full snapshot -----------------------------------------------------------

    @Test
    fun `first sync downloads the full snapshot`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(snapshot(3, listOf(1, 2, 3)))

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.SnapshotApplied(3, 3, FullSyncReason.FIRST_SYNC)), result)
        assertEquals(setOf(hash(1), hash(2), hash(3)), store.synced.keys)
        assertEquals(1, store.commits)
        val current = state.current()
        assertEquals(3L, current.version)
        assertEquals(NOW, current.lastSuccessAt)
        assertNull(current.lastError)
        assertEquals(listOf("/v1/signatures/version", "/v1/signatures/full"), paths())
        assertTrue("staged download is deleted", workDirectory.listFiles().isNullOrEmpty())
    }

    @Test
    fun `second sync downloads only the delta`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(snapshot(3, listOf(1, 2, 3)))
        engine().sync()

        server.enqueue(version(4, count = 3))
        server.enqueue(delta(since = 3, until = 4, additions = listOf(4), removals = listOf(1)))
        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.DeltaApplied(3, 4, upserts = 1, removals = 1)), result)
        assertEquals(setOf(hash(2), hash(3), hash(4)), store.synced.keys)
        assertEquals(4L, state.current().version)
        val requests = paths()
        assertEquals(listOf("/v1/signatures/delta"), requests.drop(3).filter { it != "/v1/signatures/version" })
        assertEquals(1, requests.count { it == "/v1/signatures/full" })
    }

    @Test
    fun `snapshot works without gzip and replaces previously synced rows`() = runTest {
        givenSynced(version = 2, 7, 8)
        server.enqueue(version(9, count = 1))
        server.enqueue(conflict())
        server.enqueue(snapshot(9, listOf(5), gzip = false))

        engine().sync()

        assertEquals(setOf(hash(5)), store.synced.keys)
    }

    // --- Normal / empty delta -------------------------------------------------------------------

    @Test
    fun `normal delta is collected across pages and applied in one transaction`() = runTest {
        givenSynced(version = 5, 1, 2, 3)
        server.enqueue(version(7, count = 4))
        server.enqueue(delta(since = 5, until = 7, additions = listOf(10, 11), cursor = "page-2"))
        server.enqueue(delta(since = 5, until = 7, additions = listOf(12), removals = listOf(2, 3)))
        val commitsBefore = store.commits

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.DeltaApplied(5, 7, upserts = 3, removals = 2)), result)
        assertEquals(setOf(hash(1), hash(10), hash(11), hash(12)), store.synced.keys)
        assertEquals("one transaction for all pages", commitsBefore + 1, store.commits)
        assertEquals(7L, state.current().version)
        server.takeRequest()
        val first = server.takeRequest()
        val second = server.takeRequest()
        assertEquals("5", first.url.queryParameter("since"))
        assertNull(first.url.queryParameter("cursor"))
        assertEquals("5", second.url.queryParameter("since"))
        assertEquals("page-2", second.url.queryParameter("cursor"))
    }

    @Test
    fun `delta maps wire values and keeps the last change per hash`() = runTest {
        givenSynced(version = 1, 1)
        server.enqueue(version(2, count = 2))
        server.enqueue(
            json(
                """{"since":1,"until":2,"latest_version":2,"next_cursor":null,
                "additions":[{"hash":"${hash(9)}","algorithm":"sha256","family":null,"severity":"critical","version":2},
                             {"hash":"${md5(4)}","algorithm":"md5","family":"  Joker ","severity":"low","version":2}],
                "removals":[]}"""
            )
        )

        engine().sync()

        val sha = store.rows.getValue(hash(9))
        assertEquals(Severity.CRITICAL, sha.severity)
        assertEquals("Unknown", sha.family)
        assertEquals(SignatureAlgorithm.MD5, store.rows.getValue(md5(4)).algorithm)
        assertEquals("Joker", store.rows.getValue(md5(4)).family)
        assertEquals(NOW.toEpochMilli(), sha.addedAt)
    }

    @Test
    fun `empty delta advances the version without touching the store`() = runTest {
        givenSynced(version = 5, 1, 2)
        server.enqueue(version(6, count = 2))
        server.enqueue(delta(since = 5, until = 6))
        val commitsBefore = store.commits

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.DeltaApplied(5, 6, upserts = 0, removals = 0)), result)
        assertEquals(commitsBefore, store.commits)
        assertEquals(6L, state.current().version)
    }

    @Test
    fun `up to date makes one request and changes nothing`() = runTest {
        givenSynced(version = 5, 1, 2)
        server.enqueue(version(5, count = 2))

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.UpToDate(5)), result)
        assertEquals(listOf("/v1/signatures/version"), paths())
    }

    // --- Server errors --------------------------------------------------------------------------

    @Test
    fun `server error leaves store and version unchanged and is reported`() = runTest {
        givenSynced(version = 5, 1, 2)
        server.enqueue(MockResponse.Builder().code(503).build())

        val result = engine().sync()

        assertFailure(SyncErrorKind.SERVER, result)
        assertEquals(setOf(hash(1), hash(2)), store.synced.keys)
        val current = state.current()
        assertEquals(5L, current.version)
        assertEquals(SyncErrorKind.SERVER, current.lastError)
        assertEquals(NOW, current.lastAttemptAt)
    }

    @Test
    fun `server error on a later delta page applies nothing`() = runTest {
        givenSynced(version = 5, 1, 2)
        val commitsBefore = store.commits
        server.enqueue(version(7, count = 3))
        server.enqueue(delta(since = 5, until = 7, additions = listOf(10), removals = listOf(1), cursor = "c"))
        server.enqueue(MockResponse.Builder().code(500).build())

        assertFailure(SyncErrorKind.SERVER, engine().sync())

        assertEquals(commitsBefore, store.commits)
        assertEquals(setOf(hash(1), hash(2)), store.synced.keys)
        assertEquals(5L, state.current().version)
    }

    @Test
    fun `success after a failure clears the error`() = runTest {
        givenSynced(version = 5, 1)
        server.enqueue(MockResponse.Builder().code(502).build())
        engine().sync()
        server.enqueue(version(5, count = 1))

        engine().sync()

        assertNull(state.current().lastError)
    }

    @Test
    fun `authentication and rate limit errors are classified`() = runTest {
        server.enqueue(MockResponse.Builder().code(401).build())
        assertFailure(SyncErrorKind.UNAUTHORIZED, engine().sync())

        server.enqueue(MockResponse.Builder().code(429).addHeader("Retry-After", "60").build())
        assertFailure(SyncErrorKind.RATE_LIMITED, engine().sync())
    }

    @Test
    fun `unreachable server is a network error`() = runTest {
        val url = server.url("/")
        server.close()

        val result = SignatureSyncEngine(
            BlackShieldHttp.createApi(NetworkConfig(baseUrl = url, apiKey = "k")),
            store,
            state,
            workDirectory,
            CLOCK,
            SyncConfig()
        ).sync()

        assertFailure(SyncErrorKind.NETWORK, result)
    }

    // --- Partial downloads ----------------------------------------------------------------------

    @Test
    fun `snapshot connection dropped mid-body is discarded`() = runTest {
        givenSynced(version = 4, 1, 2)
        server.enqueue(version(9, count = 2_000))
        server.enqueue(conflict())
        server.enqueue(
            MockResponse
                .Builder()
                .addHeader("Content-Encoding", "gzip")
                .body(gzip(snapshotText(9, (1..2_000).toList())))
                .onResponseBody(SocketEffect.CloseSocket())
                .build()
        )

        assertFailure(SyncErrorKind.INCOMPLETE_DOWNLOAD, engine().sync())

        assertEquals(setOf(hash(1), hash(2)), store.synced.keys)
        assertEquals(4L, state.current().version)
        assertTrue(workDirectory.listFiles().isNullOrEmpty())
    }

    @Test
    fun `snapshot without its end line is discarded`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(
            MockResponse
                .Builder()
                .addHeader("Content-Encoding", "gzip")
                .body(gzip(snapshotText(3, listOf(1, 2, 3)).lines().dropLast(2).joinToString("\n", postfix = "\n")))
                .build()
        )

        assertFailure(SyncErrorKind.INCOMPLETE_DOWNLOAD, engine().sync())

        assertTrue(store.rows.isEmpty())
        assertEquals(0L, state.current().version)
    }

    @Test
    fun `delta page connection dropped applies nothing`() = runTest {
        givenSynced(version = 5, 1)
        val commitsBefore = store.commits
        server.enqueue(version(6, count = 2))
        server.enqueue(delta(since = 5, until = 6, additions = listOf(2), cursor = "c"))
        server.enqueue(
            MockResponse
                .Builder()
                .body(deltaText(since = 5, until = 6, additions = (100..400).toList()))
                .onResponseBody(SocketEffect.CloseSocket())
                .build()
        )

        assertFailure(SyncErrorKind.NETWORK, engine().sync())

        assertEquals(commitsBefore, store.commits)
        assertEquals(5L, state.current().version)
    }

    // --- Corrupted payloads ---------------------------------------------------------------------

    @Test
    fun `corrupted delta payload applies nothing`() = runTest {
        givenSynced(version = 5, 1)
        for (bad in listOf(
            """{"hash":"${"z".repeat(64)}","algorithm":"sha256","severity":"high","version":6}""",
            """{"hash":"${hash(2)}","algorithm":"sha512","severity":"high","version":6}""",
            """{"hash":"${hash(2)}","algorithm":"sha256","severity":"apocalyptic","version":6}""",
            """{"hash":"${hash(0xABCDEF).uppercase()}","algorithm":"sha256","severity":"high","version":6}""",
            """{"hash":"${md5(2)}","algorithm":"sha256","severity":"high","version":6}"""
        )) {
            server.enqueue(version(6, count = 2))
            server.enqueue(json("""{"since":5,"until":6,"latest_version":6,"additions":[$bad],"removals":[]}"""))

            assertFailure(SyncErrorKind.CORRUPT_DATA, engine().sync())
        }
        server.enqueue(version(6, count = 2))
        server.enqueue(json("""{"since":5,"until":6,"latest_version":6,"additions":[{"hash":"""))
        assertFailure(SyncErrorKind.CORRUPT_DATA, engine().sync())

        assertEquals(setOf(hash(1)), store.synced.keys)
        assertEquals(5L, state.current().version)
    }

    @Test
    fun `corrupted snapshot row rolls the whole snapshot back`() = runTest {
        givenSynced(version = 4, 1, 2)
        server.enqueue(version(9, count = 3))
        server.enqueue(conflict())
        val text =
            snapshotText(9, listOf(5, 6, 7)).replace(
                """{"hash":"${hash(7)}","algorithm":"sha256","family":"Family7","severity":"high"}""",
                """{"hash":"${hash(7)}","algorithm":"sha256","family":"Family7","severity":"none"}"""
            )
        server.enqueue(MockResponse.Builder().body(text).build())

        assertFailure(SyncErrorKind.CORRUPT_DATA, engine(SyncConfig(snapshotBatchSize = 1)).sync())

        assertEquals("rows written before the bad line are rolled back", setOf(hash(1), hash(2)), store.synced.keys)
        assertEquals(4L, state.current().version)
    }

    @Test
    fun `snapshot whose end count disagrees is rejected`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(
            MockResponse.Builder().body(
                snapshotText(3, listOf(1, 2, 3)).replace("\"count\":3}", "\"count\":4}")
            ).build()
        )

        assertFailure(SyncErrorKind.CORRUPT_DATA, engine().sync())
        assertTrue(store.rows.isEmpty())
    }

    @Test
    fun `snapshot with duplicate hashes fails verification`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(snapshot(3, listOf(1, 1, 2)))

        assertFailure(SyncErrorKind.CORRUPT_DATA, engine().sync())
        assertTrue(store.rows.isEmpty())
    }

    @Test
    fun `garbage instead of gzip is corrupt data`() = runTest {
        server.enqueue(version(3, count = 3))
        server.enqueue(MockResponse.Builder().addHeader("Content-Encoding", "gzip").body("definitely not gzip").build())

        val result = engine().sync()

        assertTrue(
            result is SyncResult.Failure &&
                result.error in setOf(SyncErrorKind.CORRUPT_DATA, SyncErrorKind.INCOMPLETE_DOWNLOAD)
        )
        assertTrue(store.rows.isEmpty())
    }

    // --- Version gaps / damaged local state -----------------------------------------------------

    @Test
    fun `version gap the server cannot bridge falls back to the full snapshot`() = runTest {
        givenSynced(version = 3, 1, 2)
        server.enqueue(version(40, count = 2))
        server.enqueue(conflict())
        server.enqueue(snapshot(40, listOf(2, 30)))

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.SnapshotApplied(40, 2, FullSyncReason.SERVER_RESET)), result)
        assertEquals(setOf(hash(2), hash(30)), store.synced.keys)
        assertEquals(40L, state.current().version)
    }

    @Test
    fun `local version ahead of the server means the server was rebuilt`() = runTest {
        givenSynced(version = 50, 1)
        server.enqueue(version(2, count = 1))
        server.enqueue(snapshot(2, listOf(9)))

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.SnapshotApplied(2, 1, FullSyncReason.SERVER_RESET)), result)
        assertEquals(setOf(hash(9)), store.synced.keys)
        assertEquals(2L, state.current().version)
    }

    @Test
    fun `delta larger than the limit is replaced by the snapshot`() = runTest {
        givenSynced(version = 1, 1)
        server.enqueue(version(2, count = 4))
        server.enqueue(delta(since = 1, until = 2, additions = listOf(2, 3, 4), cursor = "more"))
        server.enqueue(snapshot(2, listOf(1, 2, 3, 4)))

        val result = engine(SyncConfig(maxDeltaEntries = 2)).sync()

        assertEquals(SyncResult.Success(SyncOutcome.SnapshotApplied(2, 4, FullSyncReason.DELTA_TOO_LARGE)), result)
        assertFalse("stopped paging once over the limit", paths().contains("/v1/signatures/delta?cursor"))
    }

    @Test
    fun `count mismatch with the server rebuilds a damaged store`() = runTest {
        givenSynced(version = 5, 1, 2)
        store.rows.remove(hash(2)) // e.g. rows lost outside sync
        server.enqueue(version(5, count = 2))
        server.enqueue(snapshot(5, listOf(1, 2)))

        val result = engine().sync()

        assertEquals(SyncResult.Success(SyncOutcome.SnapshotApplied(5, 2, FullSyncReason.STORE_MISMATCH)), result)
        assertEquals(setOf(hash(1), hash(2)), store.synced.keys)
    }

    @Test
    fun `rows from other sources survive every kind of sync`() = runTest {
        val seed = MalwareSignature(md5(77), SignatureAlgorithm.MD5, "EICAR", "debug-seed", Severity.HIGH, 0)
        store.rows[seed.hash] = seed
        server.enqueue(version(1, count = 1))
        server.enqueue(snapshot(1, listOf(1)))
        engine().sync()
        server.enqueue(version(2, count = 0))
        server.enqueue(delta(since = 1, until = 2, removals = listOf(1)))
        engine().sync()

        assertEquals(seed, store.rows[seed.hash])
        assertTrue(store.synced.isEmpty())
    }

    // --- Helpers --------------------------------------------------------------------------------

    private fun engine(config: SyncConfig = SyncConfig()) = SignatureSyncEngine(
        BlackShieldHttp.createApi(NetworkConfig(baseUrl = server.url("/"), apiKey = "test-key")),
        store,
        state,
        workDirectory,
        CLOCK,
        config
    )

    private suspend fun givenSynced(version: Long, vararg ids: Int) {
        for (id in ids) store.rows[hash(id)] = synced(id)
        state.setVersion(version)
    }

    private fun paths(): List<String> = buildList {
        while (true) {
            val request: RecordedRequest = server.takeRequest(10, java.util.concurrent.TimeUnit.MILLISECONDS) ?: break
            add(request.url.encodedPath)
        }
    }

    private fun assertFailure(expected: SyncErrorKind, result: SyncResult) {
        assertTrue("expected $expected failure, got $result", result is SyncResult.Failure && result.error == expected)
    }

    private companion object {
        val NOW: Instant = Instant.parse("2026-11-13T12:00:00Z")
        val CLOCK: Clock = Clock.fixed(NOW, ZoneOffset.UTC)

        fun hash(n: Int) = "%064x".format(n)

        fun md5(n: Int) = "%032x".format(n)

        fun synced(n: Int) = MalwareSignature(
            hash(n),
            SignatureAlgorithm.SHA256,
            "Family$n",
            SignatureSyncStore.SOURCE,
            Severity.HIGH,
            0
        )

        fun json(body: String) = MockResponse.Builder().addHeader("Content-Type", "application/json").body(body).build()

        fun version(version: Long, count: Long) = json("""{"version":$version,"created_at":null,"count":$count}""")

        fun deltaText(
            since: Long,
            until: Long,
            additions: List<Int> = emptyList(),
            removals: List<Int> = emptyList(),
            cursor: String? = null
        ): String {
            val adds = additions.joinToString(",") {
                """{"hash":"${hash(
                    it
                )}","algorithm":"sha256","family":"Family$it","severity":"high","version":$until}"""
            }
            val rems = removals.joinToString(",") { """{"hash":"${hash(it)}","algorithm":"sha256","version":$until}""" }
            val next = cursor?.let { "\"$it\"" } ?: "null"
            return """{"since":$since,"until":$until,"latest_version":$until,""" +
                """"additions":[$adds],"removals":[$rems],"next_cursor":$next}"""
        }

        fun delta(
            since: Long,
            until: Long = since,
            additions: List<Int> = emptyList(),
            removals: List<Int> = emptyList(),
            cursor: String? = null
        ): MockResponse = MockResponse
            .Builder()
            .addHeader("Content-Type", "application/json")
            .addHeader("Content-Encoding", "gzip")
            .body(gzip(deltaText(since, until, additions, removals, cursor)))
            .build()

        /** What the server answers when it cannot serve a delta from the requested version. */
        fun conflict(): MockResponse = json("""{"detail":{"code":"version_ahead"}}""").newBuilder().code(409).build()

        fun snapshotText(version: Long, ids: List<Int>): String = buildString {
            append(
                """{"type":"header","format":1,"version":$version,"count":${ids.size},"created_at":null}"""
            ).append('\n')
            for (id in ids) {
                append(
                    """{"hash":"${hash(id)}","algorithm":"sha256","family":"Family$id","severity":"high"}"""
                ).append('\n')
            }
            append("""{"type":"end","version":$version,"count":${ids.size}}""").append('\n')
        }

        fun snapshot(version: Long, ids: List<Int>, gzip: Boolean = true): MockResponse {
            val builder = MockResponse.Builder().addHeader("Content-Type", "application/x-ndjson")
            return if (gzip) {
                builder.addHeader("Content-Encoding", "gzip").body(gzip(snapshotText(version, ids))).build()
            } else {
                builder.body(snapshotText(version, ids)).build()
            }
        }

        fun gzip(text: String): Buffer = Buffer().also { buffer ->
            GzipSink(buffer).buffer().use { it.writeUtf8(text) }
        }
    }
}
