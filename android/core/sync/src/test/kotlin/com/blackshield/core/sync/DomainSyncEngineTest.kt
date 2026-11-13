package com.blackshield.core.sync

import com.blackshield.core.data.model.BlockedDomain
import com.blackshield.core.data.model.DomainCategory
import com.blackshield.core.data.repository.DomainSyncStore
import com.blackshield.core.network.BlackShieldHttp
import com.blackshield.core.network.NetworkConfig
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class DomainSyncEngineTest {
    private val server = MockWebServer()
    private val store = FakeDomainStore()
    private val state = SyncStateRepository(InMemoryPreferencesDataStore())
    private val clock = Clock.fixed(Instant.ofEpochMilli(1_700_000_000_000), ZoneOffset.UTC)

    @Before
    fun setUp() = server.start()

    @After
    fun tearDown() = server.close()

    private fun engine() = DomainSyncEngine(
        BlackShieldHttp.createApi(NetworkConfig(baseUrl = server.url("/"), apiKey = "test-key")),
        store,
        state,
        clock,
        SyncConfig(pageSize = 2, maxDeltaEntries = 3)
    )

    private fun ok(body: String) =
        MockResponse.Builder().code(200).addHeader("Content-Type", "application/json").body(body).build()

    private fun version(version: Long, count: Long) =
        ok("""{"version": $version, "created_at": null, "count": $count}""")

    private fun page(
        since: Long,
        until: Long,
        add: List<Pair<String, String>> = emptyList(),
        remove: List<String> = emptyList(),
        next: String? = null
    ) = ok(
        buildJsonObject {
            put("since", since)
            put("until", until)
            put("latest_version", until)
            put(
                "additions",
                buildJsonArray {
                    add.forEach { (domain, category) ->
                        add(
                            buildJsonObject {
                                put("domain", domain)
                                put("category", category)
                                put("version", until)
                            }
                        )
                    }
                }
            )
            put(
                "removals",
                buildJsonArray {
                    remove.forEach { domain ->
                        add(
                            buildJsonObject {
                                put("domain", domain)
                                put("version", until)
                            }
                        )
                    }
                }
            )
            put("next_cursor", next)
        }.toString()
    )

    @Test
    fun `first sync downloads every domain from version 0 across pages`() = runTest {
        server.enqueue(version(5, count = 3))
        server.enqueue(page(0, 5, add = listOf("a.example" to "malware", "b.example" to "phishing"), next = "c1"))
        server.enqueue(page(0, 5, add = listOf("c.example" to "malware"), remove = listOf("old.example")))

        val result = engine().sync()

        assertEquals(DomainSyncResult.Success(DomainSyncOutcome.FullApplied(5, 3, FullSyncReason.FIRST_SYNC)), result)
        assertEquals(DomainCategory.PHISHING, store.domains.getValue("b.example").category)
        assertEquals(setOf("a.example", "b.example", "c.example"), store.domains.keys)
        assertEquals(5L, state.current().version)
        assertEquals("/v1/domains/version", server.takeRequest().url.encodedPath)
        val first = server.takeRequest().url
        assertEquals("/v1/domains/delta", first.encodedPath)
        assertEquals("0", first.queryParameter("since"))
        assertEquals("c1", server.takeRequest().url.queryParameter("cursor"))
    }

    @Test
    fun `later syncs apply only the delta`() = runTest {
        store.replaceAll(
            listOf(
                BlockedDomain("a.example", DomainCategory.MALWARE, 1),
                BlockedDomain("b.example", DomainCategory.MALWARE, 1)
            )
        )
        state.setVersion(5)
        server.enqueue(version(7, count = 2))
        server.enqueue(page(5, 7, add = listOf("c.example" to "phishing"), remove = listOf("a.example")))

        val result = engine().sync()

        assertEquals(DomainSyncResult.Success(DomainSyncOutcome.DeltaApplied(5, 7, 1, 1)), result)
        assertEquals(setOf("b.example", "c.example"), store.domains.keys)
        assertEquals(7L, state.current().version)
        server.takeRequest()
        assertEquals("5", server.takeRequest().url.queryParameter("since"))
    }

    @Test
    fun `up to date with a matching count costs one request`() = runTest {
        store.replaceAll(listOf(BlockedDomain("a.example", DomainCategory.MALWARE, 1)))
        state.setVersion(3)
        server.enqueue(version(3, count = 1))
        assertEquals(DomainSyncResult.Success(DomainSyncOutcome.UpToDate(3)), engine().sync())
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a damaged store, a server reset or a huge delta fall back to the full list`() = runTest {
        state.setVersion(3)
        server.enqueue(version(3, count = 9)) // local count 0 != 9
        server.enqueue(page(0, 3, add = listOf("a.example" to "malware")))
        val damaged = engine().sync() as DomainSyncResult.Failure // server promised 9, sent 1
        assertEquals(SyncErrorKind.CORRUPT_DATA, damaged.error)

        state.setVersion(3)
        server.enqueue(version(4, count = 1))
        server.enqueue(MockResponse.Builder().code(409).build())
        server.enqueue(page(0, 4, add = listOf("z.example" to "malware")))
        assertEquals(
            DomainSyncResult.Success(DomainSyncOutcome.FullApplied(4, 1, FullSyncReason.SERVER_RESET)),
            engine().sync()
        )

        server.enqueue(version(9, count = 1))
        server.enqueue(page(4, 9, add = listOf("1.example" to "malware", "2.example" to "malware"), next = "x"))
        server.enqueue(page(4, 9, add = listOf("3.example" to "malware", "4.example" to "malware"), next = "y"))
        server.enqueue(page(0, 9, add = listOf("only.example" to "malware")))
        assertEquals(
            DomainSyncResult.Success(DomainSyncOutcome.FullApplied(9, 1, FullSyncReason.DELTA_TOO_LARGE)),
            engine().sync()
        )
    }

    @Test
    fun `invalid payloads are rejected and change nothing`() = runTest {
        server.enqueue(version(2, count = 1))
        server.enqueue(page(0, 2, add = listOf("NOT A DOMAIN" to "malware")))
        assertEquals(SyncErrorKind.CORRUPT_DATA, (engine().sync() as DomainSyncResult.Failure).error)

        server.enqueue(version(2, count = 1))
        server.enqueue(page(0, 2, add = listOf("a.example" to "adware")))
        assertEquals(SyncErrorKind.CORRUPT_DATA, (engine().sync() as DomainSyncResult.Failure).error)
        assertTrue(store.domains.isEmpty())
        assertEquals(0L, state.current().version)
    }

    private class FakeDomainStore : DomainSyncStore {
        val domains = LinkedHashMap<String, BlockedDomain>()
        private val count = MutableStateFlow(0L)

        override suspend fun count(): Long = domains.size.toLong()

        override fun observeCount(): Flow<Long> = count

        override suspend fun all(): List<BlockedDomain> = domains.values.toList()

        override suspend fun applyDelta(upserts: List<BlockedDomain>, removals: Collection<String>) {
            removals.forEach(domains::remove)
            upserts.forEach { domains[it.domain] = it }
            count.value = domains.size.toLong()
        }

        override suspend fun replaceAll(domains: List<BlockedDomain>) {
            this.domains.clear()
            applyDelta(domains, emptyList())
        }
    }
}
