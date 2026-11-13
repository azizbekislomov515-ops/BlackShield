package com.blackshield.core.sync

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.repository.SignatureBatchSink
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.data.repository.StoreVerificationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * In-memory [SignatureSyncStore] with the same all-or-nothing semantics as the Room one: each
 * write works on a copy that replaces [rows] only if the whole call succeeds. (The Room
 * implementation's atomicity is covered by the instrumented SignatureSyncStoreTest.)
 */
class FakeSyncStore : SignatureSyncStore {
    val rows = LinkedHashMap<String, MalwareSignature>()
    var commits = 0
        private set
    private val count = MutableStateFlow(0L)

    val synced: Map<String, MalwareSignature> get() = rows.filterValues { it.source == SignatureSyncStore.SOURCE }

    override suspend fun syncedCount(): Long = synced.size.toLong()

    override fun observeSignatureCount(): Flow<Long> = count

    override suspend fun applyDelta(upserts: List<MalwareSignature>, removals: Collection<String>) {
        if (upserts.isEmpty() && removals.isEmpty()) return
        val copy = LinkedHashMap(rows)
        removals.forEach { hash -> if (copy[hash]?.source == SignatureSyncStore.SOURCE) copy.remove(hash) }
        upserts.forEach { copy[it.hash] = it }
        commit(copy)
    }

    override suspend fun replaceAll(producer: suspend (SignatureBatchSink) -> Long): Long {
        val copy = LinkedHashMap(rows)
        copy.values.removeAll { it.source == SignatureSyncStore.SOURCE }
        val expected = producer(SignatureBatchSink { batch -> batch.forEach { copy[it.hash] = it } })
        val actual = copy.values.count { it.source == SignatureSyncStore.SOURCE }.toLong()
        if (actual != expected) throw StoreVerificationException("expected $expected, got $actual")
        commit(copy)
        return actual
    }

    private fun commit(newRows: Map<String, MalwareSignature>) {
        rows.clear()
        rows.putAll(newRows)
        commits++
        count.value = rows.size.toLong()
    }
}
