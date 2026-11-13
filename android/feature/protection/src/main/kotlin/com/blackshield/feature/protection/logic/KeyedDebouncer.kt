package com.blackshield.feature.protection.logic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Runs [action] for a key once events for it have been quiet for [quietMillis]. Bursts collapse
 * into one run: an app update delivers PACKAGE_ADDED and PACKAGE_REPLACED together, and a
 * download touches its MediaStore row many times. No polling: each key costs one delayed coroutine.
 *
 * The latest value submitted for a key wins.
 */
class KeyedDebouncer<K, V>(
    private val scope: CoroutineScope,
    private val quietMillis: Long,
    private val action: suspend (key: K, value: V) -> Unit
) {
    private val pending = HashMap<K, Job>()
    private val lock = Mutex()

    suspend fun submit(key: K, value: V) {
        lock.withLock {
            pending.remove(key)?.cancel()
            pending[key] =
                scope.launch {
                    delay(quietMillis)
                    lock.withLock { pending.remove(key) }
                    action(key, value)
                }
        }
    }

    suspend fun pendingCount(): Int = lock.withLock { pending.size }
}
