package com.blackshield.feature.scan

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.transform

/**
 * Emits the first value immediately, then at most one value per [periodMillis], always ending on
 * the latest value. Unlike `debounce`, it keeps updating during a continuous stream of changes.
 */
internal fun <T> Flow<T>.throttleLatest(periodMillis: Long): Flow<T> = conflate().transform {
    emit(it)
    delay(periodMillis)
}
