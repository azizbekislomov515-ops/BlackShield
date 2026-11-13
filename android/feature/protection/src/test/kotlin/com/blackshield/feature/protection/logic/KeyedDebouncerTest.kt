package com.blackshield.feature.protection.logic

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class KeyedDebouncerTest {
    private val runs = mutableListOf<Pair<String, Int>>()

    /** advanceUntilIdle() does not run backgroundScope work (kotlinx-coroutines-test 1.7+), so advance the clock. */
    private fun TestScope.settle() {
        advanceTimeBy(10_000)
        runCurrent()
    }

    private fun TestScope.debouncer(quiet: Long = 300) = KeyedDebouncer<String, Int>(backgroundScope, quiet) {
            key,
            value
        ->
        runs += key to value
    }

    @Test
    fun `a burst for one key runs once, with the latest value, after the quiet period`() = runTest {
        val debouncer = debouncer()

        debouncer.submit("com.app", 1) // PACKAGE_ADDED
        advanceTimeBy(100)
        debouncer.submit("com.app", 2) // PACKAGE_REPLACED, same update
        advanceTimeBy(299)
        runCurrent()
        assertEquals(emptyList<Pair<String, Int>>(), runs)

        advanceTimeBy(2)
        runCurrent()
        assertEquals(listOf("com.app" to 2), runs)
    }

    @Test
    fun `different keys do not delay each other`() = runTest {
        val debouncer = debouncer()

        debouncer.submit("a", 1)
        advanceTimeBy(200)
        debouncer.submit("b", 1)
        advanceTimeBy(101)
        runCurrent()

        assertEquals(listOf("a" to 1), runs)
        settle()
        assertEquals(listOf("a" to 1, "b" to 1), runs)
        assertEquals(0, debouncer.pendingCount())
    }

    @Test
    fun `events after a run start a new run`() = runTest {
        val debouncer = debouncer()

        debouncer.submit("a", 1)
        settle()
        debouncer.submit("a", 2)
        settle()

        assertEquals(listOf("a" to 1, "a" to 2), runs)
    }

    @Test
    fun `a steady stream of events keeps postponing until it stops`() = runTest {
        val debouncer = debouncer(quiet = 1_500)

        repeat(10) { i ->
            debouncer.submit("Download/app.apk", i) // a download rewriting its MediaStore row
            advanceTimeBy(1_000)
        }
        runCurrent()
        assertEquals(emptyList<Pair<String, Int>>(), runs)

        advanceTimeBy(600)
        runCurrent()
        assertEquals(listOf("Download/app.apk" to 9), runs)
    }
}
