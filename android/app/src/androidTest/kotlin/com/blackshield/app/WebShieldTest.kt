package com.blackshield.app

import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.BlockedDomain
import com.blackshield.core.data.model.DomainCategory
import com.blackshield.feature.webshield.WebShieldEntryPoint
import com.blackshield.feature.webshield.WebShieldStatus
import dagger.hilt.android.EntryPointAccessors
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Web Shield end to end on a device with internet access. The VPN permission is granted with
 * `appops` (no dialog). Lookups are made by the shell user with `ping`: this app is excluded from
 * its own VPN, so its own lookups would bypass the filter, like they do in production.
 */
@RunWith(AndroidJUnit4::class)
class WebShieldTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val webShield = EntryPointAccessors.fromApplication(
        context.applicationContext,
        WebShieldEntryPoint::class.java
    )

    @Before
    fun setUp() {
        assumeTrue("executeShellCommandRwe needs Android 12", Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertNull("VPN permission granted", webShield.webShieldController().consentIntent())
        assumeTrue("needs internet", resolves(ALLOWED))
        runBlocking {
            webShield.blockedDomains().applyDelta(
                listOf(BlockedDomain(BLOCKED, DomainCategory.MALWARE, 0)),
                emptyList()
            )
            webShield.webShieldController().enable()
        }
        waitFor("Web Shield on with the test domain loaded") {
            val status = webShield.webShieldRuntime().status.value
            status is WebShieldStatus.On && status.upstreamServers > 0 &&
                webShield.webShieldRuntime().filter.blocklist.contains(BLOCKED)
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            webShield.webShieldController().disable()
            webShield.blockedDomains().applyDelta(emptyList(), listOf(BLOCKED))
        }
        waitFor("Web Shield off") { webShield.webShieldRuntime().status.value !is WebShieldStatus.On }
        shell("svc wifi enable")
        shell("appops set ${context.packageName} ACTIVATE_VPN default")
    }

    @Test
    fun blockedDomainsFailToResolveAndOthersStillWork() {
        assertBlocked()
        assertTrue("normal lookups still work", resolves(ALLOWED))

        // "Allow once" lets it through without waiting for any cache to expire.
        webShield.webShieldRuntime().filter.allowTemporarily(BLOCKED, 60_000)
        assertTrue("allowed once", resolves(BLOCKED))
    }

    @Test
    fun recoversAfterWifiAndMobileDataSwitches() {
        assertBlocked()
        for (step in listOf("svc wifi disable", "svc wifi enable")) {
            val before = (webShield.webShieldRuntime().status.value as WebShieldStatus.On).upstreamServers
            shell(step)
            Log.i(TAG, "$step (upstream servers before: $before)")
            // Give the default network time to switch (mobile data on the emulator, then Wi-Fi again).
            waitFor("lookups to work after '$step'", timeoutMillis = 30_000) { resolves(ALLOWED) }
            val status = webShield.webShieldRuntime().status.value
            assertTrue("still on after '$step': $status", status is WebShieldStatus.On)
            assertBlocked()
        }
    }

    private fun assertBlocked() {
        // A fresh subdomain each time: never answered from a cache.
        val name = "t${UUID.randomUUID().toString().take(8)}.$BLOCKED"
        val output = shell("ping -c 1 -W 1 $name")
        assertTrue("$name must not resolve: $output", output.contains("unknown host"))
    }

    /** True if the shell user's lookup of [host] returned an address. */
    private fun resolves(host: String): Boolean = shell("ping -c 1 -W 1 $host").let { it.contains("PING $host (") }

    private fun waitFor(what: String, timeoutMillis: Long = 15_000, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > deadline) throw AssertionError("timed out waiting for $what")
            SystemClock.sleep(POLL_MILLIS)
        }
    }

    /** stdout and stderr of [command] (ping reports "unknown host" on stderr). */
    private fun shell(command: String): String {
        val (stdout, stdin, stderr) = instrumentation.uiAutomation.executeShellCommandRwe(command)
        stdin.close()
        val err = ParcelFileDescriptor.AutoCloseInputStream(stderr)
        val out = ParcelFileDescriptor.AutoCloseInputStream(stdout).use { it.readBytes().toString(Charsets.UTF_8) }
        return out + err.use { it.readBytes().toString(Charsets.UTF_8) }
    }

    private companion object {
        const val TAG = "WebShieldTest"
        const val POLL_MILLIS = 250L

        /** Real, resolvable domains (IANA's examples): the blocked one must fail only because of Web Shield. */
        const val BLOCKED = "example.org"
        const val ALLOWED = "example.com"
    }
}
