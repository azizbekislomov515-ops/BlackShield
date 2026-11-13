package com.blackshield.feature.webshield.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import com.blackshield.core.data.model.DomainCategory
import com.blackshield.core.data.model.WebActivityEntry
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.data.prefs.WebShieldStatsRepository
import com.blackshield.core.data.repository.DomainSyncStore
import com.blackshield.core.data.repository.WebActivityRepository
import com.blackshield.core.data.repository.WebAllowListRepository
import com.blackshield.feature.webshield.R
import com.blackshield.feature.webshield.StopReason
import com.blackshield.feature.webshield.WebShieldNotifications
import com.blackshield.feature.webshield.WebShieldRuntime
import com.blackshield.feature.webshield.WebShieldStatus
import com.blackshield.feature.webshield.blocklist.DomainMatch
import com.blackshield.feature.webshield.blocklist.DomainMatcher
import com.blackshield.feature.webshield.dns.IpPackets
import dagger.hilt.android.AndroidEntryPoint
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.consumeEach
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Web Shield: a local VPN that carries only DNS. The interface routes just two virtual addresses
 * (the DNS server it advertises, IPv4 and IPv6), so all other traffic goes straight to the real
 * network and nothing is ever sent to a remote VPN server. Each query is checked against the
 * blocklist: blocked names get NXDOMAIN, everything else is forwarded unchanged to the real
 * network's resolver ([DnsForwarder]) and the answer relayed back.
 *
 * Privacy: domains are never logged. Only aggregate counters are stored, plus blocked lookups if
 * the user enabled the local activity log.
 */
@AndroidEntryPoint
class WebShieldVpnService : VpnService() {
    @Inject lateinit var runtime: WebShieldRuntime

    @Inject lateinit var store: DomainSyncStore

    @Inject lateinit var allowList: WebAllowListRepository

    @Inject lateinit var stats: WebShieldStatsRepository

    @Inject lateinit var activity: WebActivityRepository

    @Inject lateinit var preferences: UserPreferencesRepository

    @Inject lateinit var notifications: WebShieldNotifications

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var session: Session? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START, SERVICE_INTERFACE -> start(alwaysOnStart = intent.action == SERVICE_INTERFACE)
            else -> scope.launch { restartIfEnabled() } // restarted by the system after the process died
        }
        return START_STICKY
    }

    private suspend fun restartIfEnabled() {
        if (preferences.webShieldEnabled.first() && prepare(this) == null) {
            withContext(Dispatchers.Main) { start(alwaysOnStart = false) }
        } else {
            stopSelf()
        }
    }

    private fun start(alwaysOnStart: Boolean) {
        if (session != null) return
        if (alwaysOnStart) scope.launch { preferences.setWebShieldEnabled(true) } // chosen as always-on VPN in settings
        runtime.publish(WebShieldStatus.Starting)
        val tun =
            try {
                configure().establish()
            } catch (e: IllegalStateException) {
                Timber.w(e, "VPN interface not created")
                null
            } catch (e: SecurityException) {
                Timber.w(e, "VPN interface not created")
                null
            }
        if (tun == null) {
            // establish() returns null when the permission is gone (revoked, or another always-on VPN).
            val reason = if (prepare(this) != null) StopReason.NO_PERMISSION else StopReason.ESTABLISH_FAILED
            runtime.publish(WebShieldStatus.Stopped(reason))
            stopSelf()
            return
        }
        session = Session(tun).also { it.start() }
    }

    private fun configure(): Builder {
        val builder =
            Builder()
                .setSession(getString(R.string.webshield_vpn_session))
                .addAddress(INTERFACE_V4, PREFIX_V4)
                .addAddress(INTERFACE_V6, PREFIX_V6)
                .addDnsServer(DNS_V4)
                .addDnsServer(DNS_V6)
                // Only the virtual DNS server is routed into the VPN: no other traffic enters it.
                .addRoute(DNS_V4, PREFIX_V4)
                .addRoute(DNS_V6, PREFIX_V6)
                .setMtu(MTU)
                .setBlocking(false)
                // Our own traffic (forwarded queries, signature sync) uses the real network directly.
                .addDisallowedApplication(packageName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false) // follow the real network
        packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            builder.setConfigureIntent(PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE))
        }
        return builder
    }

    override fun onRevoke() {
        // Another VPN app took over, or the user disconnected us in system settings: respect it.
        Timber.i("Web Shield VPN revoked")
        scope.launch(NonCancellable) { preferences.setWebShieldEnabled(false) }
        notifications.revoked()
        shutdown(WebShieldStatus.Stopped(StopReason.REVOKED))
    }

    override fun onDestroy() {
        shutdown(if (runtime.status.value is WebShieldStatus.Stopped) runtime.status.value else WebShieldStatus.Off)
        scope.cancel()
        super.onDestroy()
    }

    private fun shutdown(status: WebShieldStatus) {
        session?.stop()
        session = null
        runtime.publish(status)
        stopSelf()
    }

    /** One established VPN interface and everything that serves it. */
    private inner class Session(tun: android.os.ParcelFileDescriptor) {
        private val tracker =
            UpstreamTracker(getSystemService(ConnectivityManager::class.java)) { upstream ->
                setUnderlyingNetworks(upstream.network?.let { arrayOf(it) })
                publishOn()
            }
        private val forwarder = DnsForwarder({ tracker.upstream.value }, { protect(it) })
        private val handler = DnsPacketHandler(runtime.filter, BlockMode.NXDOMAIN, ::onBlocked)
        private val loop = TunLoop(tun, ::onPacket)
        private val jobs = mutableListOf<Job>()
        private val inFlight = AtomicInteger()
        private val blockedMalware = AtomicLong()
        private val blockedPhishing = AtomicLong()
        private val pendingActivity = ConcurrentLinkedQueue<WebActivityEntry>()
        private val flushRequests = Channel<Unit>(Channel.CONFLATED)

        @Volatile private var notify = true

        @Volatile private var logActivity = false

        fun start() {
            tracker.start()
            jobs += scope.launch { loadBlocklist() }
            jobs +=
                scope.launch {
                    allowList.domains.collect { list ->
                        runtime.filter.allowlist =
                            DomainMatcher.build(list.map { it to DomainCategory.MALWARE })
                    }
                }
            jobs += scope.launch { preferences.webShieldNotifyBlocked.collect { notify = it } }
            jobs += scope.launch { preferences.webShieldActivityLog.collect { logActivity = it } }
            jobs +=
                scope.launch {
                    runtime.stopRequests.collect { withContext(Dispatchers.Main) { shutdown(WebShieldStatus.Off) } }
                }
            jobs += scope.launch { flushOnDemand() }
            loop.start()
            publishOn()
            Timber.i("Web Shield started")
        }

        fun stop() {
            loop.stop()
            tracker.stop()
            jobs.forEach { it.cancel() }
            scope.launch(NonCancellable) { flush() }
            Timber.i("Web Shield stopped")
        }

        @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
        private suspend fun loadBlocklist() {
            // observeCount re-emits after every write; a sync writes in one transaction, debounce anyway.
            store.observeCount().debounce(RELOAD_DEBOUNCE_MILLIS).collectLatest {
                val domains = store.all()
                runtime.filter.blocklist = DomainMatcher.build(domains.map { it.domain to it.category })
                publishOn()
            }
        }

        private fun onPacket(buffer: ByteArray, length: Int) {
            val packet = IpPackets.parseUdp(buffer, length) ?: return
            if (inFlight.incrementAndGet() > MAX_IN_FLIGHT) {
                inFlight.decrementAndGet()
                return // overloaded: drop, the resolver retries
            }
            scope.launch(Dispatchers.IO) {
                try {
                    handler.handle(packet, forwarder::forward)?.let(loop::write)
                } finally {
                    inFlight.decrementAndGet()
                }
            }
        }

        private fun onBlocked(name: String, match: DomainMatch) {
            when (match.category) {
                DomainCategory.MALWARE -> blockedMalware.incrementAndGet()
                DomainCategory.PHISHING -> blockedPhishing.incrementAndGet()
            }
            if (logActivity) {
                pendingActivity +=
                    WebActivityEntry(domain = name, category = match.category, blockedAt = System.currentTimeMillis())
            }
            if (notify) notifications.blocked(match.listed, match.category)
            flushRequests.trySend(Unit)
        }

        /**
         * Writes counters a moment after a block (batching bursts into one write) instead of on a
         * timer: nothing is written, and no thread wakes up, while nothing is blocked.
         */
        private suspend fun flushOnDemand() {
            flushRequests.consumeEach {
                delay(FLUSH_DELAY_MILLIS)
                flush()
            }
        }

        private suspend fun flush() {
            stats.add(blockedMalware.getAndSet(0), blockedPhishing.getAndSet(0))
            val entries = generateSequence { pendingActivity.poll() }.toList()
            if (logActivity) activity.record(entries)
        }

        fun publishOn() {
            if (session !== this && session != null) return
            val upstream = tracker.upstream.value
            runtime.publish(
                WebShieldStatus.On(
                    blockedDomains = runtime.filter.blocklist.size,
                    upstreamServers = upstream.servers.size,
                    privateDnsBypass = upstream.privateDnsServer,
                    alwaysOn = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn
                )
            )
        }
    }

    companion object {
        const val ACTION_START = "com.blackshield.webshield.START"

        // Private addresses unlikely to collide with a real network; only DNS_V4/DNS_V6 are routed.
        const val INTERFACE_V4 = "10.111.222.1"
        const val DNS_V4 = "10.111.222.2"
        const val INTERFACE_V6 = "fd00:b1a5:5e1d::1"
        const val DNS_V6 = "fd00:b1a5:5e1d::2"
        private const val PREFIX_V4 = 32
        private const val PREFIX_V6 = 128
        private const val MTU = 1500
        private const val MAX_IN_FLIGHT = 128
        private const val FLUSH_DELAY_MILLIS = 2_000L
        private const val RELOAD_DEBOUNCE_MILLIS = 500L
    }
}
