package com.blackshield.feature.webshield.vpn

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileDescriptor
import java.io.InterruptedIOException
import timber.log.Timber

/**
 * Reads packets from the (non-blocking) VPN interface on one thread. It sleeps in `poll()` until a
 * packet arrives or [stop] wakes it through a pipe: no busy loop, no timer, so an idle Web Shield
 * costs no CPU. (A plain blocking read cannot be interrupted by closing the descriptor.)
 */
class TunLoop(private val tun: ParcelFileDescriptor, private val onPacket: (ByteArray, Int) -> Unit) {
    private val wake: Array<FileDescriptor> = Os.pipe()
    private val writeLock = Any()

    @Volatile
    private var running = true
    private val thread = Thread(::run, "webshield-tun")

    fun start() = thread.start()

    /** Writes one packet back to the interface; dropped if the interface is gone or full. */
    fun write(packet: ByteArray) {
        if (!running) return
        synchronized(writeLock) {
            try {
                Os.write(tun.fileDescriptor, packet, 0, packet.size)
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EAGAIN) Timber.d("tun write failed: %s", e.message)
            } catch (_: InterruptedIOException) {
                // the client will retry its query
            }
        }
    }

    /** Wakes the reader, waits for it to exit, and closes everything. Idempotent. */
    fun stop() {
        if (!running) return
        running = false
        runCatching { Os.write(wake[1], byteArrayOf(1), 0, 1) }
        if (Thread.currentThread() != thread) thread.join(JOIN_MILLIS)
        synchronized(writeLock) {
            runCatching { tun.close() }
        }
        wake.forEach { runCatching { Os.close(it) } }
    }

    private fun run() {
        val buffer = ByteArray(MAX_PACKET)
        val fds =
            arrayOf(
                StructPollfd().apply {
                    fd = tun.fileDescriptor
                    events = OsConstants.POLLIN.toShort()
                },
                StructPollfd().apply {
                    fd = wake[0]
                    events = OsConstants.POLLIN.toShort()
                }
            )
        while (running && pollOnce(fds, buffer)) {
            // pollOnce handles one wake-up
        }
        running = false
    }

    /** Waits for packets or the stop signal and handles them; false when the loop must end. */
    private fun pollOnce(fds: Array<StructPollfd>, buffer: ByteArray): Boolean {
        fds.forEach { it.revents = 0 }
        val polled =
            try {
                Os.poll(fds, -1)
                true
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EINTR) Timber.w("poll failed: %s", e.message)
                e.errno == OsConstants.EINTR
            }
        val events = fds[0].revents.toInt()
        val stopRequested = fds[1].revents.toInt() != 0
        val failed = events and (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0
        val readable = events and OsConstants.POLLIN != 0
        // Not polled: a real error ends the loop. Interrupted (EINTR, nothing set): poll again.
        return polled && !stopRequested && !failed && (!readable || drain(buffer))
    }

    /** Reads every queued packet; false when the interface is gone. */
    private fun drain(buffer: ByteArray): Boolean {
        var alive = true
        var more = true
        while (more) {
            val length =
                try {
                    Os.read(tun.fileDescriptor, buffer, 0, buffer.size)
                } catch (e: ErrnoException) {
                    alive = e.errno == OsConstants.EAGAIN
                    -1
                } catch (_: InterruptedIOException) {
                    -1
                }
            if (length > 0) onPacket(buffer, length) else more = false
            if (length == 0) alive = false
        }
        return alive
    }

    private companion object {
        const val MAX_PACKET = 32_767
        const val JOIN_MILLIS = 2_000L
    }
}
