package com.droidshare.wifi

import java.io.InterruptedIOException

/**
 * Cooperative transfer control. Pause takes effect at the next bounded I/O chunk;
 * cancel stops the logical operation at its next checkpoint.
 */
class TransferControl {
    private val monitor = Object()
    @Volatile private var paused = false
    @Volatile private var cancelled = false

    fun pause() = synchronized(monitor) {
        if (!cancelled) paused = true
    }

    fun resume() = synchronized(monitor) {
        paused = false
        monitor.notifyAll()
    }

    fun cancel() = synchronized(monitor) {
        cancelled = true
        paused = false
        monitor.notifyAll()
    }

    fun isPaused(): Boolean = paused
    fun isCancelled(): Boolean = cancelled

    fun checkpoint() = synchronized(monitor) {
        if (cancelled) throw InterruptedIOException("Transfer cancelled by user.")
        while (paused && !cancelled) {
            try {
                monitor.wait()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                throw InterruptedIOException("Transfer interrupted.")
            }
        }
        if (cancelled) throw InterruptedIOException("Transfer cancelled by user.")
    }
}
