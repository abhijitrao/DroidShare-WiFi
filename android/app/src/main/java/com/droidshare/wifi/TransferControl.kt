package com.droidshare.wifi

import java.io.InterruptedIOException

/**
 * Cooperative transfer control. Pause takes effect at the next bounded I/O chunk;
 * cancel closes the logical operation at its next checkpoint.
 */
class TransferControl {
    @Volatile private var paused = false
    @Volatile private var cancelled = false

    fun pause() {
        if (!cancelled) paused = true
    }

    @Synchronized fun resume() {
        paused = false
        (this as java.lang.Object).notifyAll()
    }

    @Synchronized fun cancel() {
        cancelled = true
        paused = false
        (this as java.lang.Object).notifyAll()
    }

    fun isPaused(): Boolean = paused
    fun isCancelled(): Boolean = cancelled

    @Synchronized fun checkpoint() {
        if (cancelled) throw InterruptedIOException("Transfer cancelled by user.")
        while (paused && !cancelled) {
            try {
                (this as java.lang.Object).wait()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                throw InterruptedIOException("Transfer interrupted.")
            }
        }
        if (cancelled) throw InterruptedIOException("Transfer cancelled by user.")
    }
}
