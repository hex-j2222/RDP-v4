package com.gotohex.rdp.rdp.protocol

import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/**
 * TEMPORARY diagnostic helper (debug build of the connection-failure fix).
 *
 * Captures a timestamped, in-memory trace of every step of the RDP
 * connection attempt (TCP connect, X.224, TLS, NLA/CredSSP, MCS, etc.) so it
 * can be copied straight out of the app's error screen — no `adb logcat`
 * needed.
 *
 * Usage:
 *   RdpLog.clear()                 // called once per connect() attempt
 *   RdpLog.d("STEP 1: TCP connected")
 *   RdpLog.e("X.224 connection rejected", throwable)
 *   val text = RdpLog.dump()       // full text to copy/share
 *
 * This is intentionally a plain in-memory singleton (no DI) so it can be
 * called from anywhere, including deep inside RdpClient, without threading
 * a reference through every function.
 */
object RdpLog {

    private const val TAG = "RdpClient"
    private const val MAX_LINES = 500

    private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    // CopyOnWriteArrayList: connect() runs on Dispatchers.IO while the UI
    // reads the log on the main thread — this avoids ConcurrentModification
    // without needing a Mutex for what is a very low-frequency write path.
    private val lines = CopyOnWriteArrayList<String>()

    private fun append(level: String, msg: String, t: Throwable? = null) {
        val stamp = timeFmt.format(Date())
        var line = "$stamp $level $msg"
        if (t != null) line += "  [${t::class.java.simpleName}: ${t.message}]"
        lines.add(line)
        while (lines.size > MAX_LINES) lines.removeAt(0)
    }

    fun d(msg: String) {
        Log.d(TAG, msg)
        append("D", msg)
    }

    fun w(msg: String, t: Throwable? = null) {
        Log.w(TAG, msg, t)
        append("W", msg, t)
    }

    fun e(msg: String, t: Throwable? = null) {
        Log.e(TAG, msg, t)
        append("E", msg, t)
    }

    /**
     * Logs a labeled hex dump of raw bytes, e.g. for inspecting exactly what
     * was sent/received at a given protocol step. Output is wrapped at 16
     * bytes per line so it stays readable when copy/shared from the error
     * screen. Truncates very large buffers (e.g. bitmap data) to keep the
     * trace readable — full length is always shown in the label.
     */
    fun hex(label: String, data: ByteArray, maxBytes: Int = 512) {
        val shown = data.size > maxBytes
        val toPrint = if (shown) data.copyOf(maxBytes) else data
        val sb = StringBuilder()
        sb.append("$label (${data.size} bytes${if (shown) ", showing first $maxBytes" else ""}):\n")
        var i = 0
        while (i < toPrint.size) {
            val end = minOf(i + 16, toPrint.size)
            val lineBytes = toPrint.copyOfRange(i, end)
            val hexPart = lineBytes.joinToString(" ") { "%02X".format(it) }
            sb.append("  ").append(hexPart).append("\n")
            i = end
        }
        if (toPrint.isEmpty()) sb.append("  (empty)\n")
        d(sb.toString().trimEnd())
    }

    /** Clears the buffer. Call at the start of each connect() attempt. */
    fun clear() = lines.clear()

    /** Returns the full captured trace as one copy/share-able string. */
    fun dump(): String {
        if (lines.isEmpty()) return "(no log lines captured)"
        return lines.joinToString("\n")
    }
}
