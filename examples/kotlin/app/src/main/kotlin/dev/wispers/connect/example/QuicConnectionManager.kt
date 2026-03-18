package dev.wispers.connect.example

import android.util.Log
import dev.wispers.connect.handles.Node
import dev.wispers.connect.handles.QuicConnection
import dev.wispers.connect.handles.QuicStream
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Manages a persistent QUIC connection to a peer node.
 *
 * Establishes the connection on first use and reconnects lazily if it drops.
 * Thread-safe for concurrent stream requests from shouldInterceptRequest.
 */
class QuicConnectionManager(
    private val node: Node,
    private val peerNodeNumber: Int = 1
) {
    private val mutex = Mutex()
    private var connection: QuicConnection? = null

    /**
     * Open a new stream on the persistent connection.
     *
     * Establishes the connection if not yet connected, or reconnects if
     * the previous connection dropped.
     */
    suspend fun openStream(): QuicStream {
        mutex.withLock {
            val conn = connection
            if (conn != null && !conn.isClosed) {
                try {
                    return conn.openStream()
                } catch (e: Exception) {
                    Log.w(TAG, "openStream failed on existing connection, reconnecting: ${e.message}")
                    try { conn.close() } catch (_: Exception) {}
                    connection = null
                }
            }

            // Establish new connection
            Log.d(TAG, "Establishing new QUIC connection to node $peerNodeNumber")
            val newConn = node.connectQuic(peerNodeNumber)
            Log.d(TAG, "QUIC connection established")
            connection = newConn
            return newConn.openStream()
        }
    }

    companion object {
        private const val TAG = "WispersQUIC"
    }

    fun close() {
        try {
            connection?.close()
        } catch (_: Exception) {}
        connection = null
    }
}
