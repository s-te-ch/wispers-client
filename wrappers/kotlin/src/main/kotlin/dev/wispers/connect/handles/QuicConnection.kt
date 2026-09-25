package dev.wispers.connect.handles

import com.sun.jna.Pointer
import dev.wispers.connect.internal.CallbackBridge
import dev.wispers.connect.internal.Callbacks
import dev.wispers.connect.internal.NativeLibrary
import dev.wispers.connect.types.QuicCloseInfo
import dev.wispers.connect.types.WispersException
import dev.wispers.connect.types.WispersStatus
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.time.Duration

/**
 * Handle to a QUIC P2P connection.
 *
 * QUIC provides reliable, multiplexed streams over UDP. Each stream is
 * independent - data on one stream doesn't block others.
 *
 * Use for data that requires delivery guarantees (file transfer, RPC)
 * or when you need multiple independent communication channels.
 *
 * Typical usage:
 * ```kotlin
 * val conn = node.connectQuic(peerNodeNumber)
 *
 * // Open a stream and send request
 * val stream = conn.openStream()
 * stream.write("REQUEST".toByteArray())
 * stream.finish()  // Signal end of write
 *
 * // Read response
 * val response = stream.read(1024)
 * stream.close()
 *
 * // Accept streams from peer
 * launch {
 *     while (isActive) {
 *         val inStream = conn.acceptStream()
 *         launch { handleStream(inStream) }
 *     }
 * }
 *
 * conn.close()
 * ```
 */
class QuicConnection internal constructor(
    pointer: Pointer,
    private val lib: NativeLibrary = NativeLibrary.INSTANCE
) : Handle(pointer) {

    /**
     * Open a new bidirectional stream.
     *
     * @return A new QUIC stream handle
     * @throws WispersException.ConnectionFailed if the connection is broken
     */
    suspend fun openStream(): QuicStream {
        val result = suspendCancellableCoroutine<Any?> { cont ->
            val ptr = requireOpen()
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_quic_connection_open_stream_async(ptr, ctx, Callbacks.quicStream)
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        val streamPtr = result as? Pointer ?: throw WispersException.NullPointer("QUIC stream is null")
        return QuicStream(streamPtr, lib)
    }

    /**
     * Accept an incoming stream from the peer.
     *
     * Suspends until the peer opens a new stream.
     *
     * @return The incoming QUIC stream handle
     * @throws WispersException.ConnectionFailed if the connection is broken
     */
    suspend fun acceptStream(): QuicStream {
        val result = suspendCancellableCoroutine<Any?> { cont ->
            val ptr = requireOpen()
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_quic_connection_accept_stream_async(ptr, ctx, Callbacks.quicStream)
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        val streamPtr = result as? Pointer ?: throw WispersException.NullPointer("QUIC stream is null")
        return QuicStream(streamPtr, lib)
    }

    /**
     * Check that the peer is still reachable.
     *
     * Sends a QUIC PING and waits for the peer's transport to acknowledge it.
     *
     * @param timeout How long to wait for the acknowledgement.
     * @throws WispersException.Timeout if no acknowledgement arrives in time
     * @throws WispersException.ConnectionFailed if the connection is closed or closing
     */
    suspend fun ping(timeout: Duration): Unit = suspendCancellableCoroutine { cont ->
        val ptr = requireOpen()
        val timeoutMs = if (timeout.isPositive()) {
            timeout.inWholeMilliseconds.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        } else {
            0
        }
        val ctx = CallbackBridge.register(cont)

        val status = lib.wispers_quic_connection_ping_async(ptr, timeoutMs, ctx, Callbacks.basic)
        if (status != WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
        }
    }

    /**
     * Close the connection.
     *
     * **This consumes the handle** - it cannot be used afterward.
     * All open streams will be terminated.
     *
     * @throws WispersException.ConnectionFailed on error
     */
    suspend fun closeAsync(): Unit = suspendCancellableCoroutine { cont ->
        val ptr = consume() ?: throw IllegalStateException("Handle already consumed")
        val ctx = CallbackBridge.register(cont)

        val status = lib.wispers_quic_connection_close_async(ptr, ctx, Callbacks.basic)
        if (status != WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
        }
    }

    /**
     * Close the connection, with error code and reason.
     *
     * [errorCode] and [reason] are application-defined; the peer reads them
     * with [peerCloseInfo]. [errorCode] must be in 0 to 2^62-1 (QUIC's limit);
     * [reason] is truncated to 1024 bytes.
     *
     * **This consumes the handle** - it cannot be used afterward.
     * All open streams will be terminated.
     *
     * @throws WispersException.ConnectionFailed on error
     */
    suspend fun closeWithErrorAsync(errorCode: Long, reason: String = ""): Unit =
        suspendCancellableCoroutine { cont ->
            val ptr = consume() ?: throw IllegalStateException("Handle already consumed")
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_quic_connection_close_with_error_async(
                ptr, errorCode, reason, ctx, Callbacks.basic
            )
            if (status != WispersStatus.SUCCESS.code) {
                // The async op never started, so the handle wasn't consumed.
                lib.wispers_quic_connection_free(ptr)
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

    /**
     * How the peer closed the connection, or `null` if it hasn't.
     *
     * Set as soon as the peer's close arrives; stream operations then fail
     * with [WispersException.ConnectionFailed].
     */
    fun peerCloseInfo(): QuicCloseInfo? {
        val infoPtr = lib.wispers_quic_connection_peer_close_info(requireOpen()) ?: return null
        try {
            return QuicCloseInfo(
                closedByApp = lib.wispers_quic_close_info_closed_by_app(infoPtr) != 0.toByte(),
                errorCode = lib.wispers_quic_close_info_error_code(infoPtr),
                reason = lib.wispers_quic_close_info_reason(infoPtr)?.getString(0, "UTF-8") ?: ""
            )
        } finally {
            lib.wispers_quic_close_info_free(infoPtr)
        }
    }

    /**
     * Close the connection synchronously.
     *
     * Prefer [closeAsync] when in a coroutine context for proper cleanup.
     */
    override fun close() {
        val ptr = consume() ?: return
        // Can't do async close from close(), just free the handle
        lib.wispers_quic_connection_free(ptr)
    }

    override fun doClose(pointer: Pointer) {
        lib.wispers_quic_connection_free(pointer)
    }
}
