package dev.wispers.connect.handles

import com.sun.jna.Pointer
import dev.wispers.connect.internal.CallbackBridge
import dev.wispers.connect.internal.Callbacks
import dev.wispers.connect.internal.NativeLibrary
import dev.wispers.connect.types.WispersException
import dev.wispers.connect.types.WispersStatus
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A serving session for a wispers node.
 *
 * A serving session connects the node to the hub and makes it reachable by peers.
 * You must call [runEventLoop] in a coroutine to start serving.
 *
 * Typical usage:
 * ```kotlin
 * val session = node.startServing()
 *
 * // Start the event loop in a coroutine
 * val job = scope.launch {
 *     session.runEventLoop()
 * }
 *
 * // Generate activation codes for new nodes
 * val code = session.generateActivationCode()
 * println("Activation code: $code")
 *
 * // Accept incoming connections (activated nodes only)
 * scope.launch {
 *     while (isActive) {
 *         val conn = session.acceptQuic()
 *         launch { handleConnection(conn) }
 *     }
 * }
 *
 * // Shutdown when done
 * session.shutdown()
 * job.join()
 * ```
 */
class ServingSession internal constructor(
    private val servingHandle: Pointer,
    private var sessionHandle: Pointer?,
    private val incomingHandle: Pointer?,
    private val lib: NativeLibrary
) : AutoCloseable {

    private val closed = AtomicBoolean(false)
    private val eventLoopStarted = AtomicBoolean(false)

    /**
     * Whether this session can accept incoming P2P connections.
     *
     * Only activated nodes can accept connections. Registered nodes can
     * serve (for activation code generation) but not accept P2P connections.
     */
    val canAcceptConnections: Boolean
        get() = incomingHandle != null

    /**
     * Run the serving event loop.
     *
     * This suspends until the session ends (via [shutdown] or error).
     * You must call this for the session to function.
     *
     * **Can only be called once** - the session handle is consumed.
     *
     * @throws IllegalStateException if already called
     * @throws WispersException.HubError on hub communication failure
     */
    suspend fun runEventLoop(): Unit = suspendCancellableCoroutine { cont ->
        if (eventLoopStarted.getAndSet(true)) {
            throw IllegalStateException("Event loop already started")
        }

        val ptr = sessionHandle ?: throw IllegalStateException("Session handle is null")
        sessionHandle = null  // Consumed
        val ctx = CallbackBridge.register(cont)

        val status = lib.wispers_serving_session_run_async(ptr, ctx, Callbacks.basic)
        if (status != WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
        }
    }

    /**
     * Generate an activation code for endorsing a new node.
     *
     * Share this code with a new device to allow it to activate and join
     * the connectivity group.
     *
     * The activation code format is "node_number-secret" (e.g., "1-abc123xyz0").
     *
     * @return The activation code string
     * @throws WispersException.HubError on hub communication failure
     */
    suspend fun generateActivationCode(): String {
        val result = suspendCancellableCoroutine<Any?> { cont ->
            requireOpen()
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_serving_handle_generate_pairing_code_async(
                servingHandle, ctx, Callbacks.activationCode
            )
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        val codePtr = result as? Pointer ?: throw WispersException.NullPointer("Activation code is null")
        return try {
            codePtr.getString(0, "UTF-8")
        } finally {
            lib.wispers_string_free(codePtr)
        }
    }

    /**
     * Accept an incoming UDP connection.
     *
     * Suspends until a peer connects via UDP.
     *
     * @return The UDP connection
     * @throws WispersException.InvalidState if node is not activated
     * @throws WispersException.ConnectionFailed if the session ended or an error occurred
     */
    suspend fun acceptUdp(): UdpConnection {
        requireOpen()
        val incoming = incomingHandle
            ?: throw WispersException.InvalidState("Node must be activated to accept connections")

        val result = suspendCancellableCoroutine<Any?> { cont ->
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_incoming_accept_udp_async(incoming, ctx, Callbacks.udpConnection)
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        val connPtr = result as? Pointer ?: throw WispersException.NullPointer("UDP connection is null")
        return UdpConnection(connPtr, lib)
    }

    /**
     * Accept an incoming QUIC connection.
     *
     * Suspends until a peer connects via QUIC.
     *
     * @return The QUIC connection
     * @throws WispersException.InvalidState if node is not activated
     * @throws WispersException.ConnectionFailed if the session ended or an error occurred
     */
    suspend fun acceptQuic(): QuicConnection {
        requireOpen()
        val incoming = incomingHandle
            ?: throw WispersException.InvalidState("Node must be activated to accept connections")

        val result = suspendCancellableCoroutine<Any?> { cont ->
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_incoming_accept_quic_async(incoming, ctx, Callbacks.quicConnection)
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        val connPtr = result as? Pointer ?: throw WispersException.NullPointer("QUIC connection is null")
        return QuicConnection(connPtr, lib)
    }

    /**
     * Request the session to shut down.
     *
     * This signals [runEventLoop] to stop. The event loop will complete
     * after shutdown.
     *
     * @throws WispersException.HubError on error
     */
    suspend fun shutdown(): Unit = suspendCancellableCoroutine { cont ->
        requireOpen()
        val ctx = CallbackBridge.register(cont)

        val status = lib.wispers_serving_handle_shutdown_async(servingHandle, ctx, Callbacks.basic)
        if (status != WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
        }
    }

    private fun requireOpen() {
        if (closed.get()) {
            throw IllegalStateException("Session has been closed")
        }
    }

    /**
     * Close the session and release resources.
     *
     * Prefer calling [shutdown] first for graceful termination.
     */
    override fun close() {
        if (closed.getAndSet(true)) {
            return
        }

        lib.wispers_serving_handle_free(servingHandle)
        sessionHandle?.let { lib.wispers_serving_session_free(it) }
        incomingHandle?.let { lib.wispers_incoming_connections_free(it) }
    }
}
