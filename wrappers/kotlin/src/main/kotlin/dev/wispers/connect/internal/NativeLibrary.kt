package dev.wispers.connect.internal

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

/**
 * JNA interface declaring all wispers-connect C FFI functions.
 *
 * This interface maps to the native library "wispers_connect".
 * All functions match the signatures in wispers_connect.h.
 */
interface NativeLibrary : Library {

    companion object {
        /**
         * Load the native library. The library must be available in the
         * system library path or bundled with the app.
         */
        val INSTANCE: NativeLibrary by lazy {
            Native.load("wispers_connect", NativeLibrary::class.java)
        }
    }

    // =========================================================================
    // Storage lifecycle
    // =========================================================================

    /**
     * Create a new in-memory storage (for testing).
     */
    fun wispers_storage_new_in_memory(): Pointer?

    /**
     * Create storage with host-provided callbacks.
     */
    fun wispers_storage_new_with_callbacks(
        callbacks: NativeTypes.WispersNodeStorageCallbacks.ByReference?
    ): Pointer?

    /**
     * Free a storage handle.
     */
    fun wispers_storage_free(handle: Pointer?)

    /**
     * Read registration from local storage (sync, no hub contact).
     * Returns SUCCESS with out_info populated if registered, NOT_FOUND if not.
     */
    fun wispers_storage_read_registration(
        handle: Pointer?,
        outInfo: NativeTypes.WispersRegistrationInfo?
    ): Int

    /**
     * Override the hub address (for testing).
     */
    fun wispers_storage_override_hub_addr(
        handle: Pointer?,
        hubAddr: String?
    ): Int

    /**
     * Restore or initialize node state asynchronously.
     */
    fun wispers_storage_restore_or_init_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersInitCallback?
    ): Int

    // =========================================================================
    // Node operations
    // =========================================================================

    /**
     * Free a node handle.
     */
    fun wispers_node_free(handle: Pointer?)

    /**
     * Get the current state of the node.
     */
    fun wispers_node_state(handle: Pointer?): Int

    /**
     * Register the node with the hub using a registration token.
     */
    fun wispers_node_register_async(
        handle: Pointer?,
        token: String?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Activate the node by pairing with an endorser.
     */
    fun wispers_node_activate_async(
        handle: Pointer?,
        activationCode: String?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Logout the node (consumes handle).
     */
    fun wispers_node_logout_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Get the group's activation state and node list.
     */
    fun wispers_node_group_info_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersGroupInfoCallback?
    ): Int

    /**
     * Start a serving session.
     */
    fun wispers_node_start_serving_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersStartServingCallback?
    ): Int

    /**
     * Connect to a peer node using UDP transport.
     */
    fun wispers_node_connect_udp_async(
        handle: Pointer?,
        peerNodeNumber: Int,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersUdpConnectionCallback?
    ): Int

    /**
     * Connect to a peer node using QUIC transport.
     */
    fun wispers_node_connect_quic_async(
        handle: Pointer?,
        peerNodeNumber: Int,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersQuicConnectionCallback?
    ): Int

    // =========================================================================
    // UDP Connection operations
    // =========================================================================

    /**
     * Send data over a UDP connection (sync).
     */
    fun wispers_udp_connection_send(
        handle: Pointer?,
        data: Pointer?,
        len: Long
    ): Int

    /**
     * Receive data from a UDP connection.
     */
    fun wispers_udp_connection_recv_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersDataCallback?
    ): Int

    /**
     * Close a UDP connection (consumes handle).
     */
    fun wispers_udp_connection_close(handle: Pointer?)

    /**
     * Free a UDP connection handle.
     */
    fun wispers_udp_connection_free(handle: Pointer?)

    // =========================================================================
    // QUIC Connection operations
    // =========================================================================

    /**
     * Open a new bidirectional stream on a QUIC connection.
     */
    fun wispers_quic_connection_open_stream_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersQuicStreamCallback?
    ): Int

    /**
     * Accept an incoming stream from the peer.
     */
    fun wispers_quic_connection_accept_stream_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersQuicStreamCallback?
    ): Int

    /**
     * Close a QUIC connection (consumes handle).
     */
    fun wispers_quic_connection_close_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Free a QUIC connection handle.
     */
    fun wispers_quic_connection_free(handle: Pointer?)

    /**
     * Free a QUIC stream handle.
     */
    fun wispers_quic_stream_free(handle: Pointer?)

    // =========================================================================
    // QUIC Stream operations
    // =========================================================================

    /**
     * Write data to a QUIC stream.
     */
    fun wispers_quic_stream_write_async(
        handle: Pointer?,
        data: Pointer?,
        len: Long,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Read data from a QUIC stream.
     */
    fun wispers_quic_stream_read_async(
        handle: Pointer?,
        maxLen: Long,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersDataCallback?
    ): Int

    /**
     * Close the stream for writing (send FIN).
     */
    fun wispers_quic_stream_finish_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Shutdown the stream (stop sending and receiving).
     */
    fun wispers_quic_stream_shutdown_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    // =========================================================================
    // Serving operations
    // =========================================================================

    /**
     * Generate an activation code for endorsing a new node.
     */
    fun wispers_serving_handle_generate_pairing_code_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersActivationCodeCallback?
    ): Int

    /**
     * Run the serving session event loop (consumes session).
     */
    fun wispers_serving_session_run_async(
        session: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Request the serving session to shut down.
     */
    fun wispers_serving_handle_shutdown_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersCallback?
    ): Int

    /**
     * Free a serving handle.
     */
    fun wispers_serving_handle_free(handle: Pointer?)

    /**
     * Free a serving session handle.
     */
    fun wispers_serving_session_free(session: Pointer?)

    /**
     * Free an incoming connections handle.
     */
    fun wispers_incoming_connections_free(incoming: Pointer?)

    /**
     * Accept an incoming UDP connection.
     */
    fun wispers_incoming_accept_udp_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersUdpConnectionCallback?
    ): Int

    /**
     * Accept an incoming QUIC connection.
     */
    fun wispers_incoming_accept_quic_async(
        handle: Pointer?,
        ctx: Pointer?,
        callback: NativeCallbacks.WispersQuicConnectionCallback?
    ): Int

    // =========================================================================
    // Utilities
    // =========================================================================

    /**
     * Free strings allocated by the library.
     */
    fun wispers_string_free(ptr: Pointer?)

    /**
     * Free a registration info struct and its strings.
     */
    fun wispers_registration_info_free(info: NativeTypes.WispersRegistrationInfo?)

    /**
     * Free a group info and all contained strings.
     */
    fun wispers_group_info_free(groupInfo: Pointer?)

    /**
     * Free a node list and all contained strings.
     */
    fun wispers_node_list_free(list: Pointer?)
}
