package dev.wispers.connect.internal

import com.sun.jna.Callback
import com.sun.jna.Pointer

/**
 * JNA Callback interfaces for wispers-connect async operations.
 *
 * These are the callback function signatures expected by the C API.
 * Each callback receives a context pointer (ctx) that carries the continuation ID.
 */
object NativeCallbacks {

    // =========================================================================
    // Async operation callbacks
    // =========================================================================

    /**
     * Basic completion callback (no result value).
     *
     * C signature:
     * ```
     * void (*WispersCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail
     * );
     * ```
     */
    fun interface WispersCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?)
    }

    /**
     * Callback for restore_or_init. Returns node handle and state.
     *
     * C signature:
     * ```
     * void (*WispersInitCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersNodeHandle *handle,
     *     WispersNodeState state
     * );
     * ```
     */
    fun interface WispersInitCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, handle: Pointer?, state: Int)
    }

    /**
     * Callback that receives group info.
     *
     * C signature:
     * ```
     * void (*WispersGroupInfoCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersGroupInfo *group_info
     * );
     * ```
     */
    fun interface WispersGroupInfoCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, groupInfo: Pointer?)
    }

    /**
     * Callback for start_serving that receives session components.
     *
     * C signature:
     * ```
     * void (*WispersStartServingCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersServingHandle *serving_handle,
     *     WispersServingSession *session,
     *     WispersIncomingConnections *incoming
     * );
     * ```
     */
    fun interface WispersStartServingCallback : Callback {
        fun invoke(
            ctx: Pointer?,
            status: Int,
            errorDetail: String?,
            servingHandle: Pointer?,
            session: Pointer?,
            incoming: Pointer?
        )
    }

    /**
     * Callback that receives an activation code string.
     *
     * C signature:
     * ```
     * void (*WispersPairingCodeCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     char *pairing_code
     * );
     * ```
     */
    fun interface WispersActivationCodeCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, activationCode: Pointer?)
    }

    /**
     * Callback that receives a UDP connection handle.
     *
     * C signature:
     * ```
     * void (*WispersUdpConnectionCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersUdpConnectionHandle *connection
     * );
     * ```
     */
    fun interface WispersUdpConnectionCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, connection: Pointer?)
    }

    /**
     * Callback that receives data (UDP recv, QUIC read).
     *
     * C signature:
     * ```
     * void (*WispersDataCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     const uint8_t *data,
     *     size_t len
     * );
     * ```
     */
    fun interface WispersDataCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, data: Pointer?, len: Long)
    }

    /**
     * Callback that receives a QUIC connection handle.
     *
     * C signature:
     * ```
     * void (*WispersQuicConnectionCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersQuicConnectionHandle *connection
     * );
     * ```
     */
    fun interface WispersQuicConnectionCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, connection: Pointer?)
    }

    /**
     * Callback that receives a QUIC stream handle.
     *
     * C signature:
     * ```
     * void (*WispersQuicStreamCallback)(
     *     void *ctx,
     *     WispersStatus status,
     *     const char *error_detail,
     *     WispersQuicStreamHandle *stream
     * );
     * ```
     */
    fun interface WispersQuicStreamCallback : Callback {
        fun invoke(ctx: Pointer?, status: Int, errorDetail: String?, stream: Pointer?)
    }

    // =========================================================================
    // Storage callbacks (host-provided)
    // =========================================================================

    /**
     * Load root key callback.
     *
     * C signature:
     * ```
     * WispersStatus (*load_root_key)(
     *     void *ctx,
     *     uint8_t *out_key,
     *     size_t out_key_len
     * );
     * ```
     */
    fun interface LoadRootKeyCallback : Callback {
        fun invoke(ctx: Pointer?, outKey: Pointer?, outKeyLen: Long): Int
    }

    /**
     * Save root key callback.
     *
     * C signature:
     * ```
     * WispersStatus (*save_root_key)(
     *     void *ctx,
     *     const uint8_t *key,
     *     size_t key_len
     * );
     * ```
     */
    fun interface SaveRootKeyCallback : Callback {
        fun invoke(ctx: Pointer?, key: Pointer?, keyLen: Long): Int
    }

    /**
     * Delete root key callback.
     *
     * C signature:
     * ```
     * WispersStatus (*delete_root_key)(
     *     void *ctx
     * );
     * ```
     */
    fun interface DeleteRootKeyCallback : Callback {
        fun invoke(ctx: Pointer?): Int
    }

    /**
     * Load registration callback.
     *
     * C signature:
     * ```
     * WispersStatus (*load_registration)(
     *     void *ctx,
     *     uint8_t *buffer,
     *     size_t buffer_len,
     *     size_t *out_len
     * );
     * ```
     */
    fun interface LoadRegistrationCallback : Callback {
        fun invoke(ctx: Pointer?, buffer: Pointer?, bufferLen: Long, outLen: Pointer?): Int
    }

    /**
     * Save registration callback.
     *
     * C signature:
     * ```
     * WispersStatus (*save_registration)(
     *     void *ctx,
     *     const uint8_t *buffer,
     *     size_t buffer_len
     * );
     * ```
     */
    fun interface SaveRegistrationCallback : Callback {
        fun invoke(ctx: Pointer?, buffer: Pointer?, bufferLen: Long): Int
    }

    /**
     * Delete registration callback.
     *
     * C signature:
     * ```
     * WispersStatus (*delete_registration)(
     *     void *ctx
     * );
     * ```
     */
    fun interface DeleteRegistrationCallback : Callback {
        fun invoke(ctx: Pointer?): Int
    }
}
