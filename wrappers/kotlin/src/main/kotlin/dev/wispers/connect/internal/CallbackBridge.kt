package dev.wispers.connect.internal

import com.sun.jna.Pointer
import dev.wispers.connect.types.WispersException
import dev.wispers.connect.types.WispersStatus
import kotlinx.coroutines.CancellableContinuation
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Bridge between C callbacks and Kotlin coroutines.
 *
 * This object manages the mapping between async C operations and Kotlin
 * suspend functions. When starting an async operation:
 *
 * 1. Register a continuation with [register], receiving a context pointer
 * 2. Pass the context pointer to the C function as `void* ctx`
 * 3. When the C callback fires, it calls back with the same context pointer
 * 4. The callback singleton uses [resumeSuccess] or [resumeException] to
 *    complete the continuation
 *
 * The context pointer is actually a numeric ID encoded as a pointer value
 * using [Pointer.createConstant]. This avoids needing actual memory allocation
 * and prevents any possibility of use-after-free.
 */
object CallbackBridge {
    private val nextId = AtomicLong(0)
    private val continuations = ConcurrentHashMap<Long, CancellableContinuation<*>>()

    /**
     * Register a continuation and return a context pointer to pass to C.
     *
     * The continuation will be automatically unregistered if cancelled.
     */
    fun <T> register(continuation: CancellableContinuation<T>): Pointer {
        val id = nextId.incrementAndGet()
        continuations[id] = continuation
        continuation.invokeOnCancellation {
            continuations.remove(id)
        }
        return Pointer.createConstant(id)
    }

    /**
     * Resume a continuation with a successful result.
     *
     * @param ctx The context pointer passed to the C callback
     * @param result The result value to resume with
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> resumeSuccess(ctx: Pointer?, result: T) {
        val id = Pointer.nativeValue(ctx)
        val continuation = continuations.remove(id) as? CancellableContinuation<T>
        continuation?.resume(result)
    }

    /**
     * Resume a continuation with an exception.
     *
     * @param ctx The context pointer passed to the C callback
     * @param exception The exception to resume with
     */
    fun resumeException(ctx: Pointer?, exception: Throwable) {
        val id = Pointer.nativeValue(ctx)
        val continuation = continuations.remove(id)
        continuation?.resumeWithException(exception)
    }

    /**
     * Resume a continuation with an exception derived from a status code.
     *
     * @param ctx The context pointer passed to the C callback
     * @param status The C status code (non-zero indicates error)
     * @param errorDetail Optional human-readable detail from the Rust library
     */
    fun resumeWithStatus(ctx: Pointer?, status: Int, errorDetail: String? = null) {
        if (status == WispersStatus.SUCCESS.code) {
            resumeSuccess(ctx, Unit)
        } else {
            resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }
}

/**
 * Singleton callback instances for async operations.
 *
 * JNA holds weak references to callback objects, so they can be garbage
 * collected if not held strongly. By making these singletons, we ensure
 * they remain alive for the lifetime of the application.
 *
 * Each callback type has a single instance that routes to the appropriate
 * continuation via [CallbackBridge].
 */
object Callbacks {

    /**
     * Basic completion callback - resumes with Unit on success.
     */
    val basic = NativeCallbacks.WispersCallback { ctx, status, errorDetail ->
        CallbackBridge.resumeWithStatus(ctx, status, errorDetail)
    }

    /**
     * Init callback - resumes with (Pointer, NodeState) pair on success.
     */
    val init = NativeCallbacks.WispersInitCallback { ctx, status, errorDetail, handle, state ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, Pair(handle, state))
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * Group info callback - resumes with Pointer to group info on success.
     */
    val groupInfo = NativeCallbacks.WispersGroupInfoCallback { ctx, status, errorDetail, groupInfo ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, groupInfo)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * Start serving callback - resumes with triple of handles on success.
     */
    val startServing = NativeCallbacks.WispersStartServingCallback { ctx, status, errorDetail, servingHandle, session, incoming ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, Triple(servingHandle, session, incoming))
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * Activation code callback - resumes with Pointer to string on success.
     */
    val activationCode = NativeCallbacks.WispersActivationCodeCallback { ctx, status, errorDetail, activationCode ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, activationCode)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * UDP connection callback - resumes with Pointer to connection on success.
     */
    val udpConnection = NativeCallbacks.WispersUdpConnectionCallback { ctx, status, errorDetail, connection ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, connection)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * Data callback - resumes with ByteArray on success.
     * The data buffer from C is only valid during the callback, so we copy it.
     */
    val data = NativeCallbacks.WispersDataCallback { ctx, status, errorDetail, data, len ->
        if (status == WispersStatus.SUCCESS.code) {
            val bytes = if (data != null && len > 0) {
                data.getByteArray(0, len.toInt())
            } else {
                ByteArray(0)
            }
            CallbackBridge.resumeSuccess(ctx, bytes)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * QUIC connection callback - resumes with Pointer to connection on success.
     */
    val quicConnection = NativeCallbacks.WispersQuicConnectionCallback { ctx, status, errorDetail, connection ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, connection)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }

    /**
     * QUIC stream callback - resumes with Pointer to stream on success.
     */
    val quicStream = NativeCallbacks.WispersQuicStreamCallback { ctx, status, errorDetail, stream ->
        if (status == WispersStatus.SUCCESS.code) {
            CallbackBridge.resumeSuccess(ctx, stream)
        } else {
            CallbackBridge.resumeException(ctx, WispersException.fromStatus(status, errorDetail))
        }
    }
}
