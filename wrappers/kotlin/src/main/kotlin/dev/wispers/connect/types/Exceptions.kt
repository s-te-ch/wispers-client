package dev.wispers.connect.types

/**
 * Base exception for all wispers-connect errors.
 * Sealed hierarchy enables exhaustive when-matching.
 */
sealed class WispersException(
    message: String,
    val status: WispersStatus,
    cause: Throwable? = null
) : Exception(message, cause) {

    /** Null pointer passed to FFI function. */
    class NullPointer(message: String = "Null pointer") :
        WispersException(message, WispersStatus.NULL_POINTER)

    /** Invalid UTF-8 string encoding. */
    class InvalidUtf8(message: String = "Invalid UTF-8 string") :
        WispersException(message, WispersStatus.INVALID_UTF8)

    /** Storage operation failed. */
    class StoreError(message: String = "Storage error") :
        WispersException(message, WispersStatus.STORE_ERROR)

    /** Node is already registered. */
    class AlreadyRegistered(message: String = "Node is already registered") :
        WispersException(message, WispersStatus.ALREADY_REGISTERED)

    /** Node is not registered. */
    class NotRegistered(message: String = "Node is not registered") :
        WispersException(message, WispersStatus.NOT_REGISTERED)

    /** Requested resource not found. */
    class NotFound(message: String = "Not found") :
        WispersException(message, WispersStatus.NOT_FOUND)

    /** Provided buffer is too small. */
    class BufferTooSmall(message: String = "Buffer too small") :
        WispersException(message, WispersStatus.BUFFER_TOO_SMALL)

    /** Required callback is missing. */
    class MissingCallback(message: String = "Missing callback") :
        WispersException(message, WispersStatus.MISSING_CALLBACK)

    /** Invalid activation code format. */
    class InvalidActivationCode(message: String = "Invalid activation code") :
        WispersException(message, WispersStatus.INVALID_ACTIVATION_CODE)

    /** Activation with endorser failed. */
    class ActivationFailed(message: String = "Activation failed") :
        WispersException(message, WispersStatus.ACTIVATION_FAILED)

    /** Hub communication error. */
    class HubError(message: String = "Hub error") :
        WispersException(message, WispersStatus.HUB_ERROR)

    /** P2P connection failed. */
    class ConnectionFailed(message: String = "Connection failed") :
        WispersException(message, WispersStatus.CONNECTION_FAILED)

    /** Operation timed out. */
    class Timeout(message: String = "Timeout") :
        WispersException(message, WispersStatus.TIMEOUT)

    /** Operation not valid in current node state. */
    class InvalidState(message: String = "Invalid state for operation") :
        WispersException(message, WispersStatus.INVALID_STATE)

    /** Node removed from connectivity group. */
    class Unauthenticated(message: String = "Node removed from connectivity group") :
        WispersException(message, WispersStatus.UNAUTHENTICATED)

    /** Peer explicitly rejected the request. */
    class PeerRejected(message: String = "Peer rejected request") :
        WispersException(message, WispersStatus.PEER_REJECTED)

    /** Peer node is offline or unreachable. */
    class PeerUnavailable(message: String = "Peer unavailable") :
        WispersException(message, WispersStatus.PEER_UNAVAILABLE)

    /** Unknown error status. */
    class Unknown(status: WispersStatus, message: String = "Unknown error: $status") :
        WispersException(message, status)

    companion object {
        /**
         * Create an appropriate exception for the given status code.
         *
         * @param detail Optional human-readable detail from the Rust library.
         */
        fun fromStatus(code: Int, detail: String? = null): WispersException {
            val status = try {
                WispersStatus.fromCode(code)
            } catch (e: IllegalArgumentException) {
                return Unknown(WispersStatus.SUCCESS, detail ?: "Unknown status code: $code")
            }
            return fromStatus(status, detail)
        }

        /**
         * Create an appropriate exception for the given status.
         *
         * @param detail Optional human-readable detail from the Rust library.
         *               When provided, used as the exception message instead of the default.
         */
        fun fromStatus(status: WispersStatus, detail: String? = null): WispersException = when (status) {
            WispersStatus.SUCCESS -> throw IllegalArgumentException("Cannot create exception for SUCCESS")
            WispersStatus.NULL_POINTER -> NullPointer(detail ?: "Null pointer")
            WispersStatus.INVALID_UTF8 -> InvalidUtf8(detail ?: "Invalid UTF-8 string")
            WispersStatus.STORE_ERROR -> StoreError(detail ?: "Storage error")
            WispersStatus.ALREADY_REGISTERED -> AlreadyRegistered(detail ?: "Node is already registered")
            WispersStatus.NOT_REGISTERED -> NotRegistered(detail ?: "Node is not registered")
            WispersStatus.NOT_FOUND -> NotFound(detail ?: "Not found")
            WispersStatus.BUFFER_TOO_SMALL -> BufferTooSmall(detail ?: "Buffer too small")
            WispersStatus.MISSING_CALLBACK -> MissingCallback(detail ?: "Missing callback")
            WispersStatus.INVALID_ACTIVATION_CODE -> InvalidActivationCode(detail ?: "Invalid activation code")
            WispersStatus.ACTIVATION_FAILED -> ActivationFailed(detail ?: "Activation failed")
            WispersStatus.HUB_ERROR -> HubError(detail ?: "Hub error")
            WispersStatus.CONNECTION_FAILED -> ConnectionFailed(detail ?: "Connection failed")
            WispersStatus.TIMEOUT -> Timeout(detail ?: "Timeout")
            WispersStatus.INVALID_STATE -> InvalidState(detail ?: "Invalid state for operation")
            WispersStatus.UNAUTHENTICATED -> Unauthenticated(detail ?: "Node removed from connectivity group")
            WispersStatus.PEER_REJECTED -> PeerRejected(detail ?: "Peer rejected request")
            WispersStatus.PEER_UNAVAILABLE -> PeerUnavailable(detail ?: "Peer unavailable")
        }
    }
}
