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

    /** Operation not valid in current state. */
    @Deprecated("Use InvalidState instead")
    class UnexpectedStage(message: String = "Unexpected stage") :
        @Suppress("DEPRECATION")
        WispersException(message, WispersStatus.UNEXPECTED_STAGE)

    /** Requested resource not found. */
    class NotFound(message: String = "Not found") :
        WispersException(message, WispersStatus.NOT_FOUND)

    /** Provided buffer is too small. */
    class BufferTooSmall(message: String = "Buffer too small") :
        WispersException(message, WispersStatus.BUFFER_TOO_SMALL)

    /** Required callback is missing. */
    class MissingCallback(message: String = "Missing callback") :
        WispersException(message, WispersStatus.MISSING_CALLBACK)

    /** Invalid pairing code format. */
    class InvalidPairingCode(message: String = "Invalid pairing code") :
        WispersException(message, WispersStatus.INVALID_PAIRING_CODE)

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

    /** Unknown error status. */
    class Unknown(status: WispersStatus, message: String = "Unknown error: $status") :
        WispersException(message, status)

    companion object {
        /**
         * Create an appropriate exception for the given status code.
         */
        fun fromStatus(code: Int): WispersException {
            val status = try {
                WispersStatus.fromCode(code)
            } catch (e: IllegalArgumentException) {
                return Unknown(WispersStatus.SUCCESS, "Unknown status code: $code")
            }
            return fromStatus(status)
        }

        /**
         * Create an appropriate exception for the given status.
         */
        @Suppress("DEPRECATION")
        fun fromStatus(status: WispersStatus): WispersException = when (status) {
            WispersStatus.SUCCESS -> throw IllegalArgumentException("Cannot create exception for SUCCESS")
            WispersStatus.NULL_POINTER -> NullPointer()
            WispersStatus.INVALID_UTF8 -> InvalidUtf8()
            WispersStatus.STORE_ERROR -> StoreError()
            WispersStatus.ALREADY_REGISTERED -> AlreadyRegistered()
            WispersStatus.NOT_REGISTERED -> NotRegistered()
            WispersStatus.UNEXPECTED_STAGE -> UnexpectedStage()
            WispersStatus.NOT_FOUND -> NotFound()
            WispersStatus.BUFFER_TOO_SMALL -> BufferTooSmall()
            WispersStatus.MISSING_CALLBACK -> MissingCallback()
            WispersStatus.INVALID_PAIRING_CODE -> InvalidPairingCode()
            WispersStatus.ACTIVATION_FAILED -> ActivationFailed()
            WispersStatus.HUB_ERROR -> HubError()
            WispersStatus.CONNECTION_FAILED -> ConnectionFailed()
            WispersStatus.TIMEOUT -> Timeout()
            WispersStatus.INVALID_STATE -> InvalidState()
        }
    }
}
