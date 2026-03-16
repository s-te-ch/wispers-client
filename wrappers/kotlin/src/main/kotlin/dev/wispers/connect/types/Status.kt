package dev.wispers.connect.types

/**
 * Status codes returned by wispers-connect FFI functions.
 * Mirrors the C enum WispersStatus.
 */
enum class WispersStatus(val code: Int) {
    SUCCESS(0),
    NULL_POINTER(1),
    INVALID_UTF8(2),
    STORE_ERROR(3),
    ALREADY_REGISTERED(4),
    NOT_REGISTERED(5),
    NOT_FOUND(6),
    BUFFER_TOO_SMALL(7),
    MISSING_CALLBACK(8),
    INVALID_ACTIVATION_CODE(9),
    ACTIVATION_FAILED(10),
    HUB_ERROR(11),
    CONNECTION_FAILED(12),
    TIMEOUT(13),
    INVALID_STATE(14),
    UNAUTHENTICATED(15),
    PEER_REJECTED(16),
    PEER_UNAVAILABLE(17);

    companion object {
        private val codeMap = entries.associateBy { it.code }

        fun fromCode(code: Int): WispersStatus =
            codeMap[code] ?: throw IllegalArgumentException("Unknown status code: $code")
    }
}
