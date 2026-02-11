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
    @Deprecated("Use INVALID_STATE instead", ReplaceWith("INVALID_STATE"))
    UNEXPECTED_STAGE(6),
    NOT_FOUND(7),
    BUFFER_TOO_SMALL(8),
    MISSING_CALLBACK(9),
    INVALID_PAIRING_CODE(10),
    ACTIVATION_FAILED(11),
    HUB_ERROR(12),
    CONNECTION_FAILED(13),
    TIMEOUT(14),
    INVALID_STATE(15);

    companion object {
        private val codeMap = entries.associateBy { it.code }

        fun fromCode(code: Int): WispersStatus =
            codeMap[code] ?: throw IllegalArgumentException("Unknown status code: $code")
    }
}
