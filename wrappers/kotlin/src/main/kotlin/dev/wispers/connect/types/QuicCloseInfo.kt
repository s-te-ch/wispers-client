package dev.wispers.connect.types

/**
 * How the peer closed a QUIC connection.
 */
data class QuicCloseInfo(
    /**
     * `true` if the peer's application closed the connection, `false` if its
     * QUIC stack did; [errorCode] is then a QUIC transport error code
     * (RFC 9000 section 20.1).
     */
    val closedByApp: Boolean,

    /** The error code the peer sent (0 to 2^62-1). */
    val errorCode: Long,

    /** The reason phrase the peer sent. */
    val reason: String
)
