package dev.wispers.connect.types

/**
 * Activation status of a node in the connectivity group.
 *
 * This reflects whether a node appears in the roster, which is separate from
 * the node lifecycle state (Pending/Registered/Activated).
 */
enum class ActivationStatus(val code: Int) {
    /** Caller is not activated, can't see roster details. */
    UNKNOWN(0),

    /** Node is registered but not in roster (not activated). */
    NOT_ACTIVATED(1),

    /** Node is in roster and not revoked. */
    ACTIVATED(2);

    companion object {
        private val codeMap = entries.associateBy { it.code }

        fun fromCode(code: Int): ActivationStatus =
            codeMap[code] ?: UNKNOWN
    }
}

/**
 * Information about a node in the connectivity group.
 */
data class NodeInfo(
    /** The node's unique number within the connectivity group. */
    val nodeNumber: Int,

    /** Human-readable name of the node. */
    val name: String,

    /** Whether this node is the current node (self). */
    val isSelf: Boolean,

    /** Activation status of this node. */
    val activationStatus: ActivationStatus,

    /** Last time the node was seen (milliseconds since epoch), or null if unknown. */
    val lastSeenAtMillis: Long?
)
