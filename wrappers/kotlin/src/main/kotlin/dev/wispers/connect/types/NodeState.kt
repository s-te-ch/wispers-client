package dev.wispers.connect.types

/**
 * Represents the lifecycle state of a wispers node.
 *
 * Nodes progress through states: Pending -> Registered -> Activated -> Revoked.
 */
sealed class NodeState {
    /** Node needs to register with the hub using a registration token. */
    data object Pending : NodeState()

    /** Node is registered but not yet activated (needs activation). */
    data object Registered : NodeState()

    /** Node is fully activated and ready for P2P connections. */
    data object Activated : NodeState()

    /** Node has been revoked from the connectivity group's roster. */
    data object Revoked : NodeState()

    companion object {
        private const val CODE_PENDING = 0
        private const val CODE_REGISTERED = 1
        private const val CODE_ACTIVATED = 2
        private const val CODE_REVOKED = 3

        fun fromCode(code: Int): NodeState = when (code) {
            CODE_PENDING -> Pending
            CODE_REGISTERED -> Registered
            CODE_ACTIVATED -> Activated
            CODE_REVOKED -> Revoked
            else -> throw IllegalArgumentException("Unknown node state code: $code")
        }
    }
}
