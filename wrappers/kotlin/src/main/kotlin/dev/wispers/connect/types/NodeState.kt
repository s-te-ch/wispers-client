package dev.wispers.connect.types

/**
 * Represents the lifecycle state of a wispers node.
 *
 * Nodes progress through states: Pending -> Registered -> Activated
 */
sealed class NodeState {
    /** Node needs to register with the hub using a registration token. */
    data object Pending : NodeState()

    /** Node is registered but not yet activated (needs pairing with endorser). */
    data object Registered : NodeState()

    /** Node is fully activated and ready for P2P connections. */
    data object Activated : NodeState()

    companion object {
        private const val CODE_PENDING = 0
        private const val CODE_REGISTERED = 1
        private const val CODE_ACTIVATED = 2

        fun fromCode(code: Int): NodeState = when (code) {
            CODE_PENDING -> Pending
            CODE_REGISTERED -> Registered
            CODE_ACTIVATED -> Activated
            else -> throw IllegalArgumentException("Unknown node state code: $code")
        }
    }
}
