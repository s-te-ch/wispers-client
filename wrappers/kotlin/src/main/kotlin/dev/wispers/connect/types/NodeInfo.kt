package dev.wispers.connect.types

/**
 * Information about a node in the connectivity group.
 */
data class NodeInfo(
    /** The node's unique number within the connectivity group. */
    val nodeNumber: Int,

    /** Human-readable name of the node. */
    val name: String,

    /** Opaque metadata string (e.g. JSON like `{"platform":"android"}`). */
    val metadata: String,

    /** Whether this node is the current node (self). */
    val isSelf: Boolean,

    /**
     * This node's lifecycle state observed from the local node — the same
     * [NodeState] you'd get from the node directly. `Pending` never appears for a
     * listed node.
     */
    val state: NodeState,

    /** Last time the node was seen (milliseconds since epoch), or null if unknown. */
    val lastSeenAtMillis: Long?,

    /** Whether the node currently has an active connection to the hub. */
    val isOnline: Boolean
)
