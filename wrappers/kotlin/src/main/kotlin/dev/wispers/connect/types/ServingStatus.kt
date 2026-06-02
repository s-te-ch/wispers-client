package dev.wispers.connect.types

/**
 * Snapshot of a serving session's hub connection and endorsing state.
 */
data class ServingStatus(
    /**
     * Whether the session currently holds a live hub stream. `false` while it
     * is reconnecting after a hub disconnect.
     */
    val connected: Boolean,

    /** This node's number within the connectivity group. */
    val nodeNumber: Int,

    /** Connectivity group identifier. */
    val connectivityGroupId: String,

    /** Number of activation codes awaiting use. */
    val codesOutstanding: Int,

    /** Node numbers that have paired and await cosign. */
    val nodesAwaitingCosign: List<Int>
)
