package dev.wispers.connect.types

/**
 * Activation state of the connectivity group from this node's perspective.
 */
sealed class GroupState(val code: Int) {
    /** Only node in the group — nothing to activate with. */
    data object Alone : GroupState(0)

    /** No activated nodes (empty or dead roster). Any node can pair with any other. */
    data object Bootstrap : GroupState(1)

    /** Roster exists with activated peers — this node needs a code from one. */
    data object NeedActivation : GroupState(2)

    /** This node is activated; unactivated peers exist that can be endorsed. */
    data object CanEndorse : GroupState(3)

    /** All nodes in the group are activated. */
    data object AllActivated : GroupState(4)

    companion object {
        fun fromCode(code: Int): GroupState = when (code) {
            0 -> Alone
            1 -> Bootstrap
            2 -> NeedActivation
            3 -> CanEndorse
            4 -> AllActivated
            else -> Alone
        }
    }
}

/**
 * Snapshot of the connectivity group's activation state.
 */
data class GroupInfo(
    /** Connectivity group identifier. */
    val id: String,

    /** Display name, or `null` if the group has no name set. */
    val name: String?,

    /** Unix timestamp in milliseconds when the group was created. */
    val createdAtMillis: Long,

    /** Activation state of the group from this node's perspective. */
    val state: GroupState,

    /** All nodes in the connectivity group. */
    val nodes: List<NodeInfo>
)
