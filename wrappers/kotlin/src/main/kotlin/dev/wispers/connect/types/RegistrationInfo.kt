package dev.wispers.connect.types

/**
 * Registration information for a node.
 * Retrieved from local storage without contacting the hub.
 */
data class RegistrationInfo(
    /** The connectivity group ID (UUID string). */
    val connectivityGroupId: String,

    /** The node's unique number within the connectivity group. */
    val nodeNumber: Int
)
