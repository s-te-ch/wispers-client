package dev.wispers.connect.internal

import com.sun.jna.Pointer
import com.sun.jna.Structure

/**
 * JNA Structure mappings for wispers-connect C types.
 */
object NativeTypes {

    /**
     * Registration info returned by wispers_storage_read_registration.
     * Strings are owned and must be freed with wispers_string_free().
     */
    @Structure.FieldOrder("connectivityGroupId", "nodeNumber", "authToken", "attestationJwt")
    open class WispersRegistrationInfo : Structure() {
        @JvmField var connectivityGroupId: Pointer? = null
        @JvmField var nodeNumber: Int = 0
        @JvmField var authToken: Pointer? = null
        @JvmField var attestationJwt: Pointer? = null

        class ByReference : WispersRegistrationInfo(), Structure.ByReference
        class ByValue : WispersRegistrationInfo(), Structure.ByValue
    }

    /**
     * Node info returned in node list.
     * Name string is owned and freed by wispers_node_list_free().
     */
    @Structure.FieldOrder("nodeNumber", "name", "isSelf", "activationStatus", "lastSeenAtMillis", "isOnline")
    open class WispersNode : Structure {
        @JvmField var nodeNumber: Int = 0
        @JvmField var name: Pointer? = null
        @JvmField var isSelf: Byte = 0      // C bool is 1 byte; JNA Boolean maps to int (4 bytes)
        @JvmField var activationStatus: Int = 0
        @JvmField var lastSeenAtMillis: Long = 0
        @JvmField var isOnline: Byte = 0    // C bool is 1 byte

        constructor() : super()
        constructor(p: Pointer) : super(p)

        class ByReference : WispersNode(), Structure.ByReference
        class ByValue : WispersNode(), Structure.ByValue
    }

    /**
     * List of nodes. Free with wispers_node_list_free().
     */
    @Structure.FieldOrder("nodes", "count")
    open class WispersNodeList : Structure {
        @JvmField var nodes: Pointer? = null
        @JvmField var count: Long = 0  // size_t

        constructor() : super()
        constructor(p: Pointer) : super(p)

        class ByReference : WispersNodeList(), Structure.ByReference
        class ByValue : WispersNodeList(), Structure.ByValue
    }

    /**
     * Host-provided storage callbacks.
     */
    @Structure.FieldOrder(
        "ctx",
        "loadRootKey",
        "saveRootKey",
        "deleteRootKey",
        "loadRegistration",
        "saveRegistration",
        "deleteRegistration"
    )
    open class WispersNodeStorageCallbacks : Structure() {
        @JvmField var ctx: Pointer? = null
        @JvmField var loadRootKey: NativeCallbacks.LoadRootKeyCallback? = null
        @JvmField var saveRootKey: NativeCallbacks.SaveRootKeyCallback? = null
        @JvmField var deleteRootKey: NativeCallbacks.DeleteRootKeyCallback? = null
        @JvmField var loadRegistration: NativeCallbacks.LoadRegistrationCallback? = null
        @JvmField var saveRegistration: NativeCallbacks.SaveRegistrationCallback? = null
        @JvmField var deleteRegistration: NativeCallbacks.DeleteRegistrationCallback? = null

        class ByReference : WispersNodeStorageCallbacks(), Structure.ByReference
        class ByValue : WispersNodeStorageCallbacks(), Structure.ByValue
    }
}
