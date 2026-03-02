package dev.wispers.connect.handles

import com.sun.jna.Pointer
import dev.wispers.connect.internal.CallbackBridge
import dev.wispers.connect.internal.Callbacks
import dev.wispers.connect.internal.NativeLibrary
import dev.wispers.connect.internal.NativeTypes
import dev.wispers.connect.types.NodeState
import dev.wispers.connect.types.RegistrationInfo
import dev.wispers.connect.types.WispersException
import dev.wispers.connect.types.WispersStatus
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Node storage.
 *
 * Storage manages the persistent state of a node (root key, registration).
 * Use [restoreOrInit] to get a [Node] for performing operations.
 *
 * The storage remains valid after creating a node - you can call [restoreOrInit]
 * multiple times if needed.
 */
class Storage internal constructor(
    pointer: Pointer,
    private val lib: NativeLibrary = NativeLibrary.INSTANCE,
    // Hold a strong reference to prevent GC from collecting the JNA callback
    // structure while native code still holds pointers to the callbacks.
    @Suppress("unused")
    private val callbackRef: Any? = null
) : Handle(pointer) {

    /**
     * Read registration info from local storage without contacting the hub.
     *
     * @return Registration info if the node is registered, null if not registered
     * @throws WispersException on storage errors
     */
    fun readRegistration(): RegistrationInfo? {
        val ptr = requireOpen()
        val info = NativeTypes.WispersRegistrationInfo()

        val status = lib.wispers_storage_read_registration(ptr, info)

        return when (status) {
            WispersStatus.SUCCESS.code -> {
                val result = RegistrationInfo(
                    connectivityGroupId = info.connectivityGroupId?.getString(0, "UTF-8") ?: "",
                    nodeNumber = info.nodeNumber,
                    attestationJwt = info.attestationJwt?.getString(0, "UTF-8") ?: ""
                )
                lib.wispers_registration_info_free(info)
                result
            }
            WispersStatus.NOT_FOUND.code -> null
            else -> throw WispersException.fromStatus(status)
        }
    }

    /**
     * Override the hub address for testing purposes.
     *
     * @param hubAddr The hub address to use (e.g., "localhost:8080")
     * @throws WispersException on error
     */
    fun overrideHubAddr(hubAddr: String) {
        val ptr = requireOpen()
        val status = lib.wispers_storage_override_hub_addr(ptr, hubAddr)
        if (status != WispersStatus.SUCCESS.code) {
            throw WispersException.fromStatus(status)
        }
    }

    /**
     * Restore existing node state or initialize a new node.
     *
     * Returns a [Node] and the current [NodeState]. The state indicates
     * what operations are available:
     *
     * - [NodeState.Pending]: Call [Node.register] with a registration token
     * - [NodeState.Registered]: Call [Node.activate] with a pairing code
     * - [NodeState.Activated]: Ready for P2P connections
     *
     * @return Pair of node and current state
     * @throws WispersException on error
     */
    suspend fun restoreOrInit(): Pair<Node, NodeState> {
        val result = suspendCancellableCoroutine<Any?> { cont ->
            val ptr = requireOpen()
            val ctx = CallbackBridge.register(cont)

            val status = lib.wispers_storage_restore_or_init_async(ptr, ctx, Callbacks.init)
            if (status != WispersStatus.SUCCESS.code) {
                CallbackBridge.resumeException(ctx, WispersException.fromStatus(status))
            }
        }

        @Suppress("UNCHECKED_CAST")
        val pair = result as Pair<Pointer?, Int>
        val nodePtr = pair.first ?: throw WispersException.NullPointer("Node pointer is null")
        return Node(nodePtr, lib) to NodeState.fromCode(pair.second)
    }

    override fun doClose(pointer: Pointer) {
        lib.wispers_storage_free(pointer)
    }
}
