import Foundation
import CWispersConnect

/// Wraps a `WispersNodeStorageHandle`.
public final class NodeStorage: @unchecked Sendable {
    private let ptr: OpaquePointer
    private var callbackRef: Unmanaged<StorageCallbackHolder>?

    private init(_ ptr: OpaquePointer, callbackRef: Unmanaged<StorageCallbackHolder>? = nil) {
        self.ptr = ptr
        self.callbackRef = callbackRef
    }

    /// Create in-memory storage (for testing).
    public static func inMemory() -> NodeStorage {
        let raw = wispers_storage_new_in_memory()!
        return NodeStorage(raw)
    }

    /// Create storage backed by host-provided callbacks (e.g. Keychain).
    public static func withCallbacks(_ callbacks: NodeStorageCallbacksProtocol) -> NodeStorage {
        let holder = StorageCallbackHolder(callbacks)
        var (nativeCb, unmanaged) = makeNativeStorageCallbacks(holder)
        let raw = wispers_storage_new_with_callbacks(&nativeCb)!
        return NodeStorage(raw, callbackRef: unmanaged)
    }

    /// Override the hub address (for testing/staging).
    public func overrideHubAddr(_ addr: String) throws {
        let status = addr.withCString { cAddr in
            wispers_storage_override_hub_addr(ptr, cAddr)
        }
        try WispersError.check(status)
    }

    /// Read registration from local storage (synchronous, no hub contact).
    /// Returns nil if the node is not registered.
    public func readRegistration() throws -> RegistrationInfo? {
        var cInfo = WispersRegistrationInfo()
        let status = wispers_storage_read_registration(ptr, &cInfo)
        if status.rawValue == WISPERS_STATUS_NOT_FOUND.rawValue {
            return nil
        }
        try WispersError.check(status)
        defer { wispers_registration_info_free(&cInfo) }
        return RegistrationInfo(
            connectivityGroupId: String(cString: cInfo.connectivity_group_id),
            nodeNumber: cInfo.node_number,
            authToken: String(cString: cInfo.auth_token),
            attestationJwt: String(cString: cInfo.attestation_jwt)
        )
    }

    /// Delete all persisted state (for logout when the node can't be restored).
    public func deleteState() throws {
        let status = wispers_storage_delete_state(ptr)
        try WispersError.check(status)
    }

    /// Restore or initialize node state. Returns a Node and its current state.
    public func restoreOrInit() async throws -> (Node, NodeState) {
        let result: (OpaquePointer, NodeState) = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_storage_restore_or_init_async(ptr, ctx, wispersInitCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return (Node(result.0), result.1)
    }

    /// Free the storage handle.
    public func close() {
        wispers_storage_free(ptr)
        callbackRef?.release()
        callbackRef = nil
    }

    deinit {
        close()
    }
}
