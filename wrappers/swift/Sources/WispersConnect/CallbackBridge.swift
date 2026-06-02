import Foundation
import CWispersConnect

// MARK: - Type-erased continuation for error path

private protocol AnyThrowingContinuation {
    func resumeWithError(_ error: any Error)
}

extension CheckedContinuation: AnyThrowingContinuation where E == any Error {
    func resumeWithError(_ error: any Error) {
        self.resume(throwing: error)
    }
}

// MARK: - Callback bridge

/// Thread-safe bridge between C FFI callbacks and Swift async/await.
///
/// Each async operation registers a `CheckedContinuation` in a global
/// dictionary keyed by a monotonic ID. The ID is passed to C as `void *ctx`.
/// When the C callback fires, it extracts the ID and resumes the continuation.
enum CallbackBridge {
    private static var lock = os_unfair_lock()
    private static var nextId: UInt64 = 0
    private static var pending: [UInt64: (typed: Any, erased: AnyThrowingContinuation)] = [:]

    /// Register a continuation, returning the opaque context pointer for C.
    static func register<T>(_ continuation: CheckedContinuation<T, any Error>) -> UnsafeMutableRawPointer? {
        os_unfair_lock_lock(&lock)
        nextId += 1
        let id = nextId
        pending[id] = (typed: continuation, erased: continuation)
        os_unfair_lock_unlock(&lock)
        return UnsafeMutableRawPointer(bitPattern: UInt(id))
    }

    /// Resume a pending call with a success value.
    static func resume<T>(_ ctx: UnsafeMutableRawPointer?, returning value: T) {
        guard let entry = take(ctx) else { return }
        (entry.typed as! CheckedContinuation<T, any Error>).resume(returning: value)
    }

    /// Resume a pending call with an error.
    static func resume(_ ctx: UnsafeMutableRawPointer?, throwing error: WispersError) {
        guard let entry = take(ctx) else { return }
        entry.erased.resumeWithError(error)
    }

    /// Cancel a pending call (remove without resuming). Used when the initial
    /// C call returns an error status synchronously before the callback fires.
    static func cancel(_ ctx: UnsafeMutableRawPointer?) {
        _ = take(ctx)
    }

    private static func take(_ ctx: UnsafeMutableRawPointer?) -> (typed: Any, erased: AnyThrowingContinuation)? {
        guard let ctx = ctx else { return nil }
        let id = UInt64(UInt(bitPattern: ctx))
        os_unfair_lock_lock(&lock)
        let entry = pending.removeValue(forKey: id)
        os_unfair_lock_unlock(&lock)
        return entry
    }
}

// MARK: - Helpers

/// Extract a Swift String from an optional C string.
private func swiftString(_ ptr: UnsafePointer<CChar>?) -> String? {
    ptr.map { String(cString: $0) }
}

/// Build a WispersError from a status + detail, or nil if success.
private func errorOrNil(_ status: WispersStatus, _ detail: UnsafePointer<CChar>?) -> WispersError? {
    if status.rawValue == WISPERS_STATUS_SUCCESS.rawValue { return nil }
    return WispersError.fromStatus(status, detail: swiftString(detail))
}

// MARK: - C callback functions (@convention(c))
//
// Swift imports forward-declared C struct pointers as OpaquePointer.

/// Basic completion callback — resumes with Void.
let wispersCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?
) -> Void = { ctx, status, detail in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
    } else {
        CallbackBridge.resume(ctx, returning: () as Void)
    }
}

/// Init callback — resumes with (OpaquePointer, NodeState).
let wispersInitCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?,      // WispersNodeHandle *
    WispersNodeState
) -> Void = { ctx, status, detail, handle, state in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
    } else {
        guard let handle = handle else {
            CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("Node handle is null"))
            return
        }
        let nodeState = NodeState(cValue: state)
        CallbackBridge.resume(ctx, returning: (handle, nodeState))
    }
}

/// Group info callback — copies data via accessors, frees the C handle, resumes with GroupInfo.
let wispersGroupInfoCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?   // WispersGroupInfo *
) -> Void = { ctx, status, detail, infoPtr in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let infoPtr = infoPtr else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("GroupInfo is null"))
        return
    }
    let id = swiftString(wispers_group_info_id(infoPtr)) ?? ""
    let name = swiftString(wispers_group_info_name(infoPtr))
    let createdAtMillis = wispers_group_info_created_at_millis(infoPtr)
    let state = GroupState(cValue: wispers_group_info_state(infoPtr))
    var nodes: [NodeInfo] = []
    let count = wispers_group_info_nodes_count(infoPtr)
    for i in 0..<count {
        if let nodePtr = wispers_group_info_node_at(infoPtr, i) {
            nodes.append(NodeInfo(cNode: nodePtr))
        }
    }
    wispers_group_info_free(infoPtr)
    CallbackBridge.resume(ctx, returning: GroupInfo(
        id: id, name: name, createdAtMillis: createdAtMillis, state: state, nodes: nodes
    ))
}

/// Serving status callback — copies data via accessors, frees the C handle,
/// resumes with ServingStatus.
let wispersServingStatusCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?   // WispersServingStatus *
) -> Void = { ctx, status, detail, statusPtr in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let statusPtr = statusPtr else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("ServingStatus is null"))
        return
    }
    let connected = wispers_serving_status_connected(statusPtr)
    let nodeNumber = wispers_serving_status_node_number(statusPtr)
    let groupId = swiftString(wispers_serving_status_connectivity_group_id(statusPtr)) ?? ""
    let codesOutstanding = Int(wispers_serving_status_codes_outstanding(statusPtr))
    var awaiting: [Int32] = []
    let count = wispers_serving_status_nodes_awaiting_cosign_count(statusPtr)
    for i in 0..<count {
        awaiting.append(wispers_serving_status_node_awaiting_cosign_at(statusPtr, i))
    }
    wispers_serving_status_free(statusPtr)
    CallbackBridge.resume(ctx, returning: ServingStatus(
        connected: connected,
        nodeNumber: nodeNumber,
        connectivityGroupId: groupId,
        codesOutstanding: codesOutstanding,
        nodesAwaitingCosign: awaiting
    ))
}

/// Start serving callback — resumes with three opaque pointers.
struct StartServingResult {
    let servingHandle: OpaquePointer
    let session: OpaquePointer
    let incoming: OpaquePointer?
}

let wispersStartServingCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?,      // WispersServingHandle *
    OpaquePointer?,      // WispersServingSession *
    OpaquePointer?       // WispersIncomingConnections * (nullable)
) -> Void = { ctx, status, detail, serving, session, incoming in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let serving = serving, let session = session else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("Serving handles are null"))
        return
    }
    let result = StartServingResult(
        servingHandle: serving,
        session: session,
        incoming: incoming
    )
    CallbackBridge.resume(ctx, returning: result)
}

/// Activation code callback — copies string, frees C memory, resumes with String.
let wispersActivationCodeCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    UnsafeMutablePointer<CChar>?
) -> Void = { ctx, status, detail, code in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let code = code else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("Activation code is null"))
        return
    }
    let str = String(cString: code)
    wispers_string_free(code)
    CallbackBridge.resume(ctx, returning: str)
}

/// UDP connection callback.
let wispersUdpConnectionCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?       // WispersUdpConnectionHandle *
) -> Void = { ctx, status, detail, conn in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let conn = conn else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("UDP connection is null"))
        return
    }
    CallbackBridge.resume(ctx, returning: conn)
}

/// Data callback — copies bytes into Data, resumes.
let wispersDataCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    UnsafePointer<UInt8>?,
    Int
) -> Void = { ctx, status, detail, dataPtr, len in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    let data: Data
    if let dataPtr = dataPtr, len > 0 {
        data = Data(bytes: dataPtr, count: len)
    } else {
        data = Data()
    }
    CallbackBridge.resume(ctx, returning: data)
}

/// QUIC connection callback.
let wispersQuicConnectionCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?       // WispersQuicConnectionHandle *
) -> Void = { ctx, status, detail, conn in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let conn = conn else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("QUIC connection is null"))
        return
    }
    CallbackBridge.resume(ctx, returning: conn)
}

/// QUIC stream callback.
let wispersQuicStreamCallback: @convention(c) (
    UnsafeMutableRawPointer?,
    WispersStatus,
    UnsafePointer<CChar>?,
    OpaquePointer?       // WispersQuicStreamHandle *
) -> Void = { ctx, status, detail, stream in
    if let err = errorOrNil(status, detail) {
        CallbackBridge.resume(ctx, throwing: err)
        return
    }
    guard let stream = stream else {
        CallbackBridge.resume(ctx, throwing: WispersError.nullPointer("QUIC stream is null"))
        return
    }
    CallbackBridge.resume(ctx, returning: stream)
}
