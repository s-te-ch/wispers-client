import Foundation
import CWispersConnect

/// Wraps a `WispersNodeHandle`. Thread-safe.
public final class Node: WispersHandle, @unchecked Sendable {
    override init(_ pointer: OpaquePointer) {
        super.init(pointer)
    }

    /// The current state of the node.
    public var state: NodeState {
        guard let ptr = try? requireOpen() else { return .pending }
        let s = wispers_node_state(ptr)
        return NodeState(cValue: s)
    }

    /// Register the node with the hub using a one-time registration token.
    /// Requires: Pending state.
    public func register(token: String) async throws {
        let ptr = try requireOpen()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = token.withCString { cToken in
                wispers_node_register_async(ptr, cToken, ctx, wispersCallback)
            }
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Activate the node using an activation code from an endorser.
    /// Code format: "node_number-secret" (e.g. "1-abc123xyz0").
    /// Requires: Registered state.
    public func activate(activationCode: String) async throws {
        let ptr = try requireOpen()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = activationCode.withCString { cCode in
                wispers_node_activate_async(ptr, cCode, ctx, wispersCallback)
            }
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Logout the node. Consumes the handle.
    public func logout() async throws {
        let ptr = try consume()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_node_logout_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Get the group's activation state and node list.
    /// Requires: Registered or Activated state.
    public func groupInfo() async throws -> GroupInfo {
        let ptr = try requireOpen()
        return try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_node_group_info_async(ptr, ctx, wispersGroupInfoCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Start a serving session.
    /// Requires: Registered or Activated state.
    public func startServing() async throws -> ServingSession {
        let ptr = try requireOpen()
        let result: StartServingResult = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_node_start_serving_async(ptr, ctx, wispersStartServingCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return ServingSession(
            servingHandle: result.servingHandle,
            session: result.session,
            incoming: result.incoming
        )
    }

    /// Connect to a peer node using UDP transport.
    /// Requires: Activated state.
    public func connectUdp(peerNodeNumber: Int32) async throws -> UdpConnection {
        let ptr = try requireOpen()
        let connPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_node_connect_udp_async(
                ptr, peerNodeNumber, ctx, wispersUdpConnectionCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return UdpConnection(connPtr)
    }

    /// Connect to a peer node using QUIC transport.
    /// Requires: Activated state.
    public func connectQuic(peerNodeNumber: Int32) async throws -> QuicConnection {
        let ptr = try requireOpen()
        let connPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_node_connect_quic_async(
                ptr, peerNodeNumber, ctx, wispersQuicConnectionCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return QuicConnection(connPtr)
    }

    override func doClose(_ pointer: OpaquePointer) {
        wispers_node_free(pointer)
    }
}
