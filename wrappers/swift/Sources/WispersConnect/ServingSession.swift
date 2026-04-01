import Foundation
import CWispersConnect

/// Wraps the three handles returned by `startServing`:
/// `WispersServingHandle`, `WispersServingSession`, and optionally
/// `WispersIncomingConnections` (nil for registered-but-not-activated nodes).
public final class ServingSession: @unchecked Sendable {
    private var servingPtr: OpaquePointer?
    private var sessionPtr: OpaquePointer?
    private var incomingPtr: OpaquePointer?
    private var lock = NSLock()

    /// Whether this session can accept incoming P2P connections
    /// (true only for activated nodes).
    public var canAcceptConnections: Bool {
        lock.withLock { incomingPtr != nil }
    }

    init(servingHandle: OpaquePointer, session: OpaquePointer, incoming: OpaquePointer?) {
        self.servingPtr = servingHandle
        self.sessionPtr = session
        self.incomingPtr = incoming
    }

    // MARK: - Synchronous pointer accessors (avoid os_unfair_lock in async)

    private func takeSession() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard let ptr = sessionPtr else {
            throw WispersError.invalidState("Session already consumed")
        }
        sessionPtr = nil
        return ptr
    }

    private func requireServing() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard let ptr = servingPtr else {
            throw WispersError.invalidState("Serving handle closed")
        }
        return ptr
    }

    private func requireIncoming() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard let ptr = incomingPtr else {
            throw WispersError.invalidState("No incoming connections (node not activated?)")
        }
        return ptr
    }

    // MARK: - Public API

    /// Run the serving session event loop. Blocks until shutdown or error.
    /// The session handle is consumed by this call.
    public func runEventLoop() async throws {
        let ptr = try takeSession()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_serving_session_run_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Generate an activation code for endorsing a new node.
    public func generateActivationCode() async throws -> String {
        let ptr = try requireServing()
        return try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_serving_handle_generate_activation_code_async(
                ptr, ctx, wispersActivationCodeCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Request the serving session to shut down.
    public func shutdown() async throws {
        let ptr = try requireServing()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_serving_handle_shutdown_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Accept an incoming UDP connection from a peer.
    /// Requires: Activated state (canAcceptConnections == true).
    public func acceptUdp() async throws -> UdpConnection {
        let ptr = try requireIncoming()
        let connPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_incoming_accept_udp_async(ptr, ctx, wispersUdpConnectionCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return UdpConnection(connPtr)
    }

    /// Accept an incoming QUIC connection from a peer.
    /// Requires: Activated state (canAcceptConnections == true).
    public func acceptQuic() async throws -> QuicConnection {
        let ptr = try requireIncoming()
        let connPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_incoming_accept_quic_async(ptr, ctx, wispersQuicConnectionCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return QuicConnection(connPtr)
    }

    public func close() {
        lock.lock()
        let s = servingPtr
        let sess = sessionPtr
        let inc = incomingPtr
        servingPtr = nil
        sessionPtr = nil
        incomingPtr = nil
        lock.unlock()

        if let s = s { wispers_serving_handle_free(s) }
        if let sess = sess { wispers_serving_session_free(sess) }
        if let inc = inc { wispers_incoming_connections_free(inc) }
    }

    deinit {
        close()
    }
}
