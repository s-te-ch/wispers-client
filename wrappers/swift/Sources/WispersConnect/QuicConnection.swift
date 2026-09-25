import Foundation
import CWispersConnect

/// Wraps a `WispersQuicConnectionHandle`. Thread-safe.
public final class QuicConnection: WispersHandle, @unchecked Sendable {
    override init(_ pointer: OpaquePointer) {
        super.init(pointer)
    }

    /// Open a new bidirectional stream on this connection.
    public func openStream() async throws -> QuicStream {
        let ptr = try requireOpen()
        let streamPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_connection_open_stream_async(
                ptr, ctx, wispersQuicStreamCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return QuicStream(streamPtr)
    }

    /// Accept an incoming stream from the peer.
    public func acceptStream() async throws -> QuicStream {
        let ptr = try requireOpen()
        let streamPtr: OpaquePointer = try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_connection_accept_stream_async(
                ptr, ctx, wispersQuicStreamCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
        return QuicStream(streamPtr)
    }

    /// Check that the peer is still reachable.
    ///
    /// Sends a QUIC PING and waits for the peer's transport to acknowledge it.
    /// Throws `WispersError.timeout` if no acknowledgement arrives within
    /// `timeout` seconds (a few seconds is reasonable), and
    /// `WispersError.connectionFailed` if the connection is closed or closing.
    public func ping(timeout: TimeInterval) async throws {
        let ptr = try requireOpen()
        let timeoutMs: UInt32 =
            timeout > 0 ? UInt32(min(max(timeout * 1000, 1), Double(UInt32.max))) : 0
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_connection_ping_async(ptr, timeoutMs, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Gracefully close the QUIC connection. Consumes the handle.
    public func closeGracefully() async throws {
        let ptr = try consume()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_connection_close_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Gracefully close the QUIC connection, with error code and reason.
    /// Consumes the handle.
    ///
    /// `errorCode` and `reason` are application-defined; the peer reads them
    /// with `peerCloseInfo()`. `errorCode` must be at most 2^62-1 (QUIC's
    /// limit); `reason` is truncated to 1024 bytes.
    public func closeGracefully(errorCode: UInt64, reason: String) async throws {
        let ptr = try consume()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            // The C side copies the reason before returning.
            let status = reason.withCString { cReason in
                wispers_quic_connection_close_with_error_async(
                    ptr, errorCode, cReason, ctx, wispersCallback)
            }
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                // The async op never started, so the handle wasn't consumed.
                wispers_quic_connection_free(ptr)
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// How the peer closed the connection, or `nil` if it hasn't.
    ///
    /// Set as soon as the peer's close arrives; stream operations then fail
    /// with `WispersError.connectionFailed`.
    public func peerCloseInfo() throws -> QuicCloseInfo? {
        let ptr = try requireOpen()
        guard let info = wispers_quic_connection_peer_close_info(ptr) else {
            return nil
        }
        defer { wispers_quic_close_info_free(info) }
        return QuicCloseInfo(
            closedByApp: wispers_quic_close_info_closed_by_app(info),
            errorCode: wispers_quic_close_info_error_code(info),
            reason: wispers_quic_close_info_reason(info).map { String(cString: $0) } ?? ""
        )
    }

    override func doClose(_ pointer: OpaquePointer) {
        wispers_quic_connection_free(pointer)
    }
}
