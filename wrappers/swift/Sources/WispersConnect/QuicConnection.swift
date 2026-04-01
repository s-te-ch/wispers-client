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

    override func doClose(_ pointer: OpaquePointer) {
        wispers_quic_connection_free(pointer)
    }
}
