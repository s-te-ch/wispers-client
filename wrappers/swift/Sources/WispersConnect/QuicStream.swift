import Foundation
import CWispersConnect

/// Wraps a `WispersQuicStreamHandle`. Thread-safe.
public final class QuicStream: WispersHandle, @unchecked Sendable {
    override init(_ pointer: OpaquePointer) {
        super.init(pointer)
    }

    /// Write data to the stream.
    public func write(_ data: Data) async throws {
        let ptr = try requireOpen()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status: WispersStatus = data.withUnsafeBytes { buffer in
                let basePtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return wispers_quic_stream_write_async(
                    ptr, basePtr, buffer.count, ctx, wispersCallback)
            }
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Read up to `maxLen` bytes from the stream.
    public func read(maxLen: Int) async throws -> Data {
        let ptr = try requireOpen()
        return try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_stream_read_async(ptr, maxLen, ctx, wispersDataCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Close the stream for writing (send FIN). The stream can still be
    /// read from after calling finish.
    public func finish() async throws {
        let ptr = try requireOpen()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_stream_finish_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    /// Shutdown the stream (stop sending and receiving).
    public func shutdown() async throws {
        let ptr = try requireOpen()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_quic_stream_shutdown_async(ptr, ctx, wispersCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    override func doClose(_ pointer: OpaquePointer) {
        wispers_quic_stream_free(pointer)
    }
}
