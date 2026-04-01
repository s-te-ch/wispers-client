import Foundation
import CWispersConnect

/// Wraps a `WispersUdpConnectionHandle`. Thread-safe.
public final class UdpConnection: WispersHandle, @unchecked Sendable {
    override init(_ pointer: OpaquePointer) {
        super.init(pointer)
    }

    /// Send data over the UDP connection (synchronous, non-blocking).
    public func send(_ data: Data) throws {
        let ptr = try requireOpen()
        let status: WispersStatus = data.withUnsafeBytes { buffer in
            let basePtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return wispers_udp_connection_send(ptr, basePtr, buffer.count)
        }
        try WispersError.check(status)
    }

    /// Receive data from the UDP connection.
    public func recv() async throws -> Data {
        let ptr = try requireOpen()
        return try await withCheckedThrowingContinuation { continuation in
            let ctx = CallbackBridge.register(continuation)
            let status = wispers_udp_connection_recv_async(ptr, ctx, wispersDataCallback)
            if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
                CallbackBridge.cancel(ctx)
                continuation.resume(throwing: WispersError.fromStatus(status))
            }
        }
    }

    override func doClose(_ pointer: OpaquePointer) {
        wispers_udp_connection_close(pointer)
    }
}
