import Foundation

/// Base class for opaque C handle wrappers with lifecycle management.
///
/// Subclasses must override `doClose(_:)` to call the appropriate
/// `wispers_*_free` function. Handles are automatically freed on deinit.
public class WispersHandle {
    private var pointer: OpaquePointer?
    private var _closed = false
    private var lock = os_unfair_lock()

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
    }

    /// Returns the raw pointer, throwing if the handle has been closed.
    func requireOpen() throws -> OpaquePointer {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        guard !_closed, let ptr = pointer else {
            throw WispersError.invalidState("Handle has been closed or consumed")
        }
        return ptr
    }

    /// Returns the raw pointer and marks the handle as closed. Used for
    /// C calls that consume ownership (e.g. logout, runEventLoop).
    func consume() throws -> OpaquePointer {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        guard !_closed, let ptr = pointer else {
            throw WispersError.invalidState("Handle already closed or consumed")
        }
        _closed = true
        pointer = nil
        return ptr
    }

    func close() {
        os_unfair_lock_lock(&lock)
        guard !_closed, let ptr = pointer else {
            os_unfair_lock_unlock(&lock)
            return
        }
        _closed = true
        pointer = nil
        os_unfair_lock_unlock(&lock)
        doClose(ptr)
    }

    /// Override in subclasses to call the appropriate `wispers_*_free` function.
    func doClose(_ pointer: OpaquePointer) {
        fatalError("Subclasses must override doClose")
    }

    deinit {
        close()
    }
}
