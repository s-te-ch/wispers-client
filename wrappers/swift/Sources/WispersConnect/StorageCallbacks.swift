import Foundation
import CWispersConnect

/// Protocol for host-provided persistent storage (e.g. Keychain on iOS).
public protocol NodeStorageCallbacksProtocol: AnyObject {
    /// Load the 32-byte root key, or return nil if not stored.
    func loadRootKey() throws -> Data?
    /// Persist the root key.
    func saveRootKey(_ key: Data) throws
    /// Delete the root key.
    func deleteRootKey() throws
    /// Load the registration blob, or return nil if not stored.
    func loadRegistration() throws -> Data?
    /// Persist the registration blob.
    func saveRegistration(_ data: Data) throws
    /// Delete the registration blob.
    func deleteRegistration() throws
}

/// Prevents ARC from collecting the Swift object while C holds a pointer to it.
internal class StorageCallbackHolder {
    let callbacks: NodeStorageCallbacksProtocol
    init(_ callbacks: NodeStorageCallbacksProtocol) {
        self.callbacks = callbacks
    }
}

// MARK: - C trampoline functions

internal func makeNativeStorageCallbacks(_ holder: StorageCallbackHolder) -> (WispersNodeStorageCallbacks, Unmanaged<StorageCallbackHolder>) {
    let unmanaged = Unmanaged.passRetained(holder)
    let ctx = unmanaged.toOpaque()

    var cb = WispersNodeStorageCallbacks()
    cb.ctx = UnsafeMutableRawPointer(ctx)
    cb.load_root_key = storageLoadRootKey
    cb.save_root_key = storageSaveRootKey
    cb.delete_root_key = storageDeleteRootKey
    cb.load_registration = storageLoadRegistration
    cb.save_registration = storageSaveRegistration
    cb.delete_registration = storageDeleteRegistration
    return (cb, unmanaged)
}

private func holder(from ctx: UnsafeMutableRawPointer?) -> StorageCallbackHolder? {
    guard let ctx = ctx else { return nil }
    return Unmanaged<StorageCallbackHolder>.fromOpaque(ctx).takeUnretainedValue()
}

private let storageLoadRootKey: @convention(c) (
    UnsafeMutableRawPointer?,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> WispersStatus = { ctx, outKey, outKeyLen in
    guard let h = holder(from: ctx) else { return WISPERS_STATUS_NULL_POINTER }
    do {
        guard let key = try h.callbacks.loadRootKey() else {
            return WISPERS_STATUS_NOT_FOUND
        }
        guard key.count <= outKeyLen else { return WISPERS_STATUS_BUFFER_TOO_SMALL }
        key.withUnsafeBytes { src in
            outKey?.update(from: src.bindMemory(to: UInt8.self).baseAddress!, count: key.count)
        }
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}

private let storageSaveRootKey: @convention(c) (
    UnsafeMutableRawPointer?,
    UnsafePointer<UInt8>?,
    Int
) -> WispersStatus = { ctx, key, keyLen in
    guard let h = holder(from: ctx), let key = key else { return WISPERS_STATUS_NULL_POINTER }
    do {
        let data = Data(bytes: key, count: keyLen)
        try h.callbacks.saveRootKey(data)
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}

private let storageDeleteRootKey: @convention(c) (
    UnsafeMutableRawPointer?
) -> WispersStatus = { ctx in
    guard let h = holder(from: ctx) else { return WISPERS_STATUS_NULL_POINTER }
    do {
        try h.callbacks.deleteRootKey()
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}

private let storageLoadRegistration: @convention(c) (
    UnsafeMutableRawPointer?,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> WispersStatus = { ctx, buffer, bufferLen, outLen in
    guard let h = holder(from: ctx) else { return WISPERS_STATUS_NULL_POINTER }
    do {
        guard let data = try h.callbacks.loadRegistration() else {
            return WISPERS_STATUS_NOT_FOUND
        }
        // Always report the actual size so the caller can resize if needed.
        outLen?.pointee = data.count
        guard data.count <= bufferLen else { return WISPERS_STATUS_BUFFER_TOO_SMALL }
        data.withUnsafeBytes { src in
            buffer?.update(from: src.bindMemory(to: UInt8.self).baseAddress!, count: data.count)
        }
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}

private let storageSaveRegistration: @convention(c) (
    UnsafeMutableRawPointer?,
    UnsafePointer<UInt8>?,
    Int
) -> WispersStatus = { ctx, buffer, bufferLen in
    guard let h = holder(from: ctx), let buffer = buffer else { return WISPERS_STATUS_NULL_POINTER }
    do {
        let data = Data(bytes: buffer, count: bufferLen)
        try h.callbacks.saveRegistration(data)
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}

private let storageDeleteRegistration: @convention(c) (
    UnsafeMutableRawPointer?
) -> WispersStatus = { ctx in
    guard let h = holder(from: ctx) else { return WISPERS_STATUS_NULL_POINTER }
    do {
        try h.callbacks.deleteRegistration()
        return WISPERS_STATUS_SUCCESS
    } catch {
        return WISPERS_STATUS_STORE_ERROR
    }
}
