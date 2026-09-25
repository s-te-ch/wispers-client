//! FFI bindings for P2P connections.

use super::runtime;
use super::types::{CallbackContext, WispersCallback, WispersNodeHandle, c_str_to_string};
use crate::errors::WispersStatus;
use crate::p2p::{P2pError, QuicCloseInfo, QuicConnection, QuicStream, UdpConnection};
use std::ffi::{CString, c_void};
use std::os::raw::{c_char, c_int};
use std::ptr;

fn p2p_error_to_status(e: &P2pError) -> WispersStatus {
    match e {
        P2pError::PeerRejected(_) | P2pError::SignatureVerificationFailed => {
            WispersStatus::PeerRejected
        }
        P2pError::Hub(h) if h.is_unauthenticated() => WispersStatus::Unauthenticated,
        P2pError::Hub(h) if h.is_peer_unavailable() => WispersStatus::PeerUnavailable,
        P2pError::Hub(h) if h.is_peer_rejected() => WispersStatus::PeerRejected,
        P2pError::Hub(h) if h.is_not_found() => WispersStatus::NotFound,
        P2pError::NotActivated => WispersStatus::InvalidState,
        P2pError::Timeout => WispersStatus::Timeout,
        _ => WispersStatus::ConnectionFailed,
    }
}

// Helpers to send raw pointers across threads

struct SendableUdpConnPtr(*mut WispersUdpConnectionHandle);
unsafe impl Send for SendableUdpConnPtr {}

impl SendableUdpConnPtr {
    unsafe fn get(&self) -> &UdpConnection {
        unsafe { &(*self.0).0 }
    }
}

/// Opaque handle to a UDP P2P connection.
pub struct WispersUdpConnectionHandle(pub(crate) UdpConnection);

/// Callback that receives a UDP connection handle.
pub type WispersUdpConnectionCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        connection: *mut WispersUdpConnectionHandle,
    ),
>;

/// Callback that receives received data.
pub type WispersDataCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        data: *const u8,
        len: usize,
    ),
>;

// Free function

#[unsafe(no_mangle)]
pub extern "C" fn wispers_udp_connection_free(handle: *mut WispersUdpConnectionHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Connect to a peer node using UDP transport.
///
/// Returns `INVALID_STATE` if the node is not in Activated state.
/// The node handle is NOT consumed.
/// On success, callback receives the UDP connection handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_connect_udp_async(
    handle: *mut WispersNodeHandle,
    peer_node_number: c_int,
    ctx: *mut c_void,
    callback: WispersUdpConnectionCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let handle_clone = unsafe { &*handle }.clone();

    runtime::spawn(async move {
        let node = handle_clone.lock().await;
        let result = node.connect_udp(peer_node_number).await;

        match result {
            Ok(conn) => {
                let h = Box::into_raw(Box::new(WispersUdpConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Err(ref e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        p2p_error_to_status(e),
                        detail.as_ptr(),
                        ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Send data over a UDP connection.
///
/// This is a synchronous, non-blocking operation.
/// The connection handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_udp_connection_send(
    handle: *mut WispersUdpConnectionHandle,
    data: *const u8,
    len: usize,
) -> WispersStatus {
    if handle.is_null() || data.is_null() {
        return WispersStatus::NullPointer;
    }

    let wrapper = unsafe { &*handle };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    match wrapper.0.send(data_slice) {
        Ok(()) => WispersStatus::Success,
        Err(_) => WispersStatus::ConnectionFailed,
    }
}

/// Receive data from a UDP connection.
///
/// The connection handle is NOT consumed.
/// On success, callback receives the data buffer. The buffer is only valid
/// during the callback invocation.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_udp_connection_recv_async(
    handle: *mut WispersUdpConnectionHandle,
    ctx: *mut c_void,
    callback: WispersDataCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    // We need to keep the connection alive while receiving.
    // recv() takes &self, so we borrow via raw pointer. This is safe
    // as long as the caller doesn't free the handle while recv is pending.
    // A safer approach would be to wrap in Arc, but that changes the API.
    let ctx = CallbackContext(ctx);
    let conn_ptr_wrapper = SendableUdpConnPtr(handle);

    runtime::spawn(async move {
        let conn = unsafe { conn_ptr_wrapper.get() };
        let result = conn.recv().await;

        match result {
            Ok(data) => unsafe {
                callback(
                    ctx.ptr(),
                    WispersStatus::Success,
                    ptr::null(),
                    data.as_ptr(),
                    data.len(),
                );
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::ConnectionFailed,
                        detail.as_ptr(),
                        ptr::null(),
                        0,
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Close a UDP connection.
///
/// The connection handle is CONSUMED by this call.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_udp_connection_close(handle: *mut WispersUdpConnectionHandle) {
    if handle.is_null() {
        return;
    }

    let wrapper = unsafe { Box::from_raw(handle) };
    wrapper.0.close();
}

//------------------------------------------------------------------------------
// QUIC Connection FFI
//------------------------------------------------------------------------------

/// Opaque handle to a QUIC P2P connection.
pub struct WispersQuicConnectionHandle(pub(crate) QuicConnection);

/// Opaque handle to a QUIC stream.
pub struct WispersQuicStreamHandle(pub(crate) QuicStream);

// Helpers to send raw pointers across threads
struct SendableQuicConnPtr(*mut WispersQuicConnectionHandle);
unsafe impl Send for SendableQuicConnPtr {}

impl SendableQuicConnPtr {
    unsafe fn get(&self) -> &QuicConnection {
        unsafe { &(*self.0).0 }
    }
}

struct SendableQuicStreamPtr(*mut WispersQuicStreamHandle);
unsafe impl Send for SendableQuicStreamPtr {}

impl SendableQuicStreamPtr {
    unsafe fn get(&self) -> &QuicStream {
        unsafe { &(*self.0).0 }
    }
}

/// Callback that receives a QUIC connection handle.
pub type WispersQuicConnectionCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        connection: *mut WispersQuicConnectionHandle,
    ),
>;

/// Callback that receives a QUIC stream handle.
pub type WispersQuicStreamCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        stream: *mut WispersQuicStreamHandle,
    ),
>;

/// Free a QUIC connection handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_free(handle: *mut WispersQuicConnectionHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Free a QUIC stream handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_stream_free(handle: *mut WispersQuicStreamHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Connect to a peer node using QUIC transport.
///
/// Returns `INVALID_STATE` if the node is not in Activated state.
/// The node handle is NOT consumed.
/// On success, callback receives the QUIC connection handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_connect_quic_async(
    handle: *mut WispersNodeHandle,
    peer_node_number: c_int,
    ctx: *mut c_void,
    callback: WispersQuicConnectionCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let handle_clone = unsafe { &*handle }.clone();

    runtime::spawn(async move {
        let node = handle_clone.lock().await;
        let result = node.connect_quic(peer_node_number).await;

        match result {
            Ok(conn) => {
                let h = Box::into_raw(Box::new(WispersQuicConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Err(ref e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        p2p_error_to_status(e),
                        detail.as_ptr(),
                        ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Open a new bidirectional stream on a QUIC connection.
///
/// The connection handle is NOT consumed.
/// On success, callback receives the stream handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_open_stream_async(
    handle: *mut WispersQuicConnectionHandle,
    ctx: *mut c_void,
    callback: WispersQuicStreamCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let conn_ptr = SendableQuicConnPtr(handle);

    runtime::spawn(async move {
        let conn = unsafe { conn_ptr.get() };
        let result = conn.open_stream().await;

        match result {
            Ok(stream) => {
                let h = Box::into_raw(Box::new(WispersQuicStreamHandle(stream)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::ConnectionFailed,
                        detail.as_ptr(),
                        ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Accept an incoming stream from the peer.
///
/// The connection handle is NOT consumed.
/// On success, callback receives the stream handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_accept_stream_async(
    handle: *mut WispersQuicConnectionHandle,
    ctx: *mut c_void,
    callback: WispersQuicStreamCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let conn_ptr = SendableQuicConnPtr(handle);

    runtime::spawn(async move {
        let conn = unsafe { conn_ptr.get() };
        let result = conn.accept_stream().await;

        match result {
            Ok(stream) => {
                let h = Box::into_raw(Box::new(WispersQuicStreamHandle(stream)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::ConnectionFailed,
                        detail.as_ptr(),
                        ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Check that the peer of a QUIC connection is still reachable.
///
/// Sends a QUIC PING and waits for the peer's transport to acknowledge it.
/// Fails with `Timeout` if no acknowledgement arrives within `timeout_ms`, and
/// with `ConnectionFailed` if the connection is closed or closing.
///
/// The connection handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_ping_async(
    handle: *mut WispersQuicConnectionHandle,
    timeout_ms: u32,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let conn_ptr = SendableQuicConnPtr(handle);

    runtime::spawn(async move {
        let conn = unsafe { conn_ptr.get() };
        let timeout = std::time::Duration::from_millis(u64::from(timeout_ms));
        let result = conn.ping(timeout).await;

        match result {
            Ok(_rtt) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), p2p_error_to_status(&e), detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Close a QUIC connection.
///
/// The peer sees error code 0 and no reason.
///
/// The connection handle is CONSUMED by this call.
/// The callback is invoked when the close operation completes.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_close_async(
    handle: *mut WispersQuicConnectionHandle,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    spawn_quic_close(handle, ctx, callback, QuicConnection::close);

    WispersStatus::Success
}

/// Close a QUIC connection, with error code and reason.
///
/// `error_code` must be at most 2^62-1 (QUIC's limit). `reason` may be NULL (no
/// reason) and is truncated to 1024 bytes.
///
/// The connection handle is CONSUMED by this call, unless it returns an error
/// status. The callback is invoked when the close operation completes.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_close_with_error_async(
    handle: *mut WispersQuicConnectionHandle,
    error_code: u64,
    reason: *const c_char,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let reason = if reason.is_null() {
        String::new()
    } else {
        match c_str_to_string(reason) {
            Ok(r) => r,
            Err(status) => return status,
        }
    };

    spawn_quic_close(handle, ctx, callback, move |conn| async move {
        conn.close_with_error(error_code, &reason).await
    });

    WispersStatus::Success
}

/// Consume `handle` and run `close` on its connection in the background,
/// reporting the outcome through `callback`. Arguments must already be
/// validated. From here on the handle belongs to us.
fn spawn_quic_close<F, Fut>(
    handle: *mut WispersQuicConnectionHandle,
    ctx: *mut c_void,
    callback: unsafe extern "C" fn(*mut c_void, WispersStatus, *const c_char),
    close: F,
) where
    F: FnOnce(QuicConnection) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), P2pError>> + Send,
{
    let ctx = CallbackContext(ctx);
    let conn = unsafe { Box::from_raw(handle) }.0;

    runtime::spawn(async move {
        match close(conn).await {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, detail.as_ptr());
                }
            }
        }
    });
}

/// How the peer closed a QUIC connection. Opaque; read with the
/// `wispers_quic_close_info_*` accessors, free with `wispers_quic_close_info_free`.
pub struct WispersQuicCloseInfo {
    closed_by_app: bool,
    error_code: u64,
    reason: CString,
}

/// How the peer closed the connection, or NULL if it hasn't (or if `handle` is
/// NULL).
///
/// Non-NULL as soon as the peer's close arrives; stream operations on the
/// connection then fail with `ConnectionFailed`. The result must be freed with
/// `wispers_quic_close_info_free`.
///
/// The connection handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_connection_peer_close_info(
    handle: *mut WispersQuicConnectionHandle,
) -> *mut WispersQuicCloseInfo {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let conn = unsafe { &(*handle).0 };
    match conn.peer_close_info() {
        Some(info) => Box::into_raw(Box::new(WispersQuicCloseInfo::from_close_info(info))),
        None => ptr::null_mut(),
    }
}

impl WispersQuicCloseInfo {
    fn from_close_info(info: QuicCloseInfo) -> Self {
        // The reason came off the wire, so it may contain NULs.
        let reason = CString::new(info.reason.replace('\0', "\u{FFFD}")).unwrap_or_default();
        Self {
            closed_by_app: info.closed_by_app,
            error_code: info.error_code,
            reason,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_close_info_free(info: *mut WispersQuicCloseInfo) {
    if info.is_null() {
        return;
    }
    // SAFETY: allocated via Box::into_raw in wispers_quic_connection_peer_close_info.
    drop(unsafe { Box::from_raw(info) });
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_close_info_closed_by_app(info: *const WispersQuicCloseInfo) -> bool {
    if info.is_null() {
        return false;
    }
    unsafe { (*info).closed_by_app }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_close_info_error_code(info: *const WispersQuicCloseInfo) -> u64 {
    if info.is_null() {
        return 0;
    }
    unsafe { (*info).error_code }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_close_info_reason(
    info: *const WispersQuicCloseInfo,
) -> *const c_char {
    if info.is_null() {
        return ptr::null();
    }
    unsafe { (*info).reason.as_ptr() }
}

//------------------------------------------------------------------------------
// QUIC Stream FFI
//------------------------------------------------------------------------------

/// Write data to a QUIC stream.
///
/// The stream handle is NOT consumed.
/// The data is copied before the function returns, so the caller's buffer
/// can be freed immediately.
/// Callback is invoked when the write completes.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_stream_write_async(
    handle: *mut WispersQuicStreamHandle,
    data: *const u8,
    len: usize,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() || data.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    // Copy data before returning so caller can free their buffer
    let data_owned = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let ctx = CallbackContext(ctx);
    let stream_ptr = SendableQuicStreamPtr(handle);

    runtime::spawn(async move {
        let stream = unsafe { stream_ptr.get() };
        let result = stream.write_all(&data_owned).await;

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                log::error!("[wispers FFI] quic_stream_write error: {e:?}");
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Read data from a QUIC stream.
///
/// The stream handle is NOT consumed.
/// On success, callback receives the data buffer. The buffer is only valid
/// during the callback invocation.
/// `max_len` specifies the maximum number of bytes to read.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_stream_read_async(
    handle: *mut WispersQuicStreamHandle,
    max_len: usize,
    ctx: *mut c_void,
    callback: WispersDataCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let stream_ptr = SendableQuicStreamPtr(handle);

    runtime::spawn(async move {
        let stream = unsafe { stream_ptr.get() };
        let mut buf = vec![0u8; max_len];
        let result = stream.read(&mut buf).await;

        match result {
            Ok(n) => unsafe {
                callback(
                    ctx.ptr(),
                    WispersStatus::Success,
                    ptr::null(),
                    buf.as_ptr(),
                    n,
                );
            },
            Err(e) => {
                log::error!("[wispers FFI] quic_stream_read error: {e:?}");
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::ConnectionFailed,
                        detail.as_ptr(),
                        ptr::null(),
                        0,
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Close the stream for writing (send FIN).
///
/// The stream handle is NOT consumed. The stream can still be read from
/// after calling finish.
/// Callback is invoked when the finish completes.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_stream_finish_async(
    handle: *mut WispersQuicStreamHandle,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let stream_ptr = SendableQuicStreamPtr(handle);

    runtime::spawn(async move {
        let stream = unsafe { stream_ptr.get() };
        let result = stream.finish().await;

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                log::error!("[wispers FFI] quic_stream_finish error: {e:?}");
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Shutdown the stream (stop sending and receiving).
///
/// The stream handle is NOT consumed.
/// Callback is invoked when the shutdown completes.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_quic_stream_shutdown_async(
    handle: *mut WispersQuicStreamHandle,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let stream_ptr = SendableQuicStreamPtr(handle);

    runtime::spawn(async move {
        let stream = unsafe { stream_ptr.get() };
        let result = stream.shutdown().await;

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}
