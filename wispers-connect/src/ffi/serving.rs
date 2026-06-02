//! FFI bindings for serving sessions.

use super::p2p::{
    WispersQuicConnectionCallback, WispersQuicConnectionHandle, WispersUdpConnectionCallback,
    WispersUdpConnectionHandle,
};
use super::runtime;
use super::types::{CallbackContext, WispersCallback, WispersNodeHandle};
use crate::errors::WispersStatus;
use crate::node::{Node, NodeState};
use crate::p2p::{P2pError, QuicConnection, UdpConnection};
use crate::serving::{IncomingConnections, ServingHandle, ServingSession};
use std::ffi::{CString, c_void};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Opaque handle to a serving command interface.
///
/// Use this to generate activation codes and control the session.
/// This handle can be cloned internally and remains valid until freed.
pub struct WispersServingHandle(pub(crate) ServingHandle);

/// Opaque handle to a serving session runner.
///
/// Pass this to `wispers_serving_session_run_async` to start the event loop.
/// The session is consumed when run starts.
pub struct WispersServingSession(pub(crate) Option<ServingSession>);

/// Opaque handle to incoming P2P connection receivers.
///
/// Only present for activated nodes (not registered nodes).
/// Each receiver is wrapped in its own Arc<Mutex<>> so spawned accept tasks
/// hold a reference that outlives a `close()` call from the foreign wrapper,
/// and UDP/QUIC accepts don't block each other.
pub struct WispersIncomingConnections {
    pub(crate) udp: Arc<Mutex<tokio::sync::mpsc::Receiver<Result<UdpConnection, P2pError>>>>,
    pub(crate) quic: Arc<Mutex<tokio::sync::mpsc::Receiver<Result<QuicConnection, P2pError>>>>,
}

// Callback types for serving operations

/// Callback for start_serving that receives the session components.
pub type WispersStartServingCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        serving_handle: *mut WispersServingHandle,
        session: *mut WispersServingSession,
        incoming: *mut WispersIncomingConnections,
    ),
>;

/// Callback that receives an activation code string.
pub type WispersActivationCodeCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        activation_code: *mut c_char,
    ),
>;

// Free functions

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_free(handle: *mut WispersServingHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_session_free(handle: *mut WispersServingSession) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_incoming_connections_free(handle: *mut WispersIncomingConnections) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Clone the UDP receiver Arc out of the opaque handle.
///
/// # Safety
/// The caller must ensure `handle` is a valid, non-null pointer.
unsafe fn clone_udp_arc(
    handle: *mut WispersIncomingConnections,
) -> Arc<Mutex<tokio::sync::mpsc::Receiver<Result<UdpConnection, P2pError>>>> {
    unsafe { (*handle).udp.clone() }
}

/// Clone the QUIC receiver Arc out of the opaque handle.
///
/// # Safety
/// The caller must ensure `handle` is a valid, non-null pointer.
unsafe fn clone_quic_arc(
    handle: *mut WispersIncomingConnections,
) -> Arc<Mutex<tokio::sync::mpsc::Receiver<Result<QuicConnection, P2pError>>>> {
    unsafe { (*handle).quic.clone() }
}

/// Accept an incoming UDP connection.
///
/// The incoming connections handle is NOT consumed.
/// Waits for a peer to connect via UDP and returns the connection handle.
/// On success, callback receives the UDP connection handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_incoming_accept_udp_async(
    handle: *mut WispersIncomingConnections,
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
    let rx = unsafe { clone_udp_arc(handle) };

    runtime::spawn(async move {
        let result = rx.lock().await.recv().await;

        match result {
            Some(Ok(conn)) => {
                let h = Box::into_raw(Box::new(WispersUdpConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Some(Err(e)) => {
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
            None => {
                let detail = CString::new("channel closed (session ended)").unwrap_or_default();
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

/// Accept an incoming QUIC connection.
///
/// The incoming connections handle is NOT consumed.
/// Waits for a peer to connect via QUIC and returns the connection handle.
/// On success, callback receives the QUIC connection handle.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_incoming_accept_quic_async(
    handle: *mut WispersIncomingConnections,
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
    let rx = unsafe { clone_quic_arc(handle) };

    runtime::spawn(async move {
        let result = rx.lock().await.recv().await;

        match result {
            Some(Ok(conn)) => {
                let h = Box::into_raw(Box::new(WispersQuicConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h);
                }
            }
            Some(Err(e)) => {
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
            None => {
                let detail = CString::new("channel closed (session ended)").unwrap_or_default();
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

// Start serving function

/// Start a serving session for a node.
///
/// Registered nodes can serve for bootstrapping but cannot accept P2P connections
/// (incoming will be NULL). Activated nodes receive an incoming connections handle.
///
/// Returns INVALID_STATE if the node is in Pending state.
/// The node handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_start_serving_async(
    handle: *mut WispersNodeHandle,
    ctx: *mut c_void,
    callback: WispersStartServingCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let handle_clone = unsafe { &*handle }.clone();
    let ctx = CallbackContext(ctx);

    // Extract what we need before spawning. We hold the inner mutex
    // briefly (sync, on the calling thread) and release it before the
    // long-running async work — `start_serving_impl` doesn't touch the
    // Node at all, so there's no need to keep the lock through the
    // network round trips.
    let params = {
        let node = handle_clone.blocking_lock();
        extract_serving_params(&node)
    };
    let params = match params {
        Ok(p) => p,
        Err(status) => return status,
    };

    runtime::spawn(async move {
        let result = start_serving_impl(params).await;
        match result {
            Ok((serving_handle, session, incoming)) => {
                let h = Box::into_raw(Box::new(WispersServingHandle(serving_handle)));
                let s = Box::into_raw(Box::new(WispersServingSession(Some(session))));
                let i = Box::into_raw(Box::new(WispersIncomingConnections {
                    udp: Arc::new(Mutex::new(incoming.udp)),
                    quic: Arc::new(Mutex::new(incoming.quic)),
                }));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, ptr::null(), h, s, i);
                }
            }
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status = if e.is_unauthenticated() {
                    WispersStatus::Unauthenticated
                } else if e.is_peer_rejected() {
                    WispersStatus::PeerRejected
                } else if e.is_peer_unavailable() {
                    WispersStatus::PeerUnavailable
                } else if e.is_not_found() {
                    WispersStatus::NotFound
                } else {
                    WispersStatus::HubError
                };
                unsafe {
                    callback(
                        ctx.ptr(),
                        status,
                        detail.as_ptr(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// TTL profile for activation codes, mirroring [`crate::crypto::TtlProfile`].
/// Selects the code's entropy and validity window.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersTtlProfile {
    /// Short-lived code for live, at-the-keyboard entry.
    Interactive = 0,
    /// Long-lived code for out-of-band delivery (e.g. email).
    Asynchronous = 1,
}

impl From<WispersTtlProfile> for crate::crypto::TtlProfile {
    fn from(p: WispersTtlProfile) -> Self {
        match p {
            WispersTtlProfile::Interactive => crate::crypto::TtlProfile::Interactive,
            WispersTtlProfile::Asynchronous => crate::crypto::TtlProfile::Asynchronous,
        }
    }
}

/// Generate an activation code for endorsing a new node (interactive profile).
///
/// The serving handle is NOT consumed.
/// On success, the callback receives the activation code string (caller must free with wispers_string_free).
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_generate_activation_code_async(
    handle: *mut WispersServingHandle,
    ctx: *mut c_void,
    callback: WispersActivationCodeCallback,
) -> WispersStatus {
    generate_activation_code_impl(
        handle,
        crate::crypto::TtlProfile::Interactive,
        ctx,
        callback,
    )
}

/// Generate an activation code with an explicit TTL profile.
///
/// Like `wispers_serving_handle_generate_activation_code_async`, but lets the
/// caller pick a long-lived (`asynchronous`) code for out-of-band delivery.
/// The serving handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_generate_activation_code_with_ttl_async(
    handle: *mut WispersServingHandle,
    ttl_profile: WispersTtlProfile,
    ctx: *mut c_void,
    callback: WispersActivationCodeCallback,
) -> WispersStatus {
    generate_activation_code_impl(handle, ttl_profile.into(), ctx, callback)
}

/// Shared implementation: spawn the generation task and dispatch the result to
/// `callback`.
fn generate_activation_code_impl(
    handle: *mut WispersServingHandle,
    ttl_profile: crate::crypto::TtlProfile,
    ctx: *mut c_void,
    callback: WispersActivationCodeCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let wrapper = unsafe { &*handle };
    let serving_handle = wrapper.0.clone();
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = serving_handle
            .generate_activation_code_with_ttl(ttl_profile)
            .await;
        match result {
            Ok(pairing_code) => {
                let code_str = pairing_code.format();
                match CString::new(code_str) {
                    Ok(cstr) => unsafe {
                        callback(
                            ctx.ptr(),
                            WispersStatus::Success,
                            ptr::null(),
                            cstr.into_raw(),
                        );
                    },
                    Err(e) => {
                        let detail = CString::new(e.to_string()).unwrap_or_default();
                        unsafe {
                            callback(
                                ctx.ptr(),
                                WispersStatus::InvalidUtf8,
                                detail.as_ptr(),
                                ptr::null_mut(),
                            );
                        }
                    }
                }
            }
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status = if e.is_unauthenticated() {
                    WispersStatus::Unauthenticated
                } else {
                    WispersStatus::HubError
                };
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr(), ptr::null_mut());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Run the serving session event loop.
///
/// The session handle is CONSUMED by this call.
/// The callback is invoked when the session ends (either by shutdown or error).
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_session_run_async(
    handle: *mut WispersServingSession,
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

    // Consume the session
    let mut wrapper = unsafe { Box::from_raw(handle) };
    let session = match wrapper.0.take() {
        Some(s) => s,
        None => {
            // Session was already consumed
            return WispersStatus::InvalidState;
        }
    };
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = session.run().await;
        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status = if e.is_unauthenticated() {
                    WispersStatus::Unauthenticated
                } else if e.is_peer_rejected() {
                    WispersStatus::PeerRejected
                } else if e.is_peer_unavailable() {
                    WispersStatus::PeerUnavailable
                } else {
                    WispersStatus::HubError
                };
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Request the serving session to shut down.
///
/// The serving handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_shutdown_async(
    handle: *mut WispersServingHandle,
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

    let wrapper = unsafe { &*handle };
    let serving_handle = wrapper.0.clone();
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = serving_handle.shutdown().await;
        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), WispersStatus::HubError, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

//-- Serving status -------------------------------------------------------------

/// Snapshot of a serving session's status, exposed to C as an opaque handle.
/// Produced by `wispers_serving_handle_status_async`; read its fields via the
/// `wispers_serving_status_*` accessors, then free with
/// `wispers_serving_status_free`.
pub struct WispersServingStatus {
    connected: bool,
    node_number: c_int,
    connectivity_group_id: CString,
    codes_outstanding: usize,
    nodes_awaiting_cosign: Vec<c_int>,
}

impl WispersServingStatus {
    /// Materialize a `ServingStatus` snapshot into the FFI-owned representation.
    fn from_serving_status(status: crate::serving::ServingStatus) -> Result<Self, WispersStatus> {
        let connectivity_group_id = CString::new(status.connectivity_group_id.to_string())
            .map_err(|_| WispersStatus::InvalidUtf8)?;
        let (codes_outstanding, nodes_awaiting_cosign) = match status.endorsing {
            Some(e) => (e.codes_outstanding, e.nodes_awaiting_cosign),
            None => (0, Vec::new()),
        };
        Ok(Self {
            connected: status.connected,
            node_number: status.node_number,
            connectivity_group_id,
            codes_outstanding,
            nodes_awaiting_cosign,
        })
    }
}

/// Callback that receives a serving status handle.
pub type WispersServingStatusCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        serving_status: *mut WispersServingStatus,
    ),
>;

/// Fetch the current status of a serving session.
///
/// The serving handle is NOT consumed. On success, the callback receives a
/// `WispersServingStatus` that must be freed with `wispers_serving_status_free`.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_status_async(
    handle: *mut WispersServingHandle,
    ctx: *mut c_void,
    callback: WispersServingStatusCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let wrapper = unsafe { &*handle };
    let serving_handle = wrapper.0.clone();
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        match serving_handle.status().await {
            Ok(status) => match WispersServingStatus::from_serving_status(status) {
                Ok(ffi_status) => {
                    let ptr = Box::into_raw(Box::new(ffi_status));
                    unsafe {
                        callback(ctx.ptr(), WispersStatus::Success, ptr::null(), ptr);
                    }
                }
                Err(status) => {
                    let detail =
                        CString::new(format!("failed to build serving status: {status:?}"))
                            .unwrap_or_default();
                    unsafe {
                        callback(ctx.ptr(), status, detail.as_ptr(), ptr::null_mut());
                    }
                }
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status = if e.is_unauthenticated() {
                    WispersStatus::Unauthenticated
                } else {
                    WispersStatus::InvalidState
                };
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr(), ptr::null_mut());
                }
            }
        }
    });

    WispersStatus::Success
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_free(status: *mut WispersServingStatus) {
    if status.is_null() {
        return;
    }
    // SAFETY: allocated via Box::into_raw in wispers_serving_handle_status_async.
    drop(unsafe { Box::from_raw(status) });
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_connected(status: *const WispersServingStatus) -> bool {
    if status.is_null() {
        return false;
    }
    unsafe { (*status).connected }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_node_number(status: *const WispersServingStatus) -> c_int {
    if status.is_null() {
        return 0;
    }
    unsafe { (*status).node_number }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_connectivity_group_id(
    status: *const WispersServingStatus,
) -> *const c_char {
    if status.is_null() {
        return ptr::null();
    }
    unsafe { (*status).connectivity_group_id.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_codes_outstanding(
    status: *const WispersServingStatus,
) -> usize {
    if status.is_null() {
        return 0;
    }
    unsafe { (*status).codes_outstanding }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_nodes_awaiting_cosign_count(
    status: *const WispersServingStatus,
) -> usize {
    if status.is_null() {
        return 0;
    }
    unsafe { (*status).nodes_awaiting_cosign.len() }
}

/// Returns the node number awaiting cosign at `index`, or -1 if out of bounds.
/// Iterate `0..wispers_serving_status_nodes_awaiting_cosign_count`.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_status_node_awaiting_cosign_at(
    status: *const WispersServingStatus,
    index: usize,
) -> c_int {
    if status.is_null() {
        return -1;
    }
    let status = unsafe { &*status };
    status
        .nodes_awaiting_cosign
        .get(index)
        .copied()
        .unwrap_or(-1)
}

// Implementation helpers

/// Parameters extracted from a Node for starting a serving session.
struct ServingParams {
    hub_addr: String,
    registration: crate::types::NodeRegistration,
    signing_key: crate::crypto::SigningKeyPair,
    p2p_config: crate::serving::P2pConfig,
}

fn extract_serving_params(node: &Node) -> Result<ServingParams, WispersStatus> {
    let state = node.state();
    if state == NodeState::Pending {
        return Err(WispersStatus::InvalidState);
    }

    let registration = node
        .registration()
        .ok_or(WispersStatus::InvalidState)?
        .clone();
    let hub_addr = node.hub_addr();

    let p2p_config = crate::serving::P2pConfig {
        hub_addr: hub_addr.clone(),
        registration: registration.clone(),
    };

    Ok(ServingParams {
        hub_addr,
        registration,
        signing_key: node.signing_key().clone(),
        p2p_config,
    })
}

async fn start_serving_impl(
    params: ServingParams,
) -> Result<(ServingHandle, ServingSession, IncomingConnections), crate::hub::HubError> {
    use crate::serving::{ServingSession, open_serving_connection};

    let conn = open_serving_connection(&params.hub_addr, &params.registration).await?;

    let (handle, session, incoming) = ServingSession::new(
        conn,
        params.signing_key,
        params.registration.connectivity_group_id.clone(),
        params.registration.node_number,
        params.p2p_config,
    );

    Ok((handle, session, incoming))
}
