//! FFI bindings for serving sessions.

use super::callbacks::CallbackContext;
use super::handles::WispersNodeHandle;
use super::p2p::{
    WispersQuicConnectionCallback, WispersQuicConnectionHandle, WispersUdpConnectionCallback,
    WispersUdpConnectionHandle,
};
use super::runtime;
use crate::errors::WispersStatus;
use crate::node::{Node, NodeState};
use crate::serving::{IncomingConnections, ServingHandle, ServingSession};
use std::ffi::{c_void, CString};
use std::os::raw::c_char;

/// Opaque handle to a serving command interface.
///
/// Use this to generate pairing codes and control the session.
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
pub struct WispersIncomingConnections(pub(crate) IncomingConnections);

// Callback types for serving operations

/// Callback for start_serving that receives the session components.
pub type WispersStartServingCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        serving_handle: *mut WispersServingHandle,
        session: *mut WispersServingSession,
        incoming: *mut WispersIncomingConnections,
    ),
>;

/// Callback that receives a pairing code string.
pub type WispersPairingCodeCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, status: WispersStatus, pairing_code: *mut c_char),
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

// Helper to send incoming connections pointer across threads.
// Safety: The caller must ensure the pointer remains valid and is not accessed
// concurrently from multiple threads.
struct SendableIncomingPtr(*mut WispersIncomingConnections);
unsafe impl Send for SendableIncomingPtr {}
unsafe impl Sync for SendableIncomingPtr {}

impl SendableIncomingPtr {
    /// Get a mutable reference to the inner IncomingConnections.
    /// SAFETY: The caller must ensure the pointer is valid.
    unsafe fn get(&self) -> &mut IncomingConnections {
        unsafe { &mut (*self.0).0 }
    }
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
    let ptr = SendableIncomingPtr(handle);

    runtime::spawn(async move {
        // Safety: caller must ensure handle is valid and not used concurrently
        let incoming = unsafe { ptr.get() };
        let result = incoming.udp.recv().await;

        match result {
            Some(Ok(conn)) => {
                let h = Box::into_raw(Box::new(WispersUdpConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, h);
                }
            }
            Some(Err(_)) => {
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, std::ptr::null_mut());
                }
            }
            None => {
                // Channel closed (session ended)
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, std::ptr::null_mut());
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
    let ptr = SendableIncomingPtr(handle);

    runtime::spawn(async move {
        // Safety: caller must ensure handle is valid and not used concurrently
        let incoming = unsafe { ptr.get() };
        let result = incoming.quic.recv().await;

        match result {
            Some(Ok(conn)) => {
                let h = Box::into_raw(Box::new(WispersQuicConnectionHandle(conn)));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, h);
                }
            }
            Some(Err(_)) => {
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, std::ptr::null_mut());
                }
            }
            None => {
                // Channel closed (session ended)
                unsafe {
                    callback(ctx.ptr(), WispersStatus::ConnectionFailed, std::ptr::null_mut());
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

    let wrapper = unsafe { &*handle };
    let ctx = CallbackContext(ctx);

    // Extract what we need before spawning
    let serving_params = extract_serving_params(&wrapper.0);

    let params = match serving_params {
        Ok(p) => p,
        Err(status) => return status,
    };

    runtime::spawn(async move {
        let result = start_serving_impl(params).await;
        match result {
            Ok((serving_handle, session, incoming)) => {
                let h = Box::into_raw(Box::new(WispersServingHandle(serving_handle)));
                let s = Box::into_raw(Box::new(WispersServingSession(Some(session))));
                let i = incoming
                    .map(|inc| Box::into_raw(Box::new(WispersIncomingConnections(inc))))
                    .unwrap_or(std::ptr::null_mut());
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, h, s, i);
                }
            }
            Err(_) => {
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::HubError,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

/// Generate a pairing code for endorsing a new node.
///
/// The serving handle is NOT consumed.
/// On success, the callback receives the pairing code string (caller must free with wispers_string_free).
#[unsafe(no_mangle)]
pub extern "C" fn wispers_serving_handle_generate_pairing_code_async(
    handle: *mut WispersServingHandle,
    ctx: *mut c_void,
    callback: WispersPairingCodeCallback,
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
        let result = serving_handle.generate_pairing_secret().await;
        match result {
            Ok(pairing_code) => {
                let code_str = pairing_code.format();
                match CString::new(code_str) {
                    Ok(cstr) => {
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, cstr.into_raw());
                        }
                    }
                    Err(_) => {
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::InvalidUtf8, std::ptr::null_mut());
                        }
                    }
                }
            }
            Err(_) => {
                unsafe {
                    callback(ctx.ptr(), WispersStatus::HubError, std::ptr::null_mut());
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
    callback: super::callbacks::WispersCallback,
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
            return WispersStatus::UnexpectedStage;
        }
    };
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = session.run().await;
        let status = match result {
            Ok(()) => WispersStatus::Success,
            Err(_) => WispersStatus::HubError,
        };
        unsafe {
            callback(ctx.ptr(), status);
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
    callback: super::callbacks::WispersCallback,
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
        let status = match result {
            Ok(()) => WispersStatus::Success,
            Err(_) => WispersStatus::HubError,
        };
        unsafe {
            callback(ctx.ptr(), status);
        }
    });

    WispersStatus::Success
}

// Implementation helpers

/// Parameters extracted from a Node for starting a serving session.
struct ServingParams {
    hub_addr: String,
    registration: crate::types::NodeRegistration,
    signing_key: crate::crypto::SigningKeyPair,
    /// P2P config - only present for activated nodes
    p2p_config: Option<crate::serving::P2pConfig>,
}

fn extract_serving_params(node: &Node) -> Result<ServingParams, WispersStatus> {
    let state = node.state();
    if state == NodeState::Pending {
        return Err(WispersStatus::InvalidState);
    }

    let registration = node.registration().ok_or(WispersStatus::InvalidState)?.clone();
    let hub_addr = node.hub_addr();

    // For registered nodes, derive signing key on demand. For activated nodes, use cached key.
    let signing_key = node
        .signing_key()
        .cloned()
        .or_else(|| node.derive_signing_key())
        .ok_or(WispersStatus::InvalidState)?;

    let p2p_config = if state == NodeState::Activated {
        let x25519_key = node.encryption_key().ok_or(WispersStatus::InvalidState)?.clone();
        Some(crate::serving::P2pConfig {
            x25519_key,
            hub_addr: hub_addr.clone(),
            registration: registration.clone(),
        })
    } else {
        None
    };

    Ok(ServingParams {
        hub_addr,
        registration,
        signing_key,
        p2p_config,
    })
}

async fn start_serving_impl(
    params: ServingParams,
) -> Result<(ServingHandle, ServingSession, Option<IncomingConnections>), crate::hub::HubError> {
    use crate::hub::HubClient;
    use crate::serving::ServingSession;

    let mut client = HubClient::connect(&params.hub_addr).await?;
    let conn = client.start_serving(&params.registration).await?;

    let (handle, session, incoming) = ServingSession::new(
        conn,
        params.signing_key,
        params.registration.connectivity_group_id.clone(),
        params.registration.node_number,
        params.p2p_config,
    );

    Ok((handle, session, incoming))
}
