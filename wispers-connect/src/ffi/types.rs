//! FFI type definitions, type aliases, and memory management.
//!
//! This module contains all the types exposed through the FFI boundary,
//! including handle wrappers, data structures, callback types, and their
//! associated memory management functions.

use crate::errors::{NodeStateError, WispersStatus};
use crate::node::{Node, NodeStorage};
use crate::storage::StorageError;
use crate::types::{NodeInfo, NodeRegistration};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

// =============================================================================
// Handle wrappers
// =============================================================================

/// Opaque handle to a NodeStorage instance.
pub struct WispersNodeStorageHandle(pub(crate) NodeStorage);

/// Opaque handle to a Node instance.
pub struct WispersNodeHandle(pub(crate) Node);

// =============================================================================
// Callback context
// =============================================================================

/// Wrapper for callback context pointer that can be sent across threads.
///
/// Raw pointers aren't safe to send between threads by default. This wrapper
/// asserts that the C caller ensures the context remains valid until the
/// callback is invoked.
#[derive(Clone, Copy)]
pub struct CallbackContext(pub(crate) *mut c_void);

unsafe impl Send for CallbackContext {}
unsafe impl Sync for CallbackContext {}

impl CallbackContext {
    pub(crate) fn ptr(self) -> *mut c_void {
        self.0
    }
}

// =============================================================================
// Node state enum
// =============================================================================

/// Node state indicator for FFI.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersNodeState {
    /// Node needs to register with the hub.
    Pending = 0,
    /// Node is registered but not yet activated.
    Registered = 1,
    /// Node is activated and ready for P2P connections.
    Activated = 2,
}

// =============================================================================
// Callback type aliases
// =============================================================================

/// Basic completion callback (no result value).
///
/// Called when an async operation completes, with status indicating success/failure.
pub type WispersCallback = Option<unsafe extern "C" fn(ctx: *mut c_void, status: WispersStatus)>;

/// Callback that receives a node handle and state indicator.
///
/// Used by `wispers_storage_restore_or_init_async`. On success, the handle is
/// non-null and state indicates the current node state.
pub type WispersInitCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        handle: *mut WispersNodeHandle,
        state: WispersNodeState,
    ),
>;

/// Callback that receives a node list.
pub type WispersNodeListCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, status: WispersStatus, list: *mut WispersNodeList),
>;

// =============================================================================
// Registration info
// =============================================================================

/// Registration info returned to C callers.
#[repr(C)]
pub struct WispersRegistrationInfo {
    pub connectivity_group_id: *mut c_char,
    pub node_number: c_int,
    pub auth_token: *mut c_char,
    pub attestation_jwt: *mut c_char,
}

impl WispersRegistrationInfo {
    /// Create from a NodeRegistration, allocating C strings.
    pub(crate) fn from_registration(reg: &NodeRegistration) -> Result<Self, WispersStatus> {
        let cg_id = CString::new(reg.connectivity_group_id.to_string())
            .map_err(|_| WispersStatus::InvalidUtf8)?;
        let token_str = reg.auth_token().map(|t| t.as_str()).unwrap_or("");
        let token = CString::new(token_str).map_err(|_| WispersStatus::InvalidUtf8)?;
        let jwt_ptr = match &reg.attestation_jwt {
            Some(jwt) => CString::new(jwt.as_str())
                .map_err(|_| WispersStatus::InvalidUtf8)?
                .into_raw(),
            None => ptr::null_mut(),
        };

        Ok(Self {
            connectivity_group_id: cg_id.into_raw(),
            node_number: reg.node_number,
            auth_token: token.into_raw(),
            attestation_jwt: jwt_ptr,
        })
    }

    /// Create a zeroed/null instance.
    pub(crate) fn null() -> Self {
        Self {
            connectivity_group_id: ptr::null_mut(),
            node_number: 0,
            auth_token: ptr::null_mut(),
            attestation_jwt: ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_registration_info_free(info: *mut WispersRegistrationInfo) {
    if info.is_null() {
        return;
    }
    unsafe {
        let info = &mut *info;
        if !info.connectivity_group_id.is_null() {
            drop(CString::from_raw(info.connectivity_group_id));
            info.connectivity_group_id = ptr::null_mut();
        }
        if !info.auth_token.is_null() {
            drop(CString::from_raw(info.auth_token));
            info.auth_token = ptr::null_mut();
        }
        if !info.attestation_jwt.is_null() {
            drop(CString::from_raw(info.attestation_jwt));
            info.attestation_jwt = ptr::null_mut();
        }
    }
}

// =============================================================================
// Node list
// =============================================================================

/// Node information returned to C callers.
#[repr(C)]
pub struct WispersNode {
    pub node_number: c_int,
    pub name: *mut c_char,
    /// Whether this is the current node (self).
    pub is_self: bool,
    /// Activation status: 0 = unknown, 1 = not activated, 2 = activated.
    pub activation_status: c_int,
    pub last_seen_at_millis: i64,
    /// Whether the node currently has an active connection to the hub.
    pub is_online: bool,
}

/// Activation status values for WispersNode.
pub const WISPERS_ACTIVATION_UNKNOWN: c_int = 0;
pub const WISPERS_ACTIVATION_NOT_ACTIVATED: c_int = 1;
pub const WISPERS_ACTIVATION_ACTIVATED: c_int = 2;

/// List of nodes returned to C callers.
#[repr(C)]
pub struct WispersNodeList {
    pub nodes: *mut WispersNode,
    pub count: usize,
}

impl WispersNodeList {
    /// Create from a Vec<NodeInfo>, allocating C strings.
    pub(crate) fn from_node_infos(nodes: Vec<NodeInfo>) -> Result<Self, WispersStatus> {
        let count = nodes.len();
        if count == 0 {
            return Ok(Self {
                nodes: ptr::null_mut(),
                count: 0,
            });
        }

        let mut c_nodes: Vec<WispersNode> = Vec::with_capacity(count);
        for node in nodes {
            let name = CString::new(node.name).map_err(|_| WispersStatus::InvalidUtf8)?;
            let activation_status = match node.is_activated {
                None => WISPERS_ACTIVATION_UNKNOWN,
                Some(false) => WISPERS_ACTIVATION_NOT_ACTIVATED,
                Some(true) => WISPERS_ACTIVATION_ACTIVATED,
            };
            c_nodes.push(WispersNode {
                node_number: node.node_number,
                name: name.into_raw(),
                is_self: node.is_self,
                activation_status,
                last_seen_at_millis: node.last_seen_at_millis,
                is_online: node.is_online,
            });
        }

        let ptr = c_nodes.as_mut_ptr();
        std::mem::forget(c_nodes);

        Ok(Self { nodes: ptr, count })
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_list_free(list: *mut WispersNodeList) {
    if list.is_null() {
        return;
    }
    unsafe {
        let list = &mut *list;
        if !list.nodes.is_null() && list.count > 0 {
            // Reconstruct the Vec to properly free it
            let nodes = Vec::from_raw_parts(list.nodes, list.count, list.count);
            for node in nodes {
                if !node.name.is_null() {
                    drop(CString::from_raw(node.name));
                }
            }
        }
        list.nodes = ptr::null_mut();
        list.count = 0;
    }
}

// =============================================================================
// String utilities
// =============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn wispers_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

pub(crate) fn c_str_to_string(ptr: *const c_char) -> Result<String, WispersStatus> {
    if ptr.is_null() {
        return Err(WispersStatus::NullPointer);
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_owned())
            .map_err(|_| WispersStatus::InvalidUtf8)
    }
}

// =============================================================================
// Error conversion
// =============================================================================

impl From<NodeStateError> for WispersStatus {
    fn from(value: NodeStateError) -> Self {
        match value {
            NodeStateError::Store(ref e) => match e {
                StorageError::ForeignStatus(status) => *status,
                StorageError::MissingCallback(_) => WispersStatus::MissingCallback,
                _ => WispersStatus::StoreError,
            },
            NodeStateError::Hub(ref e) if e.is_unauthenticated() => WispersStatus::Unauthenticated,
            NodeStateError::Hub(ref e) if e.is_peer_rejected() => WispersStatus::PeerRejected,
            NodeStateError::Hub(ref e) if e.is_peer_unavailable() => WispersStatus::PeerUnavailable,
            NodeStateError::Hub(ref e) if e.is_not_found() => WispersStatus::NotFound,
            NodeStateError::Hub(_) => WispersStatus::HubError,
            NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
            NodeStateError::NotRegistered => WispersStatus::NotRegistered,
            NodeStateError::InvalidPairingCode(_) => WispersStatus::InvalidPairingCode,
            NodeStateError::MacVerificationFailed => WispersStatus::ActivationFailed,
            NodeStateError::MissingEndorserResponse => WispersStatus::ActivationFailed,
            NodeStateError::RosterVerificationFailed(_) => WispersStatus::ActivationFailed,
            NodeStateError::InvalidState { .. } => WispersStatus::InvalidState,
        }
    }
}
