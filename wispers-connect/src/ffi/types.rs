//! FFI type definitions, type aliases, and memory management.
//!
//! This module contains all the types exposed through the FFI boundary,
//! including handle wrappers, data structures, callback types, and their
//! associated memory management functions.

use crate::errors::{NodeStateError, WispersStatus};
use crate::node::{Node, NodeStorage};
use crate::storage::StorageError;
use crate::types::{GroupInfo, GroupState, NodeInfo, NodeRegistration};
use std::ffi::{CStr, CString, c_void};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::Arc;
use tokio::sync::Mutex;

// =============================================================================
// Handle wrappers
// =============================================================================

/// Opaque handle to a `NodeStorage` instance.
pub struct WispersNodeStorageHandle(pub(crate) NodeStorage);

/// Opaque handle to a Node instance.
///
/// The inner `Node` is wrapped in `Arc<tokio::sync::Mutex<…>>` so that the
/// FFI surface is sound under concurrent calls from C-side callers. The C
/// caller can hand the same pointer to multiple FFI methods on different
/// threads without violating Rust's aliasing rules: every method acquires
/// the mutex before touching the inner `Node`, so there is at most one
/// borrow at any moment.
#[derive(Clone)]
pub struct WispersNodeHandle(Arc<Mutex<Node>>);

// Lock helpers are scoped to the FFI module: `blocking_lock` panics if
// called from inside the runtime, which is a footgun we don't want
// available to non-FFI code in this crate.
impl WispersNodeHandle {
    /// Wrap a freshly-created `Node` in a handle suitable for boxing into
    /// a raw pointer for FFI return values.
    pub(in crate::ffi) fn new(node: Node) -> Self {
        Self(Arc::new(Mutex::new(node)))
    }

    /// Acquire the inner mutex asynchronously.
    pub(in crate::ffi) async fn lock(&self) -> tokio::sync::MutexGuard<'_, Node> {
        self.0.lock().await
    }

    /// Acquire the inner mutex synchronously. Panics if called from
    /// inside the library's tokio runtime — see callsite docs.
    pub(in crate::ffi) fn blocking_lock(&self) -> tokio::sync::MutexGuard<'_, Node> {
        self.0.blocking_lock()
    }
}

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
pub type WispersCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, status: WispersStatus, error_detail: *const c_char),
>;

/// Callback that receives a node handle and state indicator.
///
/// Used by `wispers_storage_restore_or_init_async`. On success, the handle is
/// non-null and state indicates the current node state.
pub type WispersInitCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        handle: *mut WispersNodeHandle,
        state: WispersNodeState,
    ),
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
    /// Create from a `NodeRegistration`, allocating C strings.
    pub(crate) fn from_registration(reg: &NodeRegistration) -> Result<Self, WispersStatus> {
        let cg_id = CString::new(reg.connectivity_group_id.to_string())
            .map_err(|_| WispersStatus::InvalidUtf8)?;
        let token_str = reg.auth_token().map_or("", super::super::types::AuthToken::as_str);
        let token = CString::new(token_str).map_err(|_| WispersStatus::InvalidUtf8)?;
        let jwt_ptr = CString::new(reg.attestation_jwt.as_str())
            .map_err(|_| WispersStatus::InvalidUtf8)?
            .into_raw();

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
    pub metadata: *mut c_char,
    /// Whether this is the current node (self).
    pub is_self: bool,
    /// Activation status: 0 = unknown, 1 = not activated, 2 = activated.
    pub activation_status: c_int,
    pub last_seen_at_millis: i64,
    /// Whether the node currently has an active connection to the hub.
    pub is_online: bool,
}

/// Activation status values for `WispersNode`.
pub const WISPERS_ACTIVATION_UNKNOWN: c_int = 0;
pub const WISPERS_ACTIVATION_NOT_ACTIVATED: c_int = 1;
pub const WISPERS_ACTIVATION_ACTIVATED: c_int = 2;

/// List of nodes returned to C callers.
#[repr(C)]
pub struct WispersNodeList {
    pub nodes: *mut WispersNode,
    pub count: usize,
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_list_free(list: *mut WispersNodeList) {
    if list.is_null() {
        return;
    }
    unsafe {
        let list = &mut *list;
        if !list.nodes.is_null() && list.count > 0 {
            // Reconstruct the Vec to properly free it; length == capacity by construction.
            #[allow(clippy::same_length_and_capacity)]
            let nodes = Vec::from_raw_parts(list.nodes, list.count, list.count);
            for node in nodes {
                if !node.name.is_null() {
                    drop(CString::from_raw(node.name));
                }
                if !node.metadata.is_null() {
                    drop(CString::from_raw(node.metadata));
                }
            }
        }
        list.nodes = ptr::null_mut();
        list.count = 0;
    }
}

// =============================================================================
// Group status
// =============================================================================

/// Group state indicator for FFI.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersGroupState {
    Alone = 0,
    Bootstrap = 1,
    NeedActivation = 2,
    CanEndorse = 3,
    AllActivated = 4,
}

impl From<&GroupState> for WispersGroupState {
    fn from(state: &GroupState) -> Self {
        match state {
            GroupState::Alone => Self::Alone,
            GroupState::Bootstrap => Self::Bootstrap,
            GroupState::NeedActivation => Self::NeedActivation,
            GroupState::CanEndorse => Self::CanEndorse,
            GroupState::AllActivated => Self::AllActivated,
        }
    }
}

/// Group info returned to C callers.
#[repr(C)]
pub struct WispersGroupInfo {
    pub state: WispersGroupState,
    pub nodes: *mut WispersNode,
    pub nodes_count: usize,
}

impl WispersGroupInfo {
    /// Create from a `GroupInfo`, allocating C strings.
    pub(crate) fn from_group_info(info: GroupInfo) -> Result<Self, WispersStatus> {
        let state = WispersGroupState::from(&info.state);
        let count = info.nodes.len();

        if count == 0 {
            return Ok(Self {
                state,
                nodes: ptr::null_mut(),
                nodes_count: 0,
            });
        }

        // Phase 1: build all CString values while they are still Rust-owned.
        // If any CString::new() fails the `?` propagates the error and the
        // Vec<(CString, CString, NodeInfo)> is dropped cleanly — no raw-pointer
        // leaks because we haven't called into_raw() on anything yet.
        let owned: Vec<(CString, CString, NodeInfo)> = info
            .nodes
            .into_iter()
            .map(|node| {
                let name =
                    CString::new(node.name.as_str()).map_err(|_| WispersStatus::InvalidUtf8)?;
                let metadata =
                    CString::new(node.metadata.as_str()).map_err(|_| WispersStatus::InvalidUtf8)?;
                Ok((name, metadata, node))
            })
            .collect::<Result<_, WispersStatus>>()?;

        // Phase 2: all strings built successfully — convert to raw pointers.
        // This loop is infallible, so no leak is possible here.
        let mut c_nodes: Vec<WispersNode> = owned
            .into_iter()
            .map(|(name, metadata, node)| {
                let activation_status = match node.is_activated {
                    None => WISPERS_ACTIVATION_UNKNOWN,
                    Some(false) => WISPERS_ACTIVATION_NOT_ACTIVATED,
                    Some(true) => WISPERS_ACTIVATION_ACTIVATED,
                };
                WispersNode {
                    node_number: node.node_number,
                    name: name.into_raw(),
                    metadata: metadata.into_raw(),
                    is_self: node.is_self,
                    activation_status,
                    last_seen_at_millis: node.last_seen_at_millis,
                    is_online: node.is_online,
                }
            })
            .collect();

        let nodes_ptr = c_nodes.as_mut_ptr();
        std::mem::forget(c_nodes);

        Ok(Self {
            state,
            nodes: nodes_ptr,
            nodes_count: count,
        })
    }
}

/// Callback that receives group info.
pub type WispersGroupInfoCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        error_detail: *const c_char,
        group_info: *mut WispersGroupInfo,
    ),
>;

#[unsafe(no_mangle)]
pub extern "C" fn wispers_group_info_free(group_info: *mut WispersGroupInfo) {
    if group_info.is_null() {
        return;
    }
    // SAFETY: `group_info` was allocated by Rust via `Box::into_raw(Box::new(...))` in
    // `handle_group_info_result`. We reconstitute the Box here to free both the inner
    // `nodes` array and the `WispersGroupInfo` allocation itself.
    // The previous implementation only freed the `nodes` array (via a borrow) and leaked
    // the `WispersGroupInfo` Box.
    let gs = unsafe { Box::from_raw(group_info) };
    if !gs.nodes.is_null() && gs.nodes_count > 0 {
        // SAFETY: `nodes` was allocated by Rust via `Vec::into_raw_parts`-equivalent
        // (`as_mut_ptr` + `mem::forget`) with length == capacity == `nodes_count`.
        #[allow(clippy::same_length_and_capacity)]
        let nodes = unsafe { Vec::from_raw_parts(gs.nodes, gs.nodes_count, gs.nodes_count) };
        for node in nodes {
            if !node.name.is_null() {
                unsafe { drop(CString::from_raw(node.name)) };
            }
            if !node.metadata.is_null() {
                unsafe { drop(CString::from_raw(node.metadata)) };
            }
        }
    }
    // `gs` (Box<WispersGroupInfo>) is dropped here, freeing the struct itself.
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
            .map(std::borrow::ToOwned::to_owned)
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
            NodeStateError::InvalidActivationCode(_) => WispersStatus::InvalidActivationCode,
            NodeStateError::MacVerificationFailed
            | NodeStateError::MissingEndorserResponse
            | NodeStateError::RosterVerificationFailed(_) => WispersStatus::ActivationFailed,
            NodeStateError::LastActiveNode | NodeStateError::InvalidState { .. } => {
                WispersStatus::InvalidState
            }
        }
    }
}
