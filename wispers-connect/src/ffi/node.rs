//! FFI functions for node lifecycle operations.
//!
//! This module contains all `wispers_storage_*` and `wispers_node_*` functions
//! for managing node storage, initialization, registration, activation, and logout.

use super::runtime;
use super::types::{
    CallbackContext, WispersCallback, WispersGroupInfo, WispersGroupInfoCallback,
    WispersInitCallback, WispersNodeHandle, WispersNodeState, WispersNodeStorageHandle,
    WispersRegistrationInfo, c_str_to_string,
};
use crate::errors::WispersStatus;
use crate::node::{NodeState, NodeStorage};
use crate::storage::foreign::WispersNodeStorageCallbacks;
use crate::storage::{ForeignNodeStateStore, InMemoryNodeStateStore};
use std::ffi::{CString, c_void};
use std::os::raw::c_char;

// =============================================================================
// Storage functions
// =============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_new_in_memory() -> *mut WispersNodeStorageHandle {
    let storage = NodeStorage::new(InMemoryNodeStateStore::new());
    Box::into_raw(Box::new(WispersNodeStorageHandle(storage)))
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_new_with_callbacks(
    callbacks: *const WispersNodeStorageCallbacks,
) -> *mut WispersNodeStorageHandle {
    if callbacks.is_null() {
        return std::ptr::null_mut();
    }

    let callbacks = unsafe { *callbacks };
    let Ok(store) = ForeignNodeStateStore::new(callbacks) else {
        return std::ptr::null_mut();
    };
    let storage = NodeStorage::new(store);
    Box::into_raw(Box::new(WispersNodeStorageHandle(storage)))
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_free(handle: *mut WispersNodeStorageHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_read_registration(
    handle: *mut WispersNodeStorageHandle,
    out_info: *mut WispersRegistrationInfo,
) -> WispersStatus {
    if handle.is_null() || out_info.is_null() {
        return WispersStatus::NullPointer;
    }

    let wrapper = unsafe { &*handle };
    let maybe_reg = wrapper.0.read_registration();

    match maybe_reg {
        Ok(Some(reg)) => match WispersRegistrationInfo::from_registration(&reg) {
            Ok(info) => {
                unsafe { *out_info = info };
                WispersStatus::Success
            }
            Err(status) => status,
        },
        Ok(None) => {
            unsafe { *out_info = WispersRegistrationInfo::null() };
            WispersStatus::NotFound
        }
        Err(_) => WispersStatus::StoreError,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_override_hub_addr(
    handle: *mut WispersNodeStorageHandle,
    hub_addr: *const c_char,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let addr = match c_str_to_string(hub_addr) {
        Ok(s) => s,
        Err(status) => return status,
    };

    let wrapper = unsafe { &*handle };
    wrapper.0.override_hub_addr(addr);

    WispersStatus::Success
}

/// Delete all persisted state. Used for logout when the node can't be restored.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_delete_state(
    handle: *mut WispersNodeStorageHandle,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let wrapper = unsafe { &*handle };
    match wrapper.0.delete_state() {
        Ok(()) => WispersStatus::Success,
        Err(e) => WispersStatus::from(e),
    }
}

/// Restore or initialize node state asynchronously.
///
/// On success, the callback receives a single node handle and the current state.
/// The storage handle remains valid and is NOT consumed by this call.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_restore_or_init_async(
    handle: *mut WispersNodeStorageHandle,
    ctx: *mut c_void,
    callback: WispersInitCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let Some(callback) = callback else {
        return WispersStatus::MissingCallback;
    };

    let wrapper = unsafe { &*handle };
    let storage = wrapper.0.clone();
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = storage.restore_or_init_node().await;
        match result {
            Ok(node) => {
                let state = node_state_to_ffi(node.state());
                let handle = Box::into_raw(Box::new(WispersNodeHandle::new(node)));
                unsafe {
                    callback(
                        ctx.ptr(),
                        WispersStatus::Success,
                        std::ptr::null(),
                        handle,
                        state,
                    );
                }
            }
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status: WispersStatus = e.into();
                unsafe {
                    callback(
                        ctx.ptr(),
                        status,
                        detail.as_ptr(),
                        std::ptr::null_mut(),
                        WispersNodeState::Pending,
                    );
                }
            }
        }
    });

    WispersStatus::Success
}

// =============================================================================
// Node functions
// =============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_free(handle: *mut WispersNodeHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Get the current state/stage of the node.
///
/// **Synchronous; acquires the inner mutex via `blocking_lock`.** Must
/// not be called from inside the library's tokio runtime (e.g. from
/// within an FFI callback that's still executing on a worker thread) —
/// `blocking_lock` panics in that context. C callers operating from
/// their own thread (UI thread, app worker, …) are unaffected.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_state(handle: *mut WispersNodeHandle) -> WispersNodeState {
    if handle.is_null() {
        return WispersNodeState::Pending;
    }

    let wrapper = unsafe { &*handle };
    let node = wrapper.blocking_lock();
    node_state_to_ffi(node.state())
}

/// Register the node with the hub using a registration token.
///
/// Returns `INVALID_STATE` if the node is not in Pending state.
/// The node handle is NOT consumed - it transitions to Registered state on success.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_register_async(
    handle: *mut WispersNodeHandle,
    token: *const c_char,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let token_str = match c_str_to_string(token) {
        Ok(s) => s,
        Err(status) => return status,
    };

    let Some(callback) = callback else {
        return WispersStatus::MissingCallback;
    };

    let ctx = CallbackContext(ctx);
    let handle_clone = unsafe { &*handle }.clone();

    runtime::spawn(async move {
        let mut node = handle_clone.lock().await;
        let result = node.register(&token_str).await;

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, std::ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status: WispersStatus = e.into();
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Activate the node using an activation code from an endorser.
///
/// The activation code format is "node_number-secret" (e.g., "1-abc123xyz0").
/// Returns `INVALID_STATE` if the node is not in Registered state.
/// The node handle is NOT consumed - it transitions to Activated state on success.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_activate_async(
    handle: *mut WispersNodeHandle,
    activation_code: *const c_char,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let activation_code_str = match c_str_to_string(activation_code) {
        Ok(s) => s,
        Err(status) => return status,
    };

    let Some(callback) = callback else {
        return WispersStatus::MissingCallback;
    };

    let ctx = CallbackContext(ctx);
    let handle_clone = unsafe { &*handle }.clone();

    runtime::spawn(async move {
        let mut node = handle_clone.lock().await;
        let result = node.activate(&activation_code_str).await;

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, std::ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status: WispersStatus = e.into();
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Logout the node (delete local state, deregister from hub if registered, revoke from roster if activated).
///
/// The node handle is CONSUMED by this call and must not be used afterward.
/// Any in-flight FFI calls on the same handle will run to completion
/// (the inner `Arc` keeps the `Node` alive), but no new FFI calls can
/// be made because the C-side pointer is freed before the spawned
/// logout task even starts.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_logout_async(
    handle: *mut WispersNodeHandle,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let Some(callback) = callback else {
        return WispersStatus::MissingCallback;
    };

    // Consume the handle box and move it into the spawned task, which
    // drops its inner Arc when it finishes. Any in-flight tasks holding
    // clones of the handle keep the Mutex<Node> alive until they finish.
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = {
            let mut node = wrapper.lock().await;
            node.logout().await
        };

        match result {
            Ok(()) => unsafe {
                callback(ctx.ptr(), WispersStatus::Success, std::ptr::null());
            },
            Err(e) => {
                let detail = CString::new(e.to_string()).unwrap_or_default();
                let status: WispersStatus = e.into();
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr());
                }
            }
        }
    });

    WispersStatus::Success
}

/// Get the group's activation state and node list.
///
/// Returns `INVALID_STATE` if the node is in Pending state.
/// The node handle is NOT consumed.
/// On success, callback receives a `WispersGroupInfo` that must be freed
/// with `wispers_group_info_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_group_info_async(
    handle: *mut WispersNodeHandle,
    ctx: *mut c_void,
    callback: WispersGroupInfoCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let Some(callback) = callback else {
        return WispersStatus::MissingCallback;
    };

    let ctx = CallbackContext(ctx);
    let handle_clone = unsafe { &*handle }.clone();

    runtime::spawn(async move {
        let node = handle_clone.lock().await;
        let result = node.group_info().await;
        handle_group_info_result(result, ctx, callback);
    });

    WispersStatus::Success
}

// =============================================================================
// Internal helpers
// =============================================================================

fn node_state_to_ffi(state: NodeState) -> WispersNodeState {
    match state {
        NodeState::Pending => WispersNodeState::Pending,
        NodeState::Registered => WispersNodeState::Registered,
        NodeState::Activated => WispersNodeState::Activated,
    }
}

fn handle_group_info_result(
    result: Result<crate::types::GroupInfo, crate::errors::NodeStateError>,
    ctx: CallbackContext,
    callback: unsafe extern "C" fn(
        *mut c_void,
        WispersStatus,
        *const c_char,
        *mut WispersGroupInfo,
    ),
) {
    match result {
        Ok(group_info) => match WispersGroupInfo::from_group_info(group_info) {
            Ok(ffi_info) => {
                let ptr = Box::into_raw(Box::new(ffi_info));
                unsafe {
                    callback(ctx.ptr(), WispersStatus::Success, std::ptr::null(), ptr);
                }
            }
            Err(status) => {
                let detail = CString::new(format!("failed to build group info: {status:?}"))
                    .unwrap_or_default();
                unsafe {
                    callback(ctx.ptr(), status, detail.as_ptr(), std::ptr::null_mut());
                }
            }
        },
        Err(e) => {
            let detail = CString::new(e.to_string()).unwrap_or_default();
            let status: WispersStatus = e.into();
            unsafe {
                callback(ctx.ptr(), status, detail.as_ptr(), std::ptr::null_mut());
            }
        }
    }
}
