use super::callbacks::{CallbackContext, WispersCallback, WispersNodeListCallback, WispersNodeState};
use super::handles::WispersNodeHandle;
use super::helpers::{c_str_to_string, WispersNodeList};
use super::runtime;
use crate::errors::WispersStatus;
use crate::node::NodeState;
use std::ffi::c_void;
use std::os::raw::c_char;

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
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_state(handle: *mut WispersNodeHandle) -> WispersNodeState {
    if handle.is_null() {
        return WispersNodeState::Pending;
    }

    let wrapper = unsafe { &*handle };
    match wrapper.0.state() {
        NodeState::Pending => WispersNodeState::Pending,
        NodeState::Registered => WispersNodeState::Registered,
        NodeState::Activated => WispersNodeState::Activated,
    }
}

/// Register the node with the hub using a registration token.
///
/// Returns INVALID_STATE if the node is not in Pending state.
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

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);

    // We need to use a raw pointer that can be sent across threads
    let handle_ptr = SendableNodePtr(handle);

    runtime::spawn(async move {
        // Safety: caller must ensure handle is valid and not used concurrently
        let wrapper = unsafe { handle_ptr.get_mut() };
        let result = wrapper.0.register(&token_str).await;

        let status = match result {
            Ok(()) => WispersStatus::Success,
            Err(e) => e.into(),
        };
        unsafe {
            callback(ctx.ptr(), status);
        }
    });

    WispersStatus::Success
}

/// Activate the node by pairing with an endorser.
///
/// The pairing code format is "node_number-secret" (e.g., "1-abc123xyz0").
/// Returns INVALID_STATE if the node is not in Registered state.
/// The node handle is NOT consumed - it transitions to Activated state on success.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_activate_async(
    handle: *mut WispersNodeHandle,
    pairing_code: *const c_char,
    ctx: *mut c_void,
    callback: WispersCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let pairing_code_str = match c_str_to_string(pairing_code) {
        Ok(s) => s,
        Err(status) => return status,
    };

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let handle_ptr = SendableNodePtr(handle);

    runtime::spawn(async move {
        // Safety: caller must ensure handle is valid and not used concurrently
        let wrapper = unsafe { handle_ptr.get_mut() };
        let result = wrapper.0.activate(&pairing_code_str).await;

        let status = match result {
            Ok(()) => WispersStatus::Success,
            Err(e) => e.into(),
        };
        unsafe {
            callback(ctx.ptr(), status);
        }
    });

    WispersStatus::Success
}

/// Logout the node (delete local state, deregister from hub if registered, revoke from roster if activated).
///
/// The node handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_logout_async(
    handle: *mut WispersNodeHandle,
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

    // Consume the handle
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    runtime::spawn(async move {
        let result = wrapper.0.logout().await;

        let status = match result {
            Ok(()) => WispersStatus::Success,
            Err(e) => e.into(),
        };
        unsafe {
            callback(ctx.ptr(), status);
        }
    });

    WispersStatus::Success
}

/// List all nodes in the connectivity group.
///
/// Returns INVALID_STATE if the node is in Pending state.
/// The node handle is NOT consumed.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_list_nodes_async(
    handle: *mut WispersNodeHandle,
    ctx: *mut c_void,
    callback: WispersNodeListCallback,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let ctx = CallbackContext(ctx);
    let handle_ptr = SendableNodePtr(handle);

    runtime::spawn(async move {
        // Safety: caller must ensure handle is valid and not used concurrently
        let wrapper = unsafe { handle_ptr.get() };
        let result = wrapper.0.list_nodes().await.map_err(|e| e.into());
        handle_list_nodes_result(result, ctx, callback);
    });

    WispersStatus::Success
}

// Helper to send node pointer across threads.
// Safety: The caller must ensure the handle remains valid and
// is not accessed concurrently from other threads.
struct SendableNodePtr(*mut WispersNodeHandle);
unsafe impl Send for SendableNodePtr {}
unsafe impl Sync for SendableNodePtr {}

impl SendableNodePtr {
    /// Get an immutable reference to the inner handle.
    /// SAFETY: The caller must ensure the pointer is valid.
    unsafe fn get(&self) -> &WispersNodeHandle {
        unsafe { &*self.0 }
    }

    /// Get a mutable reference to the inner handle.
    /// SAFETY: The caller must ensure the pointer is valid.
    unsafe fn get_mut(&self) -> &mut WispersNodeHandle {
        unsafe { &mut *self.0 }
    }
}

fn handle_list_nodes_result(
    result: Result<Vec<crate::types::NodeInfo>, WispersStatus>,
    ctx: CallbackContext,
    callback: unsafe extern "C" fn(*mut c_void, WispersStatus, *mut WispersNodeList),
) {
    match result {
        Ok(nodes) => {
            match WispersNodeList::from_node_infos(nodes) {
                Ok(list) => {
                    let list_ptr = Box::into_raw(Box::new(list));
                    unsafe {
                        callback(ctx.ptr(), WispersStatus::Success, list_ptr);
                    }
                }
                Err(status) => {
                    unsafe {
                        callback(ctx.ptr(), status, std::ptr::null_mut());
                    }
                }
            }
        }
        Err(status) => {
            unsafe {
                callback(ctx.ptr(), status, std::ptr::null_mut());
            }
        }
    }
}
