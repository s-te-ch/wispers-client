use super::callbacks::{CallbackContext, WispersNodeListCallback, WispersRegisteredCallback};
use super::handles::{
    ActivatedImpl, PendingImpl, RegisteredImpl, WispersActivatedNodeHandle,
    WispersPendingNodeHandle, WispersRegisteredNodeHandle, complete_registration_internal,
};
use super::helpers::{c_str_to_string, reset_out_ptr, WispersNodeList};
use super::runtime;
use crate::errors::WispersStatus;
use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_node_free(handle: *mut WispersPendingNodeHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_node_free(handle: *mut WispersRegisteredNodeHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_activated_node_free(handle: *mut WispersActivatedNodeHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_node_complete_registration(
    handle: *mut WispersPendingNodeHandle,
    connectivity_group_id: *const c_char,
    node_number: c_int,
    auth_token: *const c_char,
    out_registered: *mut *mut WispersRegisteredNodeHandle,
) -> WispersStatus {
    if handle.is_null() || out_registered.is_null() {
        return WispersStatus::NullPointer;
    }

    unsafe {
        reset_out_ptr(out_registered);
    }

    let connectivity = match c_str_to_string(connectivity_group_id) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let token = match c_str_to_string(auth_token) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let wrapper = unsafe { Box::from_raw(handle) };
    let registration = NodeRegistration::new(
        ConnectivityGroupId::from(connectivity),
        node_number,
        AuthToken::new(token),
    );

    match complete_registration_internal(wrapper.0, registration) {
        Ok(registered) => {
            let boxed = Box::new(WispersRegisteredNodeHandle(registered));
            unsafe {
                *out_registered = Box::into_raw(boxed);
            }
            WispersStatus::Success
        }
        Err(status) => status,
    }
}

/// Register the pending node with the hub using a registration token.
///
/// On success, the callback receives the registered state handle.
/// The pending handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_node_register_async(
    handle: *mut WispersPendingNodeHandle,
    token: *const c_char,
    ctx: *mut c_void,
    callback: WispersRegisteredCallback,
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

    // Consume the handle
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    match wrapper.0 {
        PendingImpl::InMemory(pending) => {
            runtime::spawn(async move {
                let result = pending.register(&token_str).await;
                match result {
                    Ok(registered) => {
                        let h = Box::into_raw(Box::new(WispersRegisteredNodeHandle(
                            RegisteredImpl::InMemory(registered),
                        )));
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, h);
                        }
                    }
                    Err(e) => {
                        let status = map_error_in_memory(&e);
                        unsafe {
                            callback(ctx.ptr(), status, std::ptr::null_mut());
                        }
                    }
                }
            });
        }
        PendingImpl::Foreign(pending) => {
            runtime::spawn(async move {
                let result = pending.register(&token_str).await;
                match result {
                    Ok(registered) => {
                        let h = Box::into_raw(Box::new(WispersRegisteredNodeHandle(
                            RegisteredImpl::Foreign(registered),
                        )));
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, h);
                        }
                    }
                    Err(e) => {
                        let status = map_error_foreign(&e);
                        unsafe {
                            callback(ctx.ptr(), status, std::ptr::null_mut());
                        }
                    }
                }
            });
        }
    }

    WispersStatus::Success
}

fn map_error_in_memory(
    e: &crate::errors::NodeStateError<crate::storage::InMemoryStoreError>,
) -> WispersStatus {
    use crate::errors::NodeStateError;
    match e {
        NodeStateError::Store(_) => WispersStatus::StoreError,
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

fn map_error_foreign(
    e: &crate::errors::NodeStateError<crate::storage::foreign::ForeignStoreError>,
) -> WispersStatus {
    use crate::errors::NodeStateError;
    use crate::storage::foreign::ForeignStoreError;
    match e {
        NodeStateError::Store(ForeignStoreError::Status(s)) => *s,
        NodeStateError::Store(_) => WispersStatus::StoreError,
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

/// Logout a pending node (delete local state).
///
/// The pending handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_node_logout_async(
    handle: *mut WispersPendingNodeHandle,
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

    // Consume the handle
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    match wrapper.0 {
        PendingImpl::InMemory(pending) => {
            runtime::spawn(async move {
                let result = pending.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_in_memory(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
        PendingImpl::Foreign(pending) => {
            runtime::spawn(async move {
                let result = pending.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_foreign(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
    }

    WispersStatus::Success
}

/// Logout a registered node (deregister from hub, then delete local state).
///
/// The registered handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_node_logout_async(
    handle: *mut WispersRegisteredNodeHandle,
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

    // Consume the handle
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    match wrapper.0 {
        RegisteredImpl::InMemory(registered) => {
            runtime::spawn(async move {
                let result = registered.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_in_memory(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
        RegisteredImpl::Foreign(registered) => {
            runtime::spawn(async move {
                let result = registered.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_foreign(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
    }

    WispersStatus::Success
}

/// Logout an activated node (self-revoke from roster, deregister from hub, delete local state).
///
/// The activated handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_activated_node_logout_async(
    handle: *mut WispersActivatedNodeHandle,
    ctx: *mut c_void,
    callback: super::callbacks::WispersCallback,
) -> WispersStatus {
    use super::handles::ActivatedImpl;

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

    match wrapper.0 {
        ActivatedImpl::InMemory(activated) => {
            runtime::spawn(async move {
                let result = activated.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_in_memory(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
        ActivatedImpl::Foreign(activated) => {
            runtime::spawn(async move {
                let result = activated.logout().await;
                let status = match result {
                    Ok(()) => WispersStatus::Success,
                    Err(e) => map_error_foreign(&e),
                };
                unsafe {
                    callback(ctx.ptr(), status);
                }
            });
        }
    }

    WispersStatus::Success
}

/// Activate a registered node by pairing with an endorser.
///
/// The pairing code format is "node_number-secret" (e.g., "1-abc123xyz0").
/// On success, the callback receives the activated node handle.
/// The registered handle is CONSUMED by this call and must not be used afterward.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_node_activate_async(
    handle: *mut WispersRegisteredNodeHandle,
    pairing_code: *const c_char,
    ctx: *mut c_void,
    callback: super::callbacks::WispersActivatedCallback,
) -> WispersStatus {
    use super::handles::ActivatedImpl;

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

    // Consume the handle
    let wrapper = unsafe { Box::from_raw(handle) };
    let ctx = CallbackContext(ctx);

    match wrapper.0 {
        RegisteredImpl::InMemory(registered) => {
            runtime::spawn(async move {
                let result = registered.activate(&pairing_code_str).await;
                match result {
                    Ok(activated) => {
                        let h = Box::into_raw(Box::new(WispersActivatedNodeHandle(
                            ActivatedImpl::InMemory(activated),
                        )));
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, h);
                        }
                    }
                    Err(e) => {
                        let status = map_error_in_memory(&e);
                        unsafe {
                            callback(ctx.ptr(), status, std::ptr::null_mut());
                        }
                    }
                }
            });
        }
        RegisteredImpl::Foreign(registered) => {
            runtime::spawn(async move {
                let result = registered.activate(&pairing_code_str).await;
                match result {
                    Ok(activated) => {
                        let h = Box::into_raw(Box::new(WispersActivatedNodeHandle(
                            ActivatedImpl::Foreign(activated),
                        )));
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, h);
                        }
                    }
                    Err(e) => {
                        let status = map_error_foreign(&e);
                        unsafe {
                            callback(ctx.ptr(), status, std::ptr::null_mut());
                        }
                    }
                }
            });
        }
    }

    WispersStatus::Success
}

/// List all nodes in the connectivity group for a registered node.
///
/// The registered handle is NOT consumed and remains valid after this call.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_node_list_nodes_async(
    handle: *mut WispersRegisteredNodeHandle,
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

    let wrapper = unsafe { &*handle };
    let ctx = CallbackContext(ctx);

    // Extract what we need before spawning (list_nodes only needs hub_addr and registration)
    let (hub_addr, registration) = match &wrapper.0 {
        RegisteredImpl::InMemory(registered) => {
            (registered.hub_addr(), registered.registration().clone())
        }
        RegisteredImpl::Foreign(registered) => {
            (registered.hub_addr(), registered.registration().clone())
        }
    };

    runtime::spawn(async move {
        let result = list_nodes_impl(&hub_addr, &registration).await;
        handle_list_nodes_result_hub(result, ctx, callback);
    });

    WispersStatus::Success
}

/// List all nodes in the connectivity group for an activated node.
///
/// The activated handle is NOT consumed and remains valid after this call.
#[unsafe(no_mangle)]
pub extern "C" fn wispers_activated_node_list_nodes_async(
    handle: *mut WispersActivatedNodeHandle,
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

    let wrapper = unsafe { &*handle };
    let ctx = CallbackContext(ctx);

    let (hub_addr, registration) = match &wrapper.0 {
        ActivatedImpl::InMemory(activated) => {
            (activated.hub_addr(), activated.registration().clone())
        }
        ActivatedImpl::Foreign(activated) => {
            (activated.hub_addr(), activated.registration().clone())
        }
    };

    runtime::spawn(async move {
        let result = list_nodes_impl(&hub_addr, &registration).await;
        handle_list_nodes_result_hub(result, ctx, callback);
    });

    WispersStatus::Success
}

async fn list_nodes_impl(
    hub_addr: &str,
    registration: &NodeRegistration,
) -> Result<Vec<crate::hub::Node>, crate::hub::HubError> {
    use crate::hub::HubClient;

    let mut client = HubClient::connect(hub_addr).await?;
    client.list_nodes(registration).await
}

fn handle_list_nodes_result_hub(
    result: Result<Vec<crate::hub::Node>, crate::hub::HubError>,
    ctx: CallbackContext,
    callback: unsafe extern "C" fn(*mut c_void, WispersStatus, *mut WispersNodeList),
) {
    match result {
        Ok(nodes) => {
            match WispersNodeList::from_nodes(nodes) {
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
        Err(_) => {
            unsafe {
                callback(ctx.ptr(), WispersStatus::HubError, std::ptr::null_mut());
            }
        }
    }
}

