use super::callbacks::{CallbackContext, WispersRegisteredCallback};
use super::handles::{
    PendingImpl, RegisteredImpl, WispersActivatedNodeHandle, WispersPendingNodeStateHandle,
    WispersRegisteredNodeStateHandle, complete_registration_internal,
};
use super::helpers::{c_str_to_string, reset_out_ptr};
use super::runtime;
use crate::errors::WispersStatus;
use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_state_free(handle: *mut WispersPendingNodeStateHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_state_free(handle: *mut WispersRegisteredNodeStateHandle) {
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
pub extern "C" fn wispers_pending_state_complete_registration(
    handle: *mut WispersPendingNodeStateHandle,
    connectivity_group_id: *const c_char,
    node_number: c_int,
    auth_token: *const c_char,
    out_registered: *mut *mut WispersRegisteredNodeStateHandle,
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
            let boxed = Box::new(WispersRegisteredNodeStateHandle(registered));
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
pub extern "C" fn wispers_pending_state_register_async(
    handle: *mut WispersPendingNodeStateHandle,
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
                        let h = Box::into_raw(Box::new(WispersRegisteredNodeStateHandle(
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
                        let h = Box::into_raw(Box::new(WispersRegisteredNodeStateHandle(
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
    }
}

// TODO: wispers_registered_state_logout_async - Phase 4
