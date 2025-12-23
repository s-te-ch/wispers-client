use super::handles::{
    WispersPendingNodeStateHandle, WispersRegisteredNodeStateHandle,
    complete_registration_internal, delete_registered_internal, registration_url_internal,
};
use super::helpers::{c_str_to_string, reset_out_ptr};
use crate::errors::WispersStatus;
use crate::types::{ConnectivityGroupId, NodeId, NodeRegistration};
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

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
pub extern "C" fn wispers_pending_state_registration_url(
    handle: *mut WispersPendingNodeStateHandle,
    base_url: *const c_char,
) -> *mut c_char {
    if handle.is_null() || base_url.is_null() {
        return ptr::null_mut();
    }

    let base = match c_str_to_string(base_url) {
        Ok(value) => value,
        Err(_) => return ptr::null_mut(),
    };

    let url = registration_url_internal(unsafe { &(*handle).0 }, &base);
    match CString::new(url) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_pending_state_complete_registration(
    handle: *mut WispersPendingNodeStateHandle,
    connectivity_group_id: *const c_char,
    node_id: *const c_char,
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
    let node = match c_str_to_string(node_id) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let wrapper = unsafe { Box::from_raw(handle) };
    let registration = NodeRegistration {
        connectivity_group_id: ConnectivityGroupId::from(connectivity),
        node_id: NodeId::from(node),
    };

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

#[unsafe(no_mangle)]
pub extern "C" fn wispers_registered_state_delete(
    handle: *mut WispersRegisteredNodeStateHandle,
) -> WispersStatus {
    if handle.is_null() {
        return WispersStatus::NullPointer;
    }
    let wrapper = unsafe { Box::from_raw(handle) };
    match delete_registered_internal(wrapper.0) {
        Ok(_) => WispersStatus::Success,
        Err(status) => status,
    }
}
