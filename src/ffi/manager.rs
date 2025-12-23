use super::handles::{
    ManagerImpl, WispersNodeStateManagerHandle, WispersPendingNodeStateHandle,
    WispersRegisteredNodeStateHandle, restore_or_init_internal,
};
use super::helpers::{c_str_to_string, optional_c_str, reset_out_ptr};
use crate::errors::WispersStatus;
use crate::state::NodeStateManager;
use crate::storage::foreign::WispersNodeStateStoreCallbacks;
use crate::storage::{ForeignNodeStateStore, InMemoryNodeStateStore};
use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn wispers_in_memory_manager_new() -> *mut WispersNodeStateManagerHandle {
    let manager = NodeStateManager::new(InMemoryNodeStateStore::new());
    Box::into_raw(Box::new(WispersNodeStateManagerHandle(
        ManagerImpl::InMemory(manager),
    )))
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_manager_new_with_store(
    callbacks: *const WispersNodeStateStoreCallbacks,
) -> *mut WispersNodeStateManagerHandle {
    if callbacks.is_null() {
        return std::ptr::null_mut();
    }

    let callbacks = unsafe { *callbacks };
    let store = match ForeignNodeStateStore::new(callbacks) {
        Ok(store) => store,
        Err(_) => return std::ptr::null_mut(),
    };
    let manager = NodeStateManager::new(store);
    Box::into_raw(Box::new(WispersNodeStateManagerHandle(
        ManagerImpl::Foreign(manager),
    )))
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_manager_free(handle: *mut WispersNodeStateManagerHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_manager_restore_or_init(
    handle: *mut WispersNodeStateManagerHandle,
    app_namespace: *const c_char,
    profile_namespace: *const c_char,
    out_pending: *mut *mut WispersPendingNodeStateHandle,
    out_registered: *mut *mut WispersRegisteredNodeStateHandle,
) -> WispersStatus {
    use super::handles::NodeStateStageImpl::{Pending, Registered};

    if handle.is_null() || out_pending.is_null() || out_registered.is_null() {
        return WispersStatus::NullPointer;
    }

    unsafe {
        reset_out_ptr(out_pending);
        reset_out_ptr(out_registered);
    }

    let app = match c_str_to_string(app_namespace) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let profile = match optional_c_str(profile_namespace) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let manager = unsafe { &mut (*handle).0 };
    match restore_or_init_internal(manager, app, profile) {
        Ok(Pending(pending)) => {
            let boxed = Box::new(WispersPendingNodeStateHandle(pending));
            unsafe {
                *out_pending = Box::into_raw(boxed);
            }
            WispersStatus::Success
        }
        Ok(Registered(registered)) => {
            let boxed = Box::new(WispersRegisteredNodeStateHandle(registered));
            unsafe {
                *out_registered = Box::into_raw(boxed);
            }
            WispersStatus::Success
        }
        Err(status) => status,
    }
}
