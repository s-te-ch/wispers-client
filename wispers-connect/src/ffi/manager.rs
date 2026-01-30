use super::callbacks::{CallbackContext, WispersInitCallback, WispersStage};
use super::handles::{
    ActivatedImpl, ManagerImpl, PendingImpl, RegisteredImpl, WispersActivatedNodeHandle,
    WispersNodeStorageHandle, WispersPendingNodeStateHandle, WispersRegisteredNodeStateHandle,
};
use super::helpers::{c_str_to_string, WispersRegistrationInfo};
use super::runtime;
use crate::errors::WispersStatus;
use crate::state::{NodeStateStage, NodeStorage};
use crate::storage::foreign::WispersNodeStateStoreCallbacks;
use crate::storage::{ForeignNodeStateStore, InMemoryNodeStateStore};
use std::ffi::c_void;
use std::os::raw::c_char;

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_new_in_memory() -> *mut WispersNodeStorageHandle {
    let storage = NodeStorage::new(InMemoryNodeStateStore::new());
    Box::into_raw(Box::new(WispersNodeStorageHandle(ManagerImpl::InMemory(
        storage,
    ))))
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_storage_new_with_callbacks(
    callbacks: *const WispersNodeStateStoreCallbacks,
) -> *mut WispersNodeStorageHandle {
    if callbacks.is_null() {
        return std::ptr::null_mut();
    }

    let callbacks = unsafe { *callbacks };
    let store = match ForeignNodeStateStore::new(callbacks) {
        Ok(store) => store,
        Err(_) => return std::ptr::null_mut(),
    };
    let storage = NodeStorage::new(store);
    Box::into_raw(Box::new(WispersNodeStorageHandle(ManagerImpl::Foreign(
        storage,
    ))))
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

    // Handle each variant separately to avoid type mismatch
    let maybe_reg: Result<Option<crate::types::NodeRegistration>, WispersStatus> = match &wrapper.0
    {
        ManagerImpl::InMemory(storage) => storage
            .read_registration()
            .map_err(|_| WispersStatus::StoreError),
        ManagerImpl::Foreign(storage) => storage
            .read_registration()
            .map_err(|_| WispersStatus::StoreError),
    };

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
        Err(status) => status,
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
    match &wrapper.0 {
        ManagerImpl::InMemory(storage) => storage.override_hub_addr(addr),
        ManagerImpl::Foreign(storage) => storage.override_hub_addr(addr),
    }

    WispersStatus::Success
}

/// Restore or initialize node state asynchronously.
///
/// On success, the callback receives the stage and exactly one non-null handle.
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

    let callback = match callback {
        Some(cb) => cb,
        None => return WispersStatus::MissingCallback,
    };

    let wrapper = unsafe { &*handle };
    let ctx = CallbackContext(ctx);

    // Clone the storage so we can move it into the async block
    match &wrapper.0 {
        ManagerImpl::InMemory(storage) => {
            let storage = storage.clone();
            runtime::spawn(async move {
                let result = storage.restore_or_init_node_state().await;
                match result {
                    Ok(stage) => {
                        let (stage_enum, pending, registered, activated) = match stage {
                            NodeStateStage::Pending(p) => {
                                let h = Box::into_raw(Box::new(WispersPendingNodeStateHandle(
                                    PendingImpl::InMemory(p),
                                )));
                                (WispersStage::Pending, h, std::ptr::null_mut(), std::ptr::null_mut())
                            }
                            NodeStateStage::Registered(r) => {
                                let h = Box::into_raw(Box::new(WispersRegisteredNodeStateHandle(
                                    RegisteredImpl::InMemory(r),
                                )));
                                (WispersStage::Registered, std::ptr::null_mut(), h, std::ptr::null_mut())
                            }
                            NodeStateStage::Activated(a) => {
                                let h = Box::into_raw(Box::new(WispersActivatedNodeHandle(
                                    ActivatedImpl::InMemory(a),
                                )));
                                (WispersStage::Activated, std::ptr::null_mut(), std::ptr::null_mut(), h)
                            }
                        };
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, stage_enum, pending, registered, activated);
                        }
                    }
                    Err(e) => {
                        let status = map_node_state_error_in_memory(&e);
                        unsafe {
                            callback(
                                ctx.ptr(),
                                status,
                                WispersStage::Pending,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }
            });
        }
        ManagerImpl::Foreign(storage) => {
            let storage = storage.clone();
            runtime::spawn(async move {
                let result = storage.restore_or_init_node_state().await;
                match result {
                    Ok(stage) => {
                        let (stage_enum, pending, registered, activated) = match stage {
                            NodeStateStage::Pending(p) => {
                                let h = Box::into_raw(Box::new(WispersPendingNodeStateHandle(
                                    PendingImpl::Foreign(p),
                                )));
                                (WispersStage::Pending, h, std::ptr::null_mut(), std::ptr::null_mut())
                            }
                            NodeStateStage::Registered(r) => {
                                let h = Box::into_raw(Box::new(WispersRegisteredNodeStateHandle(
                                    RegisteredImpl::Foreign(r),
                                )));
                                (WispersStage::Registered, std::ptr::null_mut(), h, std::ptr::null_mut())
                            }
                            NodeStateStage::Activated(a) => {
                                let h = Box::into_raw(Box::new(WispersActivatedNodeHandle(
                                    ActivatedImpl::Foreign(a),
                                )));
                                (WispersStage::Activated, std::ptr::null_mut(), std::ptr::null_mut(), h)
                            }
                        };
                        unsafe {
                            callback(ctx.ptr(), WispersStatus::Success, stage_enum, pending, registered, activated);
                        }
                    }
                    Err(e) => {
                        let status = map_node_state_error_foreign(&e);
                        unsafe {
                            callback(
                                ctx.ptr(),
                                status,
                                WispersStage::Pending,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            );
                        }
                    }
                }
            });
        }
    }

    WispersStatus::Success
}

fn map_node_state_error_in_memory(
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

fn map_node_state_error_foreign(
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
