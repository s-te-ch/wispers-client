//! Callback type definitions for async FFI operations.
//!
//! All async operations use callbacks to deliver results. Callbacks are invoked
//! on a runtime thread, not the calling thread.

use crate::errors::WispersStatus;
use std::ffi::c_void;

/// Wrapper for callback context pointer that can be sent across threads.
///
/// Raw pointers aren't safe to send between threads by default. This wrapper
/// asserts that the C caller ensures the context remains valid until the
/// callback is invoked.
#[derive(Clone, Copy)]
pub struct CallbackContext(pub *mut c_void);

unsafe impl Send for CallbackContext {}
unsafe impl Sync for CallbackContext {}

impl CallbackContext {
    pub fn ptr(self) -> *mut c_void {
        self.0
    }
}

/// Basic completion callback (no result value).
///
/// Called when an async operation completes, with status indicating success/failure.
pub type WispersCallback = Option<unsafe extern "C" fn(ctx: *mut c_void, status: WispersStatus)>;

/// Callback that receives a stage indicator and one of three possible handles.
///
/// Used by `wispers_storage_restore_or_init_async`. Exactly one of the handle
/// pointers will be non-null on success, corresponding to the stage value.
pub type WispersInitCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        stage: WispersStage,
        pending: *mut super::handles::WispersPendingNodeStateHandle,
        registered: *mut super::handles::WispersRegisteredNodeStateHandle,
        activated: *mut super::handles::WispersActivatedNodeHandle,
    ),
>;

/// Callback that receives a registered state handle.
pub type WispersRegisteredCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        handle: *mut super::handles::WispersRegisteredNodeStateHandle,
    ),
>;

/// Callback that receives an activated node handle.
pub type WispersActivatedCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: WispersStatus,
        handle: *mut super::handles::WispersActivatedNodeHandle,
    ),
>;

/// Node state stage indicator for FFI.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersStage {
    /// Node needs to register with the hub.
    Pending = 0,
    /// Node is registered but not yet activated.
    Registered = 1,
    /// Node is activated and ready for P2P connections.
    Activated = 2,
}
