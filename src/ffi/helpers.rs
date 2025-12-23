use crate::errors::WispersStatus;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

pub fn c_str_to_string(ptr: *const c_char) -> Result<String, WispersStatus> {
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

pub fn optional_c_str(ptr: *const c_char) -> Result<Option<String>, WispersStatus> {
    if ptr.is_null() {
        Ok(None)
    } else {
        c_str_to_string(ptr).map(Some)
    }
}

pub unsafe fn reset_out_ptr<T>(out: *mut *mut T) {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}
