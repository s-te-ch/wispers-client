use crate::errors::WispersStatus;
use crate::types::{NodeInfo, NodeRegistration};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
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

/// Registration info returned to C callers.
#[repr(C)]
pub struct WispersRegistrationInfo {
    pub connectivity_group_id: *mut c_char,
    pub node_number: c_int,
    pub auth_token: *mut c_char,
}

impl WispersRegistrationInfo {
    /// Create from a NodeRegistration, allocating C strings.
    pub fn from_registration(reg: &NodeRegistration) -> Result<Self, WispersStatus> {
        let cg_id = CString::new(reg.connectivity_group_id.to_string())
            .map_err(|_| WispersStatus::InvalidUtf8)?;
        let token_str = reg
            .auth_token()
            .map(|t| t.as_str())
            .unwrap_or("");
        let token = CString::new(token_str).map_err(|_| WispersStatus::InvalidUtf8)?;

        Ok(Self {
            connectivity_group_id: cg_id.into_raw(),
            node_number: reg.node_number,
            auth_token: token.into_raw(),
        })
    }

    /// Create a zeroed/null instance.
    pub fn null() -> Self {
        Self {
            connectivity_group_id: ptr::null_mut(),
            node_number: 0,
            auth_token: ptr::null_mut(),
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
    }
}

/// Node information returned to C callers.
#[repr(C)]
pub struct WispersNode {
    pub node_number: c_int,
    pub name: *mut c_char,
    /// Whether this is the current node (self).
    pub is_self: bool,
    /// Activation status: 0 = unknown, 1 = not activated, 2 = activated.
    pub activation_status: c_int,
    pub last_seen_at_millis: i64,
}

/// Activation status values for WispersNode.
pub const WISPERS_ACTIVATION_UNKNOWN: c_int = 0;
pub const WISPERS_ACTIVATION_NOT_ACTIVATED: c_int = 1;
pub const WISPERS_ACTIVATION_ACTIVATED: c_int = 2;

/// List of nodes returned to C callers.
#[repr(C)]
pub struct WispersNodeList {
    pub nodes: *mut WispersNode,
    pub count: usize,
}

impl WispersNodeList {
    /// Create from a Vec<NodeInfo>, allocating C strings.
    pub fn from_node_infos(nodes: Vec<NodeInfo>) -> Result<Self, WispersStatus> {
        let count = nodes.len();
        if count == 0 {
            return Ok(Self {
                nodes: ptr::null_mut(),
                count: 0,
            });
        }

        let mut c_nodes: Vec<WispersNode> = Vec::with_capacity(count);
        for node in nodes {
            let name = CString::new(node.name).map_err(|_| WispersStatus::InvalidUtf8)?;
            let activation_status = match node.is_activated {
                None => WISPERS_ACTIVATION_UNKNOWN,
                Some(false) => WISPERS_ACTIVATION_NOT_ACTIVATED,
                Some(true) => WISPERS_ACTIVATION_ACTIVATED,
            };
            c_nodes.push(WispersNode {
                node_number: node.node_number,
                name: name.into_raw(),
                is_self: node.is_self,
                activation_status,
                last_seen_at_millis: node.last_seen_at_millis,
            });
        }

        let ptr = c_nodes.as_mut_ptr();
        std::mem::forget(c_nodes);

        Ok(Self { nodes: ptr, count })
    }

    /// Create an empty list.
    pub fn empty() -> Self {
        Self {
            nodes: ptr::null_mut(),
            count: 0,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wispers_node_list_free(list: *mut WispersNodeList) {
    if list.is_null() {
        return;
    }
    unsafe {
        let list = &mut *list;
        if !list.nodes.is_null() && list.count > 0 {
            // Reconstruct the Vec to properly free it
            let nodes = Vec::from_raw_parts(list.nodes, list.count, list.count);
            for node in nodes {
                if !node.name.is_null() {
                    drop(CString::from_raw(node.name));
                }
            }
        }
        list.nodes = ptr::null_mut();
        list.count = 0;
    }
}
