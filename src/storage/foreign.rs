use crate::errors::WispersStatus;
use crate::storage::NodeStateStore;
use crate::types::{AppNamespace, NodeRegistration, NodeState, ProfileNamespace, RootKey};
use bincode;
use std::ffi::{CString, c_void};
use std::fmt;

const INITIAL_REGISTRATION_BUFFER: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WispersNodeStateStoreCallbacks {
    pub ctx: *mut c_void,
    pub load_root_key: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
            *mut u8,
            usize,
        ) -> WispersStatus,
    >,
    pub save_root_key: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
            *const u8,
            usize,
        ) -> WispersStatus,
    >,
    pub delete_root_key: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
        ) -> WispersStatus,
    >,
    pub load_registration: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
            *mut u8,
            usize,
            *mut usize,
        ) -> WispersStatus,
    >,
    pub save_registration: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
            *const u8,
            usize,
        ) -> WispersStatus,
    >,
    pub delete_registration: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
        ) -> WispersStatus,
    >,
}

unsafe impl Send for WispersNodeStateStoreCallbacks {}
unsafe impl Sync for WispersNodeStateStoreCallbacks {}

pub struct ForeignNodeStateStore {
    callbacks: WispersNodeStateStoreCallbacks,
}

#[derive(Debug)]
pub enum ForeignStoreError {
    MissingCallback(&'static str),
    CStringConversion,
    RegistrationEncode,
    RegistrationDecode,
    Status(WispersStatus),
}

impl fmt::Display for ForeignStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForeignStoreError::MissingCallback(name) => write!(f, "missing callback: {name}"),
            ForeignStoreError::CStringConversion => write!(f, "namespace contained null byte"),
            ForeignStoreError::RegistrationEncode => write!(f, "failed to encode registration"),
            ForeignStoreError::RegistrationDecode => write!(f, "failed to decode registration"),
            ForeignStoreError::Status(status) => write!(f, "store callback returned {status:?}"),
        }
    }
}

impl std::error::Error for ForeignStoreError {}

impl ForeignNodeStateStore {
    pub fn new(callbacks: WispersNodeStateStoreCallbacks) -> Result<Self, ForeignStoreError> {
        if callbacks.load_root_key.is_none() {
            return Err(ForeignStoreError::MissingCallback("load_root_key"));
        }
        if callbacks.save_root_key.is_none() {
            return Err(ForeignStoreError::MissingCallback("save_root_key"));
        }
        if callbacks.delete_root_key.is_none() {
            return Err(ForeignStoreError::MissingCallback("delete_root_key"));
        }
        if callbacks.load_registration.is_none() {
            return Err(ForeignStoreError::MissingCallback("load_registration"));
        }
        if callbacks.save_registration.is_none() {
            return Err(ForeignStoreError::MissingCallback("save_registration"));
        }
        if callbacks.delete_registration.is_none() {
            return Err(ForeignStoreError::MissingCallback("delete_registration"));
        }

        Ok(Self { callbacks })
    }

    fn namespace_to_cstring(value: &impl AsRef<str>) -> Result<CString, ForeignStoreError> {
        CString::new(value.as_ref()).map_err(|_| ForeignStoreError::CStringConversion)
    }

    fn call_load_root_key(
        &self,
        app: &CString,
        profile: &CString,
    ) -> Result<Option<[u8; crate::types::ROOT_KEY_LEN]>, ForeignStoreError> {
        let mut buffer = [0u8; crate::types::ROOT_KEY_LEN];
        let callback = self.callbacks.load_root_key.unwrap();
        let status = unsafe {
            callback(
                self.callbacks.ctx,
                app.as_ptr(),
                profile.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        match status {
            WispersStatus::Success => Ok(Some(buffer)),
            WispersStatus::NotFound => Ok(None),
            other => Err(ForeignStoreError::Status(other)),
        }
    }

    fn call_save_root_key(
        &self,
        app: &CString,
        profile: &CString,
        root_key: &[u8; crate::types::ROOT_KEY_LEN],
    ) -> Result<(), ForeignStoreError> {
        let callback = self.callbacks.save_root_key.unwrap();
        let status = unsafe {
            callback(
                self.callbacks.ctx,
                app.as_ptr(),
                profile.as_ptr(),
                root_key.as_ptr(),
                root_key.len(),
            )
        };
        match status {
            WispersStatus::Success => Ok(()),
            other => Err(ForeignStoreError::Status(other)),
        }
    }

    fn call_delete_root_key(
        &self,
        app: &CString,
        profile: &CString,
    ) -> Result<(), ForeignStoreError> {
        let callback = self.callbacks.delete_root_key.unwrap();
        let status = unsafe { callback(self.callbacks.ctx, app.as_ptr(), profile.as_ptr()) };
        match status {
            WispersStatus::Success | WispersStatus::NotFound => Ok(()),
            other => Err(ForeignStoreError::Status(other)),
        }
    }

    fn call_load_registration(
        &self,
        app: &CString,
        profile: &CString,
    ) -> Result<Option<NodeRegistration>, ForeignStoreError> {
        let callback = self.callbacks.load_registration.unwrap();
        let mut buffer = vec![0u8; INITIAL_REGISTRATION_BUFFER];
        let mut required = 0usize;

        loop {
            let status = unsafe {
                callback(
                    self.callbacks.ctx,
                    app.as_ptr(),
                    profile.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut required,
                )
            };

            match status {
                WispersStatus::Success => {
                    buffer.truncate(required);
                    return deserialize_registration(&buffer)
                        .map_err(|_| ForeignStoreError::RegistrationDecode);
                }
                WispersStatus::NotFound => return Ok(None),
                WispersStatus::BufferTooSmall => {
                    if required == 0 {
                        return Err(ForeignStoreError::Status(WispersStatus::BufferTooSmall));
                    }
                    buffer.resize(required, 0);
                }
                other => return Err(ForeignStoreError::Status(other)),
            }
        }
    }

    fn call_save_registration(
        &self,
        app: &CString,
        profile: &CString,
        registration: Option<&NodeRegistration>,
    ) -> Result<(), ForeignStoreError> {
        let callback = self.callbacks.save_registration.unwrap();
        let bytes = serialize_registration(registration)
            .map_err(|_| ForeignStoreError::RegistrationEncode)?;
        let status = unsafe {
            callback(
                self.callbacks.ctx,
                app.as_ptr(),
                profile.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        match status {
            WispersStatus::Success => Ok(()),
            other => Err(ForeignStoreError::Status(other)),
        }
    }

    fn call_delete_registration(
        &self,
        app: &CString,
        profile: &CString,
    ) -> Result<(), ForeignStoreError> {
        let callback = self.callbacks.delete_registration.unwrap();
        let status = unsafe { callback(self.callbacks.ctx, app.as_ptr(), profile.as_ptr()) };
        match status {
            WispersStatus::Success | WispersStatus::NotFound => Ok(()),
            other => Err(ForeignStoreError::Status(other)),
        }
    }
}

unsafe impl Send for ForeignNodeStateStore {}
unsafe impl Sync for ForeignNodeStateStore {}

impl NodeStateStore for ForeignNodeStateStore {
    type Error = ForeignStoreError;

    fn load(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<Option<NodeState>, Self::Error> {
        let app_c = Self::namespace_to_cstring(app_namespace)?;
        let profile_c = Self::namespace_to_cstring(profile_namespace)?;
        let root_key = match self.call_load_root_key(&app_c, &profile_c)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let registration = self.call_load_registration(&app_c, &profile_c)?;
        let mut state =
            NodeState::initialize_with_namespaces(app_namespace.clone(), profile_namespace.clone());
        state.root_key = RootKey::from_bytes(root_key);
        state.registration = registration;
        Ok(Some(state))
    }

    fn save(&self, state: &NodeState) -> Result<(), Self::Error> {
        let app_c = Self::namespace_to_cstring(&state.app_namespace)?;
        let profile_c = Self::namespace_to_cstring(&state.profile_namespace)?;
        self.call_save_root_key(&app_c, &profile_c, state.root_key.as_bytes())?;
        self.call_save_registration(&app_c, &profile_c, state.registration.as_ref())?;
        Ok(())
    }

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error> {
        let app_c = Self::namespace_to_cstring(app_namespace)?;
        let profile_c = Self::namespace_to_cstring(profile_namespace)?;
        self.call_delete_root_key(&app_c, &profile_c)?;
        self.call_delete_registration(&app_c, &profile_c)?;
        Ok(())
    }
}

fn serialize_registration(
    registration: Option<&NodeRegistration>,
) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(&registration)
}

fn deserialize_registration(bytes: &[u8]) -> Result<Option<NodeRegistration>, bincode::Error> {
    bincode::deserialize(bytes)
}
