use crate::errors::WispersStatus;
use crate::storage::{NodeStateStore, StorageError};
use crate::types::{NodeRegistration, PersistedNodeState, RootKey};
use bincode;
use std::ffi::c_void;

const INITIAL_REGISTRATION_BUFFER: usize = 256;

/// Host-provided storage callbacks.
///
/// The `ctx` pointer carries all context the host needs, including any
/// namespace or isolation information. The library does not manage namespacing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WispersNodeStorageCallbacks {
    pub ctx: *mut c_void,
    pub load_root_key:
        Option<unsafe extern "C" fn(ctx: *mut c_void, out: *mut u8, len: usize) -> WispersStatus>,
    pub save_root_key: Option<
        unsafe extern "C" fn(ctx: *mut c_void, key: *const u8, len: usize) -> WispersStatus,
    >,
    pub delete_root_key: Option<unsafe extern "C" fn(ctx: *mut c_void) -> WispersStatus>,
    pub load_registration: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> WispersStatus,
    >,
    pub save_registration: Option<
        unsafe extern "C" fn(ctx: *mut c_void, buf: *const u8, len: usize) -> WispersStatus,
    >,
    pub delete_registration: Option<unsafe extern "C" fn(ctx: *mut c_void) -> WispersStatus>,
}

unsafe impl Send for WispersNodeStorageCallbacks {}
unsafe impl Sync for WispersNodeStorageCallbacks {}

pub struct ForeignNodeStateStore {
    callbacks: WispersNodeStorageCallbacks,
}

impl ForeignNodeStateStore {
    pub fn new(callbacks: WispersNodeStorageCallbacks) -> Result<Self, StorageError> {
        if callbacks.load_root_key.is_none() {
            return Err(StorageError::MissingCallback("load_root_key"));
        }
        if callbacks.save_root_key.is_none() {
            return Err(StorageError::MissingCallback("save_root_key"));
        }
        if callbacks.delete_root_key.is_none() {
            return Err(StorageError::MissingCallback("delete_root_key"));
        }
        if callbacks.load_registration.is_none() {
            return Err(StorageError::MissingCallback("load_registration"));
        }
        if callbacks.save_registration.is_none() {
            return Err(StorageError::MissingCallback("save_registration"));
        }
        if callbacks.delete_registration.is_none() {
            return Err(StorageError::MissingCallback("delete_registration"));
        }

        Ok(Self { callbacks })
    }

    fn call_load_root_key(
        &self,
    ) -> Result<Option<[u8; crate::types::ROOT_KEY_LEN]>, StorageError> {
        let mut buffer = [0u8; crate::types::ROOT_KEY_LEN];
        let callback = self.callbacks.load_root_key.unwrap();
        let status =
            unsafe { callback(self.callbacks.ctx, buffer.as_mut_ptr(), buffer.len()) };
        match status {
            WispersStatus::Success => Ok(Some(buffer)),
            WispersStatus::NotFound => Ok(None),
            other => Err(StorageError::ForeignStatus(other)),
        }
    }

    fn call_save_root_key(
        &self,
        root_key: &[u8; crate::types::ROOT_KEY_LEN],
    ) -> Result<(), StorageError> {
        let callback = self.callbacks.save_root_key.unwrap();
        let status = unsafe { callback(self.callbacks.ctx, root_key.as_ptr(), root_key.len()) };
        match status {
            WispersStatus::Success => Ok(()),
            other => Err(StorageError::ForeignStatus(other)),
        }
    }

    fn call_delete_root_key(&self) -> Result<(), StorageError> {
        let callback = self.callbacks.delete_root_key.unwrap();
        let status = unsafe { callback(self.callbacks.ctx) };
        match status {
            WispersStatus::Success | WispersStatus::NotFound => Ok(()),
            other => Err(StorageError::ForeignStatus(other)),
        }
    }

    fn call_load_registration(&self) -> Result<Option<NodeRegistration>, StorageError> {
        let callback = self.callbacks.load_registration.unwrap();
        let mut buffer = vec![0u8; INITIAL_REGISTRATION_BUFFER];
        let mut required = 0usize;

        loop {
            let status = unsafe {
                callback(
                    self.callbacks.ctx,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut required,
                )
            };

            match status {
                WispersStatus::Success => {
                    buffer.truncate(required);
                    return deserialize_registration(&buffer)
                        .map_err(|_| StorageError::RegistrationDecode);
                }
                WispersStatus::NotFound => return Ok(None),
                WispersStatus::BufferTooSmall => {
                    if required == 0 {
                        return Err(StorageError::ForeignStatus(WispersStatus::BufferTooSmall));
                    }
                    buffer.resize(required, 0);
                }
                other => return Err(StorageError::ForeignStatus(other)),
            }
        }
    }

    fn call_save_registration(
        &self,
        registration: Option<&NodeRegistration>,
    ) -> Result<(), StorageError> {
        let callback = self.callbacks.save_registration.unwrap();
        let bytes =
            serialize_registration(registration).map_err(|_| StorageError::RegistrationEncode)?;
        let status = unsafe { callback(self.callbacks.ctx, bytes.as_ptr(), bytes.len()) };
        match status {
            WispersStatus::Success => Ok(()),
            other => Err(StorageError::ForeignStatus(other)),
        }
    }

    fn call_delete_registration(&self) -> Result<(), StorageError> {
        let callback = self.callbacks.delete_registration.unwrap();
        let status = unsafe { callback(self.callbacks.ctx) };
        match status {
            WispersStatus::Success | WispersStatus::NotFound => Ok(()),
            other => Err(StorageError::ForeignStatus(other)),
        }
    }
}

unsafe impl Send for ForeignNodeStateStore {}
unsafe impl Sync for ForeignNodeStateStore {}

impl NodeStateStore for ForeignNodeStateStore {
    fn load(&self) -> Result<Option<PersistedNodeState>, StorageError> {
        let root_key = match self.call_load_root_key()? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

        let registration = self.call_load_registration()?;
        Ok(Some(PersistedNodeState {
            root_key: RootKey::from_bytes(root_key),
            registration,
        }))
    }

    fn save(&self, state: &PersistedNodeState) -> Result<(), StorageError> {
        self.call_save_root_key(state.root_key.as_bytes())?;
        self.call_save_registration(state.registration.as_ref())?;
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        self.call_delete_root_key()?;
        self.call_delete_registration()?;
        Ok(())
    }
}

fn serialize_registration(registration: Option<&NodeRegistration>) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(&registration)
}

fn deserialize_registration(bytes: &[u8]) -> Result<Option<NodeRegistration>, bincode::Error> {
    bincode::deserialize(bytes)
}
