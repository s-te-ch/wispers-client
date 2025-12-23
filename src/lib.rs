//! Core storage primitives for the Wispers Connect client library.
//!
//! The module focuses on initialization and persistence of basic node state. A node
//! always has an `app_namespace`, an optional `profile_namespace` that defaults to
//! `"default"`, an automatically generated 32-byte root key, and optional
//! registration metadata once it has completed remote enrollment.

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::c_void,
    fmt,
    sync::{Arc, RwLock},
};
use urlencoding::encode;
use zeroize::Zeroize;

const ROOT_KEY_LEN: usize = 32;
const DEFAULT_PROFILE_NAMESPACE: &str = "default";

/// Status codes shared across the FFI boundary.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersStatus {
    Success = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    StoreError = 3,
    AlreadyRegistered = 4,
    NotRegistered = 5,
    UnexpectedStage = 6,
    NotFound = 7,
    BufferTooSmall = 8,
    MissingCallback = 9,
}

/// Identifies the integrating application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppNamespace(String);

impl AppNamespace {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for AppNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for AppNamespace {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for AppNamespace {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Identifies the profile/end-user for a given app namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProfileNamespace(String);

impl ProfileNamespace {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl Default for ProfileNamespace {
    fn default() -> Self {
        Self(DEFAULT_PROFILE_NAMESPACE.to_owned())
    }
}

impl fmt::Display for ProfileNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for ProfileNamespace {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for ProfileNamespace {
    fn from(value: T) -> Self {
        let value = value.into();
        if value.trim().is_empty() {
            Self::default()
        } else {
            Self(value)
        }
    }
}

/// Secret root key material for a node.
#[derive(Clone, PartialEq, Eq)]
struct RootKey([u8; ROOT_KEY_LEN]);

#[cfg_attr(not(test), allow(dead_code))]
impl RootKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; ROOT_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootKey([redacted; {}])", ROOT_KEY_LEN)
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Connectivity metadata produced after remote registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub connectivity_group_id: ConnectivityGroupId,
    pub node_id: NodeId,
}

/// Identifier for the node within the remote control plane.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<String>> From<T> for NodeId {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Identifier describing which connectivity group the node belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectivityGroupId(String);

impl ConnectivityGroupId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for ConnectivityGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<String>> From<T> for ConnectivityGroupId {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// Snapshot of all persisted node state; mostly kept internal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeState {
    pub(crate) app_namespace: AppNamespace,
    pub(crate) profile_namespace: ProfileNamespace,
    pub(crate) root_key: RootKey,
    pub(crate) registration: Option<NodeRegistration>,
}

impl NodeState {
    /// Creates a new node state. Profile namespace defaults to `"default"` when omitted.
    pub fn initialize(
        app_namespace: impl Into<AppNamespace>,
        profile_namespace: Option<impl Into<ProfileNamespace>>,
    ) -> Self {
        let app_namespace = app_namespace.into();
        let profile_namespace = profile_namespace
            .map(Into::into)
            .unwrap_or_else(ProfileNamespace::default);
        Self::initialize_with_namespaces(app_namespace, profile_namespace)
    }

    pub fn initialize_with_namespaces(
        app_namespace: AppNamespace,
        profile_namespace: ProfileNamespace,
    ) -> Self {
        NodeState {
            app_namespace,
            profile_namespace,
            root_key: RootKey::generate(),
            registration: None,
        }
    }

    pub fn is_registered(&self) -> bool {
        self.registration.is_some()
    }

    pub fn set_registration(&mut self, registration: NodeRegistration) {
        self.registration = Some(registration);
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

/// High-level manager that drives state initialization and persistence.
#[derive(Clone)]
pub struct NodeStateManager<S: NodeStateStore> {
    store: Arc<S>,
}

impl<S: NodeStateStore> NodeStateManager<S> {
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    pub fn restore_or_init_node_state(
        &self,
        app_namespace: impl Into<AppNamespace>,
        profile_namespace: Option<impl Into<ProfileNamespace>>,
    ) -> Result<NodeStateStage<S>, NodeStateError<S::Error>> {
        let app_namespace = app_namespace.into();
        let profile_namespace = profile_namespace
            .map(Into::into)
            .unwrap_or_else(ProfileNamespace::default);

        match self
            .store
            .load(&app_namespace, &profile_namespace)
            .map_err(NodeStateError::store)?
        {
            Some(state) => NodeStateStage::from_state(state, self.store.clone()),
            None => {
                let state = NodeState::initialize_with_namespaces(
                    app_namespace.clone(),
                    profile_namespace.clone(),
                );
                self.store.save(&state).map_err(NodeStateError::store)?;
                Ok(NodeStateStage::Pending(PendingNodeState::new(
                    state,
                    self.store.clone(),
                )))
            }
        }
    }
}

/// State machine representing whether a node still needs registration.
pub enum NodeStateStage<S: NodeStateStore> {
    Pending(PendingNodeState<S>),
    Registered(RegisteredNodeState<S>),
}

impl<S: NodeStateStore> NodeStateStage<S> {
    fn from_state(state: NodeState, store: Arc<S>) -> Result<Self, NodeStateError<S::Error>> {
        if state.is_registered() {
            Ok(Self::Registered(RegisteredNodeState::new(state, store)?))
        } else {
            Ok(Self::Pending(PendingNodeState::new(state, store)))
        }
    }

    pub fn into_pending(self) -> Option<PendingNodeState<S>> {
        if let NodeStateStage::Pending(state) = self {
            Some(state)
        } else {
            None
        }
    }

    pub fn into_registered(self) -> Option<RegisteredNodeState<S>> {
        if let NodeStateStage::Registered(state) = self {
            Some(state)
        } else {
            None
        }
    }
}

/// Pending node state that has not completed remote registration.
pub struct PendingNodeState<S: NodeStateStore> {
    state: NodeState,
    store: Arc<S>,
}

impl<S: NodeStateStore> PendingNodeState<S> {
    fn new(state: NodeState, store: Arc<S>) -> Self {
        Self { state, store }
    }

    pub fn app_namespace(&self) -> &AppNamespace {
        &self.state.app_namespace
    }

    pub fn profile_namespace(&self) -> &ProfileNamespace {
        &self.state.profile_namespace
    }

    pub fn is_registered(&self) -> bool {
        self.state.is_registered()
    }

    pub fn registration_url(&self, base_url: &str) -> String {
        let separator = if base_url.contains('?') { '&' } else { '?' };
        format!(
            "{base_url}{separator}app_namespace={}&profile_namespace={}",
            encode(self.app_namespace().as_ref()),
            encode(self.profile_namespace().as_ref())
        )
    }

    pub fn complete_registration(
        mut self,
        registration: NodeRegistration,
    ) -> Result<RegisteredNodeState<S>, NodeStateError<S::Error>> {
        if self.state.is_registered() {
            return Err(NodeStateError::AlreadyRegistered);
        }

        self.state.set_registration(registration);
        self.store
            .save(&self.state)
            .map_err(NodeStateError::store)?;
        RegisteredNodeState::new(self.state, self.store)
    }

    #[cfg(test)]
    pub(crate) fn root_key_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        self.state.root_key.as_bytes()
    }
}

/// Registered node state ready for node runtime initialization.
pub struct RegisteredNodeState<S: NodeStateStore> {
    state: NodeState,
    store: Arc<S>,
}

impl<S: NodeStateStore> RegisteredNodeState<S> {
    fn new(state: NodeState, store: Arc<S>) -> Result<Self, NodeStateError<S::Error>> {
        if state.registration.is_none() {
            return Err(NodeStateError::NotRegistered);
        }

        Ok(Self { state, store })
    }

    pub fn app_namespace(&self) -> &AppNamespace {
        &self.state.app_namespace
    }

    pub fn profile_namespace(&self) -> &ProfileNamespace {
        &self.state.profile_namespace
    }

    pub fn registration(&self) -> &NodeRegistration {
        self.state
            .registration
            .as_ref()
            .expect("registration must be present")
    }

    pub fn delete(self) -> Result<(), NodeStateError<S::Error>> {
        let app = self.state.app_namespace.clone();
        let profile = self.state.profile_namespace.clone();
        self.store
            .delete(&app, &profile)
            .map_err(NodeStateError::store)
    }
}

/// Errors introduced by higher-level node state orchestration.
#[derive(Debug)]
pub enum NodeStateError<StoreError> {
    Store(StoreError),
    AlreadyRegistered,
    NotRegistered,
}

impl<StoreError> NodeStateError<StoreError> {
    fn store(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl<StoreError: fmt::Display> fmt::Display for NodeStateError<StoreError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStateError::Store(err) => write!(f, "store error: {err}"),
            NodeStateError::AlreadyRegistered => write!(f, "node is already registered"),
            NodeStateError::NotRegistered => write!(f, "node has not completed registration"),
        }
    }
}

impl<StoreError> std::error::Error for NodeStateError<StoreError> where
    StoreError: std::error::Error + 'static
{
}

pub mod ffi {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        os::raw::c_char,
        ptr,
    };

    const INITIAL_METADATA_BUFFER: usize = 256;

    enum ManagerImpl {
        InMemory(NodeStateManager<InMemoryNodeStateStore>),
        Foreign(NodeStateManager<ForeignNodeStateStore>),
    }

    enum PendingImpl {
        InMemory(PendingNodeState<InMemoryNodeStateStore>),
        Foreign(PendingNodeState<ForeignNodeStateStore>),
    }

    enum RegisteredImpl {
        InMemory(RegisteredNodeState<InMemoryNodeStateStore>),
        Foreign(RegisteredNodeState<ForeignNodeStateStore>),
    }

    pub struct WispersNodeStateManagerHandle(ManagerImpl);
    pub struct WispersPendingNodeStateHandle(PendingImpl);
    pub struct WispersRegisteredNodeStateHandle(RegisteredImpl);

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct WispersNodeStateStoreCallbacks {
        pub ctx: *mut c_void,
        pub load_root_key: Option<
            unsafe extern "C" fn(
                *mut c_void,
                *const c_char,
                *const c_char,
                *mut u8,
                usize,
            ) -> WispersStatus,
        >,
        pub save_root_key: Option<
            unsafe extern "C" fn(
                *mut c_void,
                *const c_char,
                *const c_char,
                *const u8,
                usize,
            ) -> WispersStatus,
        >,
        pub delete_root_key: Option<
            unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> WispersStatus,
        >,
        pub load_registration: Option<
            unsafe extern "C" fn(
                *mut c_void,
                *const c_char,
                *const c_char,
                *mut u8,
                usize,
                *mut usize,
            ) -> WispersStatus,
        >,
        pub save_registration: Option<
            unsafe extern "C" fn(
                *mut c_void,
                *const c_char,
                *const c_char,
                *const u8,
                usize,
            ) -> WispersStatus,
        >,
        pub delete_registration: Option<
            unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> WispersStatus,
        >,
    }

    struct ForeignNodeStateStore {
        callbacks: WispersNodeStateStoreCallbacks,
    }

    #[derive(Debug)]
    enum ForeignStoreError {
        MissingCallback(&'static str),
        CStringConversion,
        MetadataEncode,
        MetadataDecode,
        Status(WispersStatus),
    }

    impl fmt::Display for ForeignStoreError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ForeignStoreError::MissingCallback(name) => {
                    write!(f, "missing callback: {name}")
                }
                ForeignStoreError::CStringConversion => write!(f, "namespace contained null byte"),
                ForeignStoreError::MetadataEncode => write!(f, "failed to encode node metadata"),
                ForeignStoreError::MetadataDecode => write!(f, "failed to decode node metadata"),
                ForeignStoreError::Status(status) => {
                    write!(f, "store callback returned {status:?}")
                }
            }
        }
    }

    impl std::error::Error for ForeignStoreError {}

    impl ForeignNodeStateStore {
        fn new(callbacks: WispersNodeStateStoreCallbacks) -> Result<Self, ForeignStoreError> {
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
        ) -> Result<Option<[u8; ROOT_KEY_LEN]>, ForeignStoreError> {
            let mut buffer = [0u8; ROOT_KEY_LEN];
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
            root_key: &[u8; ROOT_KEY_LEN],
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
            let mut buffer = vec![0u8; INITIAL_METADATA_BUFFER];
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
                            .map_err(|_| ForeignStoreError::MetadataDecode);
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
                .map_err(|_| ForeignStoreError::MetadataEncode)?;
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

            let mut state = NodeState::initialize_with_namespaces(
                app_namespace.clone(),
                profile_namespace.clone(),
            );
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

    impl From<NodeStateError<InMemoryStoreError>> for WispersStatus {
        fn from(value: NodeStateError<InMemoryStoreError>) -> Self {
            match value {
                NodeStateError::Store(_) => WispersStatus::StoreError,
                NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
                NodeStateError::NotRegistered => WispersStatus::NotRegistered,
            }
        }
    }

    impl From<NodeStateError<ForeignStoreError>> for WispersStatus {
        fn from(value: NodeStateError<ForeignStoreError>) -> Self {
            match value {
                NodeStateError::Store(ForeignStoreError::Status(status)) => status,
                NodeStateError::Store(ForeignStoreError::MissingCallback(_)) => {
                    WispersStatus::MissingCallback
                }
                NodeStateError::Store(
                    ForeignStoreError::CStringConversion
                    | ForeignStoreError::MetadataEncode
                    | ForeignStoreError::MetadataDecode,
                ) => WispersStatus::StoreError,
                NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
                NodeStateError::NotRegistered => WispersStatus::NotRegistered,
            }
        }
    }

    fn c_str_to_string(ptr: *const c_char) -> Result<String, WispersStatus> {
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

    fn optional_c_str(ptr: *const c_char) -> Result<Option<String>, WispersStatus> {
        if ptr.is_null() {
            Ok(None)
        } else {
            c_str_to_string(ptr).map(Some)
        }
    }

    unsafe fn reset_out_ptr<T>(out: *mut *mut T) {
        if !out.is_null() {
            unsafe {
                *out = ptr::null_mut();
            }
        }
    }

    fn restore_or_init_internal(
        manager: &mut ManagerImpl,
        app_namespace: String,
        profile_namespace: Option<String>,
    ) -> Result<NodeStateStageImpl, WispersStatus> {
        match manager {
            ManagerImpl::InMemory(inner) => inner
                .restore_or_init_node_state(app_namespace, profile_namespace)
                .map(NodeStateStageImpl::from_in_memory)
                .map_err(Into::into),
            ManagerImpl::Foreign(inner) => inner
                .restore_or_init_node_state(app_namespace, profile_namespace)
                .map(NodeStateStageImpl::from_foreign)
                .map_err(Into::into),
        }
    }

    enum NodeStateStageImpl {
        Pending(PendingImpl),
        Registered(RegisteredImpl),
    }

    impl NodeStateStageImpl {
        fn from_in_memory(stage: NodeStateStage<InMemoryNodeStateStore>) -> Self {
            match stage {
                NodeStateStage::Pending(pending) => {
                    NodeStateStageImpl::Pending(PendingImpl::InMemory(pending))
                }
                NodeStateStage::Registered(registered) => {
                    NodeStateStageImpl::Registered(RegisteredImpl::InMemory(registered))
                }
            }
        }

        fn from_foreign(stage: NodeStateStage<ForeignNodeStateStore>) -> Self {
            match stage {
                NodeStateStage::Pending(pending) => {
                    NodeStateStageImpl::Pending(PendingImpl::Foreign(pending))
                }
                NodeStateStage::Registered(registered) => {
                    NodeStateStageImpl::Registered(RegisteredImpl::Foreign(registered))
                }
            }
        }
    }

    fn registration_url_internal(handle: &PendingImpl, base_url: &str) -> String {
        match handle {
            PendingImpl::InMemory(inner) => inner.registration_url(base_url),
            PendingImpl::Foreign(inner) => inner.registration_url(base_url),
        }
    }

    fn complete_registration_internal(
        pending: PendingImpl,
        registration: NodeRegistration,
    ) -> Result<RegisteredImpl, WispersStatus> {
        match pending {
            PendingImpl::InMemory(inner) => inner
                .complete_registration(registration)
                .map(RegisteredImpl::InMemory)
                .map_err(Into::into),
            PendingImpl::Foreign(inner) => inner
                .complete_registration(registration)
                .map(RegisteredImpl::Foreign)
                .map_err(Into::into),
        }
    }

    fn delete_registered_internal(registered: RegisteredImpl) -> Result<(), WispersStatus> {
        match registered {
            RegisteredImpl::InMemory(inner) => inner.delete().map_err(Into::into),
            RegisteredImpl::Foreign(inner) => inner.delete().map_err(Into::into),
        }
    }

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
            return ptr::null_mut();
        }

        let callbacks = unsafe { *callbacks };
        let store = match ForeignNodeStateStore::new(callbacks) {
            Ok(store) => store,
            Err(_) => return ptr::null_mut(),
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
            Ok(NodeStateStageImpl::Pending(pending)) => {
                let boxed = Box::new(WispersPendingNodeStateHandle(pending));
                unsafe {
                    *out_pending = Box::into_raw(boxed);
                }
                WispersStatus::Success
            }
            Ok(NodeStateStageImpl::Registered(registered)) => {
                let boxed = Box::new(WispersRegisteredNodeStateHandle(registered));
                unsafe {
                    *out_registered = Box::into_raw(boxed);
                }
                WispersStatus::Success
            }
            Err(err) => err,
        }
    }

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
    pub extern "C" fn wispers_string_free(ptr: *mut c_char) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            drop(CString::from_raw(ptr));
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
}

/// Abstraction over the persistence backend for node state.
pub trait NodeStateStore {
    type Error;

    fn load(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<Option<NodeState>, Self::Error>;

    fn save(&self, state: &NodeState) -> Result<(), Self::Error>;

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error>;
}

/// Simple, non-persistent store useful for testing and sketches.
#[derive(Clone, Default)]
pub struct InMemoryNodeStateStore {
    states: Arc<RwLock<HashMap<(AppNamespace, ProfileNamespace), NodeState>>>,
}

impl InMemoryNodeStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeStateStore for InMemoryNodeStateStore {
    type Error = InMemoryStoreError;

    fn load(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<Option<NodeState>, Self::Error> {
        let states = self
            .states
            .read()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        Ok(states
            .get(&(app_namespace.clone(), profile_namespace.clone()))
            .cloned())
    }

    fn save(&self, state: &NodeState) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .write()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        let key = (state.app_namespace.clone(), state.profile_namespace.clone());
        states.insert(key, state.clone());
        Ok(())
    }

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error> {
        let mut states = self
            .states
            .write()
            .map_err(|_| InMemoryStoreError::Poisoned)?;
        states.remove(&(app_namespace.clone(), profile_namespace.clone()));
        Ok(())
    }
}

/// Errors that can arise from the in-memory store (primarily poisoning).
#[derive(Debug, thiserror::Error)]
pub enum InMemoryStoreError {
    #[error("in-memory state lock was poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_profile_namespace() {
        let state = NodeState::initialize("app.example", None::<String>);
        assert_eq!(state.profile_namespace.as_ref(), DEFAULT_PROFILE_NAMESPACE);
        assert_eq!(state.root_key.as_bytes().len(), ROOT_KEY_LEN);
        assert!(!state.root_key.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn set_registration_populates_metadata() {
        let mut state = NodeState::initialize("app.example", Some("custom-profile"));
        let registration = NodeRegistration {
            connectivity_group_id: ConnectivityGroupId::from("group-123"),
            node_id: NodeId::from("node-456"),
        };
        state.set_registration(registration.clone());
        assert!(state.is_registered());
        assert_eq!(state.registration, Some(registration));
    }

    #[test]
    fn in_memory_store_round_trip() {
        let store = InMemoryNodeStateStore::new();
        let state = NodeState::initialize("app.example", None::<String>);
        store.save(&state).unwrap();
        let loaded = store
            .load(&state.app_namespace, &state.profile_namespace)
            .unwrap()
            .expect("state should exist");
        assert_eq!(state.app_namespace, loaded.app_namespace);
        assert_eq!(state.profile_namespace, loaded.profile_namespace);
        assert_eq!(state.registration, loaded.registration);
        assert_eq!(state.root_key.as_bytes(), loaded.root_key.as_bytes());

        store
            .delete(&state.app_namespace, &state.profile_namespace)
            .unwrap();
        assert!(
            store
                .load(&state.app_namespace, &state.profile_namespace)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn manager_initializes_and_reuses_state() {
        let manager = NodeStateManager::new(InMemoryNodeStateStore::new());
        let first_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending = first_stage
            .into_pending()
            .expect("initial state should be pending");
        assert_eq!(pending.app_namespace().as_ref(), "app.example");
        assert_eq!(
            pending.profile_namespace().as_ref(),
            DEFAULT_PROFILE_NAMESPACE
        );
        let first_key = *pending.root_key_bytes();

        let second_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending_second = second_stage
            .into_pending()
            .expect("state remains pending until registration");
        assert_eq!(pending_second.root_key_bytes(), &first_key);
    }

    #[test]
    fn completing_registration_persists_and_transitions() {
        let manager = NodeStateManager::new(InMemoryNodeStateStore::new());
        let stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending = stage
            .into_pending()
            .expect("expected pending state prior to registration");
        let registration = NodeRegistration {
            connectivity_group_id: ConnectivityGroupId::from("group-123"),
            node_id: NodeId::from("node-456"),
        };

        let registered = pending.complete_registration(registration.clone()).unwrap();
        assert_eq!(registered.registration(), &registration);

        let loaded_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        assert!(matches!(loaded_stage, NodeStateStage::Registered(_)));
    }
}
