//! Core storage primitives for the Wispers Connect client library.
//!
//! The module focuses on initialization and persistence of basic node state. A node
//! always has an `app_namespace`, an optional `profile_namespace` that defaults to
//! `"default"`, an automatically generated 32-byte root key, and optional
//! registration metadata once it has completed remote enrollment.

use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};
use urlencoding::encode;
use zeroize::Zeroize;

const ROOT_KEY_LEN: usize = 32;
const DEFAULT_PROFILE_NAMESPACE: &str = "default";

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRegistration {
    pub connectivity_group_id: ConnectivityGroupId,
    pub node_id: NodeId,
}

/// Identifier for the node within the remote control plane.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
    fn from_state(
        state: NodeState,
        store: Arc<S>,
    ) -> Result<Self, NodeStateError<S::Error>> {
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
        self.store.save(&self.state).map_err(NodeStateError::store)?;
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
    fn new(
        state: NodeState,
        store: Arc<S>,
    ) -> Result<Self, NodeStateError<S::Error>> {
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

impl<StoreError> std::error::Error for NodeStateError<StoreError>
where
    StoreError: std::error::Error + 'static,
{
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
        let states = self.states.read().map_err(|_| InMemoryStoreError::Poisoned)?;
        Ok(states
            .get(&(app_namespace.clone(), profile_namespace.clone()))
            .cloned())
    }

    fn save(&self, state: &NodeState) -> Result<(), Self::Error> {
        let mut states = self.states.write().map_err(|_| InMemoryStoreError::Poisoned)?;
        let key = (state.app_namespace.clone(), state.profile_namespace.clone());
        states.insert(key, state.clone());
        Ok(())
    }

    fn delete(
        &self,
        app_namespace: &AppNamespace,
        profile_namespace: &ProfileNamespace,
    ) -> Result<(), Self::Error> {
        let mut states = self.states.write().map_err(|_| InMemoryStoreError::Poisoned)?;
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
        assert!(store
            .load(&state.app_namespace, &state.profile_namespace)
            .unwrap()
            .is_none());
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
        assert_eq!(pending.profile_namespace().as_ref(), DEFAULT_PROFILE_NAMESPACE);
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
