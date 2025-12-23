use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub const ROOT_KEY_LEN: usize = 32;
pub const DEFAULT_PROFILE_NAMESPACE: &str = "default";

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
pub struct RootKey([u8; ROOT_KEY_LEN]);

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

#[cfg(test)]
pub(crate) fn registration_fixture() -> NodeRegistration {
    NodeRegistration {
        connectivity_group_id: ConnectivityGroupId::from("group-123"),
        node_id: NodeId::from("node-456"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_defaults_profile_namespace() {
        let state = NodeState::initialize("app.example", None::<String>);
        assert_eq!(state.profile_namespace.as_ref(), DEFAULT_PROFILE_NAMESPACE);
        assert_eq!(state.root_key.as_bytes().len(), ROOT_KEY_LEN);
        assert!(!state.root_key.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn set_registration_marks_state() {
        let mut state = NodeState::initialize("app.example", Some("custom-profile"));
        let registration = registration_fixture();
        state.set_registration(registration.clone());
        assert!(state.is_registered());
        assert_eq!(state.registration, Some(registration));
    }
}
