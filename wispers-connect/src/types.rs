use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

pub const ROOT_KEY_LEN: usize = 32;

/// Secret root key material for a node.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RootKey([u8; ROOT_KEY_LEN]);

impl RootKey {
    pub(crate) fn generate() -> Self {
        let mut bytes = [0u8; ROOT_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn from_bytes(bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
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
    pub node_number: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_token: Option<AuthToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_jwt: Option<String>,
}

impl NodeRegistration {
    pub fn new(
        connectivity_group_id: ConnectivityGroupId,
        node_number: i32,
        auth_token: AuthToken,
        attestation_jwt: Option<String>,
    ) -> Self {
        Self {
            connectivity_group_id,
            node_number,
            auth_token: Some(auth_token),
            attestation_jwt,
        }
    }

    pub fn auth_token(&self) -> Option<&AuthToken> {
        self.auth_token.as_ref()
    }
}

/// Authentication token for node-to-hub communication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthToken(String);

impl AuthToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthToken([redacted])")
    }
}

impl Drop for AuthToken {
    fn drop(&mut self) {
        self.0.zeroize();
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

/// Information about a node in the connectivity group.
///
/// This combines data from the hub (registration) and roster (activation status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    /// The node's number within the connectivity group.
    pub node_number: i32,
    /// The node's display name (may be empty).
    pub name: String,
    /// Whether this is the current node (self).
    pub is_self: bool,
    /// Whether the node is activated (in the roster and not revoked).
    /// None if we don't have roster access (not activated ourselves).
    pub is_activated: Option<bool>,
    /// Unix timestamp in milliseconds when the node was last seen.
    pub last_seen_at_millis: i64,
    /// Whether the node currently has an active connection to the hub.
    pub is_online: bool,
}

/// Snapshot of all persisted node state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedNodeState {
    pub(crate) root_key: RootKey,
    pub(crate) registration: Option<NodeRegistration>,
}

impl PersistedNodeState {
    /// Creates a new node state with a freshly generated root key.
    pub fn new() -> Self {
        PersistedNodeState {
            root_key: RootKey::generate(),
            registration: None,
        }
    }

    /// Reconstruct from stored parts. For use by `NodeStateStore` implementations.
    pub fn from_stored(
        root_key_bytes: [u8; ROOT_KEY_LEN],
        registration: Option<NodeRegistration>,
    ) -> Self {
        Self {
            root_key: RootKey::from_bytes(root_key_bytes),
            registration,
        }
    }

    /// The root key as raw bytes. For use by `NodeStateStore` implementations.
    pub fn root_key_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        self.root_key.as_bytes()
    }

    /// The registration, if any. For use by `NodeStateStore` implementations.
    pub fn registration(&self) -> Option<&NodeRegistration> {
        self.registration.as_ref()
    }

    pub fn is_registered(&self) -> bool {
        self.registration.is_some()
    }

    pub fn set_registration(&mut self, registration: NodeRegistration) {
        self.registration = Some(registration);
    }
}

impl Default for PersistedNodeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) fn registration_fixture() -> NodeRegistration {
    NodeRegistration::new(
        ConnectivityGroupId::from("group-123"),
        1,
        AuthToken::new("test-token-456"),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_generates_random_root_key() {
        let state = PersistedNodeState::new();
        assert_eq!(state.root_key.as_bytes().len(), ROOT_KEY_LEN);
        assert!(!state.root_key.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn set_registration_marks_state() {
        let mut state = PersistedNodeState::new();
        let registration = registration_fixture();
        state.set_registration(registration.clone());
        assert!(state.is_registered());
        assert_eq!(state.registration, Some(registration));
    }
}
