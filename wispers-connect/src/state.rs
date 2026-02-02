use crate::crypto::{SigningKeyPair, X25519KeyPair};
use crate::errors::NodeStateError;
use crate::node::Node;
use crate::roster::verify_roster;
use crate::storage::{NodeStateStore, SharedStore};
use crate::types::{NodeRegistration, PersistedNodeState};
use std::sync::{Arc, RwLock};

/// Default hub address for production use.
const DEFAULT_HUB_ADDR: &str = "https://hub.connect.wispers.dev";

/// Runtime configuration shared across state types (not persisted).
pub(crate) struct RuntimeConfig {
    pub(crate) hub_addr: String,
}

impl RuntimeConfig {
    /// Create a new RuntimeConfig with the default hub address.
    pub(crate) fn new() -> Self {
        Self {
            hub_addr: DEFAULT_HUB_ADDR.to_string(),
        }
    }

    /// Create a new RuntimeConfig with a custom hub address.
    pub(crate) fn new_with_addr(hub_addr: impl Into<String>) -> Self {
        Self {
            hub_addr: hub_addr.into(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) type SharedConfig = Arc<RwLock<RuntimeConfig>>;

/// High-level storage handle that drives state initialization and persistence.
#[derive(Clone)]
pub struct NodeStorage {
    store: SharedStore,
    config: SharedConfig,
}

impl NodeStorage {
    pub fn new(store: impl NodeStateStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            config: Arc::new(RwLock::new(RuntimeConfig {
                hub_addr: DEFAULT_HUB_ADDR.to_string(),
            })),
        }
    }

    /// Override the hub address (for testing).
    pub fn override_hub_addr(&self, addr: impl Into<String>) {
        self.config.write().unwrap().hub_addr = addr.into();
    }

    /// Read just the registration from local storage (sync, no hub contact).
    ///
    /// Returns `None` if not registered. This is useful when you need
    /// registration info before starting an async runtime.
    pub fn read_registration(&self) -> Result<Option<NodeRegistration>, NodeStateError> {
        let state = self.store.load().map_err(NodeStateError::store)?;
        Ok(state.and_then(|s| s.registration))
    }

    /// Initialize or restore node state.
    ///
    /// Returns a `Node` in the appropriate state:
    /// - `Pending` if not registered
    /// - `Registered` if registered but not in the roster
    /// - `Activated` if registered and in the roster
    ///
    /// This method fetches the roster from the hub when the node is registered
    /// to determine if it has been activated.
    pub async fn restore_or_init_node(&self) -> Result<Node, NodeStateError> {
        use crate::hub::HubClient;

        let state = match self.store.load().map_err(NodeStateError::store)? {
            Some(state) => state,
            None => {
                let state = PersistedNodeState::new();
                self.store.save(&state).map_err(NodeStateError::store)?;
                return Ok(Node::new_pending(
                    state,
                    self.store.clone(),
                    self.config.clone(),
                ));
            }
        };

        // Not registered yet
        if !state.is_registered() {
            return Ok(Node::new_pending(
                state,
                self.store.clone(),
                self.config.clone(),
            ));
        }

        // Registered - fetch roster to check if activated
        let registration = state.registration.as_ref().expect("checked is_registered");
        let hub_addr = self.config.read().unwrap().hub_addr.clone();

        let mut client = HubClient::connect(hub_addr)
            .await
            .map_err(NodeStateError::hub)?;

        // Fetch unverified first - we need to check if we're in it before we can verify
        let roster = client
            .get_unverified_roster(registration)
            .await
            .map_err(NodeStateError::hub)?;

        // Check if our node is in the roster
        let is_activated = roster
            .nodes
            .iter()
            .any(|n| n.node_number == registration.node_number);

        if is_activated {
            let root_key = state.root_key.as_bytes();
            let signing_key = SigningKeyPair::derive_from_root_key(root_key);
            let encryption_key = X25519KeyPair::derive_from_root_key(root_key);

            // Verify the roster cryptographically before trusting it
            verify_roster(
                &roster,
                registration.node_number,
                &signing_key.public_key_spki(),
            )
            .map_err(NodeStateError::RosterVerificationFailed)?;

            Ok(Node::new_activated(
                state,
                self.store.clone(),
                self.config.clone(),
                signing_key,
                encryption_key,
                roster,
            ))
        } else {
            Node::new_registered(state, self.store.clone(), self.config.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeState;
    use crate::storage::InMemoryNodeStateStore;

    #[tokio::test]
    async fn storage_initializes_and_reuses_state() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let first_node = storage.restore_or_init_node().await.unwrap();
        assert_eq!(first_node.state(), NodeState::Pending);
        let first_key = *first_node.root_key_bytes();

        // Re-initialize should return the same state
        let storage2 = NodeStorage::new(InMemoryNodeStateStore::new());
        // Note: InMemoryNodeStateStore doesn't persist across instances,
        // so we test with the same storage instance
        drop(first_node);
        let second_node = storage.restore_or_init_node().await.unwrap();
        assert_eq!(second_node.state(), NodeState::Pending);
        assert_eq!(second_node.root_key_bytes(), &first_key);
        drop(storage2); // silence unused warning
    }

    #[tokio::test]
    async fn completing_registration_persists_and_transitions() {
        let store = Arc::new(InMemoryNodeStateStore::new());
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        // Create a new storage with the same store for verification
        let verify_store = store.clone();

        // Use a storage that shares the store for this test
        let shared_storage = NodeStorage {
            store: store as SharedStore,
            config: Arc::new(RwLock::new(RuntimeConfig::new())),
        };

        let mut node = shared_storage.restore_or_init_node().await.unwrap();
        assert_eq!(node.state(), NodeState::Pending);
        let registration = crate::types::registration_fixture();

        node.complete_registration(registration.clone()).unwrap();
        assert_eq!(node.state(), NodeState::Registered);
        assert_eq!(node.registration(), Some(&registration));

        // Verify registration was persisted by checking the store directly
        let loaded = verify_store
            .load()
            .unwrap()
            .expect("state should be persisted");
        assert!(loaded.is_registered());
        assert_eq!(loaded.registration.as_ref().unwrap(), &registration);

        drop(storage); // silence unused warning
    }
}
