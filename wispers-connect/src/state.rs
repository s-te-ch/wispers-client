use crate::crypto::{generate_nonce, PairingCode, SigningKeyPair};
use crate::errors::NodeStateError;
use crate::hub::proto;
use crate::storage::{NodeStateStore, SharedStore};
use crate::types::{AppNamespace, NodeRegistration, NodeState, ProfileNamespace};
use prost::Message;
use std::sync::{Arc, RwLock};
use urlencoding::encode;

/// Default hub address for production use.
const DEFAULT_HUB_ADDR: &str = "https://hub.connect.wispers.dev";

/// Runtime configuration shared across state types (not persisted).
pub(crate) struct RuntimeConfig {
    hub_addr: String,
}

pub(crate) type SharedConfig = Arc<RwLock<RuntimeConfig>>;

/// High-level storage handle that drives state initialization and persistence.
#[derive(Clone)]
pub struct NodeStorage<S: NodeStateStore> {
    store: SharedStore<S>,
    config: SharedConfig,
}

impl<S: NodeStateStore> NodeStorage<S> {
    pub fn new(store: S) -> Self {
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
            Some(state) => NodeStateStage::from_state(state, self.store.clone(), self.config.clone()),
            None => {
                let state = NodeState::initialize_with_namespaces(
                    app_namespace.clone(),
                    profile_namespace.clone(),
                );
                self.store.save(&state).map_err(NodeStateError::store)?;
                Ok(NodeStateStage::Pending(PendingNodeState::new(
                    state,
                    self.store.clone(),
                    self.config.clone(),
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
        store: SharedStore<S>,
        config: SharedConfig,
    ) -> Result<Self, NodeStateError<S::Error>> {
        if state.is_registered() {
            Ok(Self::Registered(RegisteredNodeState::new(state, store, config)?))
        } else {
            Ok(Self::Pending(PendingNodeState::new(state, store, config)))
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
    store: SharedStore<S>,
    config: SharedConfig,
}

impl<S: NodeStateStore> PendingNodeState<S> {
    pub(crate) fn new(state: NodeState, store: SharedStore<S>, config: SharedConfig) -> Self {
        Self { state, store, config }
    }

    fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
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
        RegisteredNodeState::new(self.state, self.store, self.config)
    }

    /// Register with the hub using a registration token.
    ///
    /// This connects to the hub, completes registration, persists the credentials,
    /// and returns the registered state.
    pub async fn register(
        self,
        token: &str,
    ) -> Result<RegisteredNodeState<S>, NodeStateError<S::Error>> {
        use crate::hub::HubClient;

        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;
        let registration = client
            .complete_registration(token)
            .await
            .map_err(NodeStateError::hub)?;
        self.complete_registration(registration)
    }

    #[cfg(test)]
    pub(crate) fn root_key_bytes(&self) -> &[u8; crate::types::ROOT_KEY_LEN] {
        self.state.root_key.as_bytes()
    }
}

/// Registered node state ready for node runtime initialization.
pub struct RegisteredNodeState<S: NodeStateStore> {
    state: NodeState,
    store: SharedStore<S>,
    config: SharedConfig,
}

impl<S: NodeStateStore> RegisteredNodeState<S> {
    pub(crate) fn new(
        state: NodeState,
        store: SharedStore<S>,
        config: SharedConfig,
    ) -> Result<Self, NodeStateError<S::Error>> {
        if state.registration.is_none() {
            return Err(NodeStateError::NotRegistered);
        }

        Ok(Self { state, store, config })
    }

    fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
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

    /// List all nodes in the connectivity group.
    pub async fn list_nodes(
        &self,
    ) -> Result<Vec<crate::hub::Node>, NodeStateError<S::Error>> {
        use crate::hub::HubClient;

        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;
        client
            .list_nodes(self.registration())
            .await
            .map_err(NodeStateError::hub)
    }

    /// Activate this node by pairing with an endorser node.
    ///
    /// The pairing code format is "node_number-secret" where secret is 10 base36 characters.
    /// This performs the mutual key exchange and roster update, returning an activated node.
    pub async fn activate(
        &self,
        pairing_code: &str,
    ) -> Result<ActivatedNode, NodeStateError<S::Error>> {
        use crate::hub::HubClient;

        // Parse the pairing code
        let pairing_code =
            PairingCode::parse(pairing_code).map_err(NodeStateError::InvalidPairingCode)?;
        let endorser_node_number = pairing_code.node_number;

        // Derive our signing key
        let signing_key = SigningKeyPair::derive_from_root_key(self.state.root_key.as_bytes());

        // Build the pairing request
        let nonce = generate_nonce();
        let payload = proto::pair_nodes_message::Payload {
            sender_node_number: self.registration().node_number,
            receiver_node_number: endorser_node_number,
            public_key_spki: signing_key.public_key_spki(),
            nonce: nonce.clone(),
            reply_nonce: vec![],
        };
        let payload_bytes = payload.encode_to_vec();
        let mac = pairing_code.secret.compute_mac(&payload_bytes);

        let request_message = proto::PairNodesMessage {
            payload: Some(payload),
            mac,
        };

        // Connect and send the pairing request
        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;

        let response = client
            .pair_nodes(self.registration(), request_message)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the response
        let response_payload = response
            .payload
            .ok_or(NodeStateError::MissingEndorserResponse)?;
        let response_payload_bytes = response_payload.encode_to_vec();

        if !pairing_code.secret.verify_mac(&response_payload_bytes, &response.mac) {
            return Err(NodeStateError::MacVerificationFailed);
        }

        // Verify the response is for us and contains the expected reply_nonce
        if response_payload.receiver_node_number != self.registration().node_number {
            return Err(NodeStateError::MissingEndorserResponse);
        }
        if response_payload.reply_nonce != nonce {
            return Err(NodeStateError::MacVerificationFailed);
        }

        let endorser_public_key_spki = response_payload.public_key_spki.clone();
        let endorser_nonce = response_payload.nonce.clone();

        // Fetch the current roster
        let current_roster = client
            .get_roster(self.registration())
            .await
            .map_err(NodeStateError::hub)?;

        // Build the activation addendum
        let base_version = current_roster.version;
        let base_version_hash = compute_roster_hash(&current_roster);
        let new_version = base_version + 1;

        let activation_payload = proto::connect::roster::activation::Payload {
            base_version,
            base_version_hash,
            new_version,
            new_node_number: self.registration().node_number,
            endorser_node_number,
            new_node_nonce: nonce,
            endorser_nonce,
        };
        let activation_payload_bytes = activation_payload.encode_to_vec();
        let new_node_signature = signing_key.sign(&activation_payload_bytes);

        let activation = proto::connect::roster::Activation {
            payload: Some(activation_payload),
            new_node_signature,
            endorser_signature: vec![], // Hub will get this from the endorser
        };

        // Build the new roster
        let mut new_roster = current_roster.clone();
        new_roster.version = new_version;
        new_roster.nodes.push(proto::connect::roster::Node {
            node_number: self.registration().node_number,
            public_key_spki: signing_key.public_key_spki(),
        });
        new_roster.addenda.push(proto::connect::roster::Addendum {
            kind: Some(proto::connect::roster::addendum::Kind::Activation(activation)),
        });

        // Submit the roster update
        let cosigned_roster = client
            .update_roster(self.registration(), new_roster)
            .await
            .map_err(NodeStateError::hub)?;

        Ok(ActivatedNode {
            signing_key,
            endorser_public_key_spki,
            roster: cosigned_roster,
            registration: self.registration().clone(),
        })
    }
}

/// An activated node that has completed pairing and roster update.
pub struct ActivatedNode {
    signing_key: SigningKeyPair,
    endorser_public_key_spki: Vec<u8>,
    roster: proto::connect::roster::Roster,
    registration: NodeRegistration,
}

impl ActivatedNode {
    /// Get the node's signing key pair.
    pub fn signing_key(&self) -> &SigningKeyPair {
        &self.signing_key
    }

    /// Get the endorser's public key in SPKI format.
    pub fn endorser_public_key_spki(&self) -> &[u8] {
        &self.endorser_public_key_spki
    }

    /// Get the current roster.
    pub fn roster(&self) -> &proto::connect::roster::Roster {
        &self.roster
    }

    /// Get the node registration info.
    pub fn registration(&self) -> &NodeRegistration {
        &self.registration
    }
}

/// Compute a hash of the roster for version verification.
fn compute_roster_hash(roster: &proto::connect::roster::Roster) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(roster.encode_to_vec());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryNodeStateStore;
    use crate::types::DEFAULT_PROFILE_NAMESPACE;

    #[test]
    fn manager_initializes_and_reuses_state() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let first_stage = storage
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

        let second_stage = storage
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending_second = second_stage
            .into_pending()
            .expect("state remains pending until registration");
        assert_eq!(pending_second.root_key_bytes(), &first_key);
    }

    #[test]
    fn completing_registration_persists_and_transitions() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let stage = storage
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending = stage
            .into_pending()
            .expect("expected pending state prior to registration");
        let registration = crate::types::registration_fixture();

        let registered = pending.complete_registration(registration.clone()).unwrap();
        assert_eq!(registered.registration(), &registration);

        let loaded_stage = storage
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        assert!(matches!(loaded_stage, NodeStateStage::Registered(_)));
    }
}
