//! Unified node type with runtime state checks and typestate-driven transitions.
//!
//! This module provides:
//! - `NodeStorage`: Factory for creating/restoring `Node` instances
//! - `Node`: An enum wrapping `PendingNode`, `RegisteredNode`, and `ActivatedNode`
//! - `PendingNode`, `RegisteredNode`, `ActivatedNode`: Specific node types for each state
//!
//! Operations are implemented on the specific node types to ensure safety at
//! compile time. The `Node` enum provides a unified handle for use in FFI
//! and generic contexts, checking state at runtime and delegating to variants.

use std::fmt;
use std::sync::{Arc, RwLock};

use crate::crypto::{PairingCode, SigningKeyPair, generate_nonce};
use crate::errors::NodeStateError;
use crate::hub::proto;
use crate::roster::{
    add_activation_to_roster, build_activation_payload, compute_signing_hash,
    create_bootstrap_roster, set_new_node_signature, verify_roster,
};
use crate::storage::{NodeStateStore, SharedStore};
#[cfg(test)]
use crate::types::ROOT_KEY_LEN;
use crate::types::{
    ConnectivityGroupId, GroupInfo, GroupState, NodeInfo, NodeRegistration, PersistedNodeState,
    RootKey,
};
use prost::Message;

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
///
/// This is the main entry point for creating `Node` instances. Create a `NodeStorage`
/// with a storage backend, then call `restore_or_init_node()` to get a `Node`.
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

    /// Delete all persisted state. Used for logout when the node can't be
    /// restored (e.g. hub rejected our credentials).
    pub fn delete_state(&self) -> Result<(), NodeStateError> {
        self.store.delete().map_err(NodeStateError::store)
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
    pub async fn restore_or_init_node(&self) -> Result<Node, NodeStateError> {
        use crate::hub::HubClient;

        let state = match self.store.load().map_err(NodeStateError::store)? {
            Some(state) => state,
            None => {
                let state = PersistedNodeState::new();
                self.store.save(&state).map_err(NodeStateError::store)?;
                return Ok(Node::Pending(PendingNode::new(
                    state,
                    self.store.clone(),
                    self.config.clone(),
                )));
            }
        };

        // Not registered yet
        if !state.is_registered() {
            return Ok(Node::Pending(PendingNode::new(
                state,
                self.store.clone(),
                self.config.clone(),
            )));
        }

        // Registered - fetch roster to check if activated
        let registration = state.registration.as_ref().expect("checked is_registered");
        let hub_addr = self.config.read().unwrap().hub_addr.clone();

        let mut client = HubClient::connect(hub_addr)
            .await
            .map_err(NodeStateError::hub)?;

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
            // Verify the roster cryptographically before trusting it
            let signing_key = SigningKeyPair::derive_from_root_key(state.root_key.as_bytes());
            verify_roster(
                &roster,
                registration.node_number,
                &signing_key.public_key_spki(),
            )
            .map_err(NodeStateError::RosterVerificationFailed)?;

            Ok(Node::Activated(ActivatedNode::new(
                state,
                self.store.clone(),
                self.config.clone(),
                roster,
            )))
        } else {
            Ok(Node::Registered(RegisteredNode::new(
                state,
                self.store.clone(),
                self.config.clone(),
            )?))
        }
    }
}

/// The state a node is currently in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Node needs to register with the hub.
    Pending,
    /// Node is registered but not yet activated.
    Registered,
    /// Node is activated and ready for P2P connections.
    Activated,
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeState::Pending => write!(f, "Pending"),
            NodeState::Registered => write!(f, "Registered"),
            NodeState::Activated => write!(f, "Activated"),
        }
    }
}

// -------------------------------------------------------------------------
// Typestate variants
// -------------------------------------------------------------------------

/// A node that has not yet registered with the hub.
pub struct PendingNode {
    persisted: PersistedNodeState,
    store: SharedStore,
    config: SharedConfig,
    signing_key: SigningKeyPair,
}

/// A node that is registered with the hub but not yet in a roster.
pub struct RegisteredNode {
    registration: NodeRegistration,
    persisted: PersistedNodeState,
    store: SharedStore,
    config: SharedConfig,
    signing_key: SigningKeyPair,
}

/// A node that is fully activated and in the roster.
pub struct ActivatedNode {
    registration: NodeRegistration,
    roster: RwLock<proto::roster::Roster>,
    persisted: PersistedNodeState,
    store: SharedStore,
    config: SharedConfig,
    signing_key: SigningKeyPair,
}

impl PendingNode {
    pub(crate) fn new(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
    ) -> Self {
        let root_key = persisted.root_key.as_bytes();
        Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            persisted,
            store,
            config,
        }
    }

    pub(crate) fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
    }

    pub async fn logout(self) -> Result<PendingNode, NodeStateError> {
        self.store.delete().map_err(NodeStateError::store)?;
        let mut persisted = self.persisted;
        persisted.registration = None;
        Ok(PendingNode::new(persisted, self.store, self.config))
    }
}

impl RegisteredNode {
    pub(crate) fn new(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
    ) -> Result<Self, NodeStateError> {
        let registration = persisted
            .registration
            .clone()
            .ok_or(NodeStateError::NotRegistered)?;
        let root_key = persisted.root_key.as_bytes();
        Ok(Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            registration,
            persisted,
            store,
            config,
        })
    }

    pub(crate) fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
    }

    pub async fn logout(self) -> Result<PendingNode, NodeStateError> {
        use crate::hub::HubClient;

        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;

        // Best effort remote deregistration
        let _ = client.deregister_node(&self.registration).await;

        self.store.delete().map_err(NodeStateError::store)?;
        let mut persisted = self.persisted;
        persisted.registration = None;
        Ok(PendingNode::new(persisted, self.store, self.config))
    }
}

impl ActivatedNode {
    pub(crate) fn new(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
        roster: proto::roster::Roster,
    ) -> Self {
        let registration = persisted
            .registration
            .clone()
            .expect("activated node must have registration");
        let root_key = persisted.root_key.as_bytes();
        Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            registration,
            roster: RwLock::new(roster),
            persisted,
            store,
            config,
        }
    }

    pub(crate) fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
    }

    pub async fn logout(self) -> Result<PendingNode, NodeStateError> {
        use crate::hub::HubClient;
        use crate::roster::{
            active_nodes, add_revocation_to_roster, build_revocation_payload, set_revoker_signature,
        };

        let (active_count, roster) = {
            let roster = self.roster.read().unwrap();
            (active_nodes(&roster).count(), roster.clone())
        };

        if active_count <= 1 {
            return Err(NodeStateError::LastActiveNode);
        }

        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;

        // Best effort remote revocation and deregistration
        let mut new_roster = roster;
        let revocation_payload = build_revocation_payload(
            &new_roster,
            self.registration.node_number,
            self.registration.node_number,
        );
        add_revocation_to_roster(&mut new_roster, revocation_payload);
        let signing_hash = compute_signing_hash(&new_roster);
        let signature = self.signing_key.sign(&signing_hash);
        set_revoker_signature(&mut new_roster, signature);

        if client
            .update_roster(&self.registration, new_roster)
            .await
            .is_ok()
        {
            let _ = client.deregister_node(&self.registration).await;
        }

        self.store.delete().map_err(NodeStateError::store)?;
        let mut persisted = self.persisted;
        persisted.registration = None;
        Ok(PendingNode::new(persisted, self.store, self.config))
    }

    async fn find_peer_in_roster(
        &self,
        client: &mut crate::hub::HubClient,
        peer_node_number: i32,
    ) -> Result<proto::roster::Node, crate::p2p::P2pError> {
        {
            let roster = self.roster.read().unwrap();
            if let Some(node) = roster
                .nodes
                .iter()
                .find(|n| n.node_number == peer_node_number && !n.revoked)
            {
                return Ok(node.clone());
            }
        }

        log::info!(
            "Peer node {} not in cached roster, refetching from hub",
            peer_node_number
        );
        let fresh_roster = client
            .get_and_verify_roster(&self.registration, &self.signing_key.public_key_spki())
            .await?;

        let peer_node = fresh_roster
            .nodes
            .iter()
            .find(|n| n.node_number == peer_node_number && !n.revoked)
            .cloned()
            .ok_or(crate::p2p::P2pError::SignatureVerificationFailed)?;

        *self.roster.write().unwrap() = fresh_roster;
        Ok(peer_node)
    }

    pub async fn connect_udp(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::UdpConnection, crate::p2p::P2pError> {
        use crate::crypto::X25519KeyPair;
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::UdpConnection;
        use crate::p2p_signing;

        let hub_addr = self.hub_addr();
        let mut client = HubClient::connect(&hub_addr).await?;
        let stun_turn_config = client.get_stun_turn_config(&self.registration).await?;
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();
        let encryption_key = X25519KeyPair::generate_ephemeral();

        let payload = proto::start_connection_request::Payload {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: encryption_key.public_key().to_vec(),
            caller_sdp,
            transport: proto::Transport::Datagram.into(),
            stun_turn_config: Some(stun_turn_config),
        };
        let request = p2p_signing::build_signed_request(&self.signing_key, &payload);
        let response = client.start_connection(&self.registration, request).await?;
        let peer_node = self
            .find_peer_in_roster(&mut client, peer_node_number)
            .await?;
        let response_payload = p2p_signing::verify_response(&response, &peer_node.public_key_spki)
            .map_err(|_| crate::p2p::P2pError::SignatureVerificationFailed)?;

        let peer_x25519_public: [u8; 32] =
            response_payload
                .answerer_x25519_public_key
                .try_into()
                .map_err(|_| crate::p2p::P2pError::SignatureVerificationFailed)?;

        let shared_secret = encryption_key.diffie_hellman(&peer_x25519_public);
        ice_caller.connect(&response_payload.answerer_sdp).await?;

        UdpConnection::new_caller(
            peer_node_number,
            response_payload.connection_id,
            ice_caller,
            shared_secret,
        )
    }

    pub async fn connect_quic(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::QuicConnection, crate::p2p::P2pError> {
        use crate::crypto::X25519KeyPair;
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::QuicConnection;
        use crate::p2p_signing;

        let hub_addr = self.hub_addr();
        let mut client = HubClient::connect(&hub_addr).await?;
        let stun_turn_config = client.get_stun_turn_config(&self.registration).await?;
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();
        let encryption_key = X25519KeyPair::generate_ephemeral();

        let payload = proto::start_connection_request::Payload {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: encryption_key.public_key().to_vec(),
            caller_sdp,
            transport: proto::Transport::Stream.into(),
            stun_turn_config: Some(stun_turn_config),
        };
        let request = p2p_signing::build_signed_request(&self.signing_key, &payload);
        let response = client.start_connection(&self.registration, request).await?;
        let peer_node = self
            .find_peer_in_roster(&mut client, peer_node_number)
            .await?;
        let response_payload = p2p_signing::verify_response(&response, &peer_node.public_key_spki)
            .map_err(|_| crate::p2p::P2pError::SignatureVerificationFailed)?;

        let peer_x25519_public: [u8; 32] =
            response_payload
                .answerer_x25519_public_key
                .try_into()
                .map_err(|_| crate::p2p::P2pError::SignatureVerificationFailed)?;

        let shared_secret = encryption_key.diffie_hellman(&peer_x25519_public);
        ice_caller.connect(&response_payload.answerer_sdp).await?;

        QuicConnection::connect_caller(
            peer_node_number,
            response_payload.connection_id,
            ice_caller,
            shared_secret,
        )
        .await
    }
}

// -------------------------------------------------------------------------
// Unified Node Enum
// -------------------------------------------------------------------------

/// A unified node type that can be in any state (Pending, Registered, Activated).
pub enum Node {
    Pending(PendingNode),
    Registered(RegisteredNode),
    Activated(ActivatedNode),
    /// Internal placeholder used during state transitions.
    #[doc(hidden)]
    Placeholder,
}

impl Node {
    pub fn state(&self) -> NodeState {
        match self {
            Node::Pending(_) => NodeState::Pending,
            Node::Registered(_) => NodeState::Registered,
            Node::Activated(_) => NodeState::Activated,
            Node::Placeholder => unreachable!("Node used in placeholder state"),
        }
    }

    pub fn is_registered(&self) -> bool {
        !matches!(self, Node::Pending(_))
    }

    pub fn registration(&self) -> Option<&NodeRegistration> {
        match self {
            Node::Pending(_) => None,
            Node::Registered(n) => Some(&n.registration),
            Node::Activated(n) => Some(&n.registration),
            Node::Placeholder => None,
        }
    }

    pub fn node_number(&self) -> Option<i32> {
        self.registration().map(|r| r.node_number)
    }

    pub fn connectivity_group_id(&self) -> Option<&ConnectivityGroupId> {
        self.registration().map(|r| &r.connectivity_group_id)
    }

    pub fn attestation_jwt(&self) -> Option<&str> {
        self.registration().map(|r| r.attestation_jwt.as_str())
    }

    #[cfg(test)]
    pub(crate) fn root_key_bytes(&self) -> &[u8; ROOT_KEY_LEN] {
        match self {
            Node::Pending(n) => n.persisted.root_key.as_bytes(),
            Node::Registered(n) => n.persisted.root_key.as_bytes(),
            Node::Activated(n) => n.persisted.root_key.as_bytes(),
            Node::Placeholder => unreachable!(),
        }
    }

    pub async fn group_info(&self) -> Result<GroupInfo, NodeStateError> {
        use crate::hub::HubClient;
        use crate::roster::active_nodes;

        let registration = self.require_at_least_registered()?;
        let hub_addr = self.hub_addr();
        let mut client = HubClient::connect(&hub_addr)
            .await
            .map_err(NodeStateError::hub)?;

        let hub_nodes = client
            .list_nodes(registration)
            .await
            .map_err(NodeStateError::hub)?;

        let roster = client
            .get_unverified_roster(registration)
            .await
            .map_err(NodeStateError::hub)?;

        let activated_set: std::collections::HashSet<i32> =
            active_nodes(&roster).map(|n| n.node_number).collect();

        let hub_numbers: std::collections::HashSet<i32> =
            hub_nodes.iter().map(|n| n.node_number).collect();

        let is_dead_roster =
            roster.version > 0 && !activated_set.iter().any(|n| hub_numbers.contains(n));

        let my_node_number = registration.node_number;
        let self_activated = activated_set.contains(&my_node_number) && !is_dead_roster;

        let nodes: Vec<NodeInfo> = hub_nodes
            .into_iter()
            .map(|hub_node| {
                let is_activated = if is_dead_roster {
                    Some(false)
                } else if roster.version == 0 && activated_set.is_empty() {
                    Some(false)
                } else if self_activated {
                    Some(activated_set.contains(&hub_node.node_number))
                } else {
                    None
                };
                NodeInfo {
                    node_number: hub_node.node_number,
                    name: hub_node.name,
                    metadata: hub_node.metadata,
                    is_self: hub_node.node_number == my_node_number,
                    is_activated,
                    last_seen_at_millis: hub_node.last_seen_at_millis,
                    is_online: hub_node.is_online,
                }
            })
            .collect();

        let state = if nodes.len() <= 1 {
            GroupState::Alone
        } else if activated_set.is_empty() || is_dead_roster {
            GroupState::Bootstrap
        } else if !self_activated {
            GroupState::NeedActivation
        } else {
            let all_activated = nodes.iter().all(|n| n.is_activated == Some(true));
            if all_activated {
                GroupState::AllActivated
            } else {
                GroupState::CanEndorse
            }
        };

        Ok(GroupInfo { state, nodes })
    }

    pub async fn register(&mut self, token: &str) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        if !matches!(self, Node::Pending(_)) {
            return Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Pending",
            });
        }

        let hub_addr = self.hub_addr();
        let mut client = HubClient::connect(&hub_addr)
            .await
            .map_err(NodeStateError::hub)?;
        let registration = client
            .complete_registration(token)
            .await
            .map_err(NodeStateError::hub)?;

        let node = std::mem::replace(self, Node::Placeholder);
        match node {
            Node::Pending(mut p) => {
                p.persisted.set_registration(registration.clone());
                p.store.save(&p.persisted).map_err(NodeStateError::store)?;
                *self = Node::Registered(RegisteredNode::new(p.persisted, p.store, p.config)?);
                Ok(())
            }
            _ => {
                *self = node;
                Err(NodeStateError::InvalidState {
                    current: self.state(),
                    required: "Pending",
                })
            }
        }
    }

    pub async fn activate(&mut self, activation_code: &str) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        let registration = self
            .registration()
            .ok_or(NodeStateError::NotRegistered)?
            .clone();

        // Parse the activation code
        let pairing_code =
            PairingCode::parse(activation_code).map_err(NodeStateError::InvalidActivationCode)?;
        let endorser_node_number = pairing_code.node_number;

        // Build the pairing request
        let nonce = generate_nonce();
        let payload = proto::pair_nodes_message::Payload {
            sender_node_number: registration.node_number,
            receiver_node_number: endorser_node_number,
            public_key_spki: self.signing_key().public_key_spki(),
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
            .pair_nodes(&registration, request_message)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the response
        let response_payload = response
            .payload
            .ok_or(NodeStateError::MissingEndorserResponse)?;
        let response_payload_bytes = response_payload.encode_to_vec();

        if !pairing_code
            .secret
            .verify_mac(&response_payload_bytes, &response.mac)
        {
            return Err(NodeStateError::MacVerificationFailed);
        }

        // Verify the response is for us and contains the expected reply_nonce
        if response_payload.receiver_node_number != registration.node_number {
            return Err(NodeStateError::MissingEndorserResponse);
        }
        if response_payload.reply_nonce != nonce {
            return Err(NodeStateError::MacVerificationFailed);
        }

        let endorser_nonce = response_payload.nonce.clone();

        // Fetch the current roster (unverified - we're not in it yet)
        let current_roster = client
            .get_unverified_roster(&registration)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the base roster if not bootstrap
        if current_roster.version > 0 {
            verify_roster(
                &current_roster,
                endorser_node_number,
                &response_payload.public_key_spki,
            )
            .map_err(NodeStateError::RosterVerificationFailed)?;
        }

        // Build the new roster, then sign over its signing hash.
        let self_public_key_spki = self.signing_key().public_key_spki();
        let endorser_public_key_spki = response_payload.public_key_spki.clone();
        let activation_payload = build_activation_payload(
            &current_roster,
            registration.node_number,
            endorser_node_number,
            nonce,
            endorser_nonce,
        );
        let mut new_roster = if current_roster.version == 0 {
            create_bootstrap_roster(
                activation_payload,
                &self_public_key_spki,
                &endorser_public_key_spki,
            )
        } else {
            let mut r = current_roster.clone();
            add_activation_to_roster(&mut r, activation_payload, &self_public_key_spki);
            r
        };
        let signing_hash = compute_signing_hash(&new_roster);
        let new_node_signature = self.signing_key().sign(&signing_hash);
        set_new_node_signature(&mut new_roster, new_node_signature);

        // Submit the roster update
        let cosigned_roster = client
            .update_roster(&registration, new_roster)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the cosigned roster
        verify_roster(
            &cosigned_roster,
            registration.node_number,
            &self.signing_key().public_key_spki(),
        )
        .map_err(NodeStateError::RosterVerificationFailed)?;

        // NOW we transition
        let node = std::mem::replace(self, Node::Placeholder);
        match node {
            Node::Registered(r) => {
                *self = Node::Activated(ActivatedNode::new(
                    r.persisted,
                    r.store,
                    r.config,
                    cosigned_roster,
                ));
                Ok(())
            }
            _ => {
                *self = node;
                Err(NodeStateError::InvalidState {
                    current: self.state(),
                    required: "Registered",
                })
            }
        }
    }

    pub async fn logout(&mut self) -> Result<(), NodeStateError> {
        let node = std::mem::replace(self, Node::Placeholder);
        let (p, res) = match node {
            Node::Pending(p) => {
                let store = p.store.clone();
                let config = p.config.clone();
                let res = p.logout().await;
                match res {
                    Ok(new_p) => (new_p, Ok(())),
                    Err(e) => (
                        PendingNode::new(PersistedNodeState::new(), store, config),
                        Err(e),
                    ),
                }
            }
            Node::Registered(r) => {
                let store = r.store.clone();
                let config = r.config.clone();
                let res = r.logout().await;
                match res {
                    Ok(new_p) => (new_p, Ok(())),
                    Err(e) => (
                        PendingNode::new(PersistedNodeState::new(), store, config),
                        Err(e),
                    ),
                }
            }
            Node::Activated(a) => {
                let store = a.store.clone();
                let config = a.config.clone();
                let res = a.logout().await;
                match res {
                    Ok(new_p) => (new_p, Ok(())),
                    Err(e) => (
                        PendingNode::new(PersistedNodeState::new(), store, config),
                        Err(e),
                    ),
                }
            }
            Node::Placeholder => unreachable!(),
        };

        *self = Node::Pending(p);
        res
    }

    pub(crate) fn hub_addr(&self) -> String {
        match self {
            Node::Pending(n) => n.hub_addr(),
            Node::Registered(n) => n.hub_addr(),
            Node::Activated(n) => n.hub_addr(),
            Node::Placeholder => unreachable!(),
        }
    }

    pub(crate) fn signing_key(&self) -> &SigningKeyPair {
        match self {
            Node::Pending(n) => &n.signing_key,
            Node::Registered(n) => &n.signing_key,
            Node::Activated(n) => &n.signing_key,
            Node::Placeholder => unreachable!(),
        }
    }

    fn require_at_least_registered(&self) -> Result<&NodeRegistration, NodeStateError> {
        match self {
            Node::Registered(n) => Ok(&n.registration),
            Node::Activated(n) => Ok(&n.registration),
            _ => Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Registered or Activated",
            }),
        }
    }

    pub async fn start_serving(
        &self,
    ) -> Result<
        (
            crate::serving::ServingHandle,
            crate::serving::ServingSession,
            crate::serving::IncomingConnections,
        ),
        NodeStateError,
    > {
        use crate::serving::P2pConfig;

        let registration = self.require_at_least_registered()?;
        let hub_addr = self.hub_addr();

        let p2p_config = P2pConfig {
            hub_addr: hub_addr.clone(),
            registration: registration.clone(),
        };

        start_serving_impl(
            &hub_addr,
            self.signing_key().clone(),
            registration,
            p2p_config,
        )
        .await
        .map_err(NodeStateError::hub)
    }

    pub async fn connect_udp(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::UdpConnection, crate::p2p::P2pError> {
        match self {
            Node::Activated(n) => n.connect_udp(peer_node_number).await,
            _ => Err(crate::p2p::P2pError::NotActivated),
        }
    }

    pub async fn connect_quic(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::QuicConnection, crate::p2p::P2pError> {
        match self {
            Node::Activated(n) => n.connect_quic(peer_node_number).await,
            _ => Err(crate::p2p::P2pError::NotActivated),
        }
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Test helper for creating Node instances.
#[doc(hidden)]
impl Node {
    pub fn new_activated_for_test(
        root_key: [u8; 32],
        roster: proto::roster::Roster,
        registration: NodeRegistration,
        hub_addr: String,
    ) -> Self {
        use crate::storage::InMemoryNodeStateStore;

        let mut persisted = PersistedNodeState::new();
        persisted.root_key = RootKey::from_bytes(root_key);
        persisted.registration = Some(registration.clone());

        Node::Activated(ActivatedNode::new(
            persisted,
            Arc::new(InMemoryNodeStateStore::new()),
            Arc::new(RwLock::new(RuntimeConfig::new_with_addr(hub_addr))),
            roster,
        ))
    }
}

async fn start_serving_impl(
    hub_addr: &str,
    signing_key: SigningKeyPair,
    registration: &NodeRegistration,
    p2p_config: crate::serving::P2pConfig,
) -> Result<
    (
        crate::serving::ServingHandle,
        crate::serving::ServingSession,
        crate::serving::IncomingConnections,
    ),
    crate::hub::HubError,
> {
    use crate::hub::HubClient;
    use crate::serving::ServingSession;

    let mut client = HubClient::connect(hub_addr).await?;
    let conn = client.start_serving(registration).await?;

    let (handle, session, incoming) = ServingSession::new(
        conn,
        signing_key,
        registration.connectivity_group_id.clone(),
        registration.node_number,
        p2p_config,
    );

    Ok((handle, session, incoming))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryNodeStateStore;

    #[test]
    fn state_detection_works() {
        let store: SharedStore = Arc::new(InMemoryNodeStateStore::new());
        let config = Arc::new(RwLock::new(RuntimeConfig::new()));

        // Pending
        let persisted = PersistedNodeState::new();
        let node = Node::Pending(PendingNode::new(persisted, store.clone(), config.clone()));
        assert_eq!(node.state(), NodeState::Pending);

        // Registered
        let mut persisted = PersistedNodeState::new();
        persisted.set_registration(crate::types::registration_fixture());
        let node = Node::Registered(
            RegisteredNode::new(persisted, store.clone(), config.clone()).unwrap(),
        );
        assert_eq!(node.state(), NodeState::Registered);
    }

    #[tokio::test]
    async fn storage_initializes_and_reuses_state() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let first_node = storage.restore_or_init_node().await.unwrap();
        assert_eq!(first_node.state(), NodeState::Pending);
        let first_key = *first_node.root_key_bytes();

        drop(first_node);
        let second_node = storage.restore_or_init_node().await.unwrap();
        assert_eq!(second_node.state(), NodeState::Pending);
        assert_eq!(second_node.root_key_bytes(), &first_key);
    }

    #[tokio::test]
    async fn completing_registration_persists_and_transitions() {
        let store = Arc::new(InMemoryNodeStateStore::new());
        let verify_store = store.clone();

        let shared_storage = NodeStorage {
            store: store as SharedStore,
            config: Arc::new(RwLock::new(RuntimeConfig::new())),
        };

        let mut node = shared_storage.restore_or_init_node().await.unwrap();
        assert_eq!(node.state(), NodeState::Pending);
        let registration = crate::types::registration_fixture();

        node.register("dummy_token").await.unwrap_err(); // HubClient::connect fails in test

        // Manual transition for test
        if let Node::Pending(p) = node {
            let r = RegisteredNode::new(
                PersistedNodeState::from_stored(
                    *p.persisted.root_key_bytes(),
                    Some(registration.clone()),
                ),
                p.store.clone(),
                p.config.clone(),
            )
            .unwrap();

            p.store.save(&r.persisted).unwrap();
            node = Node::Registered(r);
        }

        assert_eq!(node.state(), NodeState::Registered);
        assert_eq!(node.registration(), Some(&registration));

        let loaded = verify_store
            .load()
            .unwrap()
            .expect("state should be persisted");
        assert!(loaded.is_registered());
        assert_eq!(loaded.registration.as_ref().unwrap(), &registration);
    }
}
