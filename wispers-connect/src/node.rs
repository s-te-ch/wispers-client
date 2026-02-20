//! Unified node type with runtime state checks.
//!
//! This module provides:
//! - `NodeStorage`: Factory for creating/restoring `Node` instances
//! - `Node`: The main node type that can be in Pending, Registered, or Activated state
//!
//! Operations check the current state at runtime and return `InvalidState` errors
//! if called in the wrong state.

use std::fmt;
use std::sync::{Arc, RwLock};

use crate::crypto::{generate_nonce, PairingCode, SigningKeyPair, X25519KeyPair};
use crate::errors::NodeStateError;
use crate::hub::proto;
use crate::roster::{
    build_activation_payload, create_activation_roster, create_bootstrap_roster, verify_roster,
};
use crate::storage::{NodeStateStore, SharedStore};
use crate::types::{ConnectivityGroupId, NodeInfo, NodeRegistration, PersistedNodeState};
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
            // Verify the roster cryptographically before trusting it
            let signing_key = SigningKeyPair::derive_from_root_key(state.root_key.as_bytes());
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
                roster,
            ))
        } else {
            Node::new_registered(state, self.store.clone(), self.config.clone())
        }
    }
}

/// The state a node is currently in (state machine state, not persisted state).
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

/// A unified node type that can be in any state (Pending, Registered, Activated).
///
/// Operations check the current state at runtime and return `InvalidState` errors
/// if called in the wrong state. Use `state()` to check the current state.
pub struct Node {
    persisted: PersistedNodeState,
    store: SharedStore,
    config: SharedConfig,
    // Derived from root key at construction time
    signing_key: SigningKeyPair,
    encryption_key: X25519KeyPair,
    // Present after activation:
    roster: Option<proto::roster::Roster>,
}

impl Node {
    /// Create a new pending node from initial state.
    pub(crate) fn new_pending(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
    ) -> Self {
        let root_key = persisted.root_key.as_bytes();
        Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            encryption_key: X25519KeyPair::derive_from_root_key(root_key),
            persisted,
            store,
            config,
            roster: None,
        }
    }

    /// Create a registered node (has registration but no roster).
    pub(crate) fn new_registered(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
    ) -> Result<Self, NodeStateError> {
        if persisted.registration.is_none() {
            return Err(NodeStateError::NotRegistered);
        }
        let root_key = persisted.root_key.as_bytes();
        Ok(Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            encryption_key: X25519KeyPair::derive_from_root_key(root_key),
            persisted,
            store,
            config,
            roster: None,
        })
    }

    /// Create an activated node (has registration and roster).
    pub(crate) fn new_activated(
        persisted: PersistedNodeState,
        store: SharedStore,
        config: SharedConfig,
        roster: proto::roster::Roster,
    ) -> Self {
        let root_key = persisted.root_key.as_bytes();
        Self {
            signing_key: SigningKeyPair::derive_from_root_key(root_key),
            encryption_key: X25519KeyPair::derive_from_root_key(root_key),
            persisted,
            store,
            config,
            roster: Some(roster),
        }
    }

    /// Get the current state of this node.
    ///
    /// - `Pending` if not registered
    /// - `Registered` if registered but not in the roster
    /// - `Activated` if registered and in the roster
    pub fn state(&self) -> NodeState {
        if self.roster.is_some() {
            NodeState::Activated
        } else if self.persisted.registration.is_some() {
            NodeState::Registered
        } else {
            NodeState::Pending
        }
    }

    /// Get the hub address.
    pub(crate) fn hub_addr(&self) -> String {
        self.config.read().unwrap().hub_addr.clone()
    }

    /// Check if node is registered (has registration info).
    pub fn is_registered(&self) -> bool {
        self.persisted.is_registered()
    }

    /// Get the registration info. Returns None if not registered.
    pub(crate) fn registration(&self) -> Option<&NodeRegistration> {
        self.persisted.registration.as_ref()
    }

    /// Get the node's number. Returns None if not registered.
    pub fn node_number(&self) -> Option<i32> {
        self.persisted.registration.as_ref().map(|r| r.node_number)
    }

    /// Get the connectivity group ID. Returns None if not registered.
    pub fn connectivity_group_id(&self) -> Option<&ConnectivityGroupId> {
        self.persisted
            .registration
            .as_ref()
            .map(|r| &r.connectivity_group_id)
    }

    /// Get the root key bytes (internal use only).
    #[cfg(test)]
    pub(crate) fn root_key_bytes(&self) -> &[u8; crate::types::ROOT_KEY_LEN] {
        self.persisted.root_key.as_bytes()
    }

    // -------------------------------------------------------------------------
    // State-checked accessors (return InvalidState if wrong state)
    // -------------------------------------------------------------------------

    fn require_pending(&self) -> Result<(), NodeStateError> {
        if self.state() != NodeState::Pending {
            return Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Pending",
            });
        }
        Ok(())
    }

    fn require_registered(&self) -> Result<&NodeRegistration, NodeStateError> {
        if self.state() != NodeState::Registered {
            return Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Registered",
            });
        }
        Ok(self.persisted.registration.as_ref().expect("checked above"))
    }

    fn require_at_least_registered(&self) -> Result<&NodeRegistration, NodeStateError> {
        match self.state() {
            NodeState::Pending => Err(NodeStateError::InvalidState {
                current: NodeState::Pending,
                required: "Registered or Activated",
            }),
            _ => Ok(self.persisted.registration.as_ref().expect("not pending")),
        }
    }

    #[allow(dead_code)]
    fn require_activated(&self) -> Result<(), NodeStateError> {
        if self.state() != NodeState::Activated {
            return Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Activated",
            });
        }
        Ok(())
    }

    /// Get the signing key.
    pub(crate) fn signing_key(&self) -> &SigningKeyPair {
        &self.signing_key
    }

    /// Get the encryption key (X25519).
    pub(crate) fn encryption_key(&self) -> &X25519KeyPair {
        &self.encryption_key
    }

    // -------------------------------------------------------------------------
    // Pending operations
    // -------------------------------------------------------------------------

    /// Complete registration with provided credentials (for testing).
    ///
    /// Requires: Pending state.
    #[cfg(test)]
    pub(crate) fn complete_registration(
        &mut self,
        registration: NodeRegistration,
    ) -> Result<(), NodeStateError> {
        self.require_pending()?;

        if self.persisted.is_registered() {
            return Err(NodeStateError::AlreadyRegistered);
        }

        self.persisted.set_registration(registration);
        self.store
            .save(&self.persisted)
            .map_err(NodeStateError::store)?;
        Ok(())
    }

    /// Register with the hub using a registration token.
    ///
    /// Requires: Pending state.
    /// Transitions to: Registered state.
    pub async fn register(&mut self, token: &str) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        self.require_pending()?;

        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;
        let registration = client
            .complete_registration(token)
            .await
            .map_err(NodeStateError::hub)?;

        self.persisted.set_registration(registration);
        self.store
            .save(&self.persisted)
            .map_err(NodeStateError::store)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Registered operations
    // -------------------------------------------------------------------------

    /// List all nodes in the connectivity group.
    ///
    /// Requires: Registered or Activated state.
    ///
    /// Returns combined information about each node:
    /// - Basic info (node_number, name, last_seen) from the hub
    /// - Activation status from the roster (if this node is activated)
    /// - `is_self` indicates whether this is the current node
    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>, NodeStateError> {
        use crate::hub::HubClient;

        let registration = self.require_at_least_registered()?;
        let mut client = HubClient::connect(self.hub_addr())
            .await
            .map_err(NodeStateError::hub)?;
        let hub_nodes = client
            .list_nodes(registration)
            .await
            .map_err(NodeStateError::hub)?;

        // Build a set of activated node numbers from the roster (if available)
        let activated_nodes: Option<std::collections::HashSet<i32>> =
            self.roster.as_ref().map(|r| {
                r.nodes
                    .iter()
                    .filter(|n| !n.revoked)
                    .map(|n| n.node_number)
                    .collect()
            });

        let my_node_number = registration.node_number;

        let nodes = hub_nodes
            .into_iter()
            .map(|hub_node| NodeInfo {
                node_number: hub_node.node_number,
                name: hub_node.name,
                is_self: hub_node.node_number == my_node_number,
                is_activated: activated_nodes
                    .as_ref()
                    .map(|set| set.contains(&hub_node.node_number)),
                last_seen_at_millis: hub_node.last_seen_at_millis,
            })
            .collect();

        Ok(nodes)
    }

    /// Start a serving session.
    ///
    /// Requires: Registered or Activated state.
    ///
    /// P2P connection requests are only accepted once the node is activated (appears
    /// in the roster). The incoming connection channels are always created; they will
    /// simply not receive any connections until activation is complete.
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

        let is_activated = self.state() == NodeState::Activated;
        log::info!(
            "Starting serving session for node {} in group {}{}",
            registration.node_number,
            registration.connectivity_group_id,
            if is_activated { "" } else { " (not yet activated)" }
        );

        let p2p_config = P2pConfig {
            x25519_key: self.encryption_key.clone(),
            hub_addr: hub_addr.clone(),
            registration: registration.clone(),
        };

        start_serving_impl(&hub_addr, self.signing_key.clone(), registration, p2p_config)
            .await
            .map_err(NodeStateError::hub)
    }

    /// Activate this node by pairing with an endorser node.
    ///
    /// Requires: Registered state.
    /// Transitions to: Activated state.
    ///
    /// The pairing code format is "node_number-secret" where secret is 10 base36 characters.
    pub async fn activate(&mut self, pairing_code: &str) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        let registration = self.require_registered()?.clone();

        // Parse the pairing code
        let pairing_code =
            PairingCode::parse(pairing_code).map_err(NodeStateError::InvalidPairingCode)?;
        let endorser_node_number = pairing_code.node_number;

        // Build the pairing request
        let nonce = generate_nonce();
        let payload = proto::pair_nodes_message::Payload {
            sender_node_number: registration.node_number,
            receiver_node_number: endorser_node_number,
            public_key_spki: self.signing_key.public_key_spki(),
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

        // Verify the base roster if not bootstrap (version > 0)
        if current_roster.version > 0 {
            verify_roster(
                &current_roster,
                endorser_node_number,
                &response_payload.public_key_spki,
            )
            .map_err(NodeStateError::RosterVerificationFailed)?;
        }

        // Build and sign the activation payload
        let activation_payload = build_activation_payload(
            &current_roster,
            endorser_node_number,
            registration.node_number,
            nonce,
            endorser_nonce,
        );
        let activation_payload_bytes = activation_payload.encode_to_vec();
        let new_node_signature = self.signing_key.sign(&activation_payload_bytes);

        // Build the new roster
        let new_roster = if current_roster.version == 0 {
            create_bootstrap_roster(
                endorser_node_number,
                &response_payload.public_key_spki,
                registration.node_number,
                &self.signing_key.public_key_spki(),
                activation_payload.new_node_nonce,
                activation_payload.endorser_nonce,
                new_node_signature,
            )
        } else {
            create_activation_roster(
                &current_roster,
                endorser_node_number,
                registration.node_number,
                &self.signing_key.public_key_spki(),
                activation_payload.new_node_nonce,
                activation_payload.endorser_nonce,
                new_node_signature,
            )
        };

        // Submit the roster update
        let cosigned_roster = client
            .update_roster(&registration, new_roster)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the cosigned roster
        verify_roster(
            &cosigned_roster,
            registration.node_number,
            &self.signing_key.public_key_spki(),
        )
        .map_err(NodeStateError::RosterVerificationFailed)?;

        // Update to activated state (keys already derived at construction)
        self.roster = Some(cosigned_roster);

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Activated operations
    // -------------------------------------------------------------------------

    /// Connect to a peer node using UDP transport.
    ///
    /// Requires: Activated state.
    pub async fn connect_udp(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::UdpConnection, crate::p2p::P2pError> {
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::{P2pError, UdpConnection};
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Check state - map to P2pError for this method's signature
        if self.state() != NodeState::Activated {
            return Err(P2pError::NotActivated);
        }

        let registration = self.persisted.registration.as_ref().expect("activated");
        let roster = self.roster.as_ref().expect("activated");
        let hub_addr = self.hub_addr();

        // Connect to hub
        let mut client = HubClient::connect(&hub_addr).await?;

        // Get STUN/TURN configuration
        let stun_turn_config = client.get_stun_turn_config(registration).await?;

        // Create ICE caller and gather candidates
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();

        // Build the StartConnectionRequest
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&peer_node_number.to_le_bytes());
        message_to_sign.extend_from_slice(&self.encryption_key.public_key());
        message_to_sign.extend_from_slice(caller_sdp.as_bytes());
        let signature = self.signing_key.sign(&message_to_sign);

        let request = proto::StartConnectionRequest {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: self.encryption_key.public_key().to_vec(),
            caller_sdp,
            signature,
            stun_turn_config: Some(stun_turn_config),
            transport: proto::Transport::Datagram.into(),
        };

        // Send to hub
        let response = client.start_connection(registration, request).await?;

        // Verify answerer's signature against roster
        let peer_node = roster
            .nodes
            .iter()
            .find(|n| n.node_number == peer_node_number)
            .ok_or(P2pError::SignatureVerificationFailed)?;

        let verifying_key = VerifyingKey::from_public_key_der(&peer_node.public_key_spki)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&response.connection_id.to_le_bytes());
        message_to_verify.extend_from_slice(&response.answerer_x25519_public_key);
        message_to_verify.extend_from_slice(response.answerer_sdp.as_bytes());

        let sig_bytes: [u8; 64] = response
            .signature
            .clone()
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;
        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(&message_to_verify, &sig)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Extract peer's X25519 public key
        let peer_x25519_public: [u8; 32] = response
            .answerer_x25519_public_key
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Derive shared secret
        let shared_secret = self.encryption_key.diffie_hellman(&peer_x25519_public);

        // Complete ICE connection
        ice_caller.connect(&response.answerer_sdp).await?;

        UdpConnection::new_caller(
            peer_node_number,
            response.connection_id,
            ice_caller,
            shared_secret,
        )
    }

    /// Connect to a peer node using QUIC transport.
    ///
    /// Requires: Activated state.
    pub async fn connect_quic(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::QuicConnection, crate::p2p::P2pError> {
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::{P2pError, QuicConnection};
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Check state - map to P2pError for this method's signature
        if self.state() != NodeState::Activated {
            return Err(P2pError::NotActivated);
        }

        let registration = self.persisted.registration.as_ref().expect("activated");
        let roster = self.roster.as_ref().expect("activated");
        let hub_addr = self.hub_addr();

        // Connect to hub
        let mut client = HubClient::connect(&hub_addr).await?;

        // Get STUN/TURN configuration
        let stun_turn_config = client.get_stun_turn_config(registration).await?;

        // Create ICE caller and gather candidates
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();

        // Build the StartConnectionRequest
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&peer_node_number.to_le_bytes());
        message_to_sign.extend_from_slice(&self.encryption_key.public_key());
        message_to_sign.extend_from_slice(caller_sdp.as_bytes());
        let signature = self.signing_key.sign(&message_to_sign);

        let request = proto::StartConnectionRequest {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: self.encryption_key.public_key().to_vec(),
            caller_sdp,
            signature,
            stun_turn_config: Some(stun_turn_config),
            transport: proto::Transport::Stream.into(),
        };

        // Send to hub
        let response = client.start_connection(registration, request).await?;

        // Verify answerer's signature against roster
        let peer_node = roster
            .nodes
            .iter()
            .find(|n| n.node_number == peer_node_number)
            .ok_or(P2pError::SignatureVerificationFailed)?;

        let verifying_key = VerifyingKey::from_public_key_der(&peer_node.public_key_spki)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&response.connection_id.to_le_bytes());
        message_to_verify.extend_from_slice(&response.answerer_x25519_public_key);
        message_to_verify.extend_from_slice(response.answerer_sdp.as_bytes());

        let sig_bytes: [u8; 64] = response
            .signature
            .clone()
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;
        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(&message_to_verify, &sig)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Extract peer's X25519 public key
        let peer_x25519_public: [u8; 32] = response
            .answerer_x25519_public_key
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Derive shared secret
        let shared_secret = self.encryption_key.diffie_hellman(&peer_x25519_public);

        // Complete ICE connection
        ice_caller.connect(&response.answerer_sdp).await?;

        // Complete QUIC handshake
        QuicConnection::connect_caller(
            peer_node_number,
            response.connection_id,
            ice_caller,
            shared_secret,
        )
        .await
    }

    // -------------------------------------------------------------------------
    // Logout (works from any state)
    // -------------------------------------------------------------------------

    /// Logout: delete local state and deregister from hub if registered.
    ///
    /// - Pending: just deletes local state
    /// - Registered: deregisters from hub, then deletes local state
    /// - Activated: self-revokes from roster, deregisters from hub, deletes local state
    pub async fn logout(self) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        match self.state() {
            NodeState::Pending => self.store.delete().map_err(NodeStateError::store),
            NodeState::Registered => {
                let registration = self.persisted.registration.as_ref().expect("registered");
                let mut client = HubClient::connect(self.hub_addr())
                    .await
                    .map_err(NodeStateError::hub)?;
                client
                    .deregister_node(registration)
                    .await
                    .map_err(NodeStateError::hub)?;
                self.store.delete().map_err(NodeStateError::store)
            }
            NodeState::Activated => {
                use crate::hub::proto::roster::revocation;
                use crate::roster::{compute_roster_hash, create_revocation_roster};

                let registration = self.persisted.registration.as_ref().expect("activated");
                let roster = self.roster.as_ref().expect("activated");

                let mut client = HubClient::connect(self.hub_addr())
                    .await
                    .map_err(NodeStateError::hub)?;

                // Step 1: Self-revoke from roster
                let base_hash = compute_roster_hash(roster);
                let payload = revocation::Payload {
                    base_version: roster.version,
                    base_version_hash: base_hash,
                    new_version: roster.version + 1,
                    revoked_node_number: registration.node_number,
                    revoker_node_number: registration.node_number,
                };
                let signature = self.signing_key.sign(&payload.encode_to_vec());

                let new_roster = create_revocation_roster(
                    roster,
                    registration.node_number,
                    registration.node_number,
                    signature,
                );

                client
                    .update_roster(registration, new_roster)
                    .await
                    .map_err(NodeStateError::hub)?;

                // Step 2: Deregister from hub
                client
                    .deregister_node(registration)
                    .await
                    .map_err(NodeStateError::hub)?;

                // Step 3: Delete local state
                self.store.delete().map_err(NodeStateError::store)
            }
        }
    }
}

/// Test helper for creating Node instances.
#[doc(hidden)]
impl Node {
    /// Create an activated Node for testing with explicit configuration.
    pub fn new_activated_for_test(
        root_key: [u8; 32],
        roster: proto::roster::Roster,
        registration: NodeRegistration,
        hub_addr: String,
    ) -> Self {
        use crate::storage::InMemoryNodeStateStore;

        let mut persisted = PersistedNodeState::new();
        persisted.root_key = crate::types::RootKey::from_bytes(root_key);
        persisted.registration = Some(registration);

        Self {
            signing_key: SigningKeyPair::derive_from_root_key(&root_key),
            encryption_key: X25519KeyPair::derive_from_root_key(&root_key),
            persisted,
            store: Arc::new(InMemoryNodeStateStore::new()),
            config: Arc::new(std::sync::RwLock::new(RuntimeConfig::new_with_addr(
                hub_addr,
            ))),
            roster: Some(roster),
        }
    }
}

/// Helper to start a serving session (used by Node for both Registered and Activated).
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
        let node = Node::new_pending(persisted, store.clone(), config.clone());
        assert_eq!(node.state(), NodeState::Pending);

        // Registered
        let mut persisted = PersistedNodeState::new();
        persisted.set_registration(crate::types::registration_fixture());
        let node = Node::new_registered(persisted, store.clone(), config.clone()).unwrap();
        assert_eq!(node.state(), NodeState::Registered);
    }

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
    }
}
