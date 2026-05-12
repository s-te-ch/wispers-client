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

use crate::crypto::{PairingCode, SigningKeyPair, generate_nonce};
use crate::errors::NodeStateError;
use crate::hub::proto;
use crate::roster::{
    add_activation_to_roster, build_activation_payload, compute_signing_hash,
    create_bootstrap_roster, set_new_node_signature, verify_roster,
};
use crate::storage::{NodeStateStore, SharedStore};
use crate::types::{
    ConnectivityGroupId, GroupInfo, GroupState, NodeInfo, NodeRegistration, PersistedNodeState,
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

        // Fetch unverified first - we need to check if we're in it before we can verify.
        // If the hub says unauthenticated/not_found, the node was removed server-side.
        // Surface this as an error so callers can decide how to handle it (e.g. prompt
        // the user to logout).
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

/// The internal state of a node.
enum InnerState {
    /// Node needs to register with the hub.
    Pending,
    /// Node is registered but not yet activated.
    Registered(NodeRegistration),
    /// Node is activated and ready for P2P connections.
    Activated {
        registration: NodeRegistration,
        roster: std::sync::RwLock<proto::roster::Roster>,
    },
}

/// A unified node type that can be in any state (Pending, Registered, Activated).
///
/// Operations check the current state at runtime and return `InvalidState` errors
/// if called in the wrong state. Use `state()` to check the current state.
pub struct Node {
    inner: InnerState,
    persisted: PersistedNodeState,
    store: SharedStore,
    config: SharedConfig,
    // Derived from root key at construction time
    signing_key: SigningKeyPair,
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
            inner: InnerState::Pending,
            persisted,
            store,
            config,
        }
    }

    /// Create a registered node (has registration but no roster).
    pub(crate) fn new_registered(
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
            inner: InnerState::Registered(registration),
            persisted,
            store,
            config,
        })
    }

    /// Create an activated node (has registration and roster).
    pub(crate) fn new_activated(
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
            inner: InnerState::Activated {
                registration,
                roster: RwLock::new(roster),
            },
            persisted,
            store,
            config,
        }
    }

    /// Get the current state of this node.
    pub fn state(&self) -> NodeState {
        match &self.inner {
            InnerState::Pending => NodeState::Pending,
            InnerState::Registered(_) => NodeState::Registered,
            InnerState::Activated { .. } => NodeState::Activated,
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
        match &self.inner {
            InnerState::Pending => None,
            InnerState::Registered(reg) => Some(reg),
            InnerState::Activated { registration, .. } => Some(registration),
        }
    }

    /// Get the node's number. Returns None if not registered.
    pub fn node_number(&self) -> Option<i32> {
        self.registration().map(|r| r.node_number)
    }

    /// Get the connectivity group ID. Returns None if not registered.
    pub fn connectivity_group_id(&self) -> Option<&ConnectivityGroupId> {
        self.registration().map(|r| &r.connectivity_group_id)
    }

    /// Get the attestation JWT. Returns None if not registered.
    pub fn attestation_jwt(&self) -> Option<&str> {
        self.registration().map(|r| r.attestation_jwt.as_str())
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
        if !matches!(self.inner, InnerState::Pending) {
            return Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Pending",
            });
        }
        Ok(())
    }

    fn require_registered(&self) -> Result<&NodeRegistration, NodeStateError> {
        match &self.inner {
            InnerState::Registered(reg) => Ok(reg),
            _ => Err(NodeStateError::InvalidState {
                current: self.state(),
                required: "Registered",
            }),
        }
    }

    fn require_at_least_registered(&self) -> Result<&NodeRegistration, NodeStateError> {
        match &self.inner {
            InnerState::Registered(reg)
            | InnerState::Activated {
                registration: reg, ..
            } => Ok(reg),
            InnerState::Pending => Err(NodeStateError::InvalidState {
                current: NodeState::Pending,
                required: "Registered or Activated",
            }),
        }
    }

    #[allow(dead_code)]
    fn require_activated(&self) -> Result<(), NodeStateError> {
        if !matches!(self.inner, InnerState::Activated { .. }) {
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

        self.persisted.set_registration(registration.clone());
        self.store
            .save(&self.persisted)
            .map_err(NodeStateError::store)?;

        self.inner = InnerState::Registered(registration);
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

        self.persisted.set_registration(registration.clone());
        self.store
            .save(&self.persisted)
            .map_err(NodeStateError::store)?;

        self.inner = InnerState::Registered(registration);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Registered operations
    // -------------------------------------------------------------------------

    /// Get the group's activation status and node list.
    ///
    /// Requires: Registered or Activated state.
    ///
    /// Fetches the hub node list and roster, analyzes activation state, and
    /// returns a unified [`GroupInfo`] containing both the group state
    /// and the full node list. This replaces the former `list_nodes()` method.
    pub async fn group_info(&self) -> Result<GroupInfo, NodeStateError> {
        use crate::hub::HubClient;
        use crate::roster::active_nodes;

        let registration = self.require_at_least_registered()?;
        let mut client = HubClient::connect(self.hub_addr())
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

        // Build a set of activated (non-revoked) roster node numbers
        let activated_set: std::collections::HashSet<i32> =
            active_nodes(&roster).map(|n| n.node_number).collect();

        // Build a set of hub-registered node numbers
        let hub_numbers: std::collections::HashSet<i32> =
            hub_nodes.iter().map(|n| n.node_number).collect();

        // Detect dead roster: version > 0 but no active roster member is still
        // registered with the hub.
        let is_dead_roster =
            roster.version > 0 && !activated_set.iter().any(|n| hub_numbers.contains(n));

        let my_node_number = registration.node_number;
        let self_activated = activated_set.contains(&my_node_number) && !is_dead_roster;

        let nodes: Vec<NodeInfo> = hub_nodes
            .into_iter()
            .map(|hub_node| {
                let is_activated = if is_dead_roster {
                    // Dead roster — treat everyone as not activated
                    Some(false)
                } else if roster.version == 0 && activated_set.is_empty() {
                    // Empty roster — we have no activation info yet, but we
                    // know nobody is activated
                    Some(false)
                } else if self_activated {
                    // We're activated — we can see the roster
                    Some(activated_set.contains(&hub_node.node_number))
                } else {
                    // We're not activated — we can't trust the roster for others
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

        // Determine the group state
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
            if is_activated {
                ""
            } else {
                " (not yet activated)"
            }
        );

        let p2p_config = P2pConfig {
            hub_addr: hub_addr.clone(),
            registration: registration.clone(),
        };

        start_serving_impl(
            &hub_addr,
            self.signing_key.clone(),
            registration,
            p2p_config,
        )
        .await
        .map_err(NodeStateError::hub)
    }

    /// Activate this node using an activation code from an endorser node.
    ///
    /// Requires: Registered state.
    /// Transitions to: Activated state.
    pub async fn activate(&mut self, activation_code: &str) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        let registration = self.require_registered()?.clone();

        // Parse the activation code
        let pairing_code =
            PairingCode::parse(activation_code).map_err(NodeStateError::InvalidActivationCode)?;
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
        let self_public_key_spki = self.signing_key.public_key_spki();
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
        let new_node_signature = self.signing_key.sign(&signing_hash);
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
            &self.signing_key.public_key_spki(),
        )
        .map_err(NodeStateError::RosterVerificationFailed)?;

        // Update to activated state (keys already derived at construction)
        self.inner = InnerState::Activated {
            registration,
            roster: RwLock::new(cosigned_roster),
        };

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Activated operations
    // -------------------------------------------------------------------------

    /// Look up a peer in the roster. If the peer isn't in the cached roster
    /// (e.g. they were activated after this node started), refetch from the hub.
    async fn find_peer_in_roster(
        &self,
        client: &mut crate::hub::HubClient,
        peer_node_number: i32,
    ) -> Result<proto::roster::Node, crate::p2p::P2pError> {
        let (registration, roster_lock) = match &self.inner {
            InnerState::Activated {
                registration,
                roster,
            } => (registration, roster),
            _ => return Err(crate::p2p::P2pError::NotActivated),
        };

        {
            let roster = roster_lock.read().unwrap();
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
            .get_and_verify_roster(registration, &self.signing_key.public_key_spki())
            .await?;

        let peer_node = fresh_roster
            .nodes
            .iter()
            .find(|n| n.node_number == peer_node_number && !n.revoked)
            .cloned()
            .ok_or(crate::p2p::P2pError::SignatureVerificationFailed)?;

        *roster_lock.write().unwrap() = fresh_roster;
        Ok(peer_node)
    }

    /// Connect to a peer node using UDP transport.
    ///
    /// Requires: Activated state.
    pub async fn connect_udp(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::UdpConnection, crate::p2p::P2pError> {
        use crate::crypto::X25519KeyPair;
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::{P2pError, UdpConnection};
        use crate::p2p_signing;

        // Check state - map to P2pError for this method's signature
        if self.state() != NodeState::Activated {
            return Err(P2pError::NotActivated);
        }

        let registration = self.persisted.registration.as_ref().expect("activated");
        let hub_addr = self.hub_addr();

        // Connect to hub
        let mut client = HubClient::connect(&hub_addr).await?;

        // Get STUN/TURN configuration
        let stun_turn_config = client.get_stun_turn_config(registration).await?;

        // Create ICE caller and gather candidates
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();

        // Generate ephemeral X25519 keypair for forward secrecy
        let encryption_key = X25519KeyPair::generate_ephemeral();

        // Build and sign the inner payload, then wrap in the envelope.
        let payload = proto::start_connection_request::Payload {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: encryption_key.public_key().to_vec(),
            caller_sdp,
            transport: proto::Transport::Datagram.into(),
            stun_turn_config: Some(stun_turn_config),
        };
        let request = p2p_signing::build_signed_request(&self.signing_key, &payload);

        // Send to hub
        let response = client.start_connection(registration, request).await?;

        // Verify answerer's signature against roster (refetch if peer is unknown)
        let peer_node = self
            .find_peer_in_roster(&mut client, peer_node_number)
            .await?;

        let response_payload = p2p_signing::verify_response(&response, &peer_node.public_key_spki)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Extract peer's X25519 public key
        let peer_x25519_public: [u8; 32] = response_payload
            .answerer_x25519_public_key
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Derive shared secret
        let shared_secret = encryption_key.diffie_hellman(&peer_x25519_public);

        // Complete ICE connection
        ice_caller.connect(&response_payload.answerer_sdp).await?;

        UdpConnection::new_caller(
            peer_node_number,
            response_payload.connection_id,
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
        use crate::crypto::X25519KeyPair;
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::{P2pError, QuicConnection};
        use crate::p2p_signing;

        // Check state - map to P2pError for this method's signature
        if self.state() != NodeState::Activated {
            return Err(P2pError::NotActivated);
        }

        let registration = self.persisted.registration.as_ref().expect("activated");
        let hub_addr = self.hub_addr();

        // Connect to hub
        let mut client = HubClient::connect(&hub_addr).await?;

        // Get STUN/TURN configuration
        let stun_turn_config = client.get_stun_turn_config(registration).await?;

        // Create ICE caller and gather candidates
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();

        // Generate ephemeral X25519 keypair for forward secrecy
        let encryption_key = X25519KeyPair::generate_ephemeral();

        // Build and sign the inner payload, then wrap in the envelope.
        let payload = proto::start_connection_request::Payload {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: encryption_key.public_key().to_vec(),
            caller_sdp,
            transport: proto::Transport::Stream.into(),
            stun_turn_config: Some(stun_turn_config),
        };
        let request = p2p_signing::build_signed_request(&self.signing_key, &payload);

        // Send to hub
        let response = client.start_connection(registration, request).await?;

        // Verify answerer's signature against roster (refetch if peer is unknown)
        let peer_node = self
            .find_peer_in_roster(&mut client, peer_node_number)
            .await?;

        let response_payload = p2p_signing::verify_response(&response, &peer_node.public_key_spki)
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Extract peer's X25519 public key
        let peer_x25519_public: [u8; 32] = response_payload
            .answerer_x25519_public_key
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Derive shared secret
        let shared_secret = encryption_key.diffie_hellman(&peer_x25519_public);

        // Complete ICE connection
        ice_caller.connect(&response_payload.answerer_sdp).await?;

        // Complete QUIC handshake
        QuicConnection::connect_caller(
            peer_node_number,
            response_payload.connection_id,
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
    ///
    /// Takes `&mut self` rather than `self` so it can be called via a
    /// `MutexGuard` from the FFI layer. This is necessary because the FFI layer
    /// stores an Arc<Mutex<Node>> to keep access sound when multiple holders
    /// may exist concurrently (C's guarantees are unsurprisingly weaker than
    /// Rust's).
    ///
    /// After a successful logout, the `Node` is reset to `Pending`. Subsequent
    /// operations fail with `NodeStateError`, except for `register()`, which
    /// starts a fresh session.
    pub async fn logout(&mut self) -> Result<(), NodeStateError> {
        use crate::hub::HubClient;

        match self.state() {
            NodeState::Pending => {
                self.store.delete().map_err(NodeStateError::store)?;
            }
            NodeState::Registered => {
                let registration = self.persisted.registration.as_ref().expect("registered");
                let mut client = HubClient::connect(self.hub_addr())
                    .await
                    .map_err(NodeStateError::hub)?;
                // If unauthenticated, node was already removed server-side — just clean up locally.
                match client.deregister_node(registration).await {
                    Ok(()) => {}
                    Err(e) if e.is_unauthenticated() || e.is_not_found() => {}
                    Err(e) => return Err(NodeStateError::hub(e)),
                }
                self.store.delete().map_err(NodeStateError::store)?;
            }
            NodeState::Activated => {
                use crate::roster::{
                    active_nodes, add_revocation_to_roster, build_revocation_payload,
                    set_revoker_signature,
                };

                let (registration, mut new_roster) = match &self.inner {
                    InnerState::Activated {
                        registration,
                        roster,
                    } => (registration.clone(), roster.read().unwrap().clone()),
                    _ => unreachable!(),
                };

                // Check: prevent revoking the last active node
                let active_count = active_nodes(&new_roster).count();
                if active_count <= 1 {
                    return Err(NodeStateError::LastActiveNode);
                }

                let mut client = HubClient::connect(self.hub_addr())
                    .await
                    .map_err(NodeStateError::hub)?;

                // Step 1: Self-revoke from roster.
                let revocation_payload = build_revocation_payload(
                    &new_roster,
                    registration.node_number, // revoked
                    registration.node_number, // revoker (self)
                );
                add_revocation_to_roster(&mut new_roster, revocation_payload);
                let signing_hash = compute_signing_hash(&new_roster);
                let signature = self.signing_key.sign(&signing_hash);
                set_revoker_signature(&mut new_roster, signature);

                // If unauthenticated, node was already removed server-side — skip to local cleanup.
                match client.update_roster(&registration, new_roster).await {
                    Ok(_) => {
                        // Step 2: Deregister from hub
                        match client.deregister_node(&registration).await {
                            Ok(()) => {}
                            Err(e) if e.is_unauthenticated() || e.is_not_found() => {}
                            Err(e) => return Err(NodeStateError::hub(e)),
                        }
                    }
                    Err(e) if e.is_unauthenticated() || e.is_not_found() => {}
                    Err(e) => return Err(NodeStateError::hub(e)),
                }

                // Step 3: Delete local state
                self.store.delete().map_err(NodeStateError::store)?;
            }
        }

        // Reset in-memory caches so state() reflects the fresh slate.
        // root_key + signing_key are intentionally left intact so a subsequent
        // register() reuses the same cryptographic identity.
        self.persisted.registration = None;
        self.inner = InnerState::Pending;

        Ok(())
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
        persisted.registration = Some(registration.clone());

        Self {
            signing_key: SigningKeyPair::derive_from_root_key(&root_key),
            inner: InnerState::Activated {
                registration,
                roster: RwLock::new(roster),
            },
            persisted,
            store: Arc::new(InMemoryNodeStateStore::new()),
            config: Arc::new(std::sync::RwLock::new(RuntimeConfig::new_with_addr(
                hub_addr,
            ))),
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
