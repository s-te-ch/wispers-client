use crate::crypto::{generate_nonce, PairingCode, SigningKeyPair, X25519KeyPair};
use crate::errors::NodeStateError;
use crate::hub::proto;
use crate::roster::{
    build_activation_payload, create_activation_roster, create_bootstrap_roster, verify_roster,
};
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

    /// Read just the registration from local storage (sync, no hub contact).
    ///
    /// Returns `None` if not registered. This is useful when you need
    /// registration info before starting an async runtime.
    pub fn read_registration(
        &self,
        app_namespace: impl Into<AppNamespace>,
        profile_namespace: Option<impl Into<ProfileNamespace>>,
    ) -> Result<Option<NodeRegistration>, NodeStateError<S::Error>> {
        let app_namespace = app_namespace.into();
        let profile_namespace = profile_namespace
            .map(Into::into)
            .unwrap_or_else(ProfileNamespace::default);

        let state = self
            .store
            .load(&app_namespace, &profile_namespace)
            .map_err(NodeStateError::store)?;

        Ok(state.and_then(|s| s.registration))
    }

    /// Initialize or restore node state.
    ///
    /// Returns the current stage:
    /// - `Pending` if not registered
    /// - `Registered` if registered but not in the roster
    /// - `Activated` if registered and in the roster
    ///
    /// This method fetches the roster from the hub when the node is registered
    /// to determine if it has been activated.
    pub async fn restore_or_init_node_state(
        &self,
        app_namespace: impl Into<AppNamespace>,
        profile_namespace: Option<impl Into<ProfileNamespace>>,
    ) -> Result<NodeStateStage<S>, NodeStateError<S::Error>> {
        use crate::hub::HubClient;

        let app_namespace = app_namespace.into();
        let profile_namespace = profile_namespace
            .map(Into::into)
            .unwrap_or_else(ProfileNamespace::default);

        let state = match self
            .store
            .load(&app_namespace, &profile_namespace)
            .map_err(NodeStateError::store)?
        {
            Some(state) => state,
            None => {
                let state = NodeState::initialize_with_namespaces(
                    app_namespace.clone(),
                    profile_namespace.clone(),
                );
                self.store.save(&state).map_err(NodeStateError::store)?;
                return Ok(NodeStateStage::Pending(PendingNodeState::new(
                    state,
                    self.store.clone(),
                    self.config.clone(),
                )));
            }
        };

        // Not registered yet
        if !state.is_registered() {
            return Ok(NodeStateStage::Pending(PendingNodeState::new(
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
            let x25519_key = X25519KeyPair::derive_from_root_key(root_key);

            // Verify the roster cryptographically before trusting it
            verify_roster(
                &roster,
                registration.node_number,
                &signing_key.public_key_spki(),
            )
            .map_err(NodeStateError::RosterVerificationFailed)?;

            Ok(NodeStateStage::Activated(ActivatedNode {
                signing_key,
                x25519_key,
                roster,
                registration: registration.clone(),
                store: self.store.clone(),
                app_namespace: state.app_namespace.clone(),
                profile_namespace: state.profile_namespace.clone(),
                config: self.config.clone(),
            }))
        } else {
            Ok(NodeStateStage::Registered(RegisteredNodeState::new(
                state,
                self.store.clone(),
                self.config.clone(),
            )?))
        }
    }

}

/// State machine representing the node's current stage.
pub enum NodeStateStage<S: NodeStateStore> {
    /// Node needs to register with the hub.
    Pending(PendingNodeState<S>),
    /// Node is registered but not yet in the roster (needs activation).
    Registered(RegisteredNodeState<S>),
    /// Node is in the roster and ready to operate.
    Activated(ActivatedNode<S>),
}

impl<S: NodeStateStore> NodeStateStage<S> {
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

    pub fn into_activated(self) -> Option<ActivatedNode<S>> {
        if let NodeStateStage::Activated(node) = self {
            Some(node)
        } else {
            None
        }
    }

    /// Logout from whatever state we're in.
    pub async fn logout(self) -> Result<(), NodeStateError<S::Error>> {
        match self {
            NodeStateStage::Pending(p) => p.logout().await,
            NodeStateStage::Registered(r) => r.logout().await,
            NodeStateStage::Activated(a) => a.logout().await,
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

    /// Logout: delete local state.
    pub async fn logout(self) -> Result<(), NodeStateError<S::Error>> {
        self.store
            .delete(&self.state.app_namespace, &self.state.profile_namespace)
            .map_err(NodeStateError::store)
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

    /// Logout: tell hub to remove node, then delete local state.
    pub async fn logout(self) -> Result<(), NodeStateError<S::Error>> {
        // TODO: tell hub to remove this node from the connectivity group
        // For now, just delete local state
        self.store
            .delete(&self.state.app_namespace, &self.state.profile_namespace)
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

    /// Start a serving session.
    ///
    /// This allows a registered (but not yet activated) node to serve,
    /// which is needed during bootstrap when no nodes are activated yet.
    /// Note: Registered nodes cannot accept P2P connections (no roster yet).
    ///
    /// # Example
    /// ```ignore
    /// let (handle, session, _) = registered.start_serving().await?;
    /// tokio::spawn(async move { session.run().await });
    /// let code = handle.generate_pairing_secret().await?;
    /// ```
    pub async fn start_serving(
        &self,
    ) -> Result<
        (
            crate::serving::ServingHandle,
            crate::serving::ServingSession,
            Option<tokio::sync::mpsc::Receiver<crate::p2p::P2pConnectionAnswerer>>,
        ),
        NodeStateError<S::Error>,
    > {
        let reg = self.registration();
        println!(
            "Starting serving session for node {} in group {} (not yet activated)",
            reg.node_number, reg.connectivity_group_id
        );

        let signing_key = SigningKeyPair::derive_from_root_key(self.state.root_key.as_bytes());
        let hub_addr = self.config.read().unwrap().hub_addr.clone();

        start_serving_impl(&hub_addr, signing_key, reg, None)
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
    ) -> Result<ActivatedNode<S>, NodeStateError<S::Error>> {
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

        let endorser_nonce = response_payload.nonce.clone();

        // Fetch the current roster (unverified - we're not in it yet)
        let current_roster = client
            .get_unverified_roster(self.registration())
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the base roster if not bootstrap (version > 0)
        // We verify from the endorser's perspective since we're not in the roster yet
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
            self.registration().node_number,
            nonce,
            endorser_nonce,
        );
        let activation_payload_bytes = activation_payload.encode_to_vec();
        let new_node_signature = signing_key.sign(&activation_payload_bytes);

        // Build the new roster using the appropriate builder
        let new_roster = if current_roster.version == 0 {
            // Bootstrap: create version 1 roster with both nodes
            create_bootstrap_roster(
                endorser_node_number,
                &response_payload.public_key_spki,
                self.registration().node_number,
                &signing_key.public_key_spki(),
                activation_payload.new_node_nonce,
                activation_payload.endorser_nonce,
                new_node_signature,
            )
        } else {
            // Normal activation: add new node to existing roster
            create_activation_roster(
                &current_roster,
                endorser_node_number,
                self.registration().node_number,
                &signing_key.public_key_spki(),
                activation_payload.new_node_nonce,
                activation_payload.endorser_nonce,
                new_node_signature,
            )
        };

        // Submit the roster update
        let cosigned_roster = client
            .update_roster(self.registration(), new_roster)
            .await
            .map_err(NodeStateError::hub)?;

        // Verify the cosigned roster - critical security check!
        // The hub could have returned a tampered roster with extra nodes.
        verify_roster(
            &cosigned_roster,
            self.registration().node_number,
            &signing_key.public_key_spki(),
        )
        .map_err(NodeStateError::RosterVerificationFailed)?;

        // Derive X25519 key for P2P connections
        let x25519_key = X25519KeyPair::derive_from_root_key(self.state.root_key.as_bytes());

        Ok(ActivatedNode {
            signing_key,
            x25519_key,
            roster: cosigned_roster,
            registration: self.registration().clone(),
            store: self.store.clone(),
            app_namespace: self.state.app_namespace.clone(),
            profile_namespace: self.state.profile_namespace.clone(),
            config: self.config.clone(),
        })
    }
}

/// An activated node that is in the roster and ready to operate.
pub struct ActivatedNode<S: NodeStateStore> {
    signing_key: SigningKeyPair,
    x25519_key: X25519KeyPair,
    roster: proto::connect::roster::Roster,
    registration: NodeRegistration,
    store: SharedStore<S>,
    app_namespace: AppNamespace,
    profile_namespace: ProfileNamespace,
    config: SharedConfig,
}

impl<S: NodeStateStore> ActivatedNode<S> {
    /// Get the node's signing key pair.
    pub fn signing_key(&self) -> &SigningKeyPair {
        &self.signing_key
    }

    /// Get the current roster.
    pub fn roster(&self) -> &proto::connect::roster::Roster {
        &self.roster
    }

    /// Get the node registration info.
    pub fn registration(&self) -> &NodeRegistration {
        &self.registration
    }

    /// Get the node's number.
    pub fn node_number(&self) -> i32 {
        self.registration.node_number
    }

    /// Logout: revoke from roster, deregister from connectivity group, delete local state.
    pub async fn logout(self) -> Result<(), NodeStateError<S::Error>> {
        // TODO: submit self-revocation to roster
        // TODO: tell hub to remove node from connectivity group
        // For now, just delete local state
        self.store
            .delete(&self.app_namespace, &self.profile_namespace)
            .map_err(NodeStateError::store)
    }

    /// Start a serving session.
    ///
    /// Connects to the hub and returns a handle + session pair + incoming connection receiver.
    /// The session should be spawned to run the event loop, while the handle
    /// can be used to send commands (e.g., generate pairing codes).
    /// The incoming connection receiver delivers P2P connections from other nodes.
    ///
    /// # Example
    /// ```ignore
    /// let (handle, session, incoming_rx) = activated.start_serving().await?;
    /// tokio::spawn(async move { session.run().await });
    /// // Handle incoming P2P connections
    /// while let Some(conn) = incoming_rx.recv().await {
    ///     conn.connect().await?; // Complete ICE
    ///     // ... use conn
    /// }
    /// ```
    pub async fn start_serving(
        &self,
    ) -> Result<
        (
            crate::serving::ServingHandle,
            crate::serving::ServingSession,
            Option<tokio::sync::mpsc::Receiver<crate::p2p::P2pConnectionAnswerer>>,
        ),
        NodeStateError<S::Error>,
    > {
        use crate::serving::P2pConfig;

        println!(
            "Starting serving session for node {} in group {}",
            self.registration.node_number, self.registration.connectivity_group_id
        );
        println!("Roster has {} nodes", self.roster.nodes.len());

        let hub_addr = self.config.read().unwrap().hub_addr.clone();

        let p2p_config = P2pConfig {
            x25519_key: self.x25519_key.clone(),
            hub_addr: hub_addr.clone(),
            registration: self.registration.clone(),
        };

        start_serving_impl(
            &hub_addr,
            self.signing_key.clone(),
            &self.registration,
            Some(p2p_config),
        )
        .await
        .map_err(NodeStateError::hub)
    }

    /// Connect to a peer node.
    ///
    /// This establishes a P2P connection to the specified peer using ICE for
    /// NAT traversal. The connection is encrypted using X25519 key exchange.
    ///
    /// # Example
    /// ```ignore
    /// let conn = activated.connect_to(42).await?;
    /// conn.send(b"hello")?;
    /// let response = conn.recv().await?;
    /// ```
    pub async fn connect_to(
        &self,
        peer_node_number: i32,
    ) -> Result<crate::p2p::P2pConnection, crate::p2p::P2pError> {
        use crate::hub::HubClient;
        use crate::ice::IceCaller;
        use crate::p2p::{P2pConnection, P2pError};

        let hub_addr = self.config.read().unwrap().hub_addr.clone();

        // Connect to hub
        let mut client = HubClient::connect(&hub_addr).await?;

        // Get STUN/TURN configuration
        let stun_turn_config = client
            .get_stun_turn_config(&self.registration)
            .await?;

        // Create ICE caller and gather candidates
        let ice_caller = IceCaller::new(&stun_turn_config)?;
        let caller_sdp = ice_caller.local_description().to_string();

        // Build the StartConnectionRequest
        // Sign: answerer_node_number || caller_x25519_public_key || caller_sdp
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&peer_node_number.to_le_bytes());
        message_to_sign.extend_from_slice(&self.x25519_key.public_key());
        message_to_sign.extend_from_slice(caller_sdp.as_bytes());
        let signature = self.signing_key.sign(&message_to_sign);

        let request = proto::StartConnectionRequest {
            answerer_node_number: peer_node_number,
            caller_x25519_public_key: self.x25519_key.public_key().to_vec(),
            caller_sdp,
            signature,
            stun_turn_config: Some(stun_turn_config),
        };

        // Send to hub, which forwards to the answerer
        let response = client
            .start_connection(&self.registration, request)
            .await?;

        // TODO: Verify answerer's signature against roster

        // Extract peer's X25519 public key
        let peer_x25519_public: [u8; 32] = response
            .answerer_x25519_public_key
            .try_into()
            .map_err(|_| P2pError::SignatureVerificationFailed)?;

        // Derive shared secret
        let shared_secret = self.x25519_key.diffie_hellman(&peer_x25519_public);

        // Complete ICE connection with answerer's SDP
        ice_caller.connect(&response.answerer_sdp).await?;

        Ok(P2pConnection::new(
            peer_node_number,
            response.connection_id,
            ice_caller,
            shared_secret,
        ))
    }
}

/// Helper to start a serving session (used by both RegisteredNodeState and ActivatedNode).
async fn start_serving_impl(
    hub_addr: &str,
    signing_key: SigningKeyPair,
    registration: &NodeRegistration,
    p2p_config: Option<crate::serving::P2pConfig>,
) -> Result<
    (
        crate::serving::ServingHandle,
        crate::serving::ServingSession,
        Option<tokio::sync::mpsc::Receiver<crate::p2p::P2pConnectionAnswerer>>,
    ),
    crate::hub::HubError,
> {
    use crate::hub::HubClient;
    use crate::serving::ServingSession;

    let mut client = HubClient::connect(hub_addr).await?;
    let conn = client.start_serving(registration).await?;

    let (handle, session, incoming_rx) = ServingSession::new(
        conn,
        signing_key,
        registration.connectivity_group_id.clone(),
        registration.node_number,
        p2p_config,
    );

    Ok((handle, session, incoming_rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryNodeStateStore;
    use crate::types::DEFAULT_PROFILE_NAMESPACE;

    #[tokio::test]
    async fn manager_initializes_and_reuses_state() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let first_stage = storage
            .restore_or_init_node_state("app.example", None::<String>)
            .await
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
            .await
            .unwrap();
        let pending_second = second_stage
            .into_pending()
            .expect("state remains pending until registration");
        assert_eq!(pending_second.root_key_bytes(), &first_key);
    }

    #[tokio::test]
    async fn completing_registration_persists_and_transitions() {
        let storage = NodeStorage::new(InMemoryNodeStateStore::new());
        let stage = storage
            .restore_or_init_node_state("app.example", None::<String>)
            .await
            .unwrap();
        let pending = stage
            .into_pending()
            .expect("expected pending state prior to registration");
        let registration = crate::types::registration_fixture();

        let registered = pending.complete_registration(registration.clone()).unwrap();
        assert_eq!(registered.registration(), &registration);

        // Verify registration was persisted by checking the store directly
        // (restore_or_init_node_state would require network access for registered nodes)
        let loaded = storage
            .store
            .load(
                &crate::types::AppNamespace::from("app.example"),
                &crate::types::ProfileNamespace::default(),
            )
            .unwrap()
            .expect("state should be persisted");
        assert!(loaded.is_registered());
        assert_eq!(loaded.registration.as_ref().unwrap(), &registration);
    }
}
