//! Serving session for handling hub requests and local commands.
//!
//! This module provides a handle + runner pattern for the serving loop:
//! - `ServingSession` is the runner that owns the event loop and state
//! - `ServingHandle` is a clone-able handle for sending commands to the session
//!
//! Endorsement logic (activation code generation, pairing, cosigning) is
//! separated into `EndorsingState` so it can be unit-tested without a hub
//! connection.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use crate::crypto::{PairingCode, PairingSecret, SigningKeyPair, TtlProfile, generate_nonce};
use crate::hub::ServingConnection;
use crate::hub::proto;
use crate::ice::IceAnswerer;
use crate::p2p::{P2pError, QuicConnection, UdpConnection};
use crate::types::{ConnectivityGroupId, NodeRegistration};
use prost::Message;
use rand::Rng;
use tokio::sync::{mpsc, oneshot};

/// Error type for serving operations.
#[derive(Debug, thiserror::Error)]
pub enum ServingError {
    #[error("hub connection error: {0}")]
    Hub(#[from] crate::hub::HubError),
    #[error("session shut down")]
    SessionShutdown,
    #[error("too many active activation sessions (max {MAX_ACTIVE_ACTIVATIONS})")]
    TooManyActivationSessions,
}

impl ServingError {
    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, ServingError::Hub(e) if e.is_unauthenticated())
    }

    pub fn is_peer_rejected(&self) -> bool {
        matches!(self, ServingError::Hub(e) if e.is_peer_rejected())
    }

    pub fn is_peer_unavailable(&self) -> bool {
        matches!(self, ServingError::Hub(e) if e.is_peer_unavailable())
    }
}

/// Configuration for P2P connection handling.
pub(crate) struct P2pConfig {
    /// Hub address for fetching fresh roster on each connection request.
    pub hub_addr: String,
    /// Node registration for authenticating with the hub.
    pub registration: crate::types::NodeRegistration,
}

/// Information about the current serving session status.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServingStatus {
    pub connected: bool,
    pub connectivity_group_id: ConnectivityGroupId,
    pub node_number: i32,
    /// Current endorsing state, if any.
    pub endorsing: Option<EndorsingStatus>,
}

/// Status of active endorsing sessions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EndorsingStatus {
    /// Number of activation codes waiting to be used by new nodes.
    pub codes_outstanding: usize,
    /// Node numbers that have paired and are awaiting cosign.
    pub nodes_awaiting_cosign: Vec<i32>,
}

/// Maximum number of concurrent activation sessions (codes + pending cosigns).
const MAX_ACTIVE_ACTIVATIONS: usize = 100;

//-- Endorsing state (testable without hub connection) -------------------------

/// A pairing secret with an expiry time.
struct TimedSecret {
    secret: PairingSecret,
    expires_at: Instant,
}

/// Internal state for a pending endorsement (keyed by new node number in the HashMap).
struct PendingEndorsement {
    new_node_pubkey: Vec<u8>,
    new_node_nonce: Vec<u8>,
    our_nonce: Vec<u8>,
}

/// Manages endorsement state: outstanding activation codes and pending cosigns.
struct EndorsingState {
    /// Test-only override for the per-profile TTL. `None` in production, where
    /// each code expires after its `TtlProfile::ttl()`.
    ttl_override: Option<Duration>,
    pairing_secrets: Vec<TimedSecret>,
    pending_endorsements: HashMap<i32, PendingEndorsement>,
}

impl EndorsingState {
    fn new() -> Self {
        Self {
            ttl_override: None,
            pairing_secrets: Vec::new(),
            pending_endorsements: HashMap::new(),
        }
    }

    /// Remove expired secrets.
    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.pairing_secrets.retain(|ts| ts.expires_at > now);
    }

    fn status(&self) -> Option<EndorsingStatus> {
        let now = Instant::now();
        let codes_outstanding = self
            .pairing_secrets
            .iter()
            .filter(|ts| ts.expires_at > now)
            .count();
        let nodes_awaiting_cosign: Vec<i32> = self.pending_endorsements.keys().copied().collect();
        if codes_outstanding == 0 && nodes_awaiting_cosign.is_empty() {
            None
        } else {
            Some(EndorsingStatus {
                codes_outstanding,
                nodes_awaiting_cosign,
            })
        }
    }

    fn generate_activation_code_with_ttl(
        &mut self,
        node_number: i32,
        ttl_profile: TtlProfile,
    ) -> Result<PairingCode, ServingError> {
        self.prune_expired();
        if self.pairing_secrets.len() + self.pending_endorsements.len() >= MAX_ACTIVE_ACTIVATIONS {
            return Err(ServingError::TooManyActivationSessions);
        }

        let ttl = self.ttl_override.unwrap_or_else(|| ttl_profile.ttl());
        let secret = PairingSecret::generate(ttl_profile);
        let code = PairingCode::new(node_number, secret.clone());
        self.pairing_secrets.push(TimedSecret {
            secret,
            expires_at: Instant::now() + ttl,
        });

        // Never log the formatted code: the secret half grants pairing within
        // the TTL window to anyone with log access.
        log::info!("Generated pairing code for node {}", code.node_number);
        Ok(code)
    }

    /// Handle a PairNodesMessage. On success, returns the reply message.
    fn pair_nodes(
        &mut self,
        msg: &proto::PairNodesMessage,
        node_number: i32,
        signing_key: &SigningKeyPair,
    ) -> Result<proto::PairNodesMessage, String> {
        let payload = msg
            .payload
            .as_ref()
            .ok_or("PairNodesMessage missing payload")?;

        log::debug!(
            "  PairNodesMessage: sender={} receiver={}",
            payload.sender_node_number,
            payload.receiver_node_number
        );

        // Prune expired secrets, then find the one that verifies this MAC
        self.prune_expired();
        let payload_bytes = payload.encode_to_vec();
        let secret_index = self
            .pairing_secrets
            .iter()
            .position(|ts| ts.secret.verify_mac(&payload_bytes, &msg.mac));

        let Some(secret_index) = secret_index else {
            if self.pairing_secrets.is_empty() {
                return Err("no active pairing session".into());
            } else {
                log::warn!(
                    "  MAC verification failed against all {} secrets",
                    self.pairing_secrets.len()
                );
                return Err("MAC verification failed".into());
            }
        };

        let secret = self.pairing_secrets.swap_remove(secret_index).secret;
        log::debug!(
            "  MAC verified successfully (secret {} of {})",
            secret_index + 1,
            self.pairing_secrets.len() + 1
        );

        // Store the new node info and generate our nonce
        let our_nonce = generate_nonce();
        self.pending_endorsements.insert(
            payload.sender_node_number,
            PendingEndorsement {
                new_node_pubkey: payload.public_key_spki.clone(),
                new_node_nonce: payload.nonce.clone(),
                our_nonce: our_nonce.clone(),
            },
        );

        // Build reply
        let reply_payload = proto::pair_nodes_message::Payload {
            sender_node_number: node_number,
            receiver_node_number: payload.sender_node_number,
            public_key_spki: signing_key.public_key_spki(),
            nonce: our_nonce,
            reply_nonce: payload.nonce.clone(),
        };
        let reply_payload_bytes = reply_payload.encode_to_vec();
        let reply_mac = secret.compute_mac(&reply_payload_bytes);

        Ok(proto::PairNodesMessage {
            payload: Some(reply_payload),
            mac: reply_mac,
        })
    }

    /// Handle a RosterCosignRequest. On success, returns the cosign response.
    fn roster_cosign(
        &mut self,
        req: &proto::RosterCosignRequest,
        node_number: i32,
        signing_key: &SigningKeyPair,
    ) -> Result<proto::RosterCosignResponse, String> {
        let new_node_number = req.new_node_number as i32;
        log::debug!("  RosterCosignRequest: new_node={}", new_node_number);

        // Look up the pending endorsement — clone fields we need so we
        // don't hold a borrow across the remove at the end.
        let pending = self
            .pending_endorsements
            .get(&new_node_number)
            .ok_or_else(|| format!("no pending endorsement for node {}", new_node_number))?;
        let expected_pubkey = pending.new_node_pubkey.clone();
        let expected_new_nonce = pending.new_node_nonce.clone();
        let expected_our_nonce = pending.our_nonce.clone();

        let roster = req.new_roster.as_ref().ok_or("missing roster")?;

        // Find the activation addendum
        let activation = roster
            .addenda
            .last()
            .and_then(|a| match &a.kind {
                Some(proto::roster::addendum::Kind::Activation(act)) => Some(act),
                _ => None,
            })
            .ok_or("no activation addendum")?;

        let activation_payload = activation
            .payload
            .as_ref()
            .ok_or("activation missing payload")?;

        // Verify nonces match the pair_nodes ceremony we previously ran.
        if activation_payload.new_node_nonce != expected_new_nonce {
            return Err("new node nonce mismatch".into());
        }
        if activation_payload.endorser_nonce != expected_our_nonce {
            return Err("endorser nonce mismatch".into());
        }

        // Verify endorser node number
        if activation_payload.endorser_node_number != node_number {
            return Err("wrong endorser node number".into());
        }

        // Cross-check the new node's pubkey in the nodes list against what
        // we exchanged via the HMAC-authenticated pair_nodes flow.
        let new_node_in_roster = roster
            .nodes
            .iter()
            .find(|n| n.node_number == new_node_number)
            .ok_or("new node not in roster")?;
        if new_node_in_roster.public_key_spki != expected_pubkey {
            return Err("nodes list new_node key does not match paired key".into());
        }

        // Cross-check our own entry: the roster must commit us to our actual
        // public key, not something the hub picked.
        let our_public_key_spki = signing_key.public_key_spki();
        let endorser_in_roster = roster
            .nodes
            .iter()
            .find(|n| n.node_number == node_number)
            .ok_or("endorser not in roster")?;
        if endorser_in_roster.public_key_spki != our_public_key_spki {
            return Err("nodes list endorser key does not match our own key".into());
        }

        log::debug!("  All verifications passed, signing activation");

        // Compute the signing hash over the entire post-activation roster
        // and sign it. The roster from the request has the new node's
        // signature already filled in, so we clone and clear before
        // hashing — `compute_signing_hash` requires empty signatures so
        // that both cosigners arrive at the same hash bytes.
        let mut roster_for_hash = roster.clone();
        crate::roster::clear_latest_addendum_signatures(&mut roster_for_hash);
        let signing_hash = crate::roster::compute_signing_hash(&roster_for_hash);
        let signature = signing_key.sign(&signing_hash);

        // Clear this pending endorsement
        self.pending_endorsements.remove(&new_node_number);

        Ok(proto::RosterCosignResponse {
            endorser_signature: signature,
        })
    }
}

//-- Reconnect control flow ----------------------------------------------------

/// Why the serve phase stopped driving the current connection.
enum ServeOutcome {
    /// A command asked the session to shut down.
    Shutdown,
    /// The hub stream dropped; reconnect and resume.
    Disconnected,
    /// An unrecoverable error (e.g. the hub rejected our credentials).
    Fatal(ServingError),
}

/// Result of a reconnect phase. The connection is boxed because it is far
/// larger than the other variants.
enum ConnectOutcome {
    Connected(Box<ServingConnection>),
    Shutdown,
    Fatal(ServingError),
}

/// Exponential backoff with jitter for hub reconnection. Calibrated for a
/// long-running daemon: quick first retries, capped so a prolonged hub outage
/// settles into steady polling rather than busy-looping.
struct ReconnectBackoff {
    current: Duration,
}

impl ReconnectBackoff {
    const BASE: Duration = Duration::from_secs(1);
    const CAP: Duration = Duration::from_secs(30);

    fn new() -> Self {
        Self {
            current: Self::BASE,
        }
    }

    /// Return the next delay (with ±20% jitter) and advance the schedule.
    /// Jitter spreads reconnect attempts so a fleet of clients doesn't stampede
    /// the hub in lockstep after a shared outage.
    fn next_delay(&mut self) -> Duration {
        let base = self.current;
        self.current = (self.current * 2).min(Self::CAP);
        let jitter = rand::thread_rng().gen_range(0.8..1.2);
        base.mul_f64(jitter)
    }
}

/// Open a fresh bidirectional serving stream to the hub.
pub(crate) async fn open_serving_connection(
    hub_addr: &str,
    registration: &NodeRegistration,
) -> Result<ServingConnection, crate::hub::HubError> {
    let client = crate::hub::HubClient::connect(hub_addr).await?;
    client.start_serving(registration).await
}

//-- ServingHandle + ServingSession --------------------------------------------

/// Commands sent from ServingHandle to ServingSession.
enum Command {
    Status {
        reply: oneshot::Sender<ServingStatus>,
    },
    GenerateActivationCode {
        ttl_profile: TtlProfile,
        reply: oneshot::Sender<Result<PairingCode, ServingError>>,
    },
    Shutdown,
}

/// Clone-able handle for interacting with a running ServingSession.
#[derive(Clone)]
pub struct ServingHandle {
    cmd_tx: mpsc::Sender<Command>,
}

impl ServingHandle {
    /// Get the current status of the serving session.
    pub async fn status(&self) -> Result<ServingStatus, ServingError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Status { reply: reply_tx })
            .await
            .map_err(|_| ServingError::SessionShutdown)?;
        reply_rx.await.map_err(|_| ServingError::SessionShutdown)
    }

    /// Generate an activation code for endorsing a new node, with the default
    /// (interactive) lifetime.
    pub async fn generate_activation_code(&self) -> Result<PairingCode, ServingError> {
        self.generate_activation_code_with_ttl(TtlProfile::default())
            .await
    }

    /// Generate an activation code with an explicit lifetime.
    pub async fn generate_activation_code_with_ttl(
        &self,
        ttl_profile: TtlProfile,
    ) -> Result<PairingCode, ServingError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GenerateActivationCode {
                ttl_profile,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ServingError::SessionShutdown)?;
        reply_rx.await.map_err(|_| ServingError::SessionShutdown)?
    }

    /// Request the session to shut down.
    pub async fn shutdown(&self) -> Result<(), ServingError> {
        self.cmd_tx
            .send(Command::Shutdown)
            .await
            .map_err(|_| ServingError::SessionShutdown)
    }
}

/// The serving session runner that owns the event loop and state.
pub struct ServingSession {
    cmd_rx: mpsc::Receiver<Command>,
    conn: ServingConnection,
    signing_key: SigningKeyPair,
    node_number: i32,
    connectivity_group_id: ConnectivityGroupId,
    endorsing: EndorsingState,
    connected: bool,
    // P2P state (always present, but connections only accepted once activated)
    p2p_config: P2pConfig,
    incoming_udp_tx: mpsc::Sender<Result<UdpConnection, P2pError>>,
    incoming_quic_tx: mpsc::Sender<Result<QuicConnection, P2pError>>,
    connection_id_counter: AtomicI64,
}

/// Receivers for incoming P2P connections.
///
/// Both channels yield `Result` to report ICE/handshake errors.
/// Connections are fully established when received.
pub struct IncomingConnections {
    /// UDP connections (raw encrypted datagrams).
    pub udp: mpsc::Receiver<Result<UdpConnection, P2pError>>,
    /// QUIC connections (reliable streams).
    pub quic: mpsc::Receiver<Result<QuicConnection, P2pError>>,
}

impl ServingSession {
    /// Create a new serving session.
    ///
    /// Returns a handle for sending commands, the session runner, and receivers
    /// for incoming P2P connections. P2P connections are only accepted once the
    /// node is activated (appears in the roster), but the channels are always created.
    pub(crate) fn new(
        conn: ServingConnection,
        signing_key: SigningKeyPair,
        connectivity_group_id: ConnectivityGroupId,
        node_number: i32,
        p2p_config: P2pConfig,
    ) -> (ServingHandle, Self, IncomingConnections) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        // Always create incoming connection channels
        let (udp_tx, udp_rx) = mpsc::channel(16);
        let (quic_tx, quic_rx) = mpsc::channel(16);
        let incoming = IncomingConnections {
            udp: udp_rx,
            quic: quic_rx,
        };

        let handle = ServingHandle { cmd_tx };
        let session = Self {
            cmd_rx,
            conn,
            signing_key,
            node_number,
            connectivity_group_id,
            endorsing: EndorsingState::new(),
            connected: false,
            p2p_config,
            incoming_udp_tx: udp_tx,
            incoming_quic_tx: quic_tx,
            connection_id_counter: AtomicI64::new(1),
        };

        (handle, session, incoming)
    }

    /// Run the serving event loop.
    ///
    /// Processes hub requests and local commands. On transient hub disconnects,
    /// retries internally with exponential backoff. Returns with `Ok` if
    /// explicitly shut down, with an `Err` if there was an unrecoverable error,
    /// typically an auth error.
    pub async fn run(mut self) -> Result<(), ServingError> {
        log::info!("ServingSession running for node {}", self.node_number);

        // Snapshot the connection params so the reconnect path can borrow them
        // without conflicting with the `&mut self` command handling.
        let hub_addr = self.p2p_config.hub_addr.clone();
        let registration = self.p2p_config.registration.clone();

        // The first connection was already established by `start_serving`.
        self.connected = true;

        loop {
            match self.serve().await {
                ServeOutcome::Shutdown => break,
                ServeOutcome::Fatal(e) => return Err(e),
                ServeOutcome::Disconnected => {
                    self.connected = false;
                }
            }

            match self.reconnect(&hub_addr, &registration).await {
                ConnectOutcome::Connected(conn) => {
                    self.conn = *conn;
                    self.connected = true;
                    log::info!("Reconnected to hub for node {}", self.node_number);
                }
                ConnectOutcome::Shutdown => break,
                ConnectOutcome::Fatal(e) => return Err(e),
            }
        }

        log::info!("ServingSession ended");
        Ok(())
    }

    /// Serve on the current connection until the hub stream drops, a command
    /// requests shutdown, or a fatal error occurs.
    async fn serve(&mut self) -> ServeOutcome {
        loop {
            tokio::select! {
                // Local commands from ServingHandle.
                cmd = self.cmd_rx.recv() => {
                    if self.dispatch_command(cmd).is_break() {
                        return ServeOutcome::Shutdown;
                    }
                }

                // Incoming hub requests.
                result = self.conn.request_stream.message() => {
                    match result {
                        Ok(Some(request)) => self.handle_hub_request(request).await,
                        Ok(None) => {
                            log::info!("Hub stream ended; will reconnect");
                            return ServeOutcome::Disconnected;
                        }
                        Err(e) => {
                            let err = crate::hub::HubError::Rpc(e);
                            if err.is_unauthenticated() {
                                log::warn!("Hub rejected authentication; stopping serving");
                                return ServeOutcome::Fatal(ServingError::Hub(err));
                            }
                            log::warn!("Hub stream error: {err}; will reconnect");
                            return ServeOutcome::Disconnected;
                        }
                    }
                }
            }
        }
    }

    /// Re-establish the hub stream, retrying with exponential backoff.
    async fn reconnect(
        &mut self,
        hub_addr: &str,
        registration: &NodeRegistration,
    ) -> ConnectOutcome {
        let mut backoff = ReconnectBackoff::new();
        loop {
            let attempt = open_serving_connection(hub_addr, registration);
            tokio::pin!(attempt);

            // Race the connection attempt against incoming commands.
            let result = loop {
                tokio::select! {
                    res = &mut attempt => break res,
                    cmd = self.cmd_rx.recv() => {
                        if self.dispatch_command(cmd).is_break() {
                            return ConnectOutcome::Shutdown;
                        }
                    }
                }
            };

            match result {
                Ok(conn) => {
                    return ConnectOutcome::Connected(Box::new(conn));
                }
                Err(e) if e.is_unauthenticated() => {
                    log::warn!("Hub rejected authentication during reconnect; stopping serving");
                    return ConnectOutcome::Fatal(ServingError::Hub(e));
                }
                Err(e) => {
                    let wait = backoff.next_delay();
                    log::warn!(
                        "Hub reconnect failed: {e}; retrying in {:.1}s",
                        wait.as_secs_f64()
                    );
                    if self.wait_while_servicing_commands(wait).await.is_break() {
                        return ConnectOutcome::Shutdown;
                    }
                }
            }
        }
    }

    /// Sleep for `dur` while still answering local commands. Returns
    /// `ControlFlow::Break` if a shutdown was requested while waiting.
    async fn wait_while_servicing_commands(&mut self, dur: Duration) -> ControlFlow<()> {
        let sleep = tokio::time::sleep(dur);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => return ControlFlow::Continue(()),
                cmd = self.cmd_rx.recv() => {
                    if self.dispatch_command(cmd).is_break() {
                        return ControlFlow::Break(());
                    }
                }
            }
        }
    }

    /// Handle one command from a `ServingHandle`. These touch only local state,
    /// so they work whether or not we currently have a hub connection. Returns
    /// `ControlFlow::Break` when the session should shut down (explicit shutdown
    /// or all handles dropped), `Continue` otherwise.
    fn dispatch_command(&mut self, cmd: Option<Command>) -> ControlFlow<()> {
        match cmd {
            Some(Command::Status { reply }) => {
                let _ = reply.send(self.build_status());
                ControlFlow::Continue(())
            }
            Some(Command::GenerateActivationCode { ttl_profile, reply }) => {
                let result = self
                    .endorsing
                    .generate_activation_code_with_ttl(self.node_number, ttl_profile);
                let _ = reply.send(result);
                ControlFlow::Continue(())
            }
            Some(Command::Shutdown) => {
                log::info!("Shutdown requested");
                ControlFlow::Break(())
            }
            None => {
                // Every `ServingHandle` was dropped, so the command channel is
                // closed: no further commands (not even shutdown) can ever
                // arrive. The session is now uncontrollable, so it self-terminates.
                log::info!("All serving handles dropped, shutting down");
                ControlFlow::Break(())
            }
        }
    }

    fn build_status(&self) -> ServingStatus {
        ServingStatus {
            connected: self.connected,
            connectivity_group_id: self.connectivity_group_id.clone(),
            node_number: self.node_number,
            endorsing: self.endorsing.status(),
        }
    }

    async fn handle_hub_request(&mut self, request: proto::ServingRequest) {
        log::debug!(
            "Received request: id={} src_node={} dest_node={}",
            request.request_id,
            request.source_node_number,
            request.dest_node_number
        );

        match request.kind {
            Some(proto::serving_request::Kind::Welcome(_)) => {
                log::debug!("  Welcome received");
            }
            Some(proto::serving_request::Kind::PairNodesMessage(msg)) => {
                match self
                    .endorsing
                    .pair_nodes(&msg, self.node_number, &self.signing_key)
                {
                    Ok(reply) => {
                        let response = proto::ServingResponse {
                            request_id: request.request_id,
                            error: String::new(),
                            kind: Some(proto::serving_response::Kind::PairNodesMessage(reply)),
                        };
                        if let Err(e) = self.conn.response_tx.send(response).await {
                            log::error!("  Failed to send response: {}", e);
                        } else {
                            log::debug!("  Sent pairing reply");
                        }
                    }
                    Err(error) => {
                        log::warn!("  PairNodes failed: {}", error);
                        self.send_error_response(request.request_id, &error).await;
                    }
                }
            }
            Some(proto::serving_request::Kind::RosterCosignRequest(req)) => {
                match self
                    .endorsing
                    .roster_cosign(&req, self.node_number, &self.signing_key)
                {
                    Ok(cosign_resp) => {
                        let response = proto::ServingResponse {
                            request_id: request.request_id,
                            error: String::new(),
                            kind: Some(proto::serving_response::Kind::RosterCosignResponse(
                                cosign_resp,
                            )),
                        };
                        if let Err(e) = self.conn.response_tx.send(response).await {
                            log::error!("  Failed to send cosign response: {}", e);
                        } else {
                            log::debug!("  Sent cosign response");
                        }
                    }
                    Err(error) => {
                        log::warn!("  RosterCosign failed: {}", error);
                        self.send_error_response(request.request_id, &error).await;
                    }
                }
            }
            Some(proto::serving_request::Kind::StartConnectionRequest(req)) => {
                self.handle_start_connection_request(
                    request.request_id,
                    request.source_node_number,
                    req,
                )
                .await;
            }
            None => {
                log::warn!("  Unknown request kind");
            }
        }
    }

    async fn handle_start_connection_request(
        &mut self,
        request_id: i64,
        caller_node_number: i32,
        req: proto::StartConnectionRequest,
    ) {
        use crate::hub::HubClient;
        use crate::p2p_signing;

        log::debug!("  StartConnectionRequest from node {}", caller_node_number,);

        // Fetch and verify fresh roster from hub
        let client = match HubClient::connect(&self.p2p_config.hub_addr).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("  Failed to connect to hub: {}", e);
                self.send_error_response(request_id, "internal error").await;
                return;
            }
        };

        let roster = match client
            .get_and_verify_roster(
                &self.p2p_config.registration,
                &self.signing_key.public_key_spki(),
            )
            .await
        {
            Ok(r) => r,
            Err(crate::hub::HubError::RosterVerification(
                crate::roster::RosterVerificationError::VerifierNotInRoster(_),
            )) => {
                // We're not in the roster yet - not activated
                log::info!("  Node not yet activated, cannot accept P2P connections");
                self.send_error_response(request_id, "node not yet activated")
                    .await;
                return;
            }
            Err(crate::hub::HubError::RosterVerification(
                crate::roster::RosterVerificationError::VerifierRevoked(_),
            )) => {
                // We've been revoked from the roster — can no longer serve.
                log::info!("  Node has been revoked, cannot accept P2P connections");
                self.send_error_response(request_id, "node has been revoked")
                    .await;
                return;
            }
            Err(e) => {
                log::error!("  Failed to fetch/verify roster: {}", e);
                self.send_error_response(request_id, "internal error").await;
                return;
            }
        };

        // Look up caller's Ed25519 public key in roster
        let Some(caller_node) = roster
            .nodes
            .iter()
            .find(|n| n.node_number == caller_node_number)
        else {
            log::warn!("  Caller node {} not found in roster", caller_node_number);
            self.send_error_response(request_id, "caller not in roster")
                .await;
            return;
        };

        let req_payload = match p2p_signing::verify_request(&req, &caller_node.public_key_spki) {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "  Signature verification failed for node {}: {}",
                    caller_node_number,
                    e
                );
                self.send_error_response(request_id, "signature verification failed")
                    .await;
                return;
            }
        };

        log::debug!(
            "  Verified caller signature: node {}, answerer_node={}",
            caller_node_number,
            req_payload.answerer_node_number
        );

        // Parse caller's X25519 public key from the verified payload
        let caller_x25519_public: [u8; 32] =
            match req_payload.caller_x25519_public_key.clone().try_into() {
                Ok(key) => key,
                Err(_) => {
                    log::warn!("  Invalid X25519 public key length");
                    self.send_error_response(request_id, "invalid X25519 public key")
                        .await;
                    return;
                }
            };

        // Generate connection ID
        let connection_id = self.connection_id_counter.fetch_add(1, Ordering::Relaxed);

        // Create IceAnswerer with caller's SDP.
        let Some(stun_turn_config) = &req_payload.stun_turn_config else {
            log::warn!("  Missing STUN/TURN config in request");
            self.send_error_response(request_id, "missing STUN/TURN config")
                .await;
            return;
        };
        let ice_answerer = match IceAnswerer::new(&req_payload.caller_sdp, stun_turn_config) {
            Ok(answerer) => answerer,
            Err(e) => {
                log::error!("  Failed to create ICE answerer: {}", e);
                self.send_error_response(request_id, &format!("ICE error: {}", e))
                    .await;
                return;
            }
        };

        let answerer_sdp = ice_answerer.local_description().to_string();

        // Generate ephemeral X25519 keypair for forward secrecy
        let encryption_key = crate::crypto::X25519KeyPair::generate_ephemeral();

        // Build and sign the inner response payload, then wrap in the envelope.
        let response_payload = proto::start_connection_response::Payload {
            connection_id,
            answerer_x25519_public_key: encryption_key.public_key().to_vec(),
            answerer_sdp,
        };
        let signed_response =
            p2p_signing::build_signed_response(&self.signing_key, &response_payload);

        // Compute shared secret
        let shared_secret = encryption_key.diffie_hellman(&caller_x25519_public);

        // Send response
        let response = proto::ServingResponse {
            request_id,
            error: String::new(),
            kind: Some(proto::serving_response::Kind::StartConnectionResponse(
                signed_response,
            )),
        };

        if let Err(e) = self.conn.response_tx.send(response).await {
            log::error!("  Failed to send StartConnectionResponse: {}", e);
            return;
        }

        log::debug!(
            "  Sent StartConnectionResponse, connection_id={}",
            connection_id
        );

        // Handle based on requested transport type
        let transport = req_payload.transport();
        match transport {
            proto::Transport::Datagram => {
                // UDP: Spawn a task to complete ICE
                // The channel receives a fully-connected UdpConnection (or error)
                let tx = self.incoming_udp_tx.clone();
                tokio::spawn(async move {
                    log::debug!("  Starting UDP ICE for connection_id={}", connection_id);
                    let result = UdpConnection::connect_answerer(
                        caller_node_number,
                        connection_id,
                        ice_answerer,
                        shared_secret,
                    )
                    .await;

                    match &result {
                        Ok(_) => {
                            log::info!("  UDP ICE completed for connection_id={}", connection_id)
                        }
                        Err(e) => log::error!(
                            "  UDP ICE failed for connection_id={}: {}",
                            connection_id,
                            e
                        ),
                    }

                    if let Err(e) = tx.send(result).await {
                        log::error!("  Failed to deliver incoming UDP connection: {}", e);
                    }
                });
                log::debug!("  Spawned UDP ICE task");
            }
            proto::Transport::Stream => {
                // QUIC: Spawn a task to complete ICE + QUIC handshake
                // The channel receives a fully-connected QuicConnection (or error)
                let tx = self.incoming_quic_tx.clone();
                tokio::spawn(async move {
                    log::debug!(
                        "  Starting QUIC handshake for connection_id={}",
                        connection_id
                    );
                    let result = QuicConnection::connect_answerer(
                        caller_node_number,
                        connection_id,
                        ice_answerer,
                        shared_secret,
                    )
                    .await;

                    match &result {
                        Ok(_) => log::info!(
                            "  QUIC handshake completed for connection_id={}",
                            connection_id
                        ),
                        Err(e) => log::error!(
                            "  QUIC handshake failed for connection_id={}: {}",
                            connection_id,
                            e
                        ),
                    }

                    if let Err(e) = tx.send(result).await {
                        log::error!("  Failed to deliver incoming QUIC connection: {}", e);
                    }
                });
                log::debug!("  Spawned QUIC handshake task");
            }
        }
    }

    async fn send_error_response(&mut self, request_id: i64, error: &str) {
        let response = proto::ServingResponse {
            request_id,
            error: error.to_string(),
            kind: None,
        };
        let _ = self.conn.response_tx.send(response).await;
    }
}

//-- Tests ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PairingCode;

    const NODE_NUMBER: i32 = 1;

    fn make_state() -> (EndorsingState, SigningKeyPair) {
        let signing_key = SigningKeyPair::derive_from_root_key(&[42u8; 32]);
        (EndorsingState::new(), signing_key)
    }

    fn make_state_with_ttl(ttl: Duration) -> (EndorsingState, SigningKeyPair) {
        let signing_key = SigningKeyPair::derive_from_root_key(&[42u8; 32]);
        let mut state = EndorsingState::new();
        state.ttl_override = Some(ttl);
        (state, signing_key)
    }

    /// Build a PairNodesMessage that a new node would send, using the given
    /// activation code's secret for MAC computation.
    fn build_pair_message(code: &PairingCode, new_node_number: i32) -> proto::PairNodesMessage {
        let new_node_key = SigningKeyPair::derive_from_root_key(&[new_node_number as u8; 32]);
        let payload = proto::pair_nodes_message::Payload {
            sender_node_number: new_node_number,
            receiver_node_number: code.node_number,
            public_key_spki: new_node_key.public_key_spki(),
            nonce: generate_nonce(),
            reply_nonce: vec![],
        };
        let payload_bytes = payload.encode_to_vec();
        let mac = code.secret.compute_mac(&payload_bytes);
        proto::PairNodesMessage {
            payload: Some(payload),
            mac,
        }
    }

    #[test]
    fn generate_multiple_codes() {
        let (mut state, _) = make_state();
        let codes: Vec<PairingCode> = (0..5)
            .map(|_| {
                state
                    .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                    .unwrap()
            })
            .collect();

        // All codes are unique
        let secrets: Vec<String> = codes.iter().map(|c| c.secret.to_base36()).collect();
        let unique: std::collections::HashSet<&String> = secrets.iter().collect();
        assert_eq!(unique.len(), 5);

        assert_eq!(state.pairing_secrets.len(), 5);
        let status = state.status().unwrap();
        assert_eq!(status.codes_outstanding, 5);
        assert!(status.nodes_awaiting_cosign.is_empty());
    }

    #[test]
    fn cap_enforced() {
        let (mut state, _) = make_state();
        for _ in 0..MAX_ACTIVE_ACTIVATIONS {
            state
                .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                .unwrap();
        }
        let err = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap_err();
        assert!(
            matches!(err, ServingError::TooManyActivationSessions),
            "expected TooManyActivationSessions, got: {}",
            err
        );
    }

    #[test]
    fn pair_with_one_code_others_remain_valid() {
        let (mut state, key) = make_state();
        let code_a = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        let code_b = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        let code_c = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();

        // Pair with code_b
        let msg = build_pair_message(&code_b, 10);
        let reply = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap();
        assert!(reply.payload.is_some());

        // code_b's secret is consumed
        assert_eq!(state.pairing_secrets.len(), 2);
        assert_eq!(state.pending_endorsements.len(), 1);
        assert!(state.pending_endorsements.contains_key(&10));

        // code_a and code_c still work
        let msg_a = build_pair_message(&code_a, 11);
        assert!(state.pair_nodes(&msg_a, NODE_NUMBER, &key).is_ok());

        let msg_c = build_pair_message(&code_c, 12);
        assert!(state.pair_nodes(&msg_c, NODE_NUMBER, &key).is_ok());

        assert_eq!(state.pairing_secrets.len(), 0);
        assert_eq!(state.pending_endorsements.len(), 3);
    }

    #[test]
    fn same_code_cannot_be_used_twice() {
        let (mut state, key) = make_state();
        let code = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();

        let msg1 = build_pair_message(&code, 10);
        assert!(state.pair_nodes(&msg1, NODE_NUMBER, &key).is_ok());

        // Same secret, different node — MAC won't match any remaining secret
        let msg2 = build_pair_message(&code, 11);
        let err = state.pair_nodes(&msg2, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("no active pairing session") || err.contains("MAC verification"));
    }

    #[test]
    fn wrong_secret_rejected() {
        let (mut state, key) = make_state();
        let _code = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();

        // Build a message with a bogus secret
        let bogus_code = PairingCode::new(1, PairingSecret::generate(TtlProfile::Interactive));
        let msg = build_pair_message(&bogus_code, 10);
        let err = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("MAC verification failed"));
    }

    #[test]
    fn no_codes_rejects_pair() {
        let (mut state, key) = make_state();
        let bogus = PairingCode::new(1, PairingSecret::generate(TtlProfile::Interactive));
        let msg = build_pair_message(&bogus, 10);
        let err = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("no active pairing session"));
    }

    #[test]
    fn status_reflects_state() {
        let (mut state, key) = make_state();
        assert!(state.status().is_none());

        state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        let s = state.status().unwrap();
        assert_eq!(s.codes_outstanding, 1);
        assert!(s.nodes_awaiting_cosign.is_empty());

        let code = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        let msg = build_pair_message(&code, 10);
        state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap();

        let s = state.status().unwrap();
        assert_eq!(s.codes_outstanding, 1); // first code still outstanding
        assert_eq!(s.nodes_awaiting_cosign, vec![10]);
    }

    #[test]
    fn cap_counts_both_secrets_and_pending() {
        let (mut state, key) = make_state();

        // Generate 50 codes
        let codes: Vec<PairingCode> = (0..50)
            .map(|_| {
                state
                    .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                    .unwrap()
            })
            .collect();

        // Pair 50 of them → 50 pending
        for (i, code) in codes.into_iter().enumerate() {
            let msg = build_pair_message(&code, 100 + i as i32);
            state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap();
        }

        assert_eq!(state.pairing_secrets.len(), 0);
        assert_eq!(state.pending_endorsements.len(), 50);

        // Generate 50 more codes → total = 100
        for _ in 0..50 {
            state
                .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                .unwrap();
        }

        // 101st should fail
        assert!(matches!(
            state
                .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                .unwrap_err(),
            ServingError::TooManyActivationSessions
        ));
    }

    #[test]
    fn pair_reply_has_correct_fields() {
        let (mut state, key) = make_state();
        let code = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        let msg = build_pair_message(&code, 10);
        let reply = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap();

        let reply_payload = reply.payload.unwrap();
        assert_eq!(reply_payload.sender_node_number, 1); // endorser
        assert_eq!(reply_payload.receiver_node_number, 10); // new node
        assert!(!reply_payload.public_key_spki.is_empty());
        assert!(!reply_payload.nonce.is_empty());
        assert_eq!(reply_payload.reply_nonce, msg.payload.unwrap().nonce);

        // Verify MAC on reply
        let reply_payload_bytes = reply_payload.encode_to_vec();
        assert!(code.secret.verify_mac(&reply_payload_bytes, &reply.mac));
    }

    #[test]
    fn expired_code_rejected() {
        let (mut state, key) = make_state_with_ttl(Duration::ZERO);
        let code = state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();

        // Code expired immediately — pairing should fail
        let msg = build_pair_message(&code, 10);
        let err = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("no active pairing session"));
        assert_eq!(state.pairing_secrets.len(), 0); // pruned
    }

    #[test]
    fn expired_codes_dont_count_toward_cap() {
        let (mut state, _) = make_state_with_ttl(Duration::ZERO);
        // Generate MAX codes — they all expire immediately
        for _ in 0..MAX_ACTIVE_ACTIVATIONS {
            state
                .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
                .unwrap();
        }
        // Should succeed because generate_activation_code prunes expired first
        state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
    }

    #[test]
    fn expired_codes_not_counted_in_status() {
        let (mut state, _) = make_state_with_ttl(Duration::ZERO);
        state
            .generate_activation_code_with_ttl(NODE_NUMBER, TtlProfile::Interactive)
            .unwrap();
        // Code expired immediately — status should show nothing
        assert!(state.status().is_none());
    }
}
