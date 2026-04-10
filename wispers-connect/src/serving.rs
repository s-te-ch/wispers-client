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
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use crate::crypto::{PairingCode, PairingSecret, SigningKeyPair, generate_nonce};
use crate::hub::ServingConnection;
use crate::hub::proto;
use crate::ice::IceAnswerer;
use crate::p2p::{P2pError, QuicConnection, UdpConnection};
use crate::types::ConnectivityGroupId;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;
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
pub struct P2pConfig {
    /// Hub address for fetching fresh roster on each connection request.
    pub hub_addr: String,
    /// Node registration for authenticating with the hub.
    pub registration: crate::types::NodeRegistration,
}

/// Information about the current serving session status.
#[derive(Debug, Clone)]
pub struct StatusInfo {
    pub connected: bool,
    pub connectivity_group_id: ConnectivityGroupId,
    pub node_number: i32,
    /// Current endorsing state, if any.
    pub endorsing: Option<EndorsingStatus>,
}

/// Status of active endorsing sessions.
#[derive(Debug, Clone)]
pub struct EndorsingStatus {
    /// Number of activation codes waiting to be used by new nodes.
    pub codes_outstanding: usize,
    /// Node numbers that have paired and are awaiting cosign.
    pub nodes_awaiting_cosign: Vec<i32>,
}

/// Maximum number of concurrent activation sessions (codes + pending cosigns).
const MAX_ACTIVE_ACTIVATIONS: usize = 100;

/// How long an activation code remains valid after generation.
///
/// This is the security margin against offline brute-force of the
/// pairing secret: the window an attacker has to crack the secret and
/// inject a forged response before it expires. `crypto::PAIRING_SECRET_LEN`
/// is calibrated against this window, so changing one without reviewing
/// the other invalidates the entropy-vs-time trade.
///
/// Also used as the client-side deadline on `pair_nodes` RPCs (see
/// `hub::HubClient::pair_nodes`) — without that deadline a malicious
/// hub could stall indefinitely and break the window bound.
pub(crate) const SECRET_TTL: Duration = Duration::from_secs(120);

//-- Endorsing state (testable without hub connection) -------------------------------------------------

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
    secret_ttl: Duration,
    pairing_secrets: Vec<TimedSecret>,
    pending_endorsements: HashMap<i32, PendingEndorsement>,
}

impl EndorsingState {
    fn new() -> Self {
        Self {
            secret_ttl: SECRET_TTL,
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

    fn generate_activation_code(&mut self, node_number: i32) -> Result<PairingCode, ServingError> {
        self.prune_expired();
        if self.pairing_secrets.len() + self.pending_endorsements.len() >= MAX_ACTIVE_ACTIVATIONS {
            return Err(ServingError::TooManyActivationSessions);
        }

        let secret = PairingSecret::generate();
        let code = PairingCode::new(node_number, secret.clone());
        self.pairing_secrets.push(TimedSecret {
            secret,
            expires_at: Instant::now() + self.secret_ttl,
        });

        log::info!("Generated pairing code: {}", code.format());
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

//-- ServingHandle + ServingSession ---------------------------------------------------------------------

/// Commands sent from ServingHandle to ServingSession.
enum Command {
    Status {
        reply: oneshot::Sender<StatusInfo>,
    },
    GenerateActivationCode {
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
    pub async fn status(&self) -> Result<StatusInfo, ServingError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Status { reply: reply_tx })
            .await
            .map_err(|_| ServingError::SessionShutdown)?;
        reply_rx.await.map_err(|_| ServingError::SessionShutdown)
    }

    /// Generate an activation code for endorsing a new node.
    ///
    /// Returns the activation code to share with the new node.
    /// Multiple codes can be outstanding simultaneously (up to 100).
    pub async fn generate_activation_code(&self) -> Result<PairingCode, ServingError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GenerateActivationCode { reply: reply_tx })
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
    pub fn new(
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
            p2p_config,
            incoming_udp_tx: udp_tx,
            incoming_quic_tx: quic_tx,
            connection_id_counter: AtomicI64::new(1),
        };

        (handle, session, incoming)
    }

    /// Run the serving event loop.
    ///
    /// This processes hub requests and local commands until shutdown or error.
    pub async fn run(mut self) -> Result<(), ServingError> {
        log::info!("ServingSession running for node {}", self.node_number);

        loop {
            tokio::select! {
                // Handle commands from ServingHandle
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Status { reply }) => {
                            let status = self.build_status();
                            let _ = reply.send(status);
                        }
                        Some(Command::GenerateActivationCode { reply }) => {
                            let result = self.endorsing.generate_activation_code(self.node_number);
                            let _ = reply.send(result);
                        }
                        Some(Command::Shutdown) => {
                            log::info!("Shutdown requested");
                            break;
                        }
                        None => {
                            // All handles dropped
                            log::info!("All handles dropped, shutting down");
                            break;
                        }
                    }
                }

                // Handle hub requests
                result = self.conn.request_stream.message() => {
                    match result {
                        Ok(Some(request)) => {
                            self.handle_hub_request(request).await;
                        }
                        Ok(None) => {
                            log::info!("Hub stream ended");
                            break;
                        }
                        Err(e) => {
                            log::error!("Hub stream error: {}", e);
                            return Err(ServingError::Hub(crate::hub::HubError::Rpc(e)));
                        }
                    }
                }
            }
        }

        log::info!("ServingSession ended");
        Ok(())
    }

    fn build_status(&self) -> StatusInfo {
        StatusInfo {
            connected: true,
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

        log::debug!(
            "  StartConnectionRequest from node {}, answerer_node={}",
            caller_node_number,
            req.answerer_node_number
        );

        // Parse caller's X25519 public key
        let caller_x25519_public: [u8; 32] = match req.caller_x25519_public_key.clone().try_into() {
            Ok(key) => key,
            Err(_) => {
                log::warn!("  Invalid X25519 public key length");
                self.send_error_response(request_id, "invalid X25519 public key")
                    .await;
                return;
            }
        };

        // Fetch and verify fresh roster from hub
        let mut client = match HubClient::connect(&self.p2p_config.hub_addr).await {
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

        let Ok(verifying_key) = VerifyingKey::from_public_key_der(&caller_node.public_key_spki)
        else {
            log::warn!(
                "  Invalid public key format for node {}",
                caller_node_number
            );
            self.send_error_response(request_id, "invalid caller public key")
                .await;
            return;
        };

        // Verify caller's Ed25519 signature
        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&req.answerer_node_number.to_le_bytes());
        message_to_verify.extend_from_slice(&req.caller_x25519_public_key);
        message_to_verify.extend_from_slice(req.caller_sdp.as_bytes());

        let Ok(signature_bytes): Result<[u8; 64], _> = req.signature.clone().try_into() else {
            log::warn!("  Invalid signature format");
            self.send_error_response(request_id, "invalid signature")
                .await;
            return;
        };
        let signature = Signature::from_bytes(&signature_bytes);

        if verifying_key
            .verify(&message_to_verify, &signature)
            .is_err()
        {
            log::warn!(
                "  Signature verification failed for node {}",
                caller_node_number
            );
            self.send_error_response(request_id, "signature verification failed")
                .await;
            return;
        }

        log::debug!("  Verified caller signature: node {}", caller_node_number);

        // Generate connection ID
        let connection_id = self.connection_id_counter.fetch_add(1, Ordering::Relaxed);

        // Create IceAnswerer with caller's SDP
        // Use the STUN/TURN config provided by caller to ensure TURN relaying works
        let Some(stun_turn_config) = &req.stun_turn_config else {
            log::warn!("  Missing STUN/TURN config in request");
            self.send_error_response(request_id, "missing STUN/TURN config")
                .await;
            return;
        };
        let ice_answerer = match IceAnswerer::new(&req.caller_sdp, stun_turn_config) {
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

        // Sign our response: connection_id || answerer_x25519_public_key || answerer_sdp
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&connection_id.to_le_bytes());
        message_to_sign.extend_from_slice(&encryption_key.public_key());
        message_to_sign.extend_from_slice(answerer_sdp.as_bytes());
        let signature = self.signing_key.sign(&message_to_sign);

        // Compute shared secret
        let shared_secret = encryption_key.diffie_hellman(&caller_x25519_public);

        // Send response
        let response = proto::ServingResponse {
            request_id,
            error: String::new(),
            kind: Some(proto::serving_response::Kind::StartConnectionResponse(
                proto::StartConnectionResponse {
                    connection_id,
                    answerer_x25519_public_key: encryption_key.public_key().to_vec(),
                    answerer_sdp,
                    signature,
                },
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
        let transport = req.transport();
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

//-- Tests ---------------------------------------------------------------------------------------------

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
        state.secret_ttl = ttl;
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
            .map(|_| state.generate_activation_code(NODE_NUMBER).unwrap())
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
            state.generate_activation_code(NODE_NUMBER).unwrap();
        }
        let err = state.generate_activation_code(NODE_NUMBER).unwrap_err();
        assert!(
            matches!(err, ServingError::TooManyActivationSessions),
            "expected TooManyActivationSessions, got: {}",
            err
        );
    }

    #[test]
    fn pair_with_one_code_others_remain_valid() {
        let (mut state, key) = make_state();
        let code_a = state.generate_activation_code(NODE_NUMBER).unwrap();
        let code_b = state.generate_activation_code(NODE_NUMBER).unwrap();
        let code_c = state.generate_activation_code(NODE_NUMBER).unwrap();

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
        let code = state.generate_activation_code(NODE_NUMBER).unwrap();

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
        let _code = state.generate_activation_code(NODE_NUMBER).unwrap();

        // Build a message with a bogus secret
        let bogus_code = PairingCode::new(1, PairingSecret::generate());
        let msg = build_pair_message(&bogus_code, 10);
        let err = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("MAC verification failed"));
    }

    #[test]
    fn no_codes_rejects_pair() {
        let (mut state, key) = make_state();
        let bogus = PairingCode::new(1, PairingSecret::generate());
        let msg = build_pair_message(&bogus, 10);
        let err = state.pair_nodes(&msg, NODE_NUMBER, &key).unwrap_err();
        assert!(err.contains("no active pairing session"));
    }

    #[test]
    fn status_reflects_state() {
        let (mut state, key) = make_state();
        assert!(state.status().is_none());

        state.generate_activation_code(NODE_NUMBER).unwrap();
        let s = state.status().unwrap();
        assert_eq!(s.codes_outstanding, 1);
        assert!(s.nodes_awaiting_cosign.is_empty());

        let code = state.generate_activation_code(NODE_NUMBER).unwrap();
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
            .map(|_| state.generate_activation_code(NODE_NUMBER).unwrap())
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
            state.generate_activation_code(NODE_NUMBER).unwrap();
        }

        // 101st should fail
        assert!(matches!(
            state.generate_activation_code(NODE_NUMBER).unwrap_err(),
            ServingError::TooManyActivationSessions
        ));
    }

    #[test]
    fn pair_reply_has_correct_fields() {
        let (mut state, key) = make_state();
        let code = state.generate_activation_code(NODE_NUMBER).unwrap();
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
        let code = state.generate_activation_code(NODE_NUMBER).unwrap();

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
            state.generate_activation_code(NODE_NUMBER).unwrap();
        }
        // Should succeed because generate_activation_code prunes expired first
        state.generate_activation_code(NODE_NUMBER).unwrap();
    }

    #[test]
    fn expired_codes_not_counted_in_status() {
        let (mut state, _) = make_state_with_ttl(Duration::ZERO);
        state.generate_activation_code(NODE_NUMBER).unwrap();
        // Code expired immediately — status should show nothing
        assert!(state.status().is_none());
    }
}
