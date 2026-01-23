//! Serving session for handling hub requests and local commands.
//!
//! This module provides a handle + runner pattern for the serving loop:
//! - `ServingSession` is the runner that owns the event loop and state
//! - `ServingHandle` is a clone-able handle for sending commands to the session

use std::sync::atomic::{AtomicI64, Ordering};

use crate::crypto::{generate_nonce, PairingCode, PairingSecret, SigningKeyPair, X25519KeyPair};
use crate::hub::proto;
use crate::hub::ServingConnection;
use crate::ice::IceAnswerer;
use crate::p2p::P2pConnectionAnswerer;
use crate::types::ConnectivityGroupId;
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
    #[error("already have active pairing session")]
    PairingSessionActive,
}

/// Configuration for P2P connection handling (optional).
///
/// When provided, the serving session can accept incoming P2P connections.
/// When not provided (e.g., for RegisteredNodeState), connection requests are rejected.
pub struct P2pConfig {
    /// X25519 key pair for key exchange.
    pub x25519_key: X25519KeyPair,
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

/// Status of an active endorsing session.
#[derive(Debug, Clone)]
pub enum EndorsingStatus {
    /// Waiting for a PairNodesMessage from the new node.
    AwaitingPairNode,
    /// Received pairing, waiting for RosterCosignRequest.
    AwaitingCosign { new_node_number: i32 },
}

/// Internal state for a pending endorsement.
struct PendingEndorsement {
    new_node_number: i32,
    new_node_pubkey: Vec<u8>,
    new_node_nonce: Vec<u8>,
    our_nonce: Vec<u8>,
}

/// Commands sent from ServingHandle to ServingSession.
enum Command {
    Status {
        reply: oneshot::Sender<StatusInfo>,
    },
    GeneratePairingSecret {
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

    /// Generate a pairing secret for endorsing a new node.
    ///
    /// Returns the pairing code to share with the new node.
    /// Only one pairing session can be active at a time.
    pub async fn generate_pairing_secret(&self) -> Result<PairingCode, ServingError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GeneratePairingSecret { reply: reply_tx })
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
    connectivity_group_id: ConnectivityGroupId,
    node_number: i32,
    // Endorsing state
    pairing_secret: Option<PairingSecret>,
    pending_endorsement: Option<PendingEndorsement>,
    // P2P state (only for activated nodes)
    p2p_config: Option<P2pConfig>,
    incoming_conn_tx: Option<mpsc::Sender<P2pConnectionAnswerer>>,
    connection_id_counter: AtomicI64,
}

impl ServingSession {
    /// Create a new serving session.
    ///
    /// Returns a handle for sending commands and the session runner.
    /// When `p2p_config` is provided, also returns a receiver for incoming P2P connections.
    pub fn new(
        conn: ServingConnection,
        signing_key: SigningKeyPair,
        connectivity_group_id: ConnectivityGroupId,
        node_number: i32,
        p2p_config: Option<P2pConfig>,
    ) -> (ServingHandle, Self, Option<mpsc::Receiver<P2pConnectionAnswerer>>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        // Create incoming connection channel if P2P is enabled
        let (incoming_conn_tx, incoming_conn_rx) = if p2p_config.is_some() {
            let (tx, rx) = mpsc::channel(16);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let handle = ServingHandle { cmd_tx };
        let session = Self {
            cmd_rx,
            conn,
            signing_key,
            connectivity_group_id,
            node_number,
            pairing_secret: None,
            pending_endorsement: None,
            p2p_config,
            incoming_conn_tx,
            connection_id_counter: AtomicI64::new(1),
        };

        (handle, session, incoming_conn_rx)
    }

    /// Run the serving event loop.
    ///
    /// This processes hub requests and local commands until shutdown or error.
    pub async fn run(mut self) -> Result<(), ServingError> {
        println!("ServingSession running for node {}", self.node_number);

        loop {
            tokio::select! {
                // Handle commands from ServingHandle
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Status { reply }) => {
                            let status = self.build_status();
                            let _ = reply.send(status);
                        }
                        Some(Command::GeneratePairingSecret { reply }) => {
                            let result = self.handle_generate_pairing_secret();
                            let _ = reply.send(result);
                        }
                        Some(Command::Shutdown) => {
                            println!("Shutdown requested");
                            break;
                        }
                        None => {
                            // All handles dropped
                            println!("All handles dropped, shutting down");
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
                            println!("Hub stream ended");
                            break;
                        }
                        Err(e) => {
                            eprintln!("Hub stream error: {}", e);
                            return Err(ServingError::Hub(crate::hub::HubError::Rpc(e)));
                        }
                    }
                }
            }
        }

        println!("ServingSession ended");
        Ok(())
    }

    fn build_status(&self) -> StatusInfo {
        let endorsing = if self.pending_endorsement.is_some() {
            Some(EndorsingStatus::AwaitingCosign {
                new_node_number: self.pending_endorsement.as_ref().unwrap().new_node_number,
            })
        } else if self.pairing_secret.is_some() {
            Some(EndorsingStatus::AwaitingPairNode)
        } else {
            None
        };

        StatusInfo {
            connected: true,
            connectivity_group_id: self.connectivity_group_id.clone(),
            node_number: self.node_number,
            endorsing,
        }
    }

    fn handle_generate_pairing_secret(&mut self) -> Result<PairingCode, ServingError> {
        // Only allow one active pairing session
        if self.pairing_secret.is_some() || self.pending_endorsement.is_some() {
            return Err(ServingError::PairingSessionActive);
        }

        let secret = PairingSecret::generate();
        let code = PairingCode::new(self.node_number, secret.clone());
        self.pairing_secret = Some(secret);

        println!("Generated pairing code: {}", code.format());
        Ok(code)
    }

    async fn handle_hub_request(&mut self, request: proto::ServingRequest) {
        println!(
            "Received request: id={} src_node={} dest_node={}",
            request.request_id, request.source_node_number, request.dest_node_number
        );

        match request.kind {
            Some(proto::serving_request::Kind::Welcome(_)) => {
                println!("  Welcome received");
            }
            Some(proto::serving_request::Kind::PairNodesMessage(msg)) => {
                self.handle_pair_nodes_message(request.request_id, msg).await;
            }
            Some(proto::serving_request::Kind::RosterCosignRequest(req)) => {
                self.handle_roster_cosign_request(request.request_id, req).await;
            }
            Some(proto::serving_request::Kind::StartConnectionRequest(req)) => {
                self.handle_start_connection_request(request.request_id, request.source_node_number, req).await;
            }
            None => {
                println!("  Unknown request kind");
            }
        }
    }

    async fn handle_pair_nodes_message(&mut self, request_id: i64, msg: proto::PairNodesMessage) {
        let Some(payload) = &msg.payload else {
            eprintln!("  PairNodesMessage missing payload");
            return;
        };

        println!(
            "  PairNodesMessage: sender={} receiver={}",
            payload.sender_node_number, payload.receiver_node_number
        );

        // Check we have an active pairing secret
        let Some(secret) = &self.pairing_secret else {
            eprintln!("  No active pairing session, ignoring");
            self.send_error_response(request_id, "no active pairing session").await;
            return;
        };

        // Verify MAC
        let payload_bytes = payload.encode_to_vec();
        if !secret.verify_mac(&payload_bytes, &msg.mac) {
            eprintln!("  MAC verification failed");
            self.send_error_response(request_id, "MAC verification failed").await;
            return;
        }

        println!("  MAC verified successfully");

        // Store the new node info and generate our nonce
        let our_nonce = generate_nonce();
        self.pending_endorsement = Some(PendingEndorsement {
            new_node_number: payload.sender_node_number,
            new_node_pubkey: payload.public_key_spki.clone(),
            new_node_nonce: payload.nonce.clone(),
            our_nonce: our_nonce.clone(),
        });

        // Build reply payload
        let reply_payload = proto::pair_nodes_message::Payload {
            sender_node_number: self.node_number,
            receiver_node_number: payload.sender_node_number,
            public_key_spki: self.signing_key.public_key_spki(),
            nonce: our_nonce,
            reply_nonce: payload.nonce.clone(),
        };
        let reply_payload_bytes = reply_payload.encode_to_vec();
        let reply_mac = secret.compute_mac(&reply_payload_bytes);

        let reply_msg = proto::PairNodesMessage {
            payload: Some(reply_payload),
            mac: reply_mac,
        };

        // Send response
        let response = proto::ServingResponse {
            request_id,
            error: String::new(),
            kind: Some(proto::serving_response::Kind::PairNodesMessage(reply_msg)),
        };

        if let Err(e) = self.conn.response_tx.send(response).await {
            eprintln!("  Failed to send response: {}", e);
        } else {
            println!("  Sent pairing reply");
        }

        // Clear pairing secret (used), keep pending_endorsement for cosign
        self.pairing_secret = None;
    }

    async fn handle_roster_cosign_request(&mut self, request_id: i64, req: proto::RosterCosignRequest) {
        println!("  RosterCosignRequest: new_node={}", req.new_node_number);

        // Check we have a pending endorsement
        let Some(pending) = &self.pending_endorsement else {
            eprintln!("  No pending endorsement, ignoring");
            self.send_error_response(request_id, "no pending endorsement").await;
            return;
        };

        // Verify it's for the node we paired with
        if req.new_node_number as i32 != pending.new_node_number {
            eprintln!(
                "  Wrong node number: expected {}, got {}",
                pending.new_node_number, req.new_node_number
            );
            self.send_error_response(request_id, "wrong node number").await;
            return;
        }

        // Get the roster and find the activation addendum
        let Some(roster) = &req.new_roster else {
            eprintln!("  Missing roster in cosign request");
            self.send_error_response(request_id, "missing roster").await;
            return;
        };

        // Find the activation addendum for this node
        let activation = roster.addenda.last().and_then(|a| {
            match &a.kind {
                Some(proto::connect::roster::addendum::Kind::Activation(act)) => Some(act),
                _ => None,
            }
        });

        let Some(activation) = activation else {
            eprintln!("  No activation addendum found");
            self.send_error_response(request_id, "no activation addendum").await;
            return;
        };

        let Some(activation_payload) = &activation.payload else {
            eprintln!("  Activation missing payload");
            self.send_error_response(request_id, "activation missing payload").await;
            return;
        };

        // Verify base_version_hash by reconstructing base roster from new_roster
        if !self.verify_base_version_hash(roster, activation_payload, pending.new_node_number) {
            eprintln!("  Base version hash mismatch");
            self.send_error_response(request_id, "base version hash mismatch").await;
            return;
        }

        // Verify nonces match
        if activation_payload.new_node_nonce != pending.new_node_nonce {
            eprintln!("  New node nonce mismatch");
            self.send_error_response(request_id, "new node nonce mismatch").await;
            return;
        }
        if activation_payload.endorser_nonce != pending.our_nonce {
            eprintln!("  Endorser nonce mismatch");
            self.send_error_response(request_id, "endorser nonce mismatch").await;
            return;
        }

        // Verify endorser node number
        if activation_payload.endorser_node_number != self.node_number {
            eprintln!("  Wrong endorser node number");
            self.send_error_response(request_id, "wrong endorser node number").await;
            return;
        }

        // Verify new node's public key in roster matches what we received in pairing
        let new_node_in_roster = roster.nodes.iter().find(|n| n.node_number == pending.new_node_number);
        let Some(new_node_in_roster) = new_node_in_roster else {
            eprintln!("  New node not found in roster");
            self.send_error_response(request_id, "new node not in roster").await;
            return;
        };
        if new_node_in_roster.public_key_spki != pending.new_node_pubkey {
            eprintln!("  Public key mismatch");
            self.send_error_response(request_id, "public key mismatch").await;
            return;
        }

        println!("  All verifications passed, signing activation");

        // Sign the activation payload
        let payload_bytes = activation_payload.encode_to_vec();
        let signature = self.signing_key.sign(&payload_bytes);

        // Send response
        let response = proto::ServingResponse {
            request_id,
            error: String::new(),
            kind: Some(proto::serving_response::Kind::RosterCosignResponse(
                proto::RosterCosignResponse {
                    endorser_signature: signature,
                },
            )),
        };

        if let Err(e) = self.conn.response_tx.send(response).await {
            eprintln!("  Failed to send cosign response: {}", e);
        } else {
            println!("  Sent cosign response");
        }

        // Clear pending endorsement
        self.pending_endorsement = None;
    }

    /// Verify the base_version_hash in an activation payload.
    ///
    /// Reconstructs the base roster from new_roster by removing the new node
    /// and the last addendum, then verifies the hash matches.
    fn verify_base_version_hash(
        &self,
        new_roster: &proto::connect::roster::Roster,
        activation_payload: &proto::connect::roster::activation::Payload,
        new_node_number: i32,
    ) -> bool {
        use sha2::{Digest, Sha256};

        // Reconstruct base roster
        let mut base_roster = new_roster.clone();

        if activation_payload.base_version == 0 {
            // Bootstrap case: base roster version 0 is completely empty
            // Both endorser and new node are added in the first roster
            base_roster.nodes.clear();
        } else {
            // Normal activation: only remove the new node
            base_roster.nodes.retain(|n| n.node_number != new_node_number);
        }

        // Remove the last addendum (the activation we're being asked to sign)
        base_roster.addenda.pop();

        // Set version to base_version
        base_roster.version = activation_payload.base_version;

        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(base_roster.encode_to_vec());
        let computed_hash = hasher.finalize().to_vec();

        // Compare
        if computed_hash != activation_payload.base_version_hash {
            eprintln!(
                "  Base hash mismatch: computed {:?}, expected {:?}",
                &computed_hash[..8],
                &activation_payload.base_version_hash[..activation_payload.base_version_hash.len().min(8)]
            );
            return false;
        }

        println!("  Base version hash verified");
        true
    }

    async fn handle_start_connection_request(
        &mut self,
        request_id: i64,
        caller_node_number: i32,
        req: proto::StartConnectionRequest,
    ) {
        use crate::hub::HubClient;

        println!(
            "  StartConnectionRequest from node {}, answerer_node={}",
            caller_node_number, req.answerer_node_number
        );

        // Check P2P is enabled
        let Some(p2p_config) = &self.p2p_config else {
            println!("  P2P not enabled (node may not be activated)");
            self.send_error_response(request_id, "P2P connections not available").await;
            return;
        };

        // Parse caller's X25519 public key
        let caller_x25519_public: [u8; 32] = match req.caller_x25519_public_key.clone().try_into() {
            Ok(key) => key,
            Err(_) => {
                println!("  Invalid X25519 public key length");
                self.send_error_response(request_id, "invalid X25519 public key").await;
                return;
            }
        };

        // Fetch and verify fresh roster from hub
        // This ensures we have the latest roster (including recently activated nodes)
        let mut client = match HubClient::connect(&p2p_config.hub_addr).await {
            Ok(c) => c,
            Err(e) => {
                println!("  Failed to connect to hub: {}", e);
                self.send_error_response(request_id, "internal error").await;
                return;
            }
        };

        let roster = match client
            .get_and_verify_roster(&p2p_config.registration, &self.signing_key.public_key_spki())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                println!("  Failed to fetch/verify roster: {}", e);
                self.send_error_response(request_id, "internal error").await;
                return;
            }
        };

        // Look up caller's Ed25519 public key in roster
        let Some(caller_node) = roster.nodes.iter().find(|n| n.node_number == caller_node_number) else {
            println!("  Caller node {} not found in roster", caller_node_number);
            self.send_error_response(request_id, "caller not in roster").await;
            return;
        };

        let Ok(pubkey_bytes): Result<[u8; 32], _> = caller_node.public_key_spki.clone().try_into() else {
            println!("  Invalid public key format for node {}", caller_node_number);
            self.send_error_response(request_id, "invalid caller public key").await;
            return;
        };

        let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_bytes) else {
            println!("  Failed to parse Ed25519 key for node {}", caller_node_number);
            self.send_error_response(request_id, "invalid caller public key").await;
            return;
        };

        // Verify caller's Ed25519 signature
        let mut message_to_verify = Vec::new();
        message_to_verify.extend_from_slice(&req.answerer_node_number.to_le_bytes());
        message_to_verify.extend_from_slice(&req.caller_x25519_public_key);
        message_to_verify.extend_from_slice(req.caller_sdp.as_bytes());

        let Ok(signature_bytes): Result<[u8; 64], _> = req.signature.clone().try_into() else {
            println!("  Invalid signature format");
            self.send_error_response(request_id, "invalid signature").await;
            return;
        };
        let signature = Signature::from_bytes(&signature_bytes);

        if verifying_key.verify(&message_to_verify, &signature).is_err() {
            println!("  Signature verification failed for node {}", caller_node_number);
            self.send_error_response(request_id, "signature verification failed").await;
            return;
        }

        println!("  Verified caller signature: node {}", caller_node_number);

        // Generate connection ID
        let connection_id = self.connection_id_counter.fetch_add(1, Ordering::Relaxed);

        // Create IceAnswerer with caller's SDP
        // Use the STUN/TURN config provided by caller to ensure TURN relaying works
        let Some(stun_turn_config) = &req.stun_turn_config else {
            println!("  Missing STUN/TURN config in request");
            self.send_error_response(request_id, "missing STUN/TURN config").await;
            return;
        };
        let ice_answerer = match IceAnswerer::new(&req.caller_sdp, stun_turn_config) {
            Ok(answerer) => answerer,
            Err(e) => {
                println!("  Failed to create ICE answerer: {}", e);
                self.send_error_response(request_id, &format!("ICE error: {}", e)).await;
                return;
            }
        };

        let answerer_sdp = ice_answerer.local_description().to_string();

        // Sign our response: connection_id || answerer_x25519_public_key || answerer_sdp
        let mut message_to_sign = Vec::new();
        message_to_sign.extend_from_slice(&connection_id.to_le_bytes());
        message_to_sign.extend_from_slice(&p2p_config.x25519_key.public_key());
        message_to_sign.extend_from_slice(answerer_sdp.as_bytes());
        let signature = self.signing_key.sign(&message_to_sign);

        // Compute shared secret
        let shared_secret = p2p_config.x25519_key.diffie_hellman(&caller_x25519_public);

        // Send response
        let response = proto::ServingResponse {
            request_id,
            error: String::new(),
            kind: Some(proto::serving_response::Kind::StartConnectionResponse(
                proto::StartConnectionResponse {
                    connection_id,
                    answerer_x25519_public_key: p2p_config.x25519_key.public_key().to_vec(),
                    answerer_sdp,
                    signature,
                },
            )),
        };

        if let Err(e) = self.conn.response_tx.send(response).await {
            eprintln!("  Failed to send StartConnectionResponse: {}", e);
            return;
        }

        println!("  Sent StartConnectionResponse, connection_id={}", connection_id);

        // Create the P2pConnectionAnswerer and spawn task to complete ICE and deliver
        let p2p_conn = P2pConnectionAnswerer::new(
            caller_node_number,
            connection_id,
            ice_answerer,
            shared_secret,
        );

        // Deliver the connection to the incoming channel
        // The ICE connection will complete asynchronously; the receiver should call connect()
        if let Some(tx) = &self.incoming_conn_tx {
            if let Err(e) = tx.send(p2p_conn).await {
                eprintln!("  Failed to deliver incoming connection: {}", e);
            } else {
                println!("  Delivered incoming connection to channel");
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
