//! Serving session for handling hub requests and local commands.
//!
//! This module provides a handle + runner pattern for the serving loop:
//! - `ServingSession` is the runner that owns the event loop and state
//! - `ServingHandle` is a clone-able handle for sending commands to the session

use crate::crypto::{generate_nonce, PairingCode, PairingSecret, SigningKeyPair};
use crate::hub::proto;
use crate::hub::ServingConnection;
use crate::types::ConnectivityGroupId;
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
}

impl ServingSession {
    /// Create a new serving session.
    ///
    /// Returns a handle for sending commands and the session runner.
    pub fn new(
        conn: ServingConnection,
        signing_key: SigningKeyPair,
        connectivity_group_id: ConnectivityGroupId,
        node_number: i32,
    ) -> (ServingHandle, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        let handle = ServingHandle { cmd_tx };
        let session = Self {
            cmd_rx,
            conn,
            signing_key,
            connectivity_group_id,
            node_number,
            pairing_secret: None,
            pending_endorsement: None,
        };

        (handle, session)
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
            "Received request: id={} dest_node={}",
            request.request_id, request.dest_node_number
        );

        match request.kind {
            Some(proto::serving_request::Kind::PairNodesMessage(msg)) => {
                self.handle_pair_nodes_message(request.request_id, msg).await;
            }
            Some(proto::serving_request::Kind::RosterCosignRequest(req)) => {
                self.handle_roster_cosign_request(request.request_id, req).await;
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

        // Reconstruct base roster: clone, remove new node, remove last addendum
        let mut base_roster = new_roster.clone();

        // Remove the new node
        base_roster.nodes.retain(|n| n.node_number != new_node_number);

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

    async fn send_error_response(&mut self, request_id: i64, error: &str) {
        let response = proto::ServingResponse {
            request_id,
            error: error.to_string(),
            kind: None,
        };
        let _ = self.conn.response_tx.send(response).await;
    }
}
