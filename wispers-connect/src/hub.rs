//! Hub client for Wispers Connect.
//!
//! This module provides the gRPC client for communicating with the Wispers Connect Hub.

use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};

/// Proto-generated types for the Hub gRPC service.
pub mod proto {
    /// Roster proto types.
    pub mod roster {
        tonic::include_proto!("connect.roster");
    }
    /// Hub proto types.
    pub mod hub {
        tonic::include_proto!("connect.hub");
    }
    pub use hub::*;
}

use proto::hub_client::HubClient as ProtoHubClient;

/// Error type for hub operations.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),
    #[error("connection failed: {0}")]
    Connection(#[from] tonic::transport::Error),
    #[error("RPC failed: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("invalid metadata: {0}")]
    Metadata(#[from] tonic::metadata::errors::InvalidMetadataValue),
    #[error("roster verification failed: {0}")]
    RosterVerification(#[from] crate::roster::RosterVerificationError),
}

impl HubError {
    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, HubError::Rpc(s) if s.code() == tonic::Code::Unauthenticated)
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, HubError::Rpc(s) if s.code() == tonic::Code::NotFound)
    }

    pub fn is_peer_rejected(&self) -> bool {
        matches!(self, HubError::Rpc(s) if s.code() == tonic::Code::FailedPrecondition)
    }

    pub fn is_peer_unavailable(&self) -> bool {
        matches!(self, HubError::Rpc(s) if s.code() == tonic::Code::Unavailable)
    }
}

/// A node in a connectivity group.
#[derive(Debug, Clone)]
pub struct Node {
    pub node_number: i32,
    pub name: String,
    pub metadata: String,
    pub last_seen_at_millis: i64,
    pub is_online: bool,
}

/// Client for communicating with the Wispers Connect Hub.
pub struct HubClient {
    client: ProtoHubClient<Channel>,
}

impl HubClient {
    /// Connect to a hub at the given address.
    ///
    /// Supports both `http://` (plaintext) and `https://` (TLS) schemes.
    pub async fn connect(hub_addr: impl Into<String>) -> Result<Self, HubError> {
        let addr = hub_addr.into();
        let mut endpoint = Channel::from_shared(addr.clone())?;

        // Configure TLS for https:// URLs
        if addr.starts_with("https://") {
            // On Android, rustls-native-certs can't find the system CA store,
            // so we use Mozilla's bundled root certificates instead.
            #[cfg(target_os = "android")]
            let tls = ClientTlsConfig::new().with_webpki_roots();
            #[cfg(not(target_os = "android"))]
            let tls = ClientTlsConfig::new().with_native_roots();
            endpoint = endpoint.tls_config(tls)?;
        }

        let channel = endpoint.connect().await?;
        Ok(Self {
            client: ProtoHubClient::new(channel),
        })
    }

    /// Complete node registration using a registration token.
    ///
    /// Returns the node's credentials for future authenticated requests.
    pub async fn complete_registration(
        &mut self,
        token: &str,
    ) -> Result<NodeRegistration, HubError> {
        let request = tonic::Request::new(proto::NodeRegistrationRequest {
            token: token.to_string(),
        });
        let response = self.client.complete_node_registration(request).await?;
        let reg = response.into_inner();
        Ok(NodeRegistration::new(
            ConnectivityGroupId::new(reg.connectivity_group_id),
            reg.node_number,
            AuthToken::new(reg.auth_token),
            reg.attestation_jwt,
        ))
    }

    /// List all nodes in the connectivity group.
    pub async fn list_nodes(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<Vec<Node>, HubError> {
        let mut request = tonic::Request::new(proto::ListNodesRequest {});
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.list_nodes(request).await?;
        let nodes = response
            .into_inner()
            .nodes
            .into_iter()
            .map(|n| Node {
                node_number: n.node_number,
                name: n.name,
                metadata: n.metadata,
                last_seen_at_millis: n.last_seen_at_millis,
                is_online: n.is_online,
            })
            .collect();
        Ok(nodes)
    }

    /// Send a pairing message to another node (routed through the hub).
    pub async fn pair_nodes(
        &mut self,
        registration: &NodeRegistration,
        message: proto::PairNodesMessage,
    ) -> Result<proto::PairNodesMessage, HubError> {
        let mut request = tonic::Request::new(message);
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.pair_nodes(request).await?;
        Ok(response.into_inner())
    }

    /// Get the current roster for the connectivity group.
    /// Fetch the roster without verification.
    ///
    /// Use this only during pre-activation flows (bootstrap, activation) when
    /// the node is not yet in the roster and cannot verify it.
    /// For activated nodes, use `get_and_verify_roster` instead.
    pub async fn get_unverified_roster(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<proto::roster::Roster, HubError> {
        let mut request = tonic::Request::new(proto::RosterRequest {});
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.get_roster(request).await?;
        Ok(response.into_inner())
    }

    /// Fetch the roster and verify it cryptographically.
    ///
    /// This is the standard method for activated nodes. It fetches the roster
    /// and verifies the signature chain before returning.
    pub async fn get_and_verify_roster(
        &mut self,
        registration: &NodeRegistration,
        verifier_public_key_spki: &[u8],
    ) -> Result<proto::roster::Roster, HubError> {
        let roster = self.get_unverified_roster(registration).await?;
        crate::roster::verify_roster(&roster, registration.node_number, verifier_public_key_spki)?;
        Ok(roster)
    }

    /// Submit a roster update. The hub will obtain the endorser's cosignature
    /// and return the fully signed roster.
    pub async fn update_roster(
        &mut self,
        registration: &NodeRegistration,
        new_roster: proto::roster::Roster,
    ) -> Result<proto::roster::Roster, HubError> {
        let mut request = tonic::Request::new(proto::UpdateRosterRequest {
            new_roster: Some(new_roster),
        });
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.update_roster(request).await?;
        response.into_inner().cosigned_roster.ok_or_else(|| {
            HubError::Rpc(tonic::Status::internal(
                "missing cosigned_roster in response",
            ))
        })
    }

    /// Start serving: open a bidirectional stream for handling incoming requests.
    ///
    /// Returns a handle for sending responses and a stream of incoming requests.
    pub async fn start_serving(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<ServingConnection, HubError> {
        let (response_tx, response_rx) = mpsc::channel::<proto::ServingResponse>(32);
        let response_stream = ReceiverStream::new(response_rx);

        let mut request = tonic::Request::new(response_stream);
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.start_serving(request).await?;
        let request_stream = response.into_inner();

        Ok(ServingConnection {
            response_tx,
            request_stream,
        })
    }

    /// Get STUN/TURN server configuration for P2P connections.
    ///
    /// Returns the server addresses and optional TURN credentials.
    pub async fn get_stun_turn_config(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<proto::StunTurnConfig, HubError> {
        let mut request = tonic::Request::new(proto::StunTurnConfigRequest {});
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.get_stun_turn_config(request).await?;
        Ok(response.into_inner())
    }

    /// Start a P2P connection to another node.
    ///
    /// The hub forwards this request to the target node and returns their response.
    pub async fn start_connection(
        &mut self,
        registration: &NodeRegistration,
        request: proto::StartConnectionRequest,
    ) -> Result<proto::StartConnectionResponse, HubError> {
        let mut grpc_request = tonic::Request::new(request);
        add_auth_metadata(grpc_request.metadata_mut(), registration)?;

        let response = self.client.start_connection(grpc_request).await?;
        Ok(response.into_inner())
    }

    /// Deregister this node from its connectivity group.
    ///
    /// This soft-deletes the node from the hub's database.
    pub async fn deregister_node(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<(), HubError> {
        let mut request = tonic::Request::new(proto::DeregisterNodeRequest {});
        add_auth_metadata(request.metadata_mut(), registration)?;

        self.client.deregister_node(request).await?;
        Ok(())
    }
}

/// A bidirectional serving connection to the hub.
pub struct ServingConnection {
    /// Send responses to requests.
    pub response_tx: mpsc::Sender<proto::ServingResponse>,
    /// Receive incoming requests.
    pub request_stream: tonic::Streaming<proto::ServingRequest>,
}

/// Add authentication metadata to a request.
fn add_auth_metadata(
    metadata: &mut tonic::metadata::MetadataMap,
    registration: &NodeRegistration,
) -> Result<(), HubError> {
    let auth_token = registration
        .auth_token()
        .expect("registration must have auth token");

    metadata.insert(
        "x-connectivity-group-id",
        MetadataValue::try_from(registration.connectivity_group_id.to_string())?,
    );
    metadata.insert(
        "x-node-number",
        MetadataValue::try_from(registration.node_number.to_string())?,
    );
    metadata.insert(
        "x-auth-token",
        MetadataValue::try_from(auth_token.as_str())?,
    );
    Ok(())
}
