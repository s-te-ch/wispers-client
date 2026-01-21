//! Hub client for Wispers Connect.
//!
//! This module provides the gRPC client for communicating with the Wispers Connect Hub.

use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

pub mod proto {
    pub mod connect {
        pub mod roster {
            tonic::include_proto!("connect.roster");
        }
        pub mod hub {
            tonic::include_proto!("connect.hub");
        }
    }
    pub use connect::hub::*;
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
}

/// A node in a connectivity group.
#[derive(Debug, Clone)]
pub struct Node {
    pub node_number: i32,
    pub name: String,
    pub last_seen_at_millis: i64,
}

/// Client for communicating with the Wispers Connect Hub.
pub struct HubClient {
    client: ProtoHubClient<Channel>,
}

impl HubClient {
    /// Connect to a hub at the given address.
    pub async fn connect(hub_addr: impl Into<String>) -> Result<Self, HubError> {
        let channel = Channel::from_shared(hub_addr.into())?
            .connect()
            .await?;
        Ok(Self {
            client: ProtoHubClient::new(channel),
        })
    }

    /// Complete node registration using a registration token.
    ///
    /// Returns the node's credentials for future authenticated requests.
    pub async fn complete_registration(&mut self, token: &str) -> Result<NodeRegistration, HubError> {
        let request = tonic::Request::new(proto::NodeRegistrationRequest {
            token: token.to_string(),
        });
        let response = self.client.complete_node_registration(request).await?;
        let reg = response.into_inner();
        Ok(NodeRegistration::new(
            ConnectivityGroupId::new(reg.connectivity_group_id),
            reg.node_number,
            AuthToken::new(reg.auth_token),
        ))
    }

    /// List all nodes in the connectivity group.
    pub async fn list_nodes(&mut self, registration: &NodeRegistration) -> Result<Vec<Node>, HubError> {
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
                last_seen_at_millis: n.last_seen_at_millis,
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
    pub async fn get_roster(
        &mut self,
        registration: &NodeRegistration,
    ) -> Result<proto::connect::roster::Roster, HubError> {
        let mut request = tonic::Request::new(proto::RosterRequest {});
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.get_roster(request).await?;
        Ok(response.into_inner())
    }

    /// Submit a roster update. The hub will obtain the endorser's cosignature
    /// and return the fully signed roster.
    pub async fn update_roster(
        &mut self,
        registration: &NodeRegistration,
        new_roster: proto::connect::roster::Roster,
    ) -> Result<proto::connect::roster::Roster, HubError> {
        let mut request = tonic::Request::new(proto::UpdateRosterRequest {
            new_roster: Some(new_roster),
        });
        add_auth_metadata(request.metadata_mut(), registration)?;

        let response = self.client.update_roster(request).await?;
        response
            .into_inner()
            .cosigned_roster
            .ok_or_else(|| HubError::Rpc(tonic::Status::internal("missing cosigned_roster in response")))
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
