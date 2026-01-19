//! Hub client for Wispers Connect.
//!
//! This module provides the gRPC client for communicating with the Wispers Connect Hub.

use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
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
    ///
    /// Requires valid credentials from a completed registration.
    pub async fn list_nodes(&mut self, registration: &NodeRegistration) -> Result<Vec<Node>, HubError> {
        let auth_token = registration
            .auth_token()
            .expect("registration must have auth token");

        let mut request = tonic::Request::new(proto::ListNodesRequest {});
        request.metadata_mut().insert(
            "x-connectivity-group-id",
            MetadataValue::try_from(registration.connectivity_group_id.to_string())?,
        );
        request.metadata_mut().insert(
            "x-node-number",
            MetadataValue::try_from(registration.node_number.to_string())?,
        );
        request.metadata_mut().insert(
            "x-auth-token",
            MetadataValue::try_from(auth_token.as_str())?,
        );

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
}
