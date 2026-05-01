//! Protobuf serialization for `NodeRegistration`.
//!
//! Public API for custom `NodeStateStore` implementations that need to
//! serialize/deserialize `NodeRegistration` (e.g. keyring-backed stores).

use crate::storage::StorageError;
use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration};
use prost::Message;

mod proto {
    tonic::include_proto!("connect.storage");
}

/// Serialize a `NodeRegistration` to protobuf bytes.
#[must_use] 
pub fn serialize_registration(reg: &NodeRegistration) -> Vec<u8> {
    let proto_reg = proto::NodeRegistration {
        connectivity_group_id: reg.connectivity_group_id.to_string(),
        node_number: reg.node_number,
        auth_token: reg
            .auth_token()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default(),
        attestation_jwt: reg.attestation_jwt.clone(),
    };
    proto_reg.encode_to_vec()
}

/// Deserialize a `NodeRegistration` from protobuf bytes.
///
/// # Errors
///
/// Returns `Err` if the bytes are not valid protobuf for a `NodeRegistration`.
pub fn deserialize_registration(bytes: &[u8]) -> Result<NodeRegistration, StorageError> {
    let proto_reg = proto::NodeRegistration::decode(bytes)
        .map_err(|e| StorageError::RegistrationCodec(e.to_string()))?;
    Ok(NodeRegistration::new(
        ConnectivityGroupId::new(proto_reg.connectivity_group_id),
        proto_reg.node_number,
        AuthToken::new(proto_reg.auth_token),
        proto_reg.attestation_jwt,
    ))
}
