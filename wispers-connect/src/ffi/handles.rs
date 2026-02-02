use crate::errors::{NodeStateError, WispersStatus};
use crate::node::Node;
use crate::state::NodeStorage;
use crate::storage::StorageError;

pub struct WispersNodeStorageHandle(pub(crate) NodeStorage);
pub struct WispersNodeHandle(pub(crate) Node);

impl From<NodeStateError> for WispersStatus {
    fn from(value: NodeStateError) -> Self {
        match value {
            NodeStateError::Store(ref e) => match e {
                StorageError::ForeignStatus(status) => *status,
                StorageError::MissingCallback(_) => WispersStatus::MissingCallback,
                _ => WispersStatus::StoreError,
            },
            NodeStateError::Hub(_) => WispersStatus::HubError,
            NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
            NodeStateError::NotRegistered => WispersStatus::NotRegistered,
            NodeStateError::InvalidPairingCode(_) => WispersStatus::InvalidPairingCode,
            NodeStateError::MacVerificationFailed => WispersStatus::ActivationFailed,
            NodeStateError::MissingEndorserResponse => WispersStatus::ActivationFailed,
            NodeStateError::RosterVerificationFailed(_) => WispersStatus::ActivationFailed,
            NodeStateError::InvalidState { .. } => WispersStatus::InvalidState,
        }
    }
}
