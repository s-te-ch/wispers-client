//! Error types and `WispersStatus` codes for the C FFI API.

use crate::storage::StorageError;
use std::fmt;

// Re-export NodeState from node module for use in error types
pub use crate::node::NodeState;

#[derive(Debug)]
pub enum NodeStateError {
    Store(StorageError),
    Hub(crate::hub::HubError),
    AlreadyRegistered,
    NotRegistered,
    InvalidActivationCode(crate::crypto::PairingCodeError),
    MacVerificationFailed,
    MissingEndorserResponse,
    RosterVerificationFailed(crate::roster::RosterVerificationError),
    /// Cannot logout: this is the last active node in the roster.
    LastActiveNode,
    /// Operation requires a different node state than the current one.
    InvalidState {
        current: NodeState,
        required: &'static str,
    },
}

impl NodeStateError {
    pub fn store(error: StorageError) -> Self {
        Self::Store(error)
    }

    pub fn hub(error: crate::hub::HubError) -> Self {
        Self::Hub(error)
    }

    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, NodeStateError::Hub(e) if e.is_unauthenticated())
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, NodeStateError::Hub(e) if e.is_not_found())
    }

    pub fn is_peer_rejected(&self) -> bool {
        matches!(self, NodeStateError::Hub(e) if e.is_peer_rejected())
    }

    pub fn is_peer_unavailable(&self) -> bool {
        matches!(self, NodeStateError::Hub(e) if e.is_peer_unavailable())
    }
}

impl fmt::Display for NodeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStateError::Store(err) => write!(f, "store error: {err}"),
            NodeStateError::Hub(err) => write!(f, "hub error: {err}"),
            NodeStateError::AlreadyRegistered => write!(f, "node is already registered"),
            NodeStateError::NotRegistered => write!(f, "node has not completed registration"),
            NodeStateError::InvalidActivationCode(err) => {
                write!(f, "invalid activation code: {err}")
            }
            NodeStateError::MacVerificationFailed => write!(f, "MAC verification failed"),
            NodeStateError::MissingEndorserResponse => write!(f, "missing endorser response"),
            NodeStateError::RosterVerificationFailed(err) => {
                write!(f, "roster verification failed: {err}")
            }
            NodeStateError::LastActiveNode => {
                write!(
                    f,
                    "cannot logout: this is the last active node in the roster — use group reset instead"
                )
            }
            NodeStateError::InvalidState { current, required } => {
                write!(
                    f,
                    "invalid state: node is {current}, but {required} is required"
                )
            }
        }
    }
}

impl std::error::Error for NodeStateError {}

/// Status codes shared across the FFI boundary.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WispersStatus {
    Success = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    StoreError = 3,
    AlreadyRegistered = 4,
    NotRegistered = 5,
    NotFound = 6,
    BufferTooSmall = 7,
    MissingCallback = 8,
    InvalidActivationCode = 9,
    ActivationFailed = 10,
    HubError = 11,
    ConnectionFailed = 12,
    Timeout = 13,
    InvalidState = 14,
    Unauthenticated = 15,
    PeerRejected = 16,
    PeerUnavailable = 17,
}
