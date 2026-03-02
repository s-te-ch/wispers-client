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
    InvalidPairingCode(crate::crypto::PairingCodeError),
    MacVerificationFailed,
    MissingEndorserResponse,
    RosterVerificationFailed(crate::roster::RosterVerificationError),
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
            NodeStateError::InvalidPairingCode(err) => write!(f, "invalid pairing code: {err}"),
            NodeStateError::MacVerificationFailed => write!(f, "MAC verification failed"),
            NodeStateError::MissingEndorserResponse => write!(f, "missing endorser response"),
            NodeStateError::RosterVerificationFailed(err) => {
                write!(f, "roster verification failed: {err}")
            }
            NodeStateError::InvalidState { current, required } => {
                write!(f, "invalid state: node is {current}, but {required} is required")
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
    UnexpectedStage = 6,
    NotFound = 7,
    BufferTooSmall = 8,
    MissingCallback = 9,
    InvalidPairingCode = 10,
    ActivationFailed = 11,
    HubError = 12,
    ConnectionFailed = 13,
    Timeout = 14,
    InvalidState = 15,
    Unauthenticated = 16,
    PeerRejected = 17,
    PeerUnavailable = 18,
}
