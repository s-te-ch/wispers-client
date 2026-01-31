use std::fmt;

// Re-export NodeStage from node module for use in error types
pub use crate::node::NodeStage;

#[derive(Debug)]
pub enum NodeStateError<StoreError> {
    Store(StoreError),
    Hub(crate::hub::HubError),
    AlreadyRegistered,
    NotRegistered,
    InvalidPairingCode(crate::crypto::PairingCodeError),
    MacVerificationFailed,
    MissingEndorserResponse,
    RosterVerificationFailed(crate::roster::RosterVerificationError),
    /// Operation requires a different node stage than the current one.
    InvalidState {
        current: NodeStage,
        required: &'static str,
    },
}

impl<StoreError> NodeStateError<StoreError> {
    pub fn store(error: StoreError) -> Self {
        Self::Store(error)
    }

    pub fn hub(error: crate::hub::HubError) -> Self {
        Self::Hub(error)
    }
}

impl<StoreError: fmt::Display> fmt::Display for NodeStateError<StoreError> {
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

impl<StoreError> std::error::Error for NodeStateError<StoreError> where
    StoreError: std::error::Error + 'static
{
}

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
}
