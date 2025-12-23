use std::fmt;

#[derive(Debug)]
pub enum NodeStateError<StoreError> {
    Store(StoreError),
    AlreadyRegistered,
    NotRegistered,
}

impl<StoreError> NodeStateError<StoreError> {
    pub fn store(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl<StoreError: fmt::Display> fmt::Display for NodeStateError<StoreError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStateError::Store(err) => write!(f, "store error: {err}"),
            NodeStateError::AlreadyRegistered => write!(f, "node is already registered"),
            NodeStateError::NotRegistered => write!(f, "node has not completed registration"),
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
}
