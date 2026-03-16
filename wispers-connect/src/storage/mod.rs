//! Node state persistence: `NodeStateStore` trait with file-based and in-memory implementations.

use crate::errors::WispersStatus;
use crate::types::PersistedNodeState;
use std::fmt;
use std::sync::Arc;

pub mod codec;
pub mod file;
pub mod foreign;
pub mod in_memory;

pub use codec::{deserialize_registration, serialize_registration};
pub use file::FileNodeStateStore;
pub use foreign::{ForeignNodeStateStore, WispersNodeStorageCallbacks};
pub use in_memory::InMemoryNodeStateStore;

/// Unified error type for all storage implementations.
#[derive(Debug)]
pub enum StorageError {
    /// Lock poisoned (in-memory store)
    Poisoned,
    /// File I/O error
    Io(std::io::Error),
    /// Invalid root key format (wrong length)
    InvalidRootKey,
    /// Registration protobuf encode/decode error
    RegistrationCodec(String),
    /// FFI callback missing
    MissingCallback(&'static str),
    /// FFI callback returned error status
    ForeignStatus(WispersStatus),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Poisoned => write!(f, "in-memory state lock was poisoned"),
            StorageError::Io(e) => write!(f, "I/O error: {e}"),
            StorageError::InvalidRootKey => write!(f, "invalid root key length"),
            StorageError::RegistrationCodec(msg) => write!(f, "registration codec error: {msg}"),
            StorageError::MissingCallback(name) => write!(f, "missing callback: {name}"),
            StorageError::ForeignStatus(status) => {
                write!(f, "store callback returned {status:?}")
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

/// Storage backend for node state.
///
/// Implementations are responsible for their own namespacing/isolation.
/// The library treats each store instance as storing exactly one node's state.
pub trait NodeStateStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedNodeState>, StorageError>;

    fn save(&self, state: &PersistedNodeState) -> Result<(), StorageError>;

    fn delete(&self) -> Result<(), StorageError>;
}

pub(crate) type SharedStore = Arc<dyn NodeStateStore>;
