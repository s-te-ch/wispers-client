// Error types are intentionally unboxed for ergonomic matching by callers.
#![allow(clippy::result_large_err)]

pub mod crypto;
mod encryption;
pub mod errors;
pub mod ffi;
pub mod hub;
mod ice;
mod juice;
pub mod node;
pub mod p2p;
mod p2p_signing;
mod quic;
pub mod roster;
pub mod serving;
pub mod storage;
pub mod types;

pub use crypto::SigningKeyPair;
pub use errors::{NodeStateError, WispersStatus};
pub use hub::HubError;
pub use node::{Node, NodeState, NodeStorage};
pub use p2p::{ConnectionState, P2pError, QuicConnection, QuicStream, UdpConnection};
pub use roster::RosterVerificationError;
pub use serving::{
    EndorsingStatus, IncomingConnections, P2pConfig, ServingError, ServingHandle, ServingSession,
    StatusInfo,
};
pub use storage::{
    FileNodeStateStore, InMemoryNodeStateStore, NodeStateStore, StorageError,
    deserialize_registration, serialize_registration,
};
pub use types::{
    ConnectivityGroupId, GroupInfo, GroupState, NodeInfo, NodeRegistration, PersistedNodeState,
    ROOT_KEY_LEN,
};
