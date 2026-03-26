// Error types are intentionally unboxed for ergonomic matching by callers.
#![allow(clippy::result_large_err)]

pub mod crypto;
pub mod encryption;
pub mod errors;
pub mod ffi;
pub mod hub;
pub mod ice;
pub mod juice;
pub mod node;
pub mod p2p;
pub mod quic;
pub mod roster;
pub mod serving;
pub mod storage;
pub mod types;

pub use crypto::SigningKeyPair;
pub use errors::{NodeStateError, WispersStatus};
pub use hub::HubError;
pub use ice::{IceAnswerer, IceCaller, IceError};
pub use node::{Node, NodeState, NodeStorage};
pub use p2p::{
    ConnectionState, P2pError, QuicConnection, QuicStream, StunTurnConfig, UdpConnection,
};
pub use roster::{
    RosterVerificationError, active_nodes, build_activation_payload, compute_roster_hash,
    create_activation_roster, create_bootstrap_roster, create_revocation_roster, verify_roster,
};
pub use serving::{
    EndorsingStatus, IncomingConnections, P2pConfig, ServingError, ServingHandle, ServingSession,
    StatusInfo,
};
pub use storage::{
    FileNodeStateStore, InMemoryNodeStateStore, NodeStateStore, StorageError,
    deserialize_registration, serialize_registration,
};
pub use types::{
    AuthToken, ConnectivityGroupId, GroupInfo, GroupState, NodeInfo, NodeRegistration,
    PersistedNodeState, ROOT_KEY_LEN,
};
