//! Wispers Connect adds secure peer-to-peer connectivity to your software.
//!
//! This library implements everything a Wispers node needs: registration with
//! the Hub (the rendezvous server), establishing node-to-node trust
//! (activation), NAT-traversing peer-to-peer connections, and a C FFI for use
//! from wrapper languages.
//!
//! If you're new to Wispers, the repo's `README.md` is a great starting point.
//!
//! # Storage
//!
//! Every Wispers node needs state storage to persist its cryptographic identity
//! and Hub registration. The library ships [`FileNodeStateStore`] and
//! [`InMemoryNodeStateStore`] for CLI tools and tests. For more serious
//! applications, you should implement [`NodeStateStore`] to plug in
//! platform-specific secure storage (e.g. macOS Keychain, Android
//! `EncryptedSharedPreferences`).
//!
//! To initialise Wispers Connect, library clients generally first instantiate
//! the storage, then call `restore_or_init_node()` to (re)create the `Node` in
//! its current state of the lifecycle.
//!
//! # Node lifecycle
//!
//! The central type is [`Node`], which progresses through three states:
//!
//! 1. **Unregistered** — the node is initialised and has generated its own
//!    cryptographic identity, but isn't connected yet. Call [`Node::register`]
//!    with a registration token from the Hub.
//! 2. **Registered** — the node can connect to the Hub rendezvous server, but
//!    hasn't yet established trust with other nodes. Call [`Node::activate`]
//!    with an activation code obtained from another, already-activated node.
//! 3. **Activated** — the node has established trust with the other nodes in
//!    the group on and can open or accept peer-to-peer connections.
//!
//! Use [`NodeStorage`] to persist and restore node state across restarts.
//!
//! # Serving and connecting
//!
//! An activated node makes itself reachable by *serving*:
//!
//! ```rust,no_run
//! # async fn example(node: &mut wispers_connect::Node) -> Result<(), Box<dyn std::error::Error>> {
//! let (handle, session, mut incoming) = node.start_serving().await?;
//! tokio::spawn(session.run());
//!
//! // Accept an incoming QUIC connection from a peer.
//! let conn = incoming.quic.recv().await.unwrap()?;
//! // Open a bidirectional stream and exchange data.
//! let stream = conn.accept_stream().await?;
//! let mut buf = [0u8; 1024];
//! let n = stream.read(&mut buf).await?;
//! stream.write_all(b"hello back").await?;
//! # Ok(())
//! # }
//! ```
//!
//! To connect to a serving peer:
//!
//! ```rust,no_run
//! # async fn example(node: &mut wispers_connect::Node) -> Result<(), Box<dyn std::error::Error>> {
//! let peer_node_number = 2;
//! let quic = node.connect_quic(peer_node_number).await?;
//! let stream = quic.open_stream().await?;
//! stream.write_all(b"hello").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Shutdown
//!
//! - [`ServingHandle::shutdown`] — stop serving and disconnect from the Hub.
//! - [`QuicConnection::close`] — close a QUIC connection.
//! - [`QuicStream::finish`] — signal end-of-write on a stream.
//! - [`Node::logout`] — revoke the node from the roster, deregister from the
//!   Hub, and wipe local state. This is permanent.
//!
//! # C FFI
//!
//! The [`ffi`] module exposes an opaque-handle + callback API for use from
//! C, Go, Kotlin/JNA, Swift, and Python. See `include/wispers_connect.h`.
//!
//! # Further reading
//!
//! - `docs/HOW_IT_WORKS.md` — architecture, trust model, security properties
//! - `docs/HOW_TO_USE.md` — integration guide (library and wconnect sidecar)
//! - `docs/INTERNALS.md` — module map, key types, FFI patterns

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
