//! Peer-to-peer connection types.
//!
//! This module provides the types for establishing and managing P2P connections
//! between activated nodes. Two transport types are supported:
//!
//! - **UDP** ([`UdpConnection`]): Raw UDP with AES-GCM encryption. Low overhead, unreliable delivery.
//! - **QUIC** ([`QuicConnection`]): QUIC streams with TLS-PSK. Reliable, ordered delivery with flow control.
//!
//! Both connection types have a unified API - callers and answerers use the same type.
//! Incoming connections are fully established before being delivered to the user.

use thiserror::Error;

use crate::encryption::{EncryptionError, P2pCipher};
use crate::ice::{IceAnswerer, IceCaller, IceError};
use crate::juice::State as IceState;
use crate::quic::{self, QuicError};

/// Connection state for a P2P connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// ICE is gathering candidates.
    Gathering,
    /// ICE is connecting to the peer.
    Connecting,
    /// Connection is established and ready for data.
    Connected,
    /// Connection has been disconnected.
    Disconnected,
    /// Connection failed (ICE failure or other error).
    Failed,
}

impl ConnectionState {
    fn from_ice_state(ice_state: IceState) -> Self {
        match ice_state {
            IceState::Disconnected => ConnectionState::Disconnected,
            IceState::Gathering => ConnectionState::Gathering,
            IceState::Connecting => ConnectionState::Connecting,
            IceState::Connected | IceState::Completed => ConnectionState::Connected,
            IceState::Failed | IceState::Unknown(_) => ConnectionState::Failed,
        }
    }

    /// Returns true if the connection is established and ready for data.
    pub fn is_connected(self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Returns true if the connection is disconnected or failed.
    pub fn is_disconnected(self) -> bool {
        matches!(
            self,
            ConnectionState::Disconnected | ConnectionState::Failed
        )
    }
}

/// Error type for P2P connection operations.
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("hub error: {0}")]
    Hub(#[from] crate::hub::HubError),

    #[error("ICE error: {0}")]
    Ice(#[from] IceError),

    #[error("encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("QUIC error: {0}")]
    Quic(#[from] QuicError),

    #[error("peer rejected connection: {0}")]
    PeerRejected(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("disconnected")]
    Disconnected,

    #[error("node not activated")]
    NotActivated,
}

//-- UDP connections -------------------------------------------------------------------------------

/// Internal enum to hold either caller or answerer UDP connection.
enum UdpConnectionInner {
    Caller { ice: IceCaller, cipher: P2pCipher },
    Answerer { ice: IceAnswerer, cipher: P2pCipher },
}

/// A UDP-based P2P connection to another node.
///
/// This provides encrypted UDP communication with a peer node after
/// successful ICE negotiation. Works for both caller and answerer roles.
pub struct UdpConnection {
    /// The peer's node number.
    pub peer_node_number: i32,

    /// Connection ID for this connection.
    pub connection_id: i64,

    /// The underlying connection (caller or answerer).
    inner: UdpConnectionInner,
}

impl UdpConnection {
    /// Create a new UDP connection as the caller (internal use).
    pub(crate) fn new_caller(
        peer_node_number: i32,
        connection_id: i64,
        ice: IceCaller,
        shared_secret: [u8; 32],
    ) -> Result<Self, P2pError> {
        let cipher = P2pCipher::new_caller(&shared_secret, connection_id)?;
        Ok(Self {
            peer_node_number,
            connection_id,
            inner: UdpConnectionInner::Caller { ice, cipher },
        })
    }

    /// Create and connect a new UDP connection as the answerer (internal use).
    ///
    /// This waits for ICE to connect before returning.
    pub(crate) async fn connect_answerer(
        peer_node_number: i32,
        connection_id: i64,
        ice: IceAnswerer,
        shared_secret: [u8; 32],
    ) -> Result<Self, P2pError> {
        // Wait for ICE connection
        ice.connect().await?;

        let cipher = P2pCipher::new_answerer(&shared_secret, connection_id)?;
        Ok(Self {
            peer_node_number,
            connection_id,
            inner: UdpConnectionInner::Answerer { ice, cipher },
        })
    }

    /// Send data to the peer.
    ///
    /// The data is encrypted before transmission.
    pub fn send(&self, data: &[u8]) -> Result<(), P2pError> {
        if self.state().is_disconnected() {
            return Err(P2pError::Disconnected);
        }
        match &self.inner {
            UdpConnectionInner::Caller { ice, cipher } => {
                let encrypted = cipher.encrypt(data)?;
                ice.send(&encrypted)?;
            }
            UdpConnectionInner::Answerer { ice, cipher } => {
                let encrypted = cipher.encrypt(data)?;
                ice.send(&encrypted)?;
            }
        }
        Ok(())
    }

    /// Receive data from the peer.
    ///
    /// Returns decrypted data from the peer.
    pub async fn recv(&self) -> Result<Vec<u8>, P2pError> {
        if self.state().is_disconnected() {
            return Err(P2pError::Disconnected);
        }
        match &self.inner {
            UdpConnectionInner::Caller { ice, cipher } => {
                let encrypted = ice.recv().await?;
                let decrypted = cipher.decrypt(&encrypted)?;
                Ok(decrypted)
            }
            UdpConnectionInner::Answerer { ice, cipher } => {
                let encrypted = ice.recv().await?;
                let decrypted = cipher.decrypt(&encrypted)?;
                Ok(decrypted)
            }
        }
    }

    /// Close the connection.
    pub fn close(self) {
        match self.inner {
            UdpConnectionInner::Caller { ice, .. } => ice.close(),
            UdpConnectionInner::Answerer { ice, .. } => ice.close(),
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        match &self.inner {
            UdpConnectionInner::Caller { ice, .. } => ConnectionState::from_ice_state(ice.state()),
            UdpConnectionInner::Answerer { ice, .. } => {
                ConnectionState::from_ice_state(ice.state())
            }
        }
    }

    /// Returns true if the connection is established and ready for data.
    pub fn is_connected(&self) -> bool {
        self.state().is_connected()
    }
}

//-- QUIC connections ------------------------------------------------------------------------------

/// Internal enum to hold either caller or answerer QUIC connection.
enum QuicConnectionInner {
    Caller(quic::Connection<IceCaller>),
    Answerer(quic::Connection<IceAnswerer>),
}

/// Internal enum to hold either caller or answerer QUIC stream.
enum QuicStreamInner {
    Caller(quic::Stream<IceCaller>),
    Answerer(quic::Stream<IceAnswerer>),
}

/// A QUIC stream for reading and writing data.
///
/// Streams provide ordered, reliable byte delivery within a QUIC connection.
pub struct QuicStream {
    inner: QuicStreamInner,
}

impl QuicStream {
    /// Get the stream ID.
    pub fn id(&self) -> u64 {
        match &self.inner {
            QuicStreamInner::Caller(s) => s.id(),
            QuicStreamInner::Answerer(s) => s.id(),
        }
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written.
    pub async fn write(&self, data: &[u8]) -> Result<usize, P2pError> {
        match &self.inner {
            QuicStreamInner::Caller(s) => Ok(s.write(data).await?),
            QuicStreamInner::Answerer(s) => Ok(s.write(data).await?),
        }
    }

    /// Write all data to the stream.
    pub async fn write_all(&self, data: &[u8]) -> Result<(), P2pError> {
        match &self.inner {
            QuicStreamInner::Caller(s) => Ok(s.write_all(data).await?),
            QuicStreamInner::Answerer(s) => Ok(s.write_all(data).await?),
        }
    }

    /// Read data from the stream.
    ///
    /// Returns the number of bytes read. Returns 0 if the stream is finished.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, P2pError> {
        match &self.inner {
            QuicStreamInner::Caller(s) => Ok(s.read(buf).await?),
            QuicStreamInner::Answerer(s) => Ok(s.read(buf).await?),
        }
    }

    /// Close the stream for writing (send FIN).
    pub async fn finish(&self) -> Result<(), P2pError> {
        match &self.inner {
            QuicStreamInner::Caller(s) => Ok(s.finish().await?),
            QuicStreamInner::Answerer(s) => Ok(s.finish().await?),
        }
    }

    /// Shutdown the stream (stop sending and receiving).
    pub async fn shutdown(&self) -> Result<(), P2pError> {
        match &self.inner {
            QuicStreamInner::Caller(s) => Ok(s.shutdown().await?),
            QuicStreamInner::Answerer(s) => Ok(s.shutdown().await?),
        }
    }
}

/// A QUIC-based P2P connection to another node.
///
/// This provides QUIC streams for reliable, ordered communication with a peer
/// node. Unlike `UdpConnection`, streams provide flow control and
/// automatic retransmission.
///
/// Works for both caller (initiator) and answerer (responder) roles.
pub struct QuicConnection {
    /// The peer's node number.
    pub peer_node_number: i32,

    /// Connection ID for this connection.
    pub connection_id: i64,

    /// The underlying QUIC connection.
    inner: QuicConnectionInner,
}

impl QuicConnection {
    /// Create and establish a new QUIC connection as the caller (internal use).
    ///
    /// This creates the QUIC connection and performs the handshake.
    /// Returns a fully-established connection ready for stream operations.
    pub(crate) async fn connect_caller(
        peer_node_number: i32,
        connection_id: i64,
        ice: IceCaller,
        shared_secret: [u8; 32],
    ) -> Result<Self, P2pError> {
        let psk = quic::derive_psk(&shared_secret);
        let quic = quic::Connection::new_caller(ice, psk, connection_id).await?;
        quic.handshake().await?;
        Ok(Self {
            peer_node_number,
            connection_id,
            inner: QuicConnectionInner::Caller(quic),
        })
    }

    /// Create and establish a new QUIC connection as the answerer (internal use).
    ///
    /// This waits for ICE to connect, then performs the QUIC handshake.
    /// Returns a fully-established connection ready for stream operations.
    pub(crate) async fn connect_answerer(
        peer_node_number: i32,
        connection_id: i64,
        ice: IceAnswerer,
        shared_secret: [u8; 32],
    ) -> Result<Self, P2pError> {
        // Wait for ICE connection
        ice.connect().await?;

        // Create QUIC connection and handshake
        let psk = quic::derive_psk(&shared_secret);
        let quic = quic::Connection::new_answerer(ice, psk, connection_id).await?;
        quic.handshake().await?;

        Ok(Self {
            peer_node_number,
            connection_id,
            inner: QuicConnectionInner::Answerer(quic),
        })
    }

    /// Open a new bidirectional stream.
    ///
    /// Returns a stream that can be used for reading and writing data.
    pub async fn open_stream(&self) -> Result<QuicStream, P2pError> {
        match &self.inner {
            QuicConnectionInner::Caller(quic) => {
                let stream = quic.open_stream().await?;
                Ok(QuicStream {
                    inner: QuicStreamInner::Caller(stream),
                })
            }
            QuicConnectionInner::Answerer(quic) => {
                let stream = quic.open_stream().await?;
                Ok(QuicStream {
                    inner: QuicStreamInner::Answerer(stream),
                })
            }
        }
    }

    /// Accept an incoming stream from the peer.
    ///
    /// Waits for the peer to open a new stream and returns it.
    pub async fn accept_stream(&self) -> Result<QuicStream, P2pError> {
        match &self.inner {
            QuicConnectionInner::Caller(quic) => {
                let stream = quic.accept_stream().await?;
                Ok(QuicStream {
                    inner: QuicStreamInner::Caller(stream),
                })
            }
            QuicConnectionInner::Answerer(quic) => {
                let stream = quic.accept_stream().await?;
                Ok(QuicStream {
                    inner: QuicStreamInner::Answerer(stream),
                })
            }
        }
    }

    /// Check if the QUIC connection is established.
    pub async fn is_established(&self) -> bool {
        match &self.inner {
            QuicConnectionInner::Caller(quic) => quic.is_established().await,
            QuicConnectionInner::Answerer(quic) => quic.is_established().await,
        }
    }

    /// Close the connection.
    pub async fn close(self) -> Result<(), P2pError> {
        match self.inner {
            QuicConnectionInner::Caller(quic) => quic.close().await?,
            QuicConnectionInner::Answerer(quic) => quic.close().await?,
        }
        Ok(())
    }
}

/// Re-export StunTurnConfig from proto.
pub use crate::hub::proto::StunTurnConfig;
