//! QUIC transport layer for stream-based P2P connections.
//!
//! This module provides QUIC connections on top of ICE-established UDP paths,
//! using quiche (Cloudflare's QUIC implementation). Authentication uses TLS 1.3
//! with a Pre-Shared Key (PSK) derived from the X25519 Diffie-Hellman exchange.

use boring::ssl::{SslContextBuilder, SslMethod};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ice::{IceAnswerer, IceCaller, IceError};

/// PSK identity used in TLS 1.3 handshake.
/// Both peers must use the same identity string.
pub const PSK_IDENTITY: &[u8] = b"wispers-connect-v1";

/// ALPN protocol identifier for QUIC connections.
pub const ALPN: &[u8] = b"wispers-connect";

/// QUIC version to use (v1 per RFC 9000).
const QUIC_VERSION: u32 = quiche::PROTOCOL_VERSION;

/// Maximum idle timeout in milliseconds.
const MAX_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Initial max data (connection-level flow control).
const INITIAL_MAX_DATA: u64 = 10_000_000; // 10 MB

/// Initial max stream data (per-stream flow control).
const INITIAL_MAX_STREAM_DATA: u64 = 1_000_000; // 1 MB

/// Maximum concurrent bidirectional streams.
const INITIAL_MAX_STREAMS_BIDI: u64 = 100;

/// Length of the derived PSK in bytes.
const PSK_LEN: usize = 32;

/// QUIC configuration error.
#[derive(Debug, thiserror::Error)]
pub enum QuicConfigError {
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("QUIC configuration failed: {0}")]
    Quic(#[from] quiche::Error),
}

/// Role in the QUIC handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicRole {
    /// Client initiates the connection (caller).
    Client,
    /// Server accepts the connection (answerer).
    Server,
}

/// Derive a TLS 1.3 Pre-Shared Key from an X25519 shared secret.
///
/// Uses HKDF-SHA256 with a domain-specific salt and info string to derive
/// a 32-byte PSK suitable for TLS 1.3 authentication.
///
/// Both peers perform the same X25519 DH exchange, so they arrive at the
/// same shared secret and thus the same PSK.
pub fn derive_psk(shared_secret: &[u8; 32]) -> [u8; PSK_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(b"wispers-connect-quic-v1"), shared_secret);
    let mut psk = [0u8; PSK_LEN];
    hk.expand(b"tls13-psk", &mut psk)
        .expect("32 bytes is valid for HKDF-SHA256");
    psk
}

/// Create a QUIC configuration with PSK authentication.
///
/// # Arguments
/// * `psk` - The pre-shared key derived from X25519 DH exchange
/// * `role` - Whether this is a client (caller) or server (answerer)
pub fn create_config(psk: [u8; PSK_LEN], role: QuicRole) -> Result<quiche::Config, QuicConfigError> {
    // Create BoringSSL context with PSK callbacks
    let mut ssl_ctx = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| QuicConfigError::Tls(e.to_string()))?;

    // Wrap PSK in Arc for sharing between callbacks
    let psk = Arc::new(psk);

    match role {
        QuicRole::Client => {
            let psk_clone = Arc::clone(&psk);
            ssl_ctx.set_psk_client_callback(move |_ssl, _hint, identity, psk_out| {
                // Write identity (null-terminated)
                if identity.len() < PSK_IDENTITY.len() + 1 {
                    return Err(boring::error::ErrorStack::get());
                }
                identity[..PSK_IDENTITY.len()].copy_from_slice(PSK_IDENTITY);
                identity[PSK_IDENTITY.len()] = 0; // null terminator

                // Write PSK
                if psk_out.len() < PSK_LEN {
                    return Err(boring::error::ErrorStack::get());
                }
                psk_out[..PSK_LEN].copy_from_slice(psk_clone.as_ref());

                Ok(PSK_LEN)
            });
        }
        QuicRole::Server => {
            let psk_clone = Arc::clone(&psk);
            ssl_ctx.set_psk_server_callback(move |_ssl, identity, psk_out| {
                // Verify identity matches expected
                if identity != Some(PSK_IDENTITY) {
                    return Err(boring::error::ErrorStack::get());
                }

                // Write PSK
                if psk_out.len() < PSK_LEN {
                    return Err(boring::error::ErrorStack::get());
                }
                psk_out[..PSK_LEN].copy_from_slice(psk_clone.as_ref());

                Ok(PSK_LEN)
            });
        }
    }

    // Create quiche config from the SSL context
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(QUIC_VERSION, ssl_ctx)?;

    // Set ALPN protocol
    config.set_application_protos(&[ALPN])?;

    // Disable certificate verification (we're using PSK)
    config.verify_peer(false);

    // Configure timeouts and flow control
    config.set_max_idle_timeout(MAX_IDLE_TIMEOUT_MS);
    config.set_initial_max_data(INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(INITIAL_MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(INITIAL_MAX_STREAMS_BIDI);

    // Disable 0-RTT for security simplicity
    // (0-RTT data can be replayed)

    Ok(config)
}

/// QUIC connection error.
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("configuration error: {0}")]
    Config(#[from] QuicConfigError),
    #[error("QUIC error: {0}")]
    Quic(#[from] quiche::Error),
    #[error("ICE error: {0}")]
    Ice(#[from] IceError),
    #[error("handshake failed")]
    HandshakeFailed,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("stream error: {0}")]
    Stream(String),
    #[error("timeout")]
    Timeout,
}

/// Maximum UDP packet size for QUIC.
const MAX_DATAGRAM_SIZE: usize = 1350;

/// QUIC connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicState {
    /// QUIC handshake in progress.
    Handshaking,
    /// Connection established, ready for streams.
    Established,
    /// Connection is closing.
    Closing,
    /// Connection is closed.
    Closed,
}

/// A QUIC connection over an ICE transport.
///
/// This wraps a quiche connection and drives the QUIC state machine
/// by exchanging UDP packets over the ICE layer.
pub struct QuicConnection<T> {
    conn: Mutex<Pin<Box<quiche::Connection>>>,
    transport: T,
}

impl<T: IceTransport> QuicConnection<T> {
    /// Create a new QUIC connection.
    ///
    /// The ICE connection must already be established before calling this.
    /// This creates the QUIC connection but does not perform the handshake.
    fn new_inner(
        transport: T,
        psk: [u8; PSK_LEN],
        role: QuicRole,
        scid: quiche::ConnectionId<'static>,
    ) -> Result<Self, QuicError> {
        let mut config = create_config(psk, role)?;

        // Placeholder addresses - we're using ICE for actual transport,
        // these are just required by quiche's API
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let conn = match role {
            QuicRole::Client => {
                // Client connects to server
                // Server name is not used for PSK but quiche requires it
                quiche::connect(None, &scid, local, peer, &mut config)?
            }
            QuicRole::Server => {
                // Server accepts from client
                quiche::accept(&scid, None, local, peer, &mut config)?
            }
        };

        Ok(Self {
            conn: Mutex::new(Box::pin(conn)),
            transport,
        })
    }

    /// Perform the QUIC handshake.
    ///
    /// This exchanges QUIC packets over the ICE transport until the
    /// handshake completes or fails.
    pub async fn handshake(&self) -> Result<(), QuicError> {
        loop {
            // Send any pending QUIC packets
            self.flush_send().await?;

            // Check if handshake is complete
            {
                let conn = self.conn.lock().await;
                if conn.is_established() {
                    return Ok(());
                }
                if conn.is_closed() {
                    return Err(QuicError::HandshakeFailed);
                }
            }

            // Wait for incoming packet or timeout
            let timeout = {
                let conn = self.conn.lock().await;
                conn.timeout()
            };

            let recv_result = if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, self.transport.recv()).await
            } else {
                // No timeout set, just wait for packet
                Ok(self.transport.recv().await)
            };

            match recv_result {
                Ok(Ok(packet)) => {
                    // Feed packet to QUIC
                    let mut conn = self.conn.lock().await;
                    let recv_info = quiche::RecvInfo {
                        from: "127.0.0.1:0".parse().unwrap(),
                        to: "127.0.0.1:0".parse().unwrap(),
                    };
                    match conn.recv(&mut packet.clone(), recv_info) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {}
                        Err(e) => return Err(QuicError::Quic(e)),
                    }
                }
                Ok(Err(e)) => {
                    // ICE error
                    return Err(QuicError::Ice(e));
                }
                Err(_) => {
                    // Timeout - call on_timeout
                    let mut conn = self.conn.lock().await;
                    conn.on_timeout();
                }
            }
        }
    }

    /// Send all pending QUIC packets over the ICE transport.
    async fn flush_send(&self) -> Result<(), QuicError> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            let mut conn = self.conn.lock().await;
            match conn.send(&mut buf) {
                Ok((len, _send_info)) => {
                    drop(conn); // Release lock before async send
                    self.transport.send(&buf[..len])?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(QuicError::Quic(e)),
            }
        }
        Ok(())
    }

    /// Get the current connection state.
    pub async fn state(&self) -> QuicState {
        let conn = self.conn.lock().await;
        if conn.is_closed() {
            QuicState::Closed
        } else if conn.is_draining() {
            QuicState::Closing
        } else if conn.is_established() {
            QuicState::Established
        } else {
            QuicState::Handshaking
        }
    }

    /// Check if the connection is established.
    pub async fn is_established(&self) -> bool {
        self.state().await == QuicState::Established
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), QuicError> {
        {
            let mut conn = self.conn.lock().await;
            conn.close(true, 0, b"close")?;
        }
        self.flush_send().await?;
        Ok(())
    }
}

/// Trait for ICE transports (abstracts IceCaller and IceAnswerer).
pub trait IceTransport: Send + Sync {
    /// Send a packet over the ICE connection.
    fn send(&self, data: &[u8]) -> Result<(), IceError>;

    /// Receive a packet from the ICE connection.
    fn recv(&self) -> impl std::future::Future<Output = Result<Vec<u8>, IceError>> + Send;
}

impl IceTransport for IceCaller {
    fn send(&self, data: &[u8]) -> Result<(), IceError> {
        IceCaller::send(self, data)
    }

    fn recv(&self) -> impl std::future::Future<Output = Result<Vec<u8>, IceError>> + Send {
        IceCaller::recv(self)
    }
}

impl IceTransport for IceAnswerer {
    fn send(&self, data: &[u8]) -> Result<(), IceError> {
        IceAnswerer::send(self, data)
    }

    fn recv(&self) -> impl std::future::Future<Output = Result<Vec<u8>, IceError>> + Send {
        IceAnswerer::recv(self)
    }
}

/// Generate a random QUIC connection ID.
fn generate_conn_id() -> quiche::ConnectionId<'static> {
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
    quiche::ConnectionId::from_vec(id.to_vec())
}

// Convenience constructors for specific ICE transport types

impl QuicConnection<IceCaller> {
    /// Create a QUIC connection as the caller (client role).
    pub fn new_caller(transport: IceCaller, psk: [u8; PSK_LEN]) -> Result<Self, QuicError> {
        let scid = generate_conn_id();
        Self::new_inner(transport, psk, QuicRole::Client, scid)
    }
}

impl QuicConnection<IceAnswerer> {
    /// Create a QUIC connection as the answerer (server role).
    pub fn new_answerer(transport: IceAnswerer, psk: [u8; PSK_LEN]) -> Result<Self, QuicError> {
        let scid = generate_conn_id();
        Self::new_inner(transport, psk, QuicRole::Server, scid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psk_derivation_deterministic() {
        let shared_secret = [42u8; 32];
        let psk1 = derive_psk(&shared_secret);
        let psk2 = derive_psk(&shared_secret);
        assert_eq!(psk1, psk2);
    }

    #[test]
    fn test_psk_derivation_different_secrets() {
        let psk1 = derive_psk(&[1u8; 32]);
        let psk2 = derive_psk(&[2u8; 32]);
        assert_ne!(psk1, psk2);
    }

    #[test]
    fn test_psk_length() {
        let psk = derive_psk(&[0u8; 32]);
        assert_eq!(psk.len(), 32);
    }

    #[test]
    fn test_psk_not_all_zeros() {
        let psk = derive_psk(&[0u8; 32]);
        assert!(psk.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_create_config_client() {
        let psk = derive_psk(&[42u8; 32]);
        let config = create_config(psk, QuicRole::Client);
        assert!(config.is_ok());
    }

    #[test]
    fn test_create_config_server() {
        let psk = derive_psk(&[42u8; 32]);
        let config = create_config(psk, QuicRole::Server);
        assert!(config.is_ok());
    }
}
