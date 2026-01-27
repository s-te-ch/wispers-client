//! QUIC transport layer for stream-based P2P connections.
//!
//! This module provides QUIC connections on top of ICE-established UDP paths,
//! using quiche (Cloudflare's QUIC implementation). Authentication uses TLS 1.3
//! with a Pre-Shared Key (PSK) derived from the X25519 Diffie-Hellman exchange.
//!
//! A background driver task handles packet I/O and timeouts, allowing the
//! application to perform long-running operations without stalling the connection.

use boring::ssl::{SslContextBuilder, SslMethod};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

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

/// Maximum UDP packet size for QUIC.
const MAX_DATAGRAM_SIZE: usize = 1350;

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

/// Shared state between QuicConnection and the background driver.
struct QuicConnectionInner<T> {
    /// The quiche connection.
    conn: Mutex<Pin<Box<quiche::Connection>>>,
    /// ICE transport for sending/receiving packets.
    transport: T,
    /// Our role (client or server).
    role: QuicRole,
    /// Notified when connection state changes (data available, established, etc.).
    state_notify: Notify,
    /// Set to true to signal the driver to stop.
    shutdown: AtomicBool,
}

impl<T: IceTransport> QuicConnectionInner<T> {
    /// Send all pending QUIC packets over the ICE transport.
    async fn flush_send(&self) -> Result<(), QuicError> {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        loop {
            let send_result = {
                let mut conn = self.conn.lock().await;
                conn.send(&mut buf)
            };

            match send_result {
                Ok((len, _send_info)) => {
                    self.transport.send(&buf[..len])?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(QuicError::Quic(e)),
            }
        }
        Ok(())
    }

    /// Process one incoming packet.
    async fn process_packet(&self, mut packet: Vec<u8>) -> Result<(), QuicError> {
        let mut conn = self.conn.lock().await;
        let recv_info = quiche::RecvInfo {
            from: "127.0.0.1:0".parse().unwrap(),
            to: "127.0.0.1:0".parse().unwrap(),
        };
        match conn.recv(&mut packet, recv_info) {
            Ok(_) => Ok(()),
            Err(quiche::Error::Done) => Ok(()),
            Err(e) => Err(QuicError::Quic(e)),
        }
    }

    /// Handle timeout.
    async fn handle_timeout(&self) {
        let mut conn = self.conn.lock().await;
        conn.on_timeout();
    }

    /// Get the current timeout duration.
    async fn timeout(&self) -> Option<std::time::Duration> {
        let conn = self.conn.lock().await;
        conn.timeout()
    }

    /// Check if connection is closed.
    async fn is_closed(&self) -> bool {
        let conn = self.conn.lock().await;
        conn.is_closed()
    }
}

/// A QUIC connection over an ICE transport.
///
/// This wraps a quiche connection and runs a background driver task that
/// handles packet I/O and timeouts. The driver keeps the connection alive
/// even when the application is not actively reading or writing.
pub struct QuicConnection<T: IceTransport + 'static> {
    inner: Arc<QuicConnectionInner<T>>,
    driver_handle: tokio::task::JoinHandle<()>,
}

impl<T: IceTransport + 'static> QuicConnection<T> {
    /// Create a new QUIC connection and start the background driver.
    ///
    /// The ICE connection must already be established before calling this.
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
            QuicRole::Client => quiche::connect(None, &scid, local, peer, &mut config)?,
            QuicRole::Server => quiche::accept(&scid, None, local, peer, &mut config)?,
        };

        let inner = Arc::new(QuicConnectionInner {
            conn: Mutex::new(Box::pin(conn)),
            transport,
            role,
            state_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
        });

        // Spawn the background driver
        let driver_inner = Arc::clone(&inner);
        let driver_handle = tokio::spawn(async move {
            driver_loop(driver_inner).await;
        });

        Ok(Self {
            inner,
            driver_handle,
        })
    }

    /// Perform the QUIC handshake.
    ///
    /// Waits until the handshake completes or fails. The background driver
    /// handles the actual packet exchange.
    pub async fn handshake(&self) -> Result<(), QuicError> {
        loop {
            // Check current state
            {
                let conn = self.inner.conn.lock().await;
                if conn.is_established() {
                    return Ok(());
                }
                if conn.is_closed() {
                    return Err(QuicError::HandshakeFailed);
                }
            }

            // Wait for state change
            self.inner.state_notify.notified().await;
        }
    }

    /// Get the current connection state.
    pub async fn state(&self) -> QuicState {
        let conn = self.inner.conn.lock().await;
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
            let mut conn = self.inner.conn.lock().await;
            let _ = conn.close(true, 0, b"close");
        }
        self.inner.flush_send().await?;
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.state_notify.notify_waiters();
        Ok(())
    }

    /// Open a new bidirectional stream.
    ///
    /// Returns a stream that can be used for reading and writing.
    /// Both client and server can open streams (they use different ID ranges).
    pub async fn open_stream(&self) -> Result<QuicStream<T>, QuicError> {
        // Stream ID assignment:
        // - Client-initiated bidi: 0, 4, 8, ... (id % 4 == 0)
        // - Server-initiated bidi: 1, 5, 9, ... (id % 4 == 1)
        let base = match self.inner.role {
            QuicRole::Client => 0u64,
            QuicRole::Server => 1u64,
        };

        let stream_id = {
            let conn = self.inner.conn.lock().await;
            // Find next available stream ID for our role
            let mut candidate = base;
            while conn.stream_finished(candidate) {
                candidate += 4;
                if candidate > 1000 {
                    return Err(QuicError::Stream("no available stream IDs".into()));
                }
            }
            candidate
        };

        // Send a zero-byte write to "open" the stream
        {
            let mut conn = self.inner.conn.lock().await;
            match conn.stream_send(stream_id, &[], false) {
                Ok(_) => {}
                Err(quiche::Error::Done) => {}
                Err(e) => return Err(QuicError::Quic(e)),
            }
        }

        // Flush to notify the peer
        self.inner.flush_send().await?;

        Ok(QuicStream {
            inner: Arc::clone(&self.inner),
            stream_id,
        })
    }

    /// Accept an incoming stream from the peer.
    ///
    /// Waits for the peer to open a new stream and returns it.
    /// Either side can accept streams opened by the other.
    pub async fn accept_stream(&self) -> Result<QuicStream<T>, QuicError> {
        loop {
            // Check for readable streams (peer has opened and sent data)
            {
                let mut conn = self.inner.conn.lock().await;
                if let Some(stream_id) = conn.stream_readable_next() {
                    return Ok(QuicStream {
                        inner: Arc::clone(&self.inner),
                        stream_id,
                    });
                }

                if conn.is_closed() {
                    return Err(QuicError::ConnectionClosed);
                }
            }

            // Wait for state change (driver will notify when packet arrives)
            self.inner.state_notify.notified().await;
        }
    }
}

impl<T: IceTransport + 'static> Drop for QuicConnection<T> {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.driver_handle.abort();
    }
}

/// Background driver loop that keeps the QUIC connection alive.
async fn driver_loop<T: IceTransport>(inner: Arc<QuicConnectionInner<T>>) {
    loop {
        // Check if we should stop
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Flush any pending outgoing packets
        if let Err(_) = inner.flush_send().await {
            break;
        }

        // Check if connection is closed
        if inner.is_closed().await {
            inner.state_notify.notify_waiters();
            break;
        }

        // Get timeout for next event
        let timeout = inner.timeout().await;

        // Wait for incoming packet or timeout
        let recv_result = if let Some(timeout_duration) = timeout {
            match tokio::time::timeout(timeout_duration, inner.transport.recv()).await {
                Ok(result) => Some(result),
                Err(_) => None, // Timeout
            }
        } else {
            // No timeout, use a reasonable default to avoid blocking forever
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                inner.transport.recv(),
            )
            .await
            {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        };

        match recv_result {
            Some(Ok(packet)) => {
                // Process the packet
                if let Err(_) = inner.process_packet(packet).await {
                    break;
                }
                // Notify waiters that state may have changed
                inner.state_notify.notify_waiters();
            }
            Some(Err(_)) => {
                // ICE error, stop the driver
                break;
            }
            None => {
                // Timeout - call on_timeout
                inner.handle_timeout().await;
                // Notify in case handshake progressed
                inner.state_notify.notify_waiters();
            }
        }
    }
}

/// A QUIC stream for reading and writing data.
///
/// Streams provide ordered, reliable byte delivery within a QUIC connection.
/// The background driver handles packet I/O, so stream operations can block
/// without stalling the connection.
pub struct QuicStream<T: IceTransport + 'static> {
    inner: Arc<QuicConnectionInner<T>>,
    stream_id: u64,
}

impl<T: IceTransport + 'static> QuicStream<T> {
    /// Get the stream ID.
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written. May write fewer bytes than
    /// requested if the stream's flow control window is limited.
    pub async fn write(&self, data: &[u8]) -> Result<usize, QuicError> {
        let written = {
            let mut conn = self.inner.conn.lock().await;
            match conn.stream_send(self.stream_id, data, false) {
                Ok(n) => n,
                Err(quiche::Error::Done) => 0,
                Err(e) => return Err(QuicError::Quic(e)),
            }
        };

        // Flush to send the data (driver will also flush, but do it now for lower latency)
        self.inner.flush_send().await?;

        Ok(written)
    }

    /// Write all data to the stream.
    ///
    /// Keeps writing until all data is sent or an error occurs.
    pub async fn write_all(&self, data: &[u8]) -> Result<(), QuicError> {
        let mut offset = 0;
        while offset < data.len() {
            let written = {
                let mut conn = self.inner.conn.lock().await;
                match conn.stream_send(self.stream_id, &data[offset..], false) {
                    Ok(n) => n,
                    Err(quiche::Error::Done) => 0,
                    Err(e) => return Err(QuicError::Quic(e)),
                }
            };

            if written > 0 {
                offset += written;
                self.inner.flush_send().await?;
            } else {
                // Flow control blocked, wait for state change
                self.inner.state_notify.notified().await;
            }
        }
        Ok(())
    }

    /// Read data from the stream.
    ///
    /// Returns the number of bytes read. Returns 0 if the stream is finished.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, QuicError> {
        loop {
            // Try to read from the stream
            {
                let mut conn = self.inner.conn.lock().await;
                match conn.stream_recv(self.stream_id, buf) {
                    Ok((len, _fin)) => return Ok(len),
                    Err(quiche::Error::Done) => {
                        // No data available yet
                        if conn.stream_finished(self.stream_id) {
                            return Ok(0); // Stream finished
                        }
                    }
                    Err(e) => return Err(QuicError::Quic(e)),
                }

                if conn.is_closed() {
                    return Err(QuicError::ConnectionClosed);
                }
            }

            // Wait for state change (driver will notify when data arrives)
            self.inner.state_notify.notified().await;
        }
    }

    /// Close the stream for writing (send FIN).
    pub async fn finish(&self) -> Result<(), QuicError> {
        {
            let mut conn = self.inner.conn.lock().await;
            match conn.stream_send(self.stream_id, &[], true) {
                Ok(_) => {}
                Err(quiche::Error::Done) => {}
                Err(e) => return Err(QuicError::Quic(e)),
            }
        }
        self.inner.flush_send().await?;
        Ok(())
    }

    /// Shutdown the stream (stop sending and receiving).
    pub async fn shutdown(&self) -> Result<(), QuicError> {
        {
            let mut conn = self.inner.conn.lock().await;
            // Shutdown both directions
            let _ = conn.stream_shutdown(self.stream_id, quiche::Shutdown::Read, 0);
            let _ = conn.stream_shutdown(self.stream_id, quiche::Shutdown::Write, 0);
        }
        self.inner.flush_send().await?;
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

/// Convert a Wispers connection ID to a QUIC connection ID.
///
/// Uses the i64 connection ID bytes directly as the QUIC source connection ID.
fn conn_id_from_i64(id: i64) -> quiche::ConnectionId<'static> {
    quiche::ConnectionId::from_vec(id.to_be_bytes().to_vec())
}

// Convenience constructors for specific ICE transport types

impl QuicConnection<IceCaller> {
    /// Create a QUIC connection as the caller (client role).
    ///
    /// The `connection_id` should be from the `StartConnectionResponse`.
    /// This starts a background driver task that handles packet I/O.
    pub fn new_caller(
        transport: IceCaller,
        psk: [u8; PSK_LEN],
        connection_id: i64,
    ) -> Result<Self, QuicError> {
        let scid = conn_id_from_i64(connection_id);
        Self::new_inner(transport, psk, QuicRole::Client, scid)
    }
}

impl QuicConnection<IceAnswerer> {
    /// Create a QUIC connection as the answerer (server role).
    ///
    /// The `connection_id` is the one generated for `StartConnectionResponse`.
    /// This starts a background driver task that handles packet I/O.
    pub fn new_answerer(
        transport: IceAnswerer,
        psk: [u8; PSK_LEN],
        connection_id: i64,
    ) -> Result<Self, QuicError> {
        let scid = conn_id_from_i64(connection_id);
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
