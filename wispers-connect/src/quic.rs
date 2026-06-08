//! QUIC transport layer for stream-based P2P connections.
//!
//! This module provides QUIC connections on top of ICE-established UDP paths,
//! using quiche (Cloudflare's QUIC implementation). Authentication uses TLS 1.3
//! with a Pre-Shared Key (PSK) derived from the X25519 Diffie-Hellman exchange.
//!
//! A background driver task handles packet I/O and timeouts, allowing the
//! application to perform long-running operations without stalling the connection.

use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod};
use boring::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
use boring::x509::{X509Builder, X509NameBuilder};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Keepalive interval in milliseconds (should be less than idle timeout).
const KEEPALIVE_INTERVAL_MS: u64 = 15_000;

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
pub fn create_config(
    psk: [u8; PSK_LEN],
    role: QuicRole,
) -> Result<quiche::Config, QuicConfigError> {
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

            // BoringSSL requires server to have a certificate even for PSK mode.
            // Generate a minimal self-signed certificate in memory.
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            let ec_key =
                EcKey::generate(&group).map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            let pkey =
                PKey::from_ec_key(ec_key).map_err(|e| QuicConfigError::Tls(e.to_string()))?;

            let mut name_builder =
                X509NameBuilder::new().map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            name_builder
                .append_entry_by_text("CN", "wispers-connect")
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            let name = name_builder.build();

            let mut cert_builder =
                X509Builder::new().map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_version(2)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_subject_name(&name)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_issuer_name(&name)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_pubkey(&pkey)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_not_before(boring::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            cert_builder
                .set_not_after(boring::asn1::Asn1Time::days_from_now(365).unwrap().as_ref())
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;

            let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
            cert_builder
                .append_extension(basic_constraints)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;

            let subject_key_id = SubjectKeyIdentifier::new()
                .build(&cert_builder.x509v3_context(None, None))
                .unwrap();
            cert_builder
                .append_extension(subject_key_id)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;

            cert_builder
                .sign(&pkey, MessageDigest::sha256())
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;

            let cert = cert_builder.build();

            ssl_ctx
                .set_private_key(&pkey)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
            ssl_ctx
                .set_certificate(&cert)
                .map_err(|e| QuicConfigError::Tls(e.to_string()))?;
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

/// Shared state between Connection and the background driver.
struct ConnectionInner<T> {
    /// The quiche connection.
    conn: Mutex<Pin<Box<quiche::Connection>>>,
    /// ICE transport for sending/receiving packets.
    transport: T,
    /// Our role (client or server).
    role: QuicRole,
    /// Local address (for recv_info).
    local_addr: SocketAddr,
    /// Peer address (for recv_info).
    peer_addr: SocketAddr,
    /// Notified when connection state changes (data available, established, etc.).
    state_notify: Notify,
    /// Set to true to signal the driver to stop.
    shutdown: AtomicBool,
    /// Stream IDs that have been accepted (to avoid returning same stream twice).
    accepted_streams: Mutex<std::collections::HashSet<u64>>,
    /// Index of the next bidirectional stream to hand out (stream_id = base + 4*n).
    next_stream_index: AtomicU64,
    /// Streams dropped without closing cleanly, queued for cleanup at the next
    /// `open_stream`/`accept_stream` (a std Mutex because `Drop` is sync). Each
    /// entry is `(stream_id, sent_fin, recv_fin)` — the two half-states captured
    /// at drop time, so the drain can shut down exactly the half/halves still open.
    pending_shutdown: std::sync::Mutex<Vec<(u64, bool, bool)>>,
}

impl<T: IceTransport> ConnectionInner<T> {
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
                    // TEMP instrumentation: if the last log line before a stall is
                    // this with no following progress, transport.send (ICE) blocked.
                    log::info!("[wispers QUIC] flush: ICE send {len}B");
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
        // recv_info: from=peer (who sent), to=local (who received)
        let recv_info = quiche::RecvInfo {
            from: self.peer_addr,
            to: self.local_addr,
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

    /// Send a keepalive PING if the connection is established.
    async fn send_keepalive(&self) -> Result<(), QuicError> {
        {
            let mut conn = self.conn.lock().await;
            if conn.is_established() {
                conn.send_ack_eliciting().map_err(QuicError::Quic)?;
            }
        }
        self.flush_send().await
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

    /// Clean up streams whose `Stream` was dropped without closing cleanly,
    /// reclaiming their MAX_STREAMS credit. Called with the connection locked.
    fn drain_pending_shutdown(&self, conn: &mut quiche::Connection) {
        let streams: Vec<(u64, bool, bool)> = {
            let mut q = self.pending_shutdown.lock().unwrap();
            std::mem::take(&mut *q)
        };
        for (id, sent_fin, recv_fin) in streams {
            // Receive half: if we never read the peer's FIN, STOP_SENDING finishes
            // it so quiche can collect the stream. Harmless if the peer already
            // finished sending.
            if !recv_fin {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
            }
            // Send half: RESET only if we didn't cleanly FIN it. Resetting a
            // finished send half would turn still-in-flight data into a
            // RESET_STREAM and truncate the response the peer is reading.
            if !sent_fin {
                let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, 0);
            }
        }
    }
}

/// A QUIC connection over an ICE transport.
///
/// This wraps a quiche connection and runs a background driver task that
/// handles packet I/O and timeouts. The driver keeps the connection alive
/// even when the application is not actively reading or writing.
pub struct Connection<T: IceTransport + 'static> {
    inner: Arc<ConnectionInner<T>>,
    driver_handle: tokio::task::JoinHandle<()>,
}

impl<T: IceTransport + 'static> Connection<T> {
    /// Create a new QUIC client connection and start the background driver.
    ///
    /// Sends the Initial packet immediately after creating the connection.
    async fn new_client(
        transport: T,
        psk: [u8; PSK_LEN],
        scid: quiche::ConnectionId<'static>,
    ) -> Result<Self, QuicError> {
        let mut config = create_config(psk, QuicRole::Client)?;

        // Placeholder addresses - we're using ICE for actual transport
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let conn = quiche::connect(None, &scid, local, peer, &mut config)?;

        let inner = Arc::new(ConnectionInner {
            conn: Mutex::new(Box::pin(conn)),
            transport,
            role: QuicRole::Client,
            local_addr: local,
            peer_addr: peer,
            state_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            accepted_streams: Mutex::new(std::collections::HashSet::new()),
            next_stream_index: AtomicU64::new(0),
            pending_shutdown: std::sync::Mutex::new(Vec::new()),
        });

        // Send Initial packet immediately (don't wait for driver)
        inner.flush_send().await?;

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

    /// Create a new QUIC server connection and start the background driver.
    ///
    /// Waits for the client's Initial packet, extracts connection IDs,
    /// then creates the server connection and processes the packet.
    async fn new_server(
        transport: T,
        psk: [u8; PSK_LEN],
        scid: quiche::ConnectionId<'static>,
    ) -> Result<Self, QuicError> {
        let mut config = create_config(psk, QuicRole::Server)?;

        // Wait for the first packet from the client
        let mut initial_packet = transport.recv().await?;

        // Parse the header to extract connection IDs
        let header = quiche::Header::from_slice(&mut initial_packet, quiche::MAX_CONN_ID_LEN)
            .map_err(QuicError::Quic)?;

        // Placeholder addresses - we're using ICE for actual transport
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Create server connection with the client's DCID as odcid
        let conn = quiche::accept(&scid, Some(&header.dcid), local, peer, &mut config)?;

        let inner = Arc::new(ConnectionInner {
            conn: Mutex::new(Box::pin(conn)),
            transport,
            role: QuicRole::Server,
            local_addr: local,
            peer_addr: peer,
            state_notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            accepted_streams: Mutex::new(std::collections::HashSet::new()),
            next_stream_index: AtomicU64::new(0),
            pending_shutdown: std::sync::Mutex::new(Vec::new()),
        });

        // Process the initial packet we already received
        inner.process_packet(initial_packet).await?;

        // Flush response immediately (don't wait for driver)
        inner.flush_send().await?;

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
    pub async fn open_stream(&self) -> Result<Stream<T>, QuicError> {
        // Bidirectional stream IDs (RFC 9000 §2.1) are client-initiated 0,4,8,…
        // and server-initiated 1,5,9,…. IDs are monotonic and never reused, so we
        // just hand out the next one for our role. The *concurrent* stream count
        // is bounded by the peer's MAX_STREAMS; when it's exhausted we wait for
        // the peer to raise it (which it does as in-flight streams close) rather
        // than failing or capping the connection's lifetime stream count.
        let base = match self.inner.role {
            QuicRole::Client => 0u64,
            QuicRole::Server => 1u64,
        };

        loop {
            let mut notified = std::pin::pin!(self.inner.state_notify.notified());
            notified.as_mut().enable();

            let opened = {
                let mut conn = self.inner.conn.lock().await;
                // Reset any abandoned streams first.
                self.inner.drain_pending_shutdown(&mut conn);
                if conn.is_closed() {
                    return Err(QuicError::ConnectionClosed);
                }
                let credit = conn.peer_streams_left_bidi();
                // TEMP instrumentation: watch the bidi-stream budget. A burst of
                // "waiting for MAX_STREAMS" right when requests hang means credit
                // isn't recycling (streams not being collected by the peer).
                if credit == 0 {
                    log::warn!("[wispers QUIC] open_stream: out of bidi credit, waiting for MAX_STREAMS");
                    // No credit right now — fall through to wait for MAX_STREAMS.
                    None
                } else {
                    log::info!("[wispers QUIC] open_stream: bidi credit left={credit}");
                    // Allocate the next ID and open it with a zero-byte send, both
                    // under the lock so the credit check and the send are atomic
                    // (concurrent callers can't over-allocate past the limit).
                    let n = self.inner.next_stream_index.fetch_add(1, Ordering::Relaxed);
                    let stream_id = base + 4 * n;
                    match conn.stream_send(stream_id, &[], false) {
                        Ok(_) | Err(quiche::Error::Done) => Some(stream_id),
                        Err(e) => return Err(QuicError::Quic(e)),
                    }
                }
            };

            // Flush outside the lock: pushes out both any queued resets and a new
            // stream's opening frame. Done even when blocked on credit so the
            // resets reach the peer and prompt it to return MAX_STREAMS.
            self.inner.flush_send().await?;

            match opened {
                Some(stream_id) => {
                    return Ok(Stream {
                        inner: Arc::clone(&self.inner),
                        stream_id,
                        recv_fin: AtomicBool::new(false),
                        sent_fin: AtomicBool::new(false),
                    });
                }
                None => notified.await,
            }
        }
    }

    /// Accept an incoming stream from the peer.
    ///
    /// Waits for the peer to open a new stream and returns it.
    /// Either side can accept streams opened by the other.
    pub async fn accept_stream(&self) -> Result<Stream<T>, QuicError> {
        loop {
            // Check for readable streams (peer has opened and sent data)
            {
                let mut conn = self.inner.conn.lock().await;
                // Reset any streams the application dropped without a clean close.
                self.inner.drain_pending_shutdown(&mut conn);
                let mut accepted = self.inner.accepted_streams.lock().await;

                // Find a readable stream that hasn't been accepted yet
                while let Some(stream_id) = conn.stream_readable_next() {
                    if !accepted.contains(&stream_id) {
                        accepted.insert(stream_id);
                        return Ok(Stream {
                            inner: Arc::clone(&self.inner),
                            stream_id,
                            recv_fin: AtomicBool::new(false),
                            sent_fin: AtomicBool::new(false),
                        });
                    }
                }

                if conn.is_closed() {
                    return Err(QuicError::ConnectionClosed);
                }
            }

            // Push out any queued resets, then wait for the next state change.
            self.inner.flush_send().await?;
            self.inner.state_notify.notified().await;
        }
    }
}

impl<T: IceTransport + 'static> Drop for Connection<T> {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.driver_handle.abort();
    }
}

/// Background driver loop that keeps the QUIC connection alive.
async fn driver_loop<T: IceTransport>(inner: Arc<ConnectionInner<T>>) {
    let mut keepalive_interval =
        tokio::time::interval(std::time::Duration::from_millis(KEEPALIVE_INTERVAL_MS));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // TEMP instrumentation: heartbeat counter so we can see in the logs whether
    // the driver keeps looping (and what wakes it) or goes dark before the idle
    // timeout. Every loop exit logs a reason.
    let mut iter: u64 = 0;
    loop {
        iter += 1;
        // Check if we should stop
        if inner.shutdown.load(Ordering::SeqCst) {
            log::warn!("[wispers QUIC] driver exit (iter {iter}): shutdown flag");
            break;
        }

        // Flush any pending outgoing packets
        log::info!("[wispers QUIC] driver iter {iter}: flushing");
        if inner.flush_send().await.is_err() {
            log::warn!("[wispers QUIC] driver exit (iter {iter}): flush_send error");
            break;
        }

        // Check if connection is closed
        if inner.is_closed().await {
            // TEMP instrumentation: surface *why* it closed. `peer_error` is the
            // CONNECTION_CLOSE we received; `local_error` is one quiche raised
            // locally (e.g. a protocol violation). `is_app` distinguishes an
            // application close from a transport/protocol error.
            let (peer_err, local_err) = {
                let conn = inner.conn.lock().await;
                let fmt = |e: Option<&quiche::ConnectionError>| {
                    e.map(|e| {
                        format!(
                            "is_app={} code={} reason={:?}",
                            e.is_app,
                            e.error_code,
                            String::from_utf8_lossy(&e.reason)
                        )
                    })
                };
                (fmt(conn.peer_error()), fmt(conn.local_error()))
            };
            log::warn!(
                "[wispers QUIC] driver exit (iter {iter}): connection closed; peer_error={peer_err:?} local_error={local_err:?}"
            );
            inner.state_notify.notify_waiters();
            break;
        }

        // Get timeout for next event
        let timeout = inner.timeout().await;
        let timeout_duration = timeout.unwrap_or(std::time::Duration::from_millis(100));
        log::info!("[wispers QUIC] driver iter {iter}: flushed, waiting (timeout {timeout_duration:?})");

        // Wait for incoming packet, timeout, or keepalive tick
        tokio::select! {
            result = inner.transport.recv() => {
                match result {
                    Ok(packet) => {
                        log::info!("[wispers QUIC] driver iter {iter}: recv {}B", packet.len());
                        // Process the packet
                        if inner.process_packet(packet).await.is_err() {
                            log::warn!("[wispers QUIC] driver exit (iter {iter}): process_packet error");
                            break;
                        }
                        // Notify waiters that state may have changed
                        inner.state_notify.notify_waiters();
                    }
                    Err(e) => {
                        // ICE error, stop the driver
                        log::warn!("[wispers QUIC] driver exit (iter {iter}): transport.recv error: {e:?}");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(timeout_duration) => {
                log::info!("[wispers QUIC] driver iter {iter}: timeout fired");
                // Timeout - call on_timeout
                inner.handle_timeout().await;
                // Notify in case handshake progressed
                inner.state_notify.notify_waiters();
            }
            _ = keepalive_interval.tick() => {
                log::info!("[wispers QUIC] driver iter {iter}: keepalive tick");
                // Send keepalive PING to prevent idle timeout
                if inner.send_keepalive().await.is_err() {
                    log::warn!("[wispers QUIC] driver exit (iter {iter}): send_keepalive error");
                    break;
                }
            }
        }
    }
    log::warn!("[wispers QUIC] driver loop ended");
}

/// A QUIC stream for reading and writing data.
///
/// Streams provide ordered, reliable byte delivery within a QUIC connection.
/// The background driver handles packet I/O, so stream operations can block
/// without stalling the connection.
pub struct Stream<T: IceTransport + 'static> {
    inner: Arc<ConnectionInner<T>>,
    stream_id: u64,
    /// Set to true once `stream_recv` returns fin, so subsequent reads
    /// return 0 without touching quiche (the stream may already be collected).
    recv_fin: AtomicBool,
    /// Set to true once we send our FIN via `finish()`. With `recv_fin` it tells
    /// `Drop` the stream closed cleanly, so it needn't be reset.
    sent_fin: AtomicBool,
}

impl<T: IceTransport + 'static> Stream<T> {
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
            // Arm the notification before the send so a flow-control window
            // update arriving between the send and the wait isn't lost.
            let mut notified = std::pin::pin!(self.inner.state_notify.notified());
            notified.as_mut().enable();

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
                // Flow control blocked, wait for the armed notification.
                notified.await;
            }
        }
        Ok(())
    }

    /// Read data from the stream.
    ///
    /// Returns the number of bytes read. Returns 0 if the stream is finished
    /// (peer sent FIN and all data has been delivered).
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, QuicError> {
        // Fast path: we already saw FIN on a previous read.  quiche may have
        // collected the stream so we must not call stream_recv again.
        if self.recv_fin.load(Ordering::Acquire) {
            return Ok(0);
        }

        loop {
            // Arm the notification before checking for data. `notify_waiters()`
            // only wakes already-registered waiters, so not doing it would
            // risk losing the wakeup.
            let mut notified = std::pin::pin!(self.inner.state_notify.notified());
            notified.as_mut().enable();

            // Try to read from the stream
            {
                let mut conn = self.inner.conn.lock().await;
                match conn.stream_recv(self.stream_id, buf) {
                    Ok((len, fin)) => {
                        if fin {
                            self.recv_fin.store(true, Ordering::Release);
                        }
                        return Ok(len);
                    }
                    Err(quiche::Error::Done) => {
                        // No data available yet
                        if conn.stream_finished(self.stream_id) {
                            self.recv_fin.store(true, Ordering::Release);
                            return Ok(0); // Stream finished
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "[wispers QUIC] stream {} recv error: {:?} (conn closed={}, draining={})",
                            self.stream_id,
                            e,
                            conn.is_closed(),
                            conn.is_draining()
                        );
                        return Err(QuicError::Quic(e));
                    }
                }

                if conn.is_closed() {
                    log::error!(
                        "[wispers QUIC] stream {} read: connection closed",
                        self.stream_id
                    );
                    return Err(QuicError::ConnectionClosed);
                }
            }

            // Wait for the armed notification (driver fires it when data arrives).
            notified.await;
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
        self.sent_fin.store(true, Ordering::Release);
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

impl<T: IceTransport + 'static> Drop for Stream<T> {
    /// Queue the stream for cleanup unless it closed cleanly. `Drop` can't take
    /// the async connection lock, so it just enqueues; the next `open_stream` /
    /// `accept_stream` drains the queue under the lock it already holds.
    fn drop(&mut self) {
        let sent_fin = self.sent_fin.load(Ordering::Acquire);
        let recv_fin = self.recv_fin.load(Ordering::Acquire);
        // Both halves closed cleanly, nothing to do.
        if sent_fin && recv_fin {
            return;
        }
        // Record both half-states so the next drain shuts down exactly the
        // half/halves left open.
        if let Ok(mut q) = self.inner.pending_shutdown.lock() {
            q.push((self.stream_id, sent_fin, recv_fin));
        }
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

impl Connection<IceCaller> {
    /// Create a QUIC connection as the caller (client role).
    ///
    /// The `connection_id` should be from the `StartConnectionResponse`.
    /// This starts a background driver task that handles packet I/O.
    /// Sends the Initial packet immediately.
    pub async fn new_caller(
        transport: IceCaller,
        psk: [u8; PSK_LEN],
        connection_id: i64,
    ) -> Result<Self, QuicError> {
        let scid = conn_id_from_i64(connection_id);
        Self::new_client(transport, psk, scid).await
    }
}

impl Connection<IceAnswerer> {
    /// Create a QUIC connection as the answerer (server role).
    ///
    /// The `connection_id` is the one generated for `StartConnectionResponse`.
    /// This starts a background driver task that handles packet I/O.
    /// Waits for the client's Initial packet before returning.
    pub async fn new_answerer(
        transport: IceAnswerer,
        psk: [u8; PSK_LEN],
        connection_id: i64,
    ) -> Result<Self, QuicError> {
        let scid = conn_id_from_i64(connection_id);
        Self::new_server(transport, psk, scid).await
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

    // --- Loopback QUIC transport for integration-style tests ---

    /// Channel-based transport that shuttles packets between two QUIC endpoints
    /// in the same process, replacing ICE/UDP entirely.
    struct ChannelTransport {
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    impl IceTransport for ChannelTransport {
        fn send(&self, data: &[u8]) -> Result<(), IceError> {
            self.tx
                .send(data.to_vec())
                .map_err(|_| IceError::ChannelClosed)
        }

        async fn recv(&self) -> Result<Vec<u8>, IceError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(IceError::ChannelClosed)
        }
    }

    /// Create a connected (client, server) QUIC pair over in-memory channels.
    async fn loopback_pair() -> (Connection<ChannelTransport>, Connection<ChannelTransport>) {
        let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();

        let client_transport = ChannelTransport {
            tx: a_tx,
            rx: tokio::sync::Mutex::new(b_rx),
        };
        let server_transport = ChannelTransport {
            tx: b_tx,
            rx: tokio::sync::Mutex::new(a_rx),
        };

        let psk = derive_psk(&[99u8; 32]);
        let client_scid = quiche::ConnectionId::from_vec(vec![1, 2, 3, 4]);
        let server_scid = quiche::ConnectionId::from_vec(vec![5, 6, 7, 8]);

        // Server must be spawned first (it blocks on the Initial packet).
        let server_fut = tokio::spawn(async move {
            Connection::new_server(server_transport, psk, server_scid).await
        });

        let client = Connection::new_client(client_transport, psk, client_scid)
            .await
            .expect("client created");

        let server = server_fut.await.unwrap().expect("server created");

        // Complete handshake on both sides.
        let (c, s) = tokio::join!(client.handshake(), server.handshake());
        c.expect("client handshake");
        s.expect("server handshake");

        (client, server)
    }

    /// Basic sanity: write → read on a single stream.
    #[tokio::test]
    async fn test_loopback_stream_basic() {
        let (client, server) = loopback_pair().await;

        let server_task = tokio::spawn(async move {
            let stream = server.accept_stream().await.unwrap();
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap(); // echo
            stream.finish().await.unwrap();
        });

        let stream = client.open_stream().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.finish().await.unwrap();

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Should get EOF (server finished)
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        server_task.await.unwrap();
    }

    /// Smoke test for concurrent stream multiplexing over a single connection.
    ///
    /// Opens many streams at once and ping-pongs single bytes on each, blocking on
    /// every echo, to exercise the stream read/write loops and the driver under
    /// heavy concurrency. Asserts every byte round-trips intact. The generous
    /// timeout is a deadlock guard: if a future change wedges a stream, this fails
    /// instead of hanging CI.
    ///
    /// Runs on the multi-threaded runtime to match the real binaries
    /// (`Builder::new_multi_thread()`), so the driver and stream tasks run in
    /// genuine parallel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_loopback_concurrent_streams() {
        use std::sync::Arc;

        // Enough concurrency to stress the shared connection mutex and the driver;
        // single-byte rounds keep a healthy run well under a second.
        const STREAMS: usize = 32;
        const ROUNDS: usize = 50;

        let (client, server) = loopback_pair().await;
        let client = Arc::new(client);
        let server = Arc::new(server);

        // Server: accept every stream and echo each byte straight back.
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut handlers = Vec::new();
                for _ in 0..STREAMS {
                    let stream = server.accept_stream().await.expect("accept");
                    handlers.push(tokio::spawn(async move {
                        let mut b = [0u8; 1];
                        loop {
                            let n = stream.read(&mut b).await.expect("server read");
                            if n == 0 {
                                break;
                            }
                            stream.write_all(&b[..n]).await.expect("server write");
                        }
                    }));
                }
                for h in handlers {
                    h.await.expect("server handler");
                }
            })
        };

        // Client: ping-pong ROUNDS single bytes per stream, blocking on each echo.
        // Each echo is a lone notify with an idle gap behind it — nothing else is
        // queued to re-poke the reader if its wakeup is lost.
        let mut clients = Vec::new();
        for i in 0..STREAMS {
            let client = Arc::clone(&client);
            clients.push(tokio::spawn(async move {
                let stream = client.open_stream().await.expect("open");
                for r in 0..ROUNDS {
                    let out = [(i ^ r) as u8];
                    stream.write_all(&out).await.expect("client write");
                    let mut inb = [0u8; 1];
                    let n = stream.read(&mut inb).await.expect("client read");
                    assert_eq!(n, 1, "stream {i} round {r}: short echo");
                    assert_eq!(inb[0], out[0], "stream {i} round {r}: wrong echo");
                }
                stream.finish().await.expect("client finish");
            }));
        }

        let run = async {
            for c in clients {
                c.await.expect("client task");
            }
            server_task.await.expect("server task");
        };

        tokio::time::timeout(std::time::Duration::from_secs(15), run)
            .await
            .expect("concurrent streams stalled — lost wakeup in read()/write_all()");
    }

    /// The sequence under investigation:
    ///   client: write → finish → read
    ///
    /// The client sends FIN *before* attempting to read the server's response.
    /// If quiche garbage-collects the stream between finish() and read(), the
    /// read will fail with InvalidStreamState.
    #[tokio::test]
    async fn test_finish_before_read() {
        let (client, server) = loopback_pair().await;

        // Server: accept stream, read request, send response, finish.
        let server_task = tokio::spawn(async move {
            let stream = server.accept_stream().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut total = Vec::new();
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
            }
            // Echo back a response
            stream.write_all(&total).await.unwrap();
            stream.finish().await.unwrap();
        });

        let stream = client.open_stream().await.unwrap();
        stream.write_all(b"request payload").await.unwrap();

        // Finish BEFORE reading — this is the sequence that fails via JNA.
        stream.finish().await.unwrap();

        // Now read the response.
        let mut buf = [0u8; 4096];
        let mut response = Vec::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }

        assert_eq!(response, b"request payload");

        server_task.await.unwrap();
    }

    /// Same as above but with multiple concurrent streams, which is closer
    /// to the WebView scenario (4 parallel HTTP requests).
    #[tokio::test]
    async fn test_finish_before_read_concurrent() {
        let (client, server) = loopback_pair().await;
        let server = Arc::new(server);

        // Server: accept streams in a loop and echo back.
        let server_clone = Arc::clone(&server);
        let server_task = tokio::spawn(async move {
            let mut handles = Vec::new();
            for _ in 0..4 {
                let stream = server_clone.accept_stream().await.unwrap();
                handles.push(tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let mut total = Vec::new();
                    loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        total.extend_from_slice(&buf[..n]);
                    }
                    stream.write_all(&total).await.unwrap();
                    stream.finish().await.unwrap();
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        });

        let client = Arc::new(client);

        // Spawn 4 concurrent client streams, all doing finish-before-read.
        let mut handles = Vec::new();
        for i in 0u8..4 {
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                let stream = client.open_stream().await.unwrap();
                let payload = format!("request {}", i);
                stream.write_all(payload.as_bytes()).await.unwrap();

                // Finish BEFORE reading
                stream.finish().await.unwrap();

                let mut buf = [0u8; 4096];
                let mut response = Vec::new();
                loop {
                    let n = stream
                        .read(&mut buf)
                        .await
                        .unwrap_or_else(|_| panic!("stream {} read failed", i));
                    if n == 0 {
                        break;
                    }
                    response.extend_from_slice(&buf[..n]);
                }

                assert_eq!(response, payload.as_bytes(), "stream {} mismatch", i);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        server_task.await.unwrap();
    }

    /// Opening more streams over a connection's lifetime than
    /// `INITIAL_MAX_STREAMS_BIDI` must work. QUIC stream IDs are monotonic and the
    /// peer raises `MAX_STREAMS` as streams close, so a long-lived connection can
    /// serve unlimited requests (bounded only by *concurrent* streams).
    ///
    /// The previous allocator scanned candidate IDs up to `4 * INITIAL_…` and
    /// never reused them, so it hard-capped a connection at `INITIAL_MAX_STREAMS_BIDI`
    /// streams *for its entire life* — the ~101st `open_stream` returned
    /// "no available stream IDs". This opens 250 sequentially and must succeed.
    #[tokio::test]
    async fn test_loopback_streams_beyond_initial_limit() {
        let (client, server) = loopback_pair().await;

        // Server: accept streams forever, echo each one's bytes back, finish.
        let server_task = tokio::spawn(async move {
            loop {
                let stream = match server.accept_stream().await {
                    Ok(s) => s,
                    Err(_) => break, // connection gone at end of test
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let mut data = Vec::new();
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => data.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = stream.write_all(&data).await;
                    let _ = stream.finish().await;
                });
            }
        });

        // Open well past the 100-stream initial limit, one at a time (each fully
        // closed before the next so credit always replenishes), verifying echoes.
        const COUNT: u64 = 250;
        for i in 0..COUNT {
            let stream = client
                .open_stream()
                .await
                .unwrap_or_else(|e| panic!("open_stream #{i} failed: {e:?}"));
            stream.write_all(b"ping").await.expect("client write");
            stream.finish().await.expect("client finish");

            let mut buf = [0u8; 64];
            let mut got = Vec::new();
            loop {
                let n = stream.read(&mut buf).await.expect("client read");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(&got[..], b"ping", "stream #{i}: echo mismatch");
        }

        server_task.abort();
    }

    /// A stream dropped without a clean close is reset by the next
    /// `open_stream`/`accept_stream` (RAII cleanup), reclaiming its MAX_STREAMS
    /// credit. Here the client *only drops* each stream — no `finish()`, no
    /// `shutdown()` — yet, because the server reads each stream (as a real relay
    /// does), opening 300 (well past the 100 initial limit) must not stall.
    ///
    /// Measured rule behind this (loopback matrix, since removed): credit is
    /// returned iff the client terminates the stream (reset/FIN) AND the server
    /// calls `stream_recv` on it. The Drop net supplies the reset; the server
    /// here supplies the read. Without the net, this same loop stalls at 100.
    #[tokio::test]
    async fn test_dropped_streams_reclaim_credit() {
        let (client, server) = loopback_pair().await;

        // Server: accept each stream and read it to completion (the reset shows
        // up as Err), which lets quiche collect it and return credit.
        let server_task = tokio::spawn(async move {
            loop {
                let stream = match server.accept_stream().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });

        let run = async {
            const COUNT: u64 = 300;
            for i in 0..COUNT {
                let stream = client
                    .open_stream()
                    .await
                    .unwrap_or_else(|e| panic!("open_stream #{i} failed: {e:?}"));
                stream.write_all(b"x").await.expect("client write");
                // Abandon: no finish(), no shutdown() — just drop. The next
                // open_stream must reset it and reclaim its credit.
                drop(stream);
            }
        };

        tokio::time::timeout(std::time::Duration::from_secs(15), run)
            .await
            .expect("credit stalled — dropped streams were not reclaimed");

        server_task.abort();
    }
}
