//! Shared infrastructure for HTTP and SOCKS5 proxies.
//!
//! This module contains common components used by both proxy implementations:
//! - Connection pooling for QUIC connections to remote nodes
//! - Timeout constants
//! - Proxy error types
//! - Wispers hostname parsing

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info};
use wispers_connect::p2p::P2pError;
use wispers_connect::{Node, QuicConnection, QuicStream};

/// Default idle timeout for pooled connections (60 seconds).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval for checking and cleaning up idle connections.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout for QUIC operations (connecting, forwarding).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Proxy-specific errors that map to HTTP status codes.
#[derive(Debug)]
pub enum ProxyError {
    /// 400 Bad Request - malformed request
    BadRequest(String),
    /// 403 Forbidden - non-wispers.link host (when egress not enabled)
    Forbidden(String),
    /// 502 Bad Gateway - upstream error
    BadGateway(String),
    /// 504 Gateway Timeout - upstream timeout
    GatewayTimeout(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::BadRequest(msg) => write!(f, "{}", msg),
            ProxyError::Forbidden(msg) => write!(f, "{}", msg),
            ProxyError::BadGateway(msg) => write!(f, "{}", msg),
            ProxyError::GatewayTimeout(msg) => write!(f, "{}", msg),
        }
    }
}

impl ProxyError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            ProxyError::BadRequest(_) => 400,
            ProxyError::Forbidden(_) => 403,
            ProxyError::BadGateway(_) => 502,
            ProxyError::GatewayTimeout(_) => 504,
        }
    }
}

/// A pooled QUIC connection with last-used timestamp.
struct PooledConnection {
    conn: Arc<QuicConnection>,
    last_used: Instant,
}

/// Pool of QUIC connections to remote nodes.
#[derive(Clone)]
pub struct ConnectionPool {
    /// Connections keyed by node number.
    connections: Arc<Mutex<HashMap<i32, PooledConnection>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Open a QUIC stream to `target_node`, using a pooled connection if
    /// possible. If the cached connection's `open_stream` fails (typically
    /// because the underlying ICE path died), it is evicted and a fresh
    /// connection is established.
    pub async fn open_stream(
        &self,
        node: &Node,
        target_node: i32,
    ) -> Result<QuicStream, OpenStreamError> {
        // Try cached.
        let cached = {
            let mut pool = self.connections.lock().await;
            pool.get_mut(&target_node).map(|entry| {
                entry.last_used = Instant::now();
                Arc::clone(&entry.conn)
            })
        };
        if let Some(conn) = cached {
            match conn.open_stream().await {
                Ok(stream) => {
                    debug!(target_node, "Reusing existing QUIC connection");
                    return Ok(stream);
                }
                Err(_) => {
                    let mut pool = self.connections.lock().await;
                    if let Some(entry) = pool.get(&target_node)
                        && Arc::ptr_eq(&entry.conn, &conn)
                    {
                        info!(target_node, "Evicting dead QUIC connection");
                        pool.remove(&target_node);
                    }
                }
            }
        }

        // Fresh connect.
        info!(target_node, "Creating new QUIC connection");
        let conn = Arc::new(
            node.connect_quic(target_node)
                .await
                .map_err(OpenStreamError::Connect)?,
        );
        let stream = conn.open_stream().await.map_err(OpenStreamError::Stream)?;
        let mut pool = self.connections.lock().await;
        pool.insert(
            target_node,
            PooledConnection {
                conn,
                last_used: Instant::now(),
            },
        );
        Ok(stream)
    }

    /// Clean up idle connections.
    pub async fn cleanup_idle(&self) {
        let mut pool = self.connections.lock().await;
        let now = Instant::now();
        let before = pool.len();

        pool.retain(|node, pooled| {
            let keep = now.duration_since(pooled.last_used) < IDLE_TIMEOUT;
            if !keep {
                debug!(target_node = node, "Closing idle connection");
            }
            keep
        });

        let removed = before - pool.len();
        if removed > 0 {
            debug!(count = removed, "Cleaned up idle connection(s)");
        }
    }
}

/// Parsed wispers.link hostname.
#[derive(Debug, Clone)]
pub struct WispersHost {
    /// The node number extracted from the hostname
    pub node_number: i32,
}

/// Parse a wispers.link hostname to extract the node number.
///
/// Expected format: `<node_number>.wispers.link`
///
/// Returns `Ok(WispersHost)` if the hostname is a valid wispers.link address,
/// or `Err(None)` if it's a non-wispers hostname (for egress routing),
/// or `Err(Some(ProxyError))` if it's malformed.
pub fn parse_wispers_host(host: &str) -> Result<WispersHost, Option<ProxyError>> {
    // Check if it's a wispers.link hostname
    let node_str = match host.strip_suffix(".wispers.link") {
        Some(s) => s,
        None => {
            // Not a wispers.link hostname - could be egress traffic
            return Err(None);
        }
    };

    // Parse node number
    let node_number: i32 = node_str.parse().map_err(|_| {
        Some(ProxyError::BadRequest(format!(
            "invalid node number in hostname: {}",
            node_str
        )))
    })?;

    if node_number <= 0 {
        return Err(Some(ProxyError::BadRequest(format!(
            "node number must be positive, got: {}",
            node_number
        ))));
    }

    Ok(WispersHost { node_number })
}

/// Failure modes for `ConnectionPool::open_stream`.
#[derive(Debug)]
pub enum OpenStreamError {
    /// Establishing a fresh connection to the peer failed (ICE/hub/auth).
    Connect(P2pError),
    /// The peer is reachable but `open_stream` on a fresh connection failed.
    Stream(P2pError),
}

impl fmt::Display for OpenStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "failed to connect to peer: {}", e),
            Self::Stream(e) => write!(f, "failed to open stream: {}", e),
        }
    }
}

impl std::error::Error for OpenStreamError {}

/// Failure modes for `send_command`.
#[derive(Debug)]
pub enum CommandError {
    /// The stream's write or read failed — the connection is probably dead.
    Io(P2pError),
    /// The server replied with an `ERROR <msg>` line.
    Rejected(String),
    /// The server's reply was neither `OK` nor `ERROR ...`.
    Protocol(String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "stream I/O failed: {}", e),
            Self::Rejected(msg) => write!(f, "remote rejected: {}", msg),
            Self::Protocol(msg) => write!(f, "unexpected response: {}", msg),
        }
    }
}

impl std::error::Error for CommandError {}

/// Send a wire-protocol command on a stream and parse the `OK` / `ERROR <msg>`
/// response.
pub async fn send_command(stream: &QuicStream, command: &str) -> Result<(), CommandError> {
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(CommandError::Io)?;

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await.map_err(CommandError::Io)?;
    let response = String::from_utf8_lossy(&buf[..n]);
    let response = response.trim();

    if let Some(msg) = response.strip_prefix("ERROR ") {
        return Err(CommandError::Rejected(msg.to_string()));
    }
    if response != "OK" {
        return Err(CommandError::Protocol(response.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wispers_host_valid() {
        let host = parse_wispers_host("3.wispers.link").unwrap();
        assert_eq!(host.node_number, 3);

        let host = parse_wispers_host("42.wispers.link").unwrap();
        assert_eq!(host.node_number, 42);

        let host = parse_wispers_host("999.wispers.link").unwrap();
        assert_eq!(host.node_number, 999);
    }

    #[test]
    fn test_parse_wispers_host_non_wispers() {
        // Non-wispers.link hosts should return Err(None) for egress routing
        let result = parse_wispers_host("example.com");
        assert!(matches!(result, Err(None)));

        let result = parse_wispers_host("google.com");
        assert!(matches!(result, Err(None)));

        let result = parse_wispers_host("localhost");
        assert!(matches!(result, Err(None)));
    }

    #[test]
    fn test_parse_wispers_host_invalid_node_number() {
        // Invalid node numbers should return Err(Some(ProxyError))
        let result = parse_wispers_host("abc.wispers.link");
        assert!(matches!(result, Err(Some(ProxyError::BadRequest(_)))));

        let result = parse_wispers_host("0.wispers.link");
        assert!(matches!(result, Err(Some(ProxyError::BadRequest(_)))));

        let result = parse_wispers_host("-1.wispers.link");
        assert!(matches!(result, Err(Some(ProxyError::BadRequest(_)))));
    }

    #[test]
    fn test_proxy_error_status_codes() {
        assert_eq!(ProxyError::BadRequest("".to_string()).status_code(), 400);
        assert_eq!(ProxyError::Forbidden("".to_string()).status_code(), 403);
        assert_eq!(ProxyError::BadGateway("".to_string()).status_code(), 502);
        assert_eq!(
            ProxyError::GatewayTimeout("".to_string()).status_code(),
            504
        );
    }
}
