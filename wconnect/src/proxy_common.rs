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

    /// Get an existing connection or create a new one.
    ///
    /// Returns an Arc to the connection so multiple requests can share it.
    pub async fn get_or_connect(
        &self,
        node: &Node,
        target_node: i32,
    ) -> Result<Arc<QuicConnection>, wispers_connect::p2p::P2pError> {
        // Check if we have an existing connection
        {
            let mut pool = self.connections.lock().await;
            if let Some(pooled) = pool.get_mut(&target_node) {
                pooled.last_used = Instant::now();
                println!("  Reusing existing QUIC connection to node {}", target_node);
                return Ok(Arc::clone(&pooled.conn));
            }
        }

        // Create a new connection
        println!("  Creating new QUIC connection to node {}", target_node);
        let conn = node.connect_quic(target_node).await?;
        let conn = Arc::new(conn);

        // Store in pool
        {
            let mut pool = self.connections.lock().await;
            pool.insert(
                target_node,
                PooledConnection {
                    conn: Arc::clone(&conn),
                    last_used: Instant::now(),
                },
            );
        }

        Ok(conn)
    }

    /// Clean up idle connections.
    pub async fn cleanup_idle(&self) {
        let mut pool = self.connections.lock().await;
        let now = Instant::now();
        let before = pool.len();

        pool.retain(|node, pooled| {
            let keep = now.duration_since(pooled.last_used) < IDLE_TIMEOUT;
            if !keep {
                println!("  Closing idle connection to node {}", node);
            }
            keep
        });

        let removed = before - pool.len();
        if removed > 0 {
            println!("  Cleaned up {} idle connection(s)", removed);
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

/// Open a QUIC stream and send a wire protocol command.
/// Returns the stream ready for use if the command succeeds, or an error message.
pub async fn open_stream_with_command(
    quic_conn: &QuicConnection,
    command: &str,
) -> Result<QuicStream, String> {
    let quic_stream = quic_conn
        .open_stream()
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    quic_stream
        .write_all(command.as_bytes())
        .await
        .map_err(|e| format!("failed to send command: {}", e))?;

    let mut response_buf = [0u8; 256];
    let n = quic_stream
        .read(&mut response_buf)
        .await
        .map_err(|e| format!("failed to read response: {}", e))?;

    let response = String::from_utf8_lossy(&response_buf[..n]);
    let response = response.trim();

    if let Some(msg) = response.strip_prefix("ERROR ") {
        return Err(format!("remote error: {}", msg));
    }

    if response != "OK" {
        return Err(format!("unexpected response: {}", response));
    }

    Ok(quic_stream)
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
