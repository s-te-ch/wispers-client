//! HTTP proxy for accessing web servers on remote nodes.
//!
//! This module implements a forward HTTP proxy that allows browsers/clients
//! to access web servers running on nodes in the connectivity group using
//! hostnames like `http://3.wispers.link/`.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use wispers_connect::{Node, NodeState, QuicConnection};

/// Default idle timeout for pooled connections (60 seconds).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval for checking and cleaning up idle connections.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);

/// Run the HTTP proxy server.
pub async fn run(hub_override: Option<&str>, profile: &str, bind_addr: &str) -> Result<()> {
    let storage = super::get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    if node.state() != NodeState::Activated {
        anyhow::bail!(
            "Node must be activated to use HTTP proxy. Current state: {:?}",
            node.state()
        );
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind to {}", bind_addr))?;

    println!("HTTP proxy listening on {}", bind_addr);
    println!("Configure your browser/client to use this as HTTP proxy");
    println!("Example: curl --proxy http://{} http://3.wispers.link/", bind_addr);

    let node = Arc::new(node);
    let pool = ConnectionPool::new();

    // Start background cleanup task
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;
            cleanup_pool.cleanup_idle().await;
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("Accepted connection from {}", addr);
                let node = Arc::clone(&node);
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, node, pool).await {
                        eprintln!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
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
struct ConnectionPool {
    /// Connections keyed by node number.
    connections: Arc<Mutex<HashMap<i32, PooledConnection>>>,
}

impl ConnectionPool {
    fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get an existing connection or create a new one.
    ///
    /// Returns an Arc to the connection so multiple requests can share it.
    async fn get_or_connect(
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
    async fn cleanup_idle(&self) {
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

/// Parsed proxy request target.
#[derive(Debug)]
struct ProxyTarget {
    /// Target node number
    node_number: i32,
    /// Target port (default 80)
    port: u16,
    /// Path including query string (e.g., "/path?query=1")
    path: String,
}

/// Parsed HTTP request ready for forwarding.
#[derive(Debug)]
struct ParsedRequest {
    /// The proxy target extracted from the URL
    target: ProxyTarget,
    /// The original request method
    method: String,
    /// HTTP version (0 for HTTP/1.0, 1 for HTTP/1.1)
    version: u8,
    /// Raw headers to forward (excluding hop-by-hop headers)
    headers: Vec<(String, String)>,
    /// Whether to keep the connection alive
    keep_alive: bool,
}

/// Handle a single client connection.
async fn handle_connection(
    mut stream: TcpStream,
    node: Arc<Node>,
    pool: ConnectionPool,
) -> Result<()> {
    let peer = stream.peer_addr()?;

    // Read the HTTP request
    let mut buf = vec![0u8; 8192];
    let mut total_read = 0;

    loop {
        if total_read >= buf.len() {
            bail!("Request too large");
        }

        let n = stream.read(&mut buf[total_read..]).await?;
        if n == 0 {
            bail!("Connection closed before complete request");
        }
        total_read += n;

        // Check if we have a complete request (ends with \r\n\r\n)
        if total_read >= 4 {
            let data = &buf[..total_read];
            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    }

    // Parse the request
    let request = match parse_request(&buf[..total_read]) {
        Ok(req) => req,
        Err(e) => {
            send_error(&mut stream, 400, &format!("Bad Request: {}", e)).await?;
            return Ok(());
        }
    };

    println!(
        "  {} -> node {}:{}{} (keep-alive: {})",
        request.method, request.target.node_number, request.target.port,
        request.target.path, request.keep_alive
    );

    // Get or create QUIC connection to target node
    let quic_conn = match pool.get_or_connect(&node, request.target.node_number).await {
        Ok(conn) => conn,
        Err(e) => {
            send_error(&mut stream, 502, &format!("Failed to connect to node: {}", e)).await?;
            return Ok(());
        }
    };

    // Forward the request
    if let Err(e) = forward_request(&mut stream, &quic_conn, &request).await {
        eprintln!("  Forward error: {}", e);
        // Don't send error response here - we may have already started sending the response
    }

    // TODO: Phase 5 - Handle keep-alive (loop back to read next request)

    println!("Connection from {} closed", peer);
    Ok(())
}

/// Forward an HTTP request through a QUIC stream to the target node.
async fn forward_request(
    client_stream: &mut TcpStream,
    quic_conn: &QuicConnection,
    request: &ParsedRequest,
) -> Result<()> {
    // Open a new stream for this request
    let quic_stream = quic_conn
        .open_stream()
        .await
        .context("failed to open QUIC stream")?;

    // Send FORWARD command
    let forward_cmd = format!("FORWARD {}\n", request.target.port);
    quic_stream
        .write_all(forward_cmd.as_bytes())
        .await
        .context("failed to send FORWARD command")?;

    // Read response (OK or ERROR)
    let mut response_buf = [0u8; 256];
    let n = quic_stream
        .read(&mut response_buf)
        .await
        .context("failed to read FORWARD response")?;

    let response = String::from_utf8_lossy(&response_buf[..n]);
    let response = response.trim();

    if response.starts_with("ERROR ") {
        let error_msg = &response[6..];
        send_error(client_stream, 502, &format!("Remote error: {}", error_msg)).await?;
        return Ok(());
    }

    if response != "OK" {
        send_error(client_stream, 502, &format!("Unexpected response: {}", response)).await?;
        return Ok(());
    }

    // Build and send the HTTP request to the remote server
    let http_request = build_http_request(request);
    quic_stream
        .write_all(http_request.as_bytes())
        .await
        .context("failed to send HTTP request")?;

    // Relay the response back to the client
    // We read from the QUIC stream and write to the client TCP stream
    let mut buf = [0u8; 8192];
    loop {
        let n = quic_stream
            .read(&mut buf)
            .await
            .context("failed to read from remote")?;

        if n == 0 {
            break;
        }

        client_stream
            .write_all(&buf[..n])
            .await
            .context("failed to write to client")?;
    }

    Ok(())
}

/// Build an HTTP request string from the parsed request.
fn build_http_request(request: &ParsedRequest) -> String {
    let mut http = String::new();

    // Request line: METHOD /path HTTP/1.1
    let version = if request.version == 0 { "1.0" } else { "1.1" };
    http.push_str(&format!(
        "{} {} HTTP/{}\r\n",
        request.method, request.target.path, version
    ));

    // Headers
    for (name, value) in &request.headers {
        http.push_str(&format!("{}: {}\r\n", name, value));
    }

    // End of headers
    http.push_str("\r\n");

    http
}

/// Parse an HTTP request from a buffer.
fn parse_request(buf: &[u8]) -> Result<ParsedRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(buf).context("failed to parse HTTP request")?;
    if status.is_partial() {
        bail!("incomplete HTTP request");
    }

    let method = req.method.context("missing method")?.to_string();
    let path = req.path.context("missing path")?;
    let version = req.version.context("missing version")?;

    // Parse the target from the absolute URL
    let target = parse_proxy_target(path)?;

    // Collect headers, filtering out hop-by-hop headers
    let mut parsed_headers = Vec::new();
    let mut keep_alive = version == 1; // HTTP/1.1 defaults to keep-alive
    let mut host_header = None;

    for header in req.headers.iter() {
        let name = header.name.to_lowercase();
        let value = String::from_utf8_lossy(header.value).to_string();

        // Check Connection header for keep-alive
        if name == "connection" {
            keep_alive = value.to_lowercase().contains("keep-alive");
            // Don't forward Connection header as-is
            continue;
        }

        // Skip other hop-by-hop headers
        if is_hop_by_hop_header(&name) {
            continue;
        }

        if name == "host" {
            host_header = Some(value.clone());
        }

        parsed_headers.push((header.name.to_string(), value));
    }

    // If Host header is missing, add it from the target
    if host_header.is_none() {
        let host = if target.port == 80 {
            format!("{}.wispers.link", target.node_number)
        } else {
            format!("{}.wispers.link:{}", target.node_number, target.port)
        };
        parsed_headers.push(("Host".to_string(), host));
    }

    Ok(ParsedRequest {
        target,
        method,
        version,
        headers: parsed_headers,
        keep_alive,
    })
}

/// Parse the proxy target from an absolute URL.
///
/// Expected format: `http://<node_number>.wispers.link[:port]/path`
fn parse_proxy_target(url: &str) -> Result<ProxyTarget> {
    // Must start with http://
    let rest = url
        .strip_prefix("http://")
        .context("proxy requests must use absolute URLs (http://...)")?;

    // Split host and path
    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    // Parse host and optional port
    let (host, port) = match host_port.rfind(':') {
        Some(pos) => {
            let port_str = &host_port[pos + 1..];
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("invalid port: {}", port_str))?;
            (&host_port[..pos], port)
        }
        None => (host_port, 80),
    };

    // Validate hostname matches <node_number>.wispers.link
    let node_str = host
        .strip_suffix(".wispers.link")
        .with_context(|| format!("hostname must end with .wispers.link, got: {}", host))?;

    let node_number: i32 = node_str
        .parse()
        .with_context(|| format!("invalid node number: {}", node_str))?;

    if node_number <= 0 {
        bail!("node number must be positive, got: {}", node_number);
    }

    Ok(ProxyTarget {
        node_number,
        port,
        path: path.to_string(),
    })
}

/// Check if a header is a hop-by-hop header that shouldn't be forwarded.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Send an HTTP error response.
async fn send_error(stream: &mut TcpStream, status: u16, message: &str) -> Result<()> {
    let status_text = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}\n",
        status, status_text, message
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_target_basic() {
        let target = parse_proxy_target("http://3.wispers.link/").unwrap();
        assert_eq!(target.node_number, 3);
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/");
    }

    #[test]
    fn test_parse_proxy_target_with_path() {
        let target = parse_proxy_target("http://42.wispers.link/api/v1/users").unwrap();
        assert_eq!(target.node_number, 42);
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/api/v1/users");
    }

    #[test]
    fn test_parse_proxy_target_with_port() {
        let target = parse_proxy_target("http://5.wispers.link:8080/test").unwrap();
        assert_eq!(target.node_number, 5);
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/test");
    }

    #[test]
    fn test_parse_proxy_target_with_query() {
        let target = parse_proxy_target("http://1.wispers.link/search?q=test&page=2").unwrap();
        assert_eq!(target.node_number, 1);
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/search?q=test&page=2");
    }

    #[test]
    fn test_parse_proxy_target_no_path() {
        let target = parse_proxy_target("http://7.wispers.link").unwrap();
        assert_eq!(target.node_number, 7);
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/");
    }

    #[test]
    fn test_parse_proxy_target_invalid_no_http() {
        assert!(parse_proxy_target("https://3.wispers.link/").is_err());
        assert!(parse_proxy_target("/path").is_err());
    }

    #[test]
    fn test_parse_proxy_target_invalid_hostname() {
        assert!(parse_proxy_target("http://example.com/").is_err());
        assert!(parse_proxy_target("http://wispers.link/").is_err());
        assert!(parse_proxy_target("http://abc.wispers.link/").is_err());
    }

    #[test]
    fn test_parse_proxy_target_invalid_node_number() {
        assert!(parse_proxy_target("http://0.wispers.link/").is_err());
        assert!(parse_proxy_target("http://-1.wispers.link/").is_err());
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop_header("connection"));
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("transfer-encoding"));
        assert!(!is_hop_by_hop_header("content-type"));
        assert!(!is_hop_by_hop_header("host"));
    }

    #[test]
    fn test_build_http_request() {
        let request = ParsedRequest {
            target: ProxyTarget {
                node_number: 3,
                port: 80,
                path: "/api/test".to_string(),
            },
            method: "GET".to_string(),
            version: 1,
            headers: vec![
                ("Host".to_string(), "3.wispers.link".to_string()),
                ("User-Agent".to_string(), "test/1.0".to_string()),
            ],
            keep_alive: true,
        };

        let http = build_http_request(&request);
        assert_eq!(
            http,
            "GET /api/test HTTP/1.1\r\nHost: 3.wispers.link\r\nUser-Agent: test/1.0\r\n\r\n"
        );
    }

    #[test]
    fn test_build_http_request_http10() {
        let request = ParsedRequest {
            target: ProxyTarget {
                node_number: 5,
                port: 8080,
                path: "/".to_string(),
            },
            method: "POST".to_string(),
            version: 0,
            headers: vec![("Host".to_string(), "5.wispers.link:8080".to_string())],
            keep_alive: false,
        };

        let http = build_http_request(&request);
        assert!(http.starts_with("POST / HTTP/1.0\r\n"));
    }
}
