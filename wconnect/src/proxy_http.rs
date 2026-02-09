//! HTTP proxy for accessing web servers on remote nodes.
//!
//! This module implements a forward HTTP proxy that allows browsers/clients
//! to access web servers running on nodes in the connectivity group using
//! hostnames like `http://3.wispers.link/`.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wispers_connect::{Node, NodeState};

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

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("Accepted connection from {}", addr);
                let node = Arc::clone(&node);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, node).await {
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
async fn handle_connection(mut stream: TcpStream, _node: Arc<Node>) -> Result<()> {
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

    // TODO: Phase 3 - Get/create QUIC connection from pool
    // TODO: Phase 4 - Forward request to target node
    // TODO: Phase 5 - Handle keep-alive

    // For now, return 502 since we can't forward yet
    send_error(&mut stream, 502, "Forwarding not yet implemented").await?;

    println!("Connection from {} closed", peer);
    Ok(())
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
}
