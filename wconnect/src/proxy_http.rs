//! HTTP proxy for accessing web servers on remote nodes.
//!
//! This module implements a forward HTTP proxy that allows browsers/clients
//! to access web servers running on nodes in the connectivity group using
//! hostnames like `http://3.wispers.link/`.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wispers_connect::{Node, NodeState, QuicConnection};

use crate::proxy_common::{
    CLEANUP_INTERVAL, ConnectionPool, ProxyError, REQUEST_TIMEOUT, open_stream_with_command,
    parse_wispers_host,
};

/// Run the HTTP proxy server.
pub async fn run(
    hub_override: Option<&str>,
    profile: &str,
    bind_addr: &str,
    egress_node: Option<i32>,
) -> Result<()> {
    let storage = super::get_storage(hub_override, profile)?;
    let node = super::load_node(&storage).await?;

    if node.state() != NodeState::Activated {
        anyhow::bail!(
            "Node must be activated to use HTTP proxy. Current state: {:?}",
            node.state()
        );
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind to {bind_addr}"))?;

    println!("HTTP proxy listening on {bind_addr}");
    if let Some(egress) = egress_node {
        println!("  Internet egress: enabled via node {egress}");
        println!(
            "Example: curl --proxy http://{bind_addr} https://example.com/"
        );
    } else {
        println!("  Internet egress: disabled (wispers.link only)");
        println!(
            "Example: curl --proxy http://{bind_addr} http://3.wispers.link/"
        );
    }

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
                println!("Accepted connection from {addr}");
                let node = Arc::clone(&node);
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = Box::pin(handle_client_connection(stream, node, pool, egress_node)).await
                    {
                        eprintln!("Connection error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("Accept error: {e}");
            }
        }
    }
}

/// Where the connection should go.
#[derive(Debug, Clone)]
enum Destination {
    /// Connect to a wispers node via FORWARD command
    WispersNode { node_number: i32, port: u16 },
    /// Connect to internet host via CONNECT command through egress node
    Internet { host: String, port: u16 },
}

/// How to handle the proxied connection.
#[derive(Debug)]
enum ProxyMode {
    /// Forward HTTP request and relay response
    HttpRequest { path: String },
    /// Raw tunnel (for HTTPS CONNECT)
    Tunnel,
}

/// Parsed proxy request target.
#[derive(Debug)]
struct ProxyTarget {
    destination: Destination,
    mode: ProxyMode,
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

/// Handle a single client connection (may process multiple requests via keep-alive).
#[allow(clippy::too_many_lines)]
async fn handle_client_connection(
    mut stream: TcpStream,
    node: Arc<Node>,
    pool: ConnectionPool,
    egress_node: Option<i32>,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut request_count = 0;

    loop {
        // Read HTTP request bytes
        let buf = match read_request_bytes(&mut stream).await {
            Ok(ReadResult::Data(buf)) => buf,
            Ok(ReadResult::Closed) => {
                // Client closed connection gracefully
                break;
            }
            Err(e) => {
                if request_count == 0 {
                    // First request - send error response
                    send_proxy_error(&mut stream, &e).await?;
                }
                break;
            }
        };

        // Parse the request
        let request = match parse_request(&buf, egress_node) {
            Ok(req) => req,
            Err(e) => {
                send_proxy_error(&mut stream, &e).await?;
                break;
            }
        };

        request_count += 1;
        let keep_alive = request.keep_alive;

        // Get target node based on destination
        let (target_node, routing_via_egress) = match &request.target.destination {
            Destination::WispersNode { node_number, .. } => (*node_number, false),
            Destination::Internet { .. } => (egress_node.unwrap(), true),
        };

        // Log the request
        match (&request.target.destination, &request.target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                println!(
                    "  {} -> node {}:{}{} (keep-alive: {})",
                    request.method, node_number, port, path, keep_alive
                );
            }
            (Destination::WispersNode { node_number, port }, ProxyMode::Tunnel) => {
                println!("  CONNECT -> node {node_number}:{port}");
            }
            (Destination::Internet { host, port }, ProxyMode::HttpRequest { path }) => {
                println!(
                    "  {} -> {}:{}{} via node {} (keep-alive: {})",
                    request.method, host, port, path, target_node, keep_alive
                );
            }
            (Destination::Internet { host, port }, ProxyMode::Tunnel) => {
                println!("  CONNECT {host}:{port} via node {target_node}");
            }
        }

        // Get or create QUIC connection to target node (with timeout)
        let quic_conn =
            match tokio::time::timeout(REQUEST_TIMEOUT, pool.get_or_connect(&node, target_node))
                .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    let msg = if routing_via_egress {
                        format!("failed to connect to egress node: {e}")
                    } else {
                        format!("failed to connect to node: {e}")
                    };
                    let err = ProxyError::BadGateway(msg);
                    send_proxy_error(&mut stream, &err).await?;
                    break;
                }
                Err(_) => {
                    let msg = if routing_via_egress {
                        "connection to egress node timed out"
                    } else {
                        "connection to node timed out"
                    };
                    let err = ProxyError::GatewayTimeout(msg.to_string());
                    send_proxy_error(&mut stream, &err).await?;
                    break;
                }
            };

        // Handle based on mode
        match &request.target.mode {
            ProxyMode::HttpRequest { path } => {
                let result = match &request.target.destination {
                    Destination::WispersNode { port, .. } => {
                        // Use FORWARD for wispers nodes
                        tokio::time::timeout(
                            REQUEST_TIMEOUT,
                            handle_wispers_request(&mut stream, &quic_conn, &request, *port, path),
                        )
                        .await
                    }
                    Destination::Internet { host, port } => {
                        // Use CONNECT for internet egress
                        tokio::time::timeout(
                            REQUEST_TIMEOUT,
                            handle_egress_request(
                                &mut stream,
                                &quic_conn,
                                &request,
                                host,
                                *port,
                                path,
                            ),
                        )
                        .await
                    }
                };

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        eprintln!("  Request error: {e}");
                        break;
                    }
                    Err(_) => {
                        let err = ProxyError::GatewayTimeout("request timed out".to_string());
                        let _ = send_proxy_error(&mut stream, &err).await;
                        break;
                    }
                }
            }
            ProxyMode::Tunnel => {
                let result = match &request.target.destination {
                    Destination::WispersNode { port, .. } => {
                        // Use FORWARD for wispers nodes tunnel
                        Box::pin(tokio::time::timeout(
                            REQUEST_TIMEOUT,
                            handle_wispers_tunnel(&mut stream, &quic_conn, *port),
                        ))
                        .await
                    }
                    Destination::Internet { host, port } => {
                        // Use CONNECT for internet tunnel
                        Box::pin(tokio::time::timeout(
                            REQUEST_TIMEOUT,
                            handle_egress_tunnel(&mut stream, &quic_conn, host, *port),
                        ))
                        .await
                    }
                };

                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        eprintln!("  Tunnel error: {e}");
                    }
                    Err(_) => {
                        let err = ProxyError::GatewayTimeout("tunnel setup timed out".to_string());
                        let _ = send_proxy_error(&mut stream, &err).await;
                    }
                }
                // Tunnels don't support keep-alive in the HTTP sense
                break;
            }
        }

        // If not keep-alive, close the connection
        if !keep_alive {
            break;
        }

        // Otherwise, loop back to handle the next request
    }

    println!(
        "Connection from {} closed ({} request{})",
        peer,
        request_count,
        if request_count == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Result of reading HTTP request bytes from the stream.
enum ReadResult {
    /// Got complete request bytes
    Data(Vec<u8>),
    /// Client closed connection gracefully (no data)
    Closed,
}

/// Read HTTP request bytes from the stream.
async fn read_request_bytes(stream: &mut TcpStream) -> Result<ReadResult, ProxyError> {
    let mut buf = vec![0u8; 8192];
    let mut total_read = 0;

    loop {
        if total_read >= buf.len() {
            return Err(ProxyError::BadRequest("request too large".to_string()));
        }

        let n = stream
            .read(&mut buf[total_read..])
            .await
            .map_err(|e| ProxyError::BadRequest(format!("failed to read request: {e}")))?;

        if n == 0 {
            if total_read == 0 {
                // Client closed connection before sending anything
                return Ok(ReadResult::Closed);
            }
            return Err(ProxyError::BadRequest(
                "connection closed before complete request".to_string(),
            ));
        }
        total_read += n;

        // Check if we have a complete request (ends with \r\n\r\n)
        if total_read >= 4 {
            let data = &buf[..total_read];
            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                buf.truncate(total_read);
                return Ok(ReadResult::Data(buf));
            }
        }
    }
}

/// Forward an HTTP request to a wispers node using FORWARD command.
async fn handle_wispers_request(
    client_stream: &mut TcpStream,
    quic_conn: &QuicConnection,
    request: &ParsedRequest,
    port: u16,
    path: &str,
) -> Result<()> {
    let command = format!("FORWARD {port}\n");
    let quic_stream = match open_stream_with_command(quic_conn, &command).await {
        Ok(s) => s,
        Err(msg) => {
            send_error(client_stream, 502, &msg).await?;
            return Ok(());
        }
    };

    // Build and send the HTTP request to the remote server
    let http_request = build_http_request(request, path);
    quic_stream
        .write_all(http_request.as_bytes())
        .await
        .context("failed to send HTTP request")?;

    // Relay the response back to the client
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

/// Forward an HTTP request via egress using CONNECT command.
async fn handle_egress_request(
    client_stream: &mut TcpStream,
    quic_conn: &QuicConnection,
    request: &ParsedRequest,
    host: &str,
    port: u16,
    path: &str,
) -> Result<()> {
    let command = format!("CONNECT {host}:{port}\n");
    let quic_stream = match open_stream_with_command(quic_conn, &command).await {
        Ok(s) => s,
        Err(msg) => {
            send_error(client_stream, 502, &msg).await?;
            return Ok(());
        }
    };

    // Build and send the HTTP request to the remote server
    let http_request = build_http_request(request, path);
    quic_stream
        .write_all(http_request.as_bytes())
        .await
        .context("failed to send HTTP request")?;

    // Relay the response back to the client
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

/// Handle HTTP CONNECT tunnel to a wispers node using FORWARD command.
async fn handle_wispers_tunnel(
    client_stream: &mut TcpStream,
    quic_conn: &QuicConnection,
    port: u16,
) -> Result<()> {
    let command = format!("FORWARD {port}\n");
    let quic_stream = match open_stream_with_command(quic_conn, &command).await {
        Ok(s) => s,
        Err(msg) => {
            send_error(client_stream, 502, &msg).await?;
            return Ok(());
        }
    };

    // Send 200 Connection Established to client
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to send 200 response")?;

    // Bidirectional relay
    let quic_stream = Arc::new(quic_stream);
    let (mut tcp_read, mut tcp_write) = client_stream.split();

    let quic_read = Arc::clone(&quic_stream);
    let quic_write = Arc::clone(&quic_stream);

    // TCP -> QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if quic_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = quic_write.finish().await;
    };

    // QUIC -> TCP
    let quic_to_tcp = async move {
        let mut buf = [0u8; 8192];
        loop {
            match quic_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    tokio::join!(tcp_to_quic, quic_to_tcp);

    Ok(())
}

/// Handle HTTP CONNECT tunnel for HTTPS traffic via egress.
async fn handle_egress_tunnel(
    client_stream: &mut TcpStream,
    quic_conn: &QuicConnection,
    host: &str,
    port: u16,
) -> Result<()> {
    let command = format!("CONNECT {host}:{port}\n");
    let quic_stream = match open_stream_with_command(quic_conn, &command).await {
        Ok(s) => s,
        Err(msg) => {
            send_error(client_stream, 502, &msg).await?;
            return Ok(());
        }
    };

    // Send 200 Connection Established to client
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("failed to send 200 response")?;

    // Bidirectional relay
    let quic_stream = Arc::new(quic_stream);
    let (mut tcp_read, mut tcp_write) = client_stream.split();

    let quic_read = Arc::clone(&quic_stream);
    let quic_write = Arc::clone(&quic_stream);

    // TCP -> QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if quic_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = quic_write.finish().await;
    };

    // QUIC -> TCP
    let quic_to_tcp = async move {
        let mut buf = [0u8; 8192];
        loop {
            match quic_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    tokio::join!(tcp_to_quic, quic_to_tcp);

    Ok(())
}

/// Build an HTTP request string from the parsed request.
fn build_http_request(request: &ParsedRequest, path: &str) -> String {
    use std::fmt::Write as _;
    let mut http = String::new();

    // Request line: METHOD /path HTTP/1.1
    let version = if request.version == 0 { "1.0" } else { "1.1" };
    let _ = write!(http, "{} {} HTTP/{}\r\n", request.method, path, version);

    // Headers
    for (name, value) in &request.headers {
        let _ = write!(http, "{name}: {value}\r\n");
    }

    // End of headers
    http.push_str("\r\n");

    http
}

/// Parse an HTTP request from a buffer.
fn parse_request(buf: &[u8], egress_node: Option<i32>) -> Result<ParsedRequest, ProxyError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req
        .parse(buf)
        .map_err(|e| ProxyError::BadRequest(format!("failed to parse HTTP request: {e}")))?;
    if status.is_partial() {
        return Err(ProxyError::BadRequest(
            "incomplete HTTP request".to_string(),
        ));
    }

    let method = req
        .method
        .ok_or_else(|| ProxyError::BadRequest("missing method".to_string()))?
        .to_string();
    let path = req
        .path
        .ok_or_else(|| ProxyError::BadRequest("missing path".to_string()))?;
    let version = req
        .version
        .ok_or_else(|| ProxyError::BadRequest("missing version".to_string()))?;

    // Handle HTTP CONNECT method for HTTPS tunneling
    if method == "CONNECT" {
        let target = parse_connect_target(path, egress_node)?;
        return Ok(ParsedRequest {
            target,
            method,
            version,
            headers: Vec::new(),
            keep_alive: false,
        });
    }

    // Parse the target from the absolute URL
    let target = parse_proxy_target(path, egress_node)?;

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

    // If Host header is missing, add it from the target (only for HTTP requests, not tunnels)
    if host_header.is_none()
        && let ProxyMode::HttpRequest { .. } = &target.mode
    {
        let host = match &target.destination {
            Destination::WispersNode { node_number, port } => {
                if *port == 80 {
                    format!("{node_number}.wispers.link")
                } else {
                    format!("{node_number}.wispers.link:{port}")
                }
            }
            Destination::Internet { host, port } => {
                if *port == 80 {
                    host.clone()
                } else {
                    format!("{host}:{port}")
                }
            }
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

/// Parse HTTP CONNECT target (host:port format).
fn parse_connect_target(target: &str, egress_node: Option<i32>) -> Result<ProxyTarget, ProxyError> {
    let (host, port) = match target.rfind(':') {
        Some(pos) => {
            let port_str = &target[pos + 1..];
            let port: u16 = port_str.parse().map_err(|_| {
                ProxyError::BadRequest(format!("invalid port in CONNECT: {port_str}"))
            })?;
            (&target[..pos], port)
        }
        None => {
            return Err(ProxyError::BadRequest(
                "CONNECT target must be host:port".to_string(),
            ));
        }
    };

    // Check if it's a wispers.link hostname
    match parse_wispers_host(host) {
        Ok(wispers_host) => Ok(ProxyTarget {
            destination: Destination::WispersNode {
                node_number: wispers_host.node_number,
                port,
            },
            mode: ProxyMode::Tunnel,
        }),
        Err(None) => {
            // Not a wispers.link hostname - require egress
            if egress_node.is_some() {
                Ok(ProxyTarget {
                    destination: Destination::Internet {
                        host: host.to_string(),
                        port,
                    },
                    mode: ProxyMode::Tunnel,
                })
            } else {
                Err(ProxyError::Forbidden(format!(
                    "CONNECT to non-wispers.link hosts requires --egress-node, got: {host}"
                )))
            }
        }
        Err(Some(e)) => Err(e),
    }
}

/// Parse the proxy target from an absolute URL.
///
/// Expected format: `http://<host>[:port]/path`
fn parse_proxy_target(url: &str, egress_node: Option<i32>) -> Result<ProxyTarget, ProxyError> {
    // Must start with http://
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(ProxyError::BadRequest(
            "proxy requests must use absolute URLs (http://...)".to_string(),
        ));
    };

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
                .map_err(|_| ProxyError::BadRequest(format!("invalid port: {port_str}")))?;
            (&host_port[..pos], port)
        }
        None => (host_port, 80),
    };

    // Check if it's a wispers.link hostname
    match parse_wispers_host(host) {
        Ok(wispers_host) => Ok(ProxyTarget {
            destination: Destination::WispersNode {
                node_number: wispers_host.node_number,
                port,
            },
            mode: ProxyMode::HttpRequest {
                path: path.to_string(),
            },
        }),
        Err(None) => {
            // Not a wispers.link hostname
            if egress_node.is_some() {
                Ok(ProxyTarget {
                    destination: Destination::Internet {
                        host: host.to_string(),
                        port,
                    },
                    mode: ProxyMode::HttpRequest {
                        path: path.to_string(),
                    },
                })
            } else {
                Err(ProxyError::Forbidden(format!(
                    "only *.wispers.link hosts are allowed without --egress-node, got: {host}"
                )))
            }
        }
        Err(Some(e)) => Err(e),
    }
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
/// Send an HTTP error response for a `ProxyError`.
async fn send_proxy_error(stream: &mut TcpStream, error: &ProxyError) -> Result<()> {
    send_error(stream, error.status_code(), &error.to_string()).await
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
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{message}\n"
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_target_basic() {
        let target = parse_proxy_target("http://3.wispers.link/", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(*node_number, 3);
                assert_eq!(*port, 80);
                assert_eq!(path, "/");
            }
            _ => panic!("expected WispersNode + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_with_path() {
        let target = parse_proxy_target("http://42.wispers.link/api/v1/users", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(*node_number, 42);
                assert_eq!(*port, 80);
                assert_eq!(path, "/api/v1/users");
            }
            _ => panic!("expected WispersNode + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_with_port() {
        let target = parse_proxy_target("http://5.wispers.link:8080/test", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(*node_number, 5);
                assert_eq!(*port, 8080);
                assert_eq!(path, "/test");
            }
            _ => panic!("expected WispersNode + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_with_query() {
        let target =
            parse_proxy_target("http://1.wispers.link/search?q=test&page=2", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(*node_number, 1);
                assert_eq!(*port, 80);
                assert_eq!(path, "/search?q=test&page=2");
            }
            _ => panic!("expected WispersNode + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_no_path() {
        let target = parse_proxy_target("http://7.wispers.link", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(*node_number, 7);
                assert_eq!(*port, 80);
                assert_eq!(path, "/");
            }
            _ => panic!("expected WispersNode + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_invalid_no_http() {
        // HTTPS and relative paths should return 400 Bad Request
        let err = parse_proxy_target("https://3.wispers.link/", None).unwrap_err();
        assert_eq!(err.status_code(), 400);

        let err = parse_proxy_target("/path", None).unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn test_parse_proxy_target_forbidden_hostname() {
        // Non-wispers.link hosts without egress should return 403 Forbidden
        let err = parse_proxy_target("http://example.com/", None).unwrap_err();
        assert_eq!(err.status_code(), 403);

        let err = parse_proxy_target("http://google.com/", None).unwrap_err();
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_parse_proxy_target_egress() {
        // Non-wispers.link hosts with egress should return Internet + HttpRequest
        let target = parse_proxy_target("http://example.com/path", Some(3)).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::Internet { host, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(host, "example.com");
                assert_eq!(*port, 80);
                assert_eq!(path, "/path");
            }
            _ => panic!("expected Internet + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_egress_with_port() {
        let target = parse_proxy_target("http://example.com:8080/api", Some(5)).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::Internet { host, port }, ProxyMode::HttpRequest { path }) => {
                assert_eq!(host, "example.com");
                assert_eq!(*port, 8080);
                assert_eq!(path, "/api");
            }
            _ => panic!("expected Internet + HttpRequest"),
        }
    }

    #[test]
    fn test_parse_proxy_target_invalid_node_number() {
        // Invalid node numbers in wispers.link should return 400
        let err = parse_proxy_target("http://abc.wispers.link/", None).unwrap_err();
        assert_eq!(err.status_code(), 400);

        let err = parse_proxy_target("http://0.wispers.link/", None).unwrap_err();
        assert_eq!(err.status_code(), 400);

        let err = parse_proxy_target("http://-1.wispers.link/", None).unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn test_parse_connect_target_internet() {
        // CONNECT to non-wispers host with egress returns Internet + Tunnel
        let target = parse_connect_target("example.com:443", Some(3)).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::Internet { host, port }, ProxyMode::Tunnel) => {
                assert_eq!(host, "example.com");
                assert_eq!(*port, 443);
            }
            _ => panic!("expected Internet + Tunnel"),
        }
    }

    #[test]
    fn test_parse_connect_target_wispers() {
        // CONNECT to wispers.link host returns WispersNode + Tunnel (no egress needed)
        let target = parse_connect_target("3.wispers.link:443", None).unwrap();
        match (&target.destination, &target.mode) {
            (Destination::WispersNode { node_number, port }, ProxyMode::Tunnel) => {
                assert_eq!(*node_number, 3);
                assert_eq!(*port, 443);
            }
            _ => panic!("expected WispersNode + Tunnel"),
        }
    }

    #[test]
    fn test_parse_connect_target_no_egress() {
        // CONNECT to non-wispers host without egress should fail
        let err = parse_connect_target("example.com:443", None).unwrap_err();
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_parse_connect_target_no_port() {
        let err = parse_connect_target("example.com", Some(3)).unwrap_err();
        assert_eq!(err.status_code(), 400);
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
                destination: Destination::WispersNode {
                    node_number: 3,
                    port: 80,
                },
                mode: ProxyMode::HttpRequest {
                    path: "/api/test".to_string(),
                },
            },
            method: "GET".to_string(),
            version: 1,
            headers: vec![
                ("Host".to_string(), "3.wispers.link".to_string()),
                ("User-Agent".to_string(), "test/1.0".to_string()),
            ],
            keep_alive: true,
        };

        let http = build_http_request(&request, "/api/test");
        assert_eq!(
            http,
            "GET /api/test HTTP/1.1\r\nHost: 3.wispers.link\r\nUser-Agent: test/1.0\r\n\r\n"
        );
    }

    #[test]
    fn test_build_http_request_http10() {
        let request = ParsedRequest {
            target: ProxyTarget {
                destination: Destination::WispersNode {
                    node_number: 5,
                    port: 8080,
                },
                mode: ProxyMode::HttpRequest {
                    path: "/".to_string(),
                },
            },
            method: "POST".to_string(),
            version: 0,
            headers: vec![("Host".to_string(), "5.wispers.link:8080".to_string())],
            keep_alive: false,
        };

        let http = build_http_request(&request, "/");
        assert!(http.starts_with("POST / HTTP/1.0\r\n"));
    }
}
