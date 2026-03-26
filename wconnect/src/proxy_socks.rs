//! SOCKS5 proxy for accessing services on remote nodes.
//!
//! This module implements a SOCKS5 proxy (RFC 1928) that allows clients
//! to access services running on nodes in the connectivity group using
//! hostnames like `3.wispers.link`.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wispers_connect::{Node, NodeState};

use crate::proxy_common::{
    CLEANUP_INTERVAL, ConnectionPool, ProxyError, REQUEST_TIMEOUT, open_stream_with_command,
    parse_wispers_host,
};

// SOCKS5 constants
const SOCKS_VERSION: u8 = 0x05;
const AUTH_NOAUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// SOCKS5 reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Run the SOCKS5 proxy server.
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
            "Node must be activated to use SOCKS5 proxy. Current state: {:?}",
            node.state()
        );
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind to {}", bind_addr))?;

    println!("SOCKS5 proxy listening on {}", bind_addr);
    if let Some(egress) = egress_node {
        println!("  Internet egress: enabled via node {}", egress);
        println!(
            "Example: curl --proxy socks5h://{} https://example.com/",
            bind_addr
        );
    } else {
        println!("  Internet egress: disabled (wispers.link only)");
        println!(
            "Example: curl --proxy socks5h://{} http://3.wispers.link/",
            bind_addr
        );
    }
    println!("  (Use socks5h:// so the proxy resolves hostnames, not curl)");

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
                    if let Err(e) = handle_client_connection(stream, node, pool, egress_node).await
                    {
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

/// Parsed SOCKS5 connect request.
#[derive(Debug)]
struct ConnectRequest {
    /// Target hostname or IP address
    host: String,
    /// Target port
    port: u16,
}

/// Handle a single SOCKS5 client connection.
async fn handle_client_connection(
    mut stream: TcpStream,
    node: Arc<Node>,
    pool: ConnectionPool,
    egress_node: Option<i32>,
) -> Result<()> {
    let peer = stream.peer_addr()?;

    // Step 1: Handle authentication negotiation
    if let Err(e) = handle_auth(&mut stream).await {
        eprintln!("  Auth failed: {}", e);
        return Ok(());
    }

    // Step 2: Handle connect request
    let request = match handle_connect_request(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            eprintln!("  Connect request failed: {}", e);
            return Ok(());
        }
    };

    println!("  CONNECT {}:{}", request.host, request.port);

    // Step 3: Route based on destination
    match route_connection(&mut stream, &node, &pool, &request, egress_node).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("  Routing failed: {}", e);
        }
    }

    println!("Connection from {} closed", peer);
    Ok(())
}

/// Handle SOCKS5 authentication negotiation.
async fn handle_auth(stream: &mut TcpStream) -> Result<(), ProxyError> {
    // Read client greeting: VER | NMETHODS | METHODS...
    let mut buf = [0u8; 258]; // max: 1 + 1 + 256 methods
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read auth request: {}", e)))?;

    if n < 2 {
        return Err(ProxyError::BadRequest("auth request too short".to_string()));
    }

    let version = buf[0];
    if version != SOCKS_VERSION {
        return Err(ProxyError::BadRequest(format!(
            "unsupported SOCKS version: {}",
            version
        )));
    }

    let nmethods = buf[1] as usize;
    if n < 2 + nmethods {
        return Err(ProxyError::BadRequest("auth request truncated".to_string()));
    }

    // Check if NOAUTH (0x00) is offered
    let methods = &buf[2..2 + nmethods];
    if !methods.contains(&AUTH_NOAUTH) {
        // Send "no acceptable methods" response
        let _ = stream.write_all(&[SOCKS_VERSION, 0xFF]).await;
        return Err(ProxyError::BadRequest(
            "client does not support NOAUTH".to_string(),
        ));
    }

    // Accept NOAUTH
    stream
        .write_all(&[SOCKS_VERSION, AUTH_NOAUTH])
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to send auth response: {}", e)))?;

    Ok(())
}

/// Handle SOCKS5 connect request.
async fn handle_connect_request(stream: &mut TcpStream) -> Result<ConnectRequest, ProxyError> {
    // Read request header: VER | CMD | RSV | ATYP
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read request header: {}", e)))?;

    let version = header[0];
    let cmd = header[1];
    // header[2] is reserved
    let atyp = header[3];

    if version != SOCKS_VERSION {
        return Err(ProxyError::BadRequest(format!(
            "unsupported SOCKS version: {}",
            version
        )));
    }

    // Only support CONNECT command
    if cmd != CMD_CONNECT {
        send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await;
        return Err(ProxyError::BadRequest(format!(
            "unsupported command: {}",
            cmd
        )));
    }

    // Parse destination address based on address type
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await.map_err(|e| {
                ProxyError::BadRequest(format!("failed to read IPv4 address: {}", e))
            })?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.map_err(|e| {
                ProxyError::BadRequest(format!("failed to read domain length: {}", e))
            })?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|e| ProxyError::BadRequest(format!("failed to read domain: {}", e)))?;
            String::from_utf8(domain)
                .map_err(|_| ProxyError::BadRequest("invalid domain name encoding".to_string()))?
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await.map_err(|e| {
                ProxyError::BadRequest(format!("failed to read IPv6 address: {}", e))
            })?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        _ => {
            send_reply(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED).await;
            return Err(ProxyError::BadRequest(format!(
                "unsupported address type: {}",
                atyp
            )));
        }
    };

    // Read port (2 bytes, big-endian)
    let mut port_buf = [0u8; 2];
    stream
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| ProxyError::BadRequest(format!("failed to read port: {}", e)))?;
    let port = u16::from_be_bytes(port_buf);

    Ok(ConnectRequest { host, port })
}

/// Route the connection based on destination hostname.
async fn route_connection(
    stream: &mut TcpStream,
    node: &Node,
    pool: &ConnectionPool,
    request: &ConnectRequest,
    egress_node: Option<i32>,
) -> Result<()> {
    // Check if it's a wispers.link hostname
    match parse_wispers_host(&request.host) {
        Ok(wispers_host) => {
            // Wispers-local: connect to node via FORWARD
            forward_to_node(stream, node, pool, wispers_host.node_number, request.port).await
        }
        Err(None) => {
            // Not a wispers.link hostname - try egress if configured
            match egress_node {
                Some(egress) => {
                    println!("  Egress via node {}", egress);
                    egress_to_node(stream, node, pool, egress, &request.host, request.port).await
                }
                None => {
                    println!("  Rejected: {} (egress not enabled)", request.host);
                    send_reply(stream, REP_NOT_ALLOWED).await;
                    Err(anyhow::anyhow!("egress not enabled"))
                }
            }
        }
        Err(Some(e)) => {
            // Invalid wispers.link hostname
            println!("  Rejected: {} ({})", request.host, e);
            send_reply(stream, REP_GENERAL_FAILURE).await;
            Err(anyhow::anyhow!("{}", e))
        }
    }
}

/// Forward connection to a wispers node using FORWARD command.
async fn forward_to_node(
    stream: &mut TcpStream,
    node: &Node,
    pool: &ConnectionPool,
    target_node: i32,
    port: u16,
) -> Result<()> {
    // Get or create QUIC connection to target node
    let quic_conn =
        match tokio::time::timeout(REQUEST_TIMEOUT, pool.get_or_connect(node, target_node)).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                println!("  Failed to connect to node {}: {}", target_node, e);
                send_reply(stream, REP_HOST_UNREACHABLE).await;
                return Err(anyhow::anyhow!("failed to connect to node: {}", e));
            }
            Err(_) => {
                println!("  Timeout connecting to node {}", target_node);
                send_reply(stream, REP_TTL_EXPIRED).await;
                return Err(anyhow::anyhow!("connection timeout"));
            }
        };

    // Open stream and send FORWARD command
    let command = format!("FORWARD {}\n", port);
    let quic_stream = match open_stream_with_command(&quic_conn, &command).await {
        Ok(s) => s,
        Err(e) => {
            println!("  FORWARD failed: {}", e);
            send_reply(stream, REP_CONNECTION_REFUSED).await;
            return Err(anyhow::anyhow!("{}", e));
        }
    };

    // Send success reply to client
    send_reply(stream, REP_SUCCESS).await;

    // Bidirectional relay
    relay(stream, quic_stream).await;

    Ok(())
}

/// Egress connection through a wispers node using CONNECT command.
async fn egress_to_node(
    stream: &mut TcpStream,
    node: &Node,
    pool: &ConnectionPool,
    egress_node: i32,
    host: &str,
    port: u16,
) -> Result<()> {
    // Get or create QUIC connection to egress node
    let quic_conn =
        match tokio::time::timeout(REQUEST_TIMEOUT, pool.get_or_connect(node, egress_node)).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                println!("  Failed to connect to egress node {}: {}", egress_node, e);
                send_reply(stream, REP_HOST_UNREACHABLE).await;
                return Err(anyhow::anyhow!("failed to connect to egress node: {}", e));
            }
            Err(_) => {
                println!("  Timeout connecting to egress node {}", egress_node);
                send_reply(stream, REP_TTL_EXPIRED).await;
                return Err(anyhow::anyhow!("connection timeout"));
            }
        };

    // Open stream and send CONNECT command
    let command = format!("CONNECT {}:{}\n", host, port);
    let quic_stream = match open_stream_with_command(&quic_conn, &command).await {
        Ok(s) => s,
        Err(e) => {
            println!("  CONNECT failed: {}", e);
            send_reply(stream, REP_CONNECTION_REFUSED).await;
            return Err(anyhow::anyhow!("{}", e));
        }
    };

    // Send success reply to client
    send_reply(stream, REP_SUCCESS).await;

    // Bidirectional relay
    relay(stream, quic_stream).await;

    Ok(())
}

/// Bidirectional relay between TCP stream and QUIC stream.
async fn relay(tcp_stream: &mut TcpStream, quic_stream: wispers_connect::QuicStream) {
    let quic_stream = Arc::new(quic_stream);
    let (mut tcp_read, mut tcp_write) = tcp_stream.split();

    let quic_read = Arc::clone(&quic_stream);
    let quic_write = Arc::clone(&quic_stream);

    // TCP -> QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = quic_write.write_all(&buf[..n]).await {
                        eprintln!("  QUIC write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("  TCP read error: {}", e);
                    break;
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
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = tcp_write.write_all(&buf[..n]).await {
                        eprintln!("  TCP write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("  QUIC read error: {}", e);
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    tokio::join!(tcp_to_quic, quic_to_tcp);
}

/// Send a SOCKS5 reply to the client.
async fn send_reply(stream: &mut TcpStream, reply_code: u8) {
    // Reply format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    // We use IPv4 address type with 0.0.0.0:0 as bind address
    let reply = [
        SOCKS_VERSION, // VER
        reply_code,    // REP
        0x00,          // RSV
        ATYP_IPV4,     // ATYP
        0,
        0,
        0,
        0, // BND.ADDR (0.0.0.0)
        0,
        0, // BND.PORT (0)
    ];
    let _ = stream.write_all(&reply).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_constants() {
        assert_eq!(SOCKS_VERSION, 0x05);
        assert_eq!(AUTH_NOAUTH, 0x00);
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
    }

    #[test]
    fn test_reply_codes() {
        assert_eq!(REP_SUCCESS, 0x00);
        assert_eq!(REP_GENERAL_FAILURE, 0x01);
        assert_eq!(REP_NOT_ALLOWED, 0x02);
        assert_eq!(REP_CONNECTION_REFUSED, 0x05);
        assert_eq!(REP_TTL_EXPIRED, 0x06);
        assert_eq!(REP_COMMAND_NOT_SUPPORTED, 0x07);
        assert_eq!(REP_ADDRESS_TYPE_NOT_SUPPORTED, 0x08);
    }

    // Helper to build auth request
    fn build_auth_request(methods: &[u8]) -> Vec<u8> {
        let mut data = vec![SOCKS_VERSION, methods.len() as u8];
        data.extend_from_slice(methods);
        data
    }

    // Helper to build connect request with IPv4
    fn build_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut data = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
        data.extend_from_slice(&ip);
        data.extend_from_slice(&port.to_be_bytes());
        data
    }

    // Helper to build connect request with domain
    fn build_connect_domain(domain: &str, port: u16) -> Vec<u8> {
        let mut data = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
        data.push(domain.len() as u8);
        data.extend_from_slice(domain.as_bytes());
        data.extend_from_slice(&port.to_be_bytes());
        data
    }

    // Helper to build connect request with IPv6
    fn build_connect_ipv6(ip: [u8; 16], port: u16) -> Vec<u8> {
        let mut data = vec![SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
        data.extend_from_slice(&ip);
        data.extend_from_slice(&port.to_be_bytes());
        data
    }

    // ===== Auth parsing tests =====

    #[test]
    fn test_auth_response_noauth() {
        // Expected response when NOAUTH is accepted
        let expected_response = [SOCKS_VERSION, AUTH_NOAUTH];
        assert_eq!(expected_response, [0x05, 0x00]);
    }

    #[test]
    fn test_auth_request_multiple_methods() {
        // Client offers multiple methods including NOAUTH
        let data = build_auth_request(&[0x02, AUTH_NOAUTH, 0x01]); // GSSAPI, NOAUTH, USERNAME
        assert_eq!(data, [0x05, 0x03, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_auth_request_structure() {
        // Verify auth request format: VER | NMETHODS | METHODS...
        let req = build_auth_request(&[AUTH_NOAUTH]);
        assert_eq!(req[0], SOCKS_VERSION);
        assert_eq!(req[1], 1); // nmethods
        assert_eq!(req[2], AUTH_NOAUTH);
    }

    // ===== Connect request parsing tests =====

    #[test]
    fn test_connect_request_ipv4_structure() {
        let req = build_connect_ipv4([192, 168, 1, 1], 8080);
        assert_eq!(req[0], SOCKS_VERSION);
        assert_eq!(req[1], CMD_CONNECT);
        assert_eq!(req[2], 0x00); // reserved
        assert_eq!(req[3], ATYP_IPV4);
        assert_eq!(&req[4..8], &[192, 168, 1, 1]);
        assert_eq!(&req[8..10], &8080u16.to_be_bytes());
    }

    #[test]
    fn test_connect_request_domain_structure() {
        let req = build_connect_domain("example.com", 443);
        assert_eq!(req[0], SOCKS_VERSION);
        assert_eq!(req[1], CMD_CONNECT);
        assert_eq!(req[2], 0x00); // reserved
        assert_eq!(req[3], ATYP_DOMAIN);
        assert_eq!(req[4], 11); // "example.com".len()
        assert_eq!(&req[5..16], b"example.com");
        assert_eq!(&req[16..18], &443u16.to_be_bytes());
    }

    #[test]
    fn test_connect_request_wispers_domain() {
        let req = build_connect_domain("3.wispers.link", 80);
        assert_eq!(req[4], 14); // "3.wispers.link".len()
        assert_eq!(&req[5..19], b"3.wispers.link");
    }

    #[test]
    fn test_connect_request_ipv6_structure() {
        // IPv6 ::1
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let req = build_connect_ipv6(ip, 8080);
        assert_eq!(req[0], SOCKS_VERSION);
        assert_eq!(req[1], CMD_CONNECT);
        assert_eq!(req[2], 0x00); // reserved
        assert_eq!(req[3], ATYP_IPV6);
        assert_eq!(&req[4..20], &ip);
        assert_eq!(&req[20..22], &8080u16.to_be_bytes());
    }

    // ===== Reply structure tests =====

    #[test]
    fn test_reply_structure() {
        // Reply format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
        let expected_success = [
            SOCKS_VERSION, // VER
            REP_SUCCESS,   // REP
            0x00,          // RSV
            ATYP_IPV4,     // ATYP
            0,
            0,
            0,
            0, // BND.ADDR
            0,
            0, // BND.PORT
        ];
        assert_eq!(expected_success.len(), 10);
        assert_eq!(expected_success[0], 0x05);
        assert_eq!(expected_success[1], 0x00);
    }

    #[test]
    fn test_reply_error_codes() {
        // Verify error reply has same structure
        let error_reply = [
            SOCKS_VERSION,
            REP_CONNECTION_REFUSED,
            0x00,
            ATYP_IPV4,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(error_reply[1], 0x05); // connection refused
    }

    // ===== Port encoding tests =====

    #[test]
    fn test_port_big_endian() {
        // Port 8080 = 0x1F90
        let port: u16 = 8080;
        let bytes = port.to_be_bytes();
        assert_eq!(bytes, [0x1F, 0x90]);

        // Port 443 = 0x01BB
        let port: u16 = 443;
        let bytes = port.to_be_bytes();
        assert_eq!(bytes, [0x01, 0xBB]);

        // Port 80 = 0x0050
        let port: u16 = 80;
        let bytes = port.to_be_bytes();
        assert_eq!(bytes, [0x00, 0x50]);
    }

    // ===== Command code tests =====

    #[test]
    fn test_unsupported_commands() {
        // BIND command
        const CMD_BIND: u8 = 0x02;
        // UDP ASSOCIATE command
        const CMD_UDP_ASSOCIATE: u8 = 0x03;

        // These should not be confused with CONNECT
        assert_ne!(CMD_BIND, CMD_CONNECT);
        assert_ne!(CMD_UDP_ASSOCIATE, CMD_CONNECT);
    }

    // ===== IPv4 formatting tests =====

    #[test]
    fn test_ipv4_address_formatting() {
        let addr = [192u8, 168, 1, 1];
        let formatted = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        assert_eq!(formatted, "192.168.1.1");

        let addr = [127u8, 0, 0, 1];
        let formatted = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        assert_eq!(formatted, "127.0.0.1");
    }

    // ===== IPv6 formatting tests =====

    #[test]
    fn test_ipv6_address_formatting() {
        use std::net::Ipv6Addr;

        // ::1 (loopback)
        let addr = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let formatted = Ipv6Addr::from(addr).to_string();
        assert_eq!(formatted, "::1");

        // 2001:db8::1
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let formatted = Ipv6Addr::from(addr).to_string();
        assert_eq!(formatted, "2001:db8::1");

        // fe80::1 (link-local)
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let formatted = Ipv6Addr::from(addr).to_string();
        assert_eq!(formatted, "fe80::1");

        // Full address: 2001:db8:85a3:0:0:8a2e:370:7334
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];
        let formatted = Ipv6Addr::from(addr).to_string();
        assert_eq!(formatted, "2001:db8:85a3::8a2e:370:7334");
    }

    // ===== Domain validation tests =====

    #[test]
    fn test_wispers_domain_parsing() {
        // These should be recognized as wispers domains
        let result = parse_wispers_host("3.wispers.link");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().node_number, 3);

        let result = parse_wispers_host("123.wispers.link");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().node_number, 123);
    }

    #[test]
    fn test_non_wispers_domain() {
        // These should NOT be recognized as wispers domains
        let result = parse_wispers_host("example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().is_none()); // None means not a wispers domain

        let result = parse_wispers_host("google.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().is_none());
    }

    #[test]
    fn test_invalid_wispers_domain() {
        // Invalid node number
        let result = parse_wispers_host("abc.wispers.link");
        assert!(result.is_err());
        assert!(result.unwrap_err().is_some()); // Some error means malformed wispers domain
    }
}
