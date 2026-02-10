//! Serving mode - handles hub connection and incoming P2P connections.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use wispers_connect::p2p::P2pError;
use wispers_connect::{
    IncomingConnections, NodeState, QuicConnection, ServingHandle, ServingSession, UdpConnection,
};

use crate::daemon;

/// Port forwarding allowlist configuration.
#[derive(Clone, Debug)]
pub enum AllowedPorts {
    /// Allow FORWARD to any port
    All,
    /// Allow FORWARD only to specific ports
    Whitelist(HashSet<u16>),
}

impl AllowedPorts {
    /// Parse the CLI argument value.
    /// Empty string means allow all ports.
    /// Comma-separated list means allow only those ports.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Ok(AllowedPorts::All);
        }

        let mut ports = HashSet::new();
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let port: u16 = part
                .parse()
                .with_context(|| format!("invalid port number: {}", part))?;
            ports.insert(port);
        }

        if ports.is_empty() {
            Ok(AllowedPorts::All)
        } else {
            Ok(AllowedPorts::Whitelist(ports))
        }
    }

    /// Check if a port is allowed.
    pub fn is_allowed(&self, port: u16) -> bool {
        match self {
            AllowedPorts::All => true,
            AllowedPorts::Whitelist(ports) => ports.contains(&port),
        }
    }
}

pub async fn serve(
    hub_override: Option<&str>,
    profile: &str,
    allowed_ports: Option<AllowedPorts>,
    allow_egress: bool,
) -> Result<()> {
    let storage = super::get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    if node.state() == NodeState::Pending {
        anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
    }

    let cg_id = node.connectivity_group_id().unwrap().to_string();
    let node_number = node.node_number().unwrap();

    // Start UDS daemon server first (so it's available while connecting to hub)
    let daemon = daemon::DaemonServer::bind(&cg_id, node_number)
        .await
        .context("failed to start daemon")?;

    // Share allowed_ports with spawned tasks
    let allowed_ports = Arc::new(allowed_ports);

    println!(
        "Serving node {} in group {} (socket: {:?})",
        node_number,
        cg_id,
        daemon.path()
    );
    if let Some(ref ports) = *allowed_ports {
        match ports {
            AllowedPorts::All => println!("  Port forwarding: all ports allowed"),
            AllowedPorts::Whitelist(set) => {
                let mut ports: Vec<_> = set.iter().collect();
                ports.sort();
                println!(
                    "  Port forwarding: allowed ports {:?}",
                    ports
                );
            }
        }
    } else {
        println!("  Port forwarding: disabled");
    }
    if allow_egress {
        println!("  Internet egress: enabled");
    } else {
        println!("  Internet egress: disabled");
    }

    // Shared state for the serving handle (None until hub connects)
    let handle_state: Arc<RwLock<Option<ServingHandle>>> = Arc::new(RwLock::new(None));

    // Spawn hub connection in background
    let connect_handle_state = handle_state.clone();
    let mut connect_task = tokio::spawn(async move {
        let result: Result<(ServingHandle, ServingSession, IncomingConnections), anyhow::Error> =
            node.start_serving()
                .await
                .map(|(handle, session, incoming)| (handle, session, incoming))
                .context("failed to start serving");

        if let Ok((handle, _session, _)) = &result {
            *connect_handle_state.write().await = Some(handle.clone());
        }
        result
    });

    // Session task (None until hub connects)
    let mut session_task: Option<
        tokio::task::JoinHandle<Result<(), wispers_connect::ServingError>>,
    > = None;

    // Incoming P2P connections receivers
    let mut incoming_udp_rx: Option<tokio::sync::mpsc::Receiver<Result<UdpConnection, P2pError>>> =
        None;
    let mut incoming_quic_rx: Option<
        tokio::sync::mpsc::Receiver<Result<QuicConnection, P2pError>>,
    > = None;

    // Accept daemon client connections, handle hub connection completing
    loop {
        tokio::select! {
            // Hub connection completed
            result = &mut connect_task, if session_task.is_none() => {
                match result {
                    Ok(Ok((handle, session, incoming))) => {
                        println!("Connected to hub");
                        *handle_state.write().await = Some(handle);
                        session_task = Some(tokio::spawn(async move { session.run().await }));
                        incoming_udp_rx = Some(incoming.udp);
                        incoming_quic_rx = Some(incoming.quic);
                    }
                    Ok(Err(e)) => {
                        return Err(e);
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Connect task panicked: {}", e));
                    }
                }
            }

            // Session completed (hub disconnected, error, or shutdown via handle)
            result = async { session_task.as_mut().unwrap().await }, if session_task.is_some() => {
                match result {
                    Ok(Ok(())) => {
                        println!("Session ended normally");
                        break;
                    }
                    Ok(Err(e)) => {
                        return Err(anyhow::anyhow!("Session error: {}", e));
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Session task panicked: {}", e));
                    }
                }
            }

            // Incoming UDP P2P connection
            Some(result) = async {
                match incoming_udp_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok(conn) => {
                        println!("Incoming UDP P2P connection from node {}", conn.peer_node_number);
                        tokio::spawn(handle_udp_connection(conn));
                    }
                    Err(e) => {
                        eprintln!("UDP connection failed: {}", e);
                    }
                }
            }

            // Incoming QUIC P2P connection
            Some(result) = async {
                match incoming_quic_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match result {
                    Ok(conn) => {
                        println!("Incoming QUIC P2P connection from node {}", conn.peer_node_number);
                        let allowed_ports = Arc::clone(&allowed_ports);
                        tokio::spawn(handle_quic_connection(conn, allowed_ports, allow_egress));
                    }
                    Err(e) => {
                        eprintln!("QUIC connection handshake failed: {}", e);
                    }
                }
            }

            // New daemon client connection
            result = daemon.accept() => {
                match result {
                    Ok(stream) => {
                        let client_handle_state = handle_state.clone();
                        tokio::spawn(async move {
                            daemon::handle_client_with_optional_handle(stream, client_handle_state).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to accept daemon connection: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle an incoming UDP P2P connection (respond to pings).
async fn handle_udp_connection(conn: UdpConnection) {
    let peer = conn.peer_node_number;
    println!(
        "  UDP connected to node {} (connection already established)",
        peer
    );

    loop {
        match conn.recv().await {
            Ok(data) => {
                if data == b"ping" {
                    println!("  Received ping from node {}, sending pong", peer);
                    if let Err(e) = conn.send(b"pong") {
                        eprintln!("  Failed to send pong to node {}: {}", peer, e);
                        break;
                    }
                } else {
                    println!("  Received {} bytes from node {}", data.len(), peer);
                }
            }
            Err(e) => {
                println!("  UDP connection to node {} closed: {}", peer, e);
                break;
            }
        }
    }
}

/// Handle an incoming QUIC P2P connection.
async fn handle_quic_connection(
    conn: QuicConnection,
    allowed_ports: Arc<Option<AllowedPorts>>,
    allow_egress: bool,
) {
    let peer = conn.peer_node_number;
    println!(
        "  QUIC connected to node {} (connection already established)",
        peer
    );

    loop {
        match conn.accept_stream().await {
            Ok(stream) => {
                let stream_id = stream.id();
                println!("  Accepted stream {} from node {}", stream_id, peer);
                let allowed_ports = Arc::clone(&allowed_ports);
                tokio::spawn(handle_quic_stream(stream, peer, stream_id, allowed_ports, allow_egress));
            }
            Err(e) => {
                println!("  QUIC connection to node {} closed: {}", peer, e);
                break;
            }
        }
    }
}

/// Handle a single QUIC stream - read command and dispatch.
async fn handle_quic_stream(
    stream: wispers_connect::QuicStream,
    _peer: i32,
    stream_id: u64,
    allowed_ports: Arc<Option<AllowedPorts>>,
    allow_egress: bool,
) {
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf).await {
        Ok(0) => {
            println!("  Stream {} closed by peer before command", stream_id);
            return;
        }
        Ok(n) => n,
        Err(e) => {
            eprintln!("  Stream {} read error: {}", stream_id, e);
            return;
        }
    };

    let data = &buf[..n];

    // Parse command (first line)
    let line = match data.iter().position(|&b| b == b'\n') {
        Some(pos) => &data[..pos],
        None => data,
    };

    match line {
        b"PING" => {
            println!("  Received PING on stream {}, sending PONG", stream_id);
            if let Err(e) = stream.write_all(b"PONG\n").await {
                eprintln!("  Failed to send PONG: {}", e);
            }
            let _ = stream.finish().await;
        }
        cmd if cmd.starts_with(b"FORWARD ") => {
            let port_str = String::from_utf8_lossy(&cmd[8..]);
            match port_str.trim().parse::<u16>() {
                Ok(port) => {
                    println!("  Received FORWARD {} on stream {}", port, stream_id);
                    handle_forward_stream(stream, port, &allowed_ports).await;
                }
                Err(_) => {
                    let _ = stream.write_all(b"ERROR invalid port\n").await;
                    let _ = stream.finish().await;
                }
            }
        }
        cmd if cmd.starts_with(b"CONNECT ") => {
            let target = String::from_utf8_lossy(&cmd[8..]).trim().to_string();
            println!("  Received CONNECT {} on stream {}", target, stream_id);
            handle_connect_stream(stream, &target, allow_egress).await;
        }
        _ => {
            println!(
                "  Unknown command on stream {}: {:?}",
                stream_id,
                String::from_utf8_lossy(line)
            );
            let _ = stream.write_all(b"ERROR unknown command\n").await;
            let _ = stream.finish().await;
        }
    }
}

/// Handle a FORWARD command - connect to local port and relay.
async fn handle_forward_stream(
    stream: wispers_connect::QuicStream,
    port: u16,
    allowed_ports: &Option<AllowedPorts>,
) {
    // Check if port forwarding is allowed
    let allowed = match allowed_ports {
        None => false,
        Some(ports) => ports.is_allowed(port),
    };

    if !allowed {
        println!("  FORWARD to port {} denied (not in allowlist)", port);
        let _ = stream.write_all(b"ERROR port not allowed\n").await;
        let _ = stream.finish().await;
        return;
    }

    let stream = Arc::new(stream);

    // Connect to localhost:port
    let tcp = match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
        Ok(tcp) => {
            if let Err(e) = stream.write_all(b"OK\n").await {
                eprintln!("  Failed to send OK: {}", e);
                return;
            }
            tcp
        }
        Err(e) => {
            let msg = format!("ERROR {}\n", e);
            let _ = stream.write_all(msg.as_bytes()).await;
            let _ = stream.finish().await;
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let stream_read = Arc::clone(&stream);
    let stream_write = Arc::clone(&stream);

    // QUIC -> TCP
    let quic_to_tcp = async move {
        let mut buf = [0u8; 8192];
        loop {
            match stream_read.read(&mut buf).await {
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

    // TCP -> QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream_write.write_all(&buf[..n]).await {
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
        let _ = stream_write.finish().await;
    };

    tokio::join!(quic_to_tcp, tcp_to_quic);
}

/// Handle a CONNECT command - connect to arbitrary host:port and relay.
async fn handle_connect_stream(
    stream: wispers_connect::QuicStream,
    target: &str,
    allow_egress: bool,
) {
    // Check if egress is allowed
    if !allow_egress {
        println!("  CONNECT to {} denied (egress not enabled)", target);
        let _ = stream.write_all(b"ERROR egress not allowed\n").await;
        let _ = stream.finish().await;
        return;
    }

    // Parse host:port
    let (host, port) = match parse_host_port(target) {
        Some(hp) => hp,
        None => {
            println!("  CONNECT invalid target: {}", target);
            let _ = stream.write_all(b"ERROR invalid target format\n").await;
            let _ = stream.finish().await;
            return;
        }
    };

    let stream = Arc::new(stream);

    // Connect to remote host:port
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(tcp) => {
            if let Err(e) = stream.write_all(b"OK\n").await {
                eprintln!("  Failed to send OK: {}", e);
                return;
            }
            tcp
        }
        Err(e) => {
            let msg = format!("ERROR {}\n", e);
            let _ = stream.write_all(msg.as_bytes()).await;
            let _ = stream.finish().await;
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let stream_read = Arc::clone(&stream);
    let stream_write = Arc::clone(&stream);

    // QUIC -> TCP
    let quic_to_tcp = async move {
        let mut buf = [0u8; 8192];
        loop {
            match stream_read.read(&mut buf).await {
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

    // TCP -> QUIC
    let tcp_to_quic = async move {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream_write.write_all(&buf[..n]).await {
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
        let _ = stream_write.finish().await;
    };

    tokio::join!(quic_to_tcp, tcp_to_quic);
}

/// Parse a "host:port" string into (host, port).
fn parse_host_port(target: &str) -> Option<(String, u16)> {
    // Find the last colon (to handle IPv6 addresses like [::1]:8080)
    let colon_pos = target.rfind(':')?;

    let host = &target[..colon_pos];
    let port_str = &target[colon_pos + 1..];

    // Host must not be empty
    if host.is_empty() {
        return None;
    }

    // Parse port
    let port: u16 = port_str.parse().ok()?;

    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_ports_parse_empty() {
        let ports = AllowedPorts::parse("").unwrap();
        assert!(matches!(ports, AllowedPorts::All));
        assert!(ports.is_allowed(80));
        assert!(ports.is_allowed(443));
        assert!(ports.is_allowed(8080));
    }

    #[test]
    fn test_allowed_ports_parse_single() {
        let ports = AllowedPorts::parse("80").unwrap();
        assert!(ports.is_allowed(80));
        assert!(!ports.is_allowed(443));
    }

    #[test]
    fn test_allowed_ports_parse_multiple() {
        let ports = AllowedPorts::parse("80,443,8080").unwrap();
        assert!(ports.is_allowed(80));
        assert!(ports.is_allowed(443));
        assert!(ports.is_allowed(8080));
        assert!(!ports.is_allowed(22));
    }

    #[test]
    fn test_allowed_ports_parse_with_spaces() {
        let ports = AllowedPorts::parse("80, 443, 8080").unwrap();
        assert!(ports.is_allowed(80));
        assert!(ports.is_allowed(443));
        assert!(ports.is_allowed(8080));
    }

    #[test]
    fn test_allowed_ports_parse_invalid() {
        assert!(AllowedPorts::parse("abc").is_err());
        assert!(AllowedPorts::parse("80,abc").is_err());
        assert!(AllowedPorts::parse("99999").is_err()); // > u16::MAX
    }

    #[test]
    fn test_parse_host_port_basic() {
        let (host, port) = parse_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_localhost() {
        let (host, port) = parse_host_port("localhost:8080").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv4() {
        let (host, port) = parse_host_port("192.168.1.1:80").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(parse_host_port("example.com").is_none()); // no port
        assert!(parse_host_port(":8080").is_none()); // no host
        assert!(parse_host_port("example.com:abc").is_none()); // invalid port
        assert!(parse_host_port("example.com:99999").is_none()); // port too large
    }
}
