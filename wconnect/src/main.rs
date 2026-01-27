mod daemon;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use wispers_connect::{FileNodeStateStore, NodeStateStage, NodeStorage};

#[derive(Parser)]
#[command(name = "wconnect")]
#[command(about = "CLI for Wispers Connect nodes")]
struct Cli {
    /// Override hub address (for testing)
    #[arg(long, env = "WCONNECT_HUB")]
    hub: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register this node using a registration token
    Register {
        /// The registration token from the integrator
        token: String,
    },
    /// Activate this node by pairing with an endorser
    Activate {
        /// The pairing code from the endorser (format: "node_number-secret")
        pairing_code: String,
    },
    /// List nodes in the connectivity group
    Nodes,
    /// Show current registration status
    Status,
    /// Clear stored credentials and state
    Logout,
    /// Start serving and handle incoming requests
    Serve {
        /// Detach and run as a background daemon
        #[arg(short = 'd', long)]
        daemon: bool,

        /// Stop a running daemon
        #[arg(long)]
        stop: bool,
    },
    /// Get a pairing code to endorse a new node (requires running daemon)
    GetPairingCode,
    /// Ping another node via P2P connection
    Ping {
        /// The node number to ping
        node_number: i32,

        /// Use QUIC transport (reliable streams) instead of UDP (datagrams)
        #[arg(long)]
        quic: bool,
    },
}

/// Read registration info synchronously (for use before tokio starts).
fn read_registration_sync() -> Result<(String, i32)> {
    let storage = get_storage(None)?;
    let reg = storage
        .read_registration("unused", None::<String>)
        .context("failed to read registration")?
        .context("not registered")?;

    Ok((reg.connectivity_group_id.to_string(), reg.node_number))
}

/// Stop a running daemon by sending shutdown command via socket.
fn stop_daemon(_hub_override: Option<&str>) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let (cg_id, node_number) = read_registration_sync()?;
    let socket_path = daemon::socket_path(&cg_id, node_number);

    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("daemon not running (socket {:?})", socket_path))?;

    // Send shutdown command
    writeln!(stream, r#"{{"cmd":"shutdown"}}"#)?;
    stream.flush()?;

    // Read response
    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    if response.contains("\"ok\":true") {
        println!("Daemon stopped.");
        Ok(())
    } else {
        anyhow::bail!("Failed to stop daemon: {}", response.trim());
    }
}

/// Daemonize the process before starting tokio.
fn daemonize_serve(_hub_override: Option<&str>) -> Result<()> {
    use daemonize::Daemonize;
    use std::fs::{self, File};

    let (cg_id, node_number) = read_registration_sync()?;

    // Create log directory
    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(".wconnect")
        .join("logs");
    fs::create_dir_all(&log_dir).context("failed to create log directory")?;

    let log_path = log_dir.join(format!("{}-{}.log", cg_id, node_number));
    let log_file = File::create(&log_path)
        .with_context(|| format!("failed to create log file {:?}", log_path))?;

    println!("Daemonizing, logging to {:?}", log_path);

    let daemonize = Daemonize::new()
        .stdout(log_file.try_clone()?)
        .stderr(log_file);

    daemonize.start().context("failed to daemonize")?;
    Ok(())
}

fn get_storage(hub_override: Option<&str>) -> Result<NodeStorage<FileNodeStateStore>> {
    let store = FileNodeStateStore::with_app_name("wconnect")
        .context("could not determine config directory")?;
    let storage = NodeStorage::new(store);
    if let Some(addr) = hub_override {
        storage.override_hub_addr(addr);
    }
    Ok(storage)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub_override: Option<String> = cli.hub.clone();

    // Handle serve --stop synchronously (no need for tokio)
    if let Command::Serve { stop: true, .. } = &cli.command {
        return stop_daemon(hub_override.as_deref());
    }

    // Handle serve --daemon: daemonize before starting tokio
    if let Command::Serve { daemon: true, .. } = &cli.command {
        daemonize_serve(hub_override.as_deref())?;
    }

    // Start tokio runtime and run async main
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?
        .block_on(async_main(cli.command, hub_override))
}

async fn async_main(command: Command, hub_override: Option<String>) -> Result<()> {
    let hub_override = hub_override.as_deref();
    match command {
        Command::Register { token } => register(hub_override, &token).await,
        Command::Activate { pairing_code } => activate(hub_override, &pairing_code).await,
        Command::Nodes => nodes(hub_override).await,
        Command::Status => status(hub_override).await,
        Command::Logout => logout(hub_override).await,
        Command::Serve { daemon: _, stop: _ } => serve(hub_override).await,
        Command::GetPairingCode => get_pairing_code(hub_override).await,
        Command::Ping { node_number, quic } => ping(hub_override, node_number, quic).await,
    }
}

async fn register(hub_override: Option<&str>, token: &str) -> Result<()> {
    let storage = get_storage(hub_override)?;

    // TODO: remove app/profile namespaces later
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    let pending = match stage {
        NodeStateStage::Pending(p) => p,
        NodeStateStage::Registered(r) => {
            let reg = r.registration();
            anyhow::bail!(
                "Already registered as node {} in group {}. Use 'wconnect logout' to clear.",
                reg.node_number,
                reg.connectivity_group_id
            );
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            anyhow::bail!(
                "Already activated as node {} in group {}. Use 'wconnect logout' to clear.",
                reg.node_number,
                reg.connectivity_group_id
            );
        }
    };

    println!("Registering with token {}...", token);

    let registered = pending
        .register(token)
        .await
        .context("registration failed")?;

    let reg = registered.registration();
    println!("Registration successful!");
    println!("  Connectivity group: {}", reg.connectivity_group_id);
    println!("  Node number: {}", reg.node_number);
    Ok(())
}

async fn activate(hub_override: Option<&str>, pairing_code: &str) -> Result<()> {
    use wispers_connect::PairingCode;

    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    let registered = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => r,
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            anyhow::bail!(
                "Already activated as node {} in group {}.",
                reg.node_number,
                reg.connectivity_group_id
            );
        }
    };

    // Parse pairing code to check for self-endorsement
    let parsed_code = PairingCode::parse(pairing_code)
        .context("invalid pairing code format")?;

    let our_node_number = registered.registration().node_number;
    if parsed_code.node_number == our_node_number {
        anyhow::bail!(
            "Cannot activate using your own pairing code (self-endorsement). \
             You need a pairing code from a different node."
        );
    }

    println!("Activating with pairing code {}...", pairing_code);

    let activated = registered
        .activate(pairing_code)
        .await
        .context("activation failed")?;

    let reg = activated.registration();
    println!("Activation successful!");
    println!("  Connectivity group: {}", reg.connectivity_group_id);
    println!("  Node number: {}", reg.node_number);
    println!("  Roster has {} nodes", activated.roster().nodes.len());
    Ok(())
}

async fn nodes(hub_override: Option<&str>) -> Result<()> {
    use std::collections::HashSet;

    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    // Get nodes from hub and optionally the roster (if activated)
    let (reg, nodes, roster_nodes) = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => {
            let reg = r.registration().clone();
            let nodes = r.list_nodes().await.context("failed to list nodes")?;
            (reg, nodes, HashSet::new())
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration().clone();
            let nodes = a.list_nodes().await.context("failed to list nodes")?;
            let roster_nodes: HashSet<i32> = a
                .roster()
                .nodes
                .iter()
                .filter(|n| !n.revoked)
                .map(|n| n.node_number)
                .collect();
            (reg, nodes, roster_nodes)
        }
    };

    if nodes.is_empty() {
        println!("No nodes in connectivity group.");
    } else {
        println!("Nodes in connectivity group {}:", reg.connectivity_group_id);
        for node in nodes {
            let name = if node.name.is_empty() {
                "(unnamed)".to_string()
            } else {
                node.name
            };

            let mut tags = Vec::new();
            if node.node_number == reg.node_number {
                tags.push("you");
            }
            if !roster_nodes.is_empty() {
                if roster_nodes.contains(&node.node_number) {
                    tags.push("activated");
                } else {
                    tags.push("not activated");
                }
            }

            let last_seen = format_last_seen(node.last_seen_at_millis);

            let tags_str = if tags.is_empty() {
                String::new()
            } else {
                format!(" ({})", tags.join(", "))
            };

            println!("  {}: {}{} - {}", node.node_number, name, tags_str, last_seen);
        }
    }
    Ok(())
}

fn format_last_seen(millis: i64) -> String {
    if millis == 0 {
        return "never connected".to_string();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let ago_ms = now - millis;
    if ago_ms < 0 {
        return "connected just now".to_string();
    }

    let ago_secs = ago_ms / 1000;
    if ago_secs < 60 {
        return "connected just now".to_string();
    }

    let ago_mins = ago_secs / 60;
    if ago_mins < 60 {
        return format!("connected {}m ago", ago_mins);
    }

    let ago_hours = ago_mins / 60;
    if ago_hours < 24 {
        return format!("connected {}h ago", ago_hours);
    }

    let ago_days = ago_hours / 24;
    format!("connected {}d ago", ago_days)
}

async fn status(hub_override: Option<&str>) -> Result<()> {
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    match stage {
        NodeStateStage::Pending(_) => {
            println!("Not registered.");
        }
        NodeStateStage::Registered(r) => {
            let reg = r.registration();
            println!("Registered (not yet activated):");
            println!("  Connectivity group: {}", reg.connectivity_group_id);
            println!("  Node number: {}", reg.node_number);
            print_daemon_status(&reg.connectivity_group_id.to_string(), reg.node_number).await;
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            println!("Activated:");
            println!("  Connectivity group: {}", reg.connectivity_group_id);
            println!("  Node number: {}", reg.node_number);
            print_daemon_status(&reg.connectivity_group_id.to_string(), reg.node_number).await;
        }
    }
    Ok(())
}

async fn print_daemon_status(cg_id: &str, node_number: i32) {
    match daemon::DaemonClient::connect(cg_id, node_number).await {
        Ok(mut client) => {
            match client.request(&daemon::Request::Status).await {
                Ok(daemon::Response::Success { data: daemon::ResponseData::Status(s), .. }) => {
                    println!("  Daemon: running (connected: {})", s.connected);
                    if let Some(endorsing) = s.endorsing {
                        match endorsing {
                            daemon::EndorsingData::AwaitingPairNode => {
                                println!("  Endorsing: awaiting pair node");
                            }
                            daemon::EndorsingData::AwaitingCosign { new_node_number } => {
                                println!("  Endorsing: awaiting cosign for node {}", new_node_number);
                            }
                        }
                    }
                }
                _ => {
                    println!("  Daemon: running (status unavailable)");
                }
            }
        }
        Err(_) => {
            println!("  Daemon: not running");
        }
    }
}

async fn logout(hub_override: Option<&str>) -> Result<()> {
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    stage.logout().await.context("failed to logout")?;
    println!("Logged out.");
    Ok(())
}

async fn serve(hub_override: Option<&str>) -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wispers_connect::p2p::P2pError;
    use wispers_connect::{IncomingConnections, QuicConnection, UdpConnection, ServingHandle, ServingSession};
    type IncomingResult = Option<IncomingConnections>;

    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    // Get registration info first (before connecting to hub)
    let (cg_id, node_number) = match &stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => {
            let reg = r.registration();
            (reg.connectivity_group_id.to_string(), reg.node_number)
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            (reg.connectivity_group_id.to_string(), reg.node_number)
        }
    };

    // Start UDS daemon server first (so it's available while connecting to hub)
    let daemon = daemon::DaemonServer::bind(&cg_id, node_number)
        .await
        .context("failed to start daemon")?;

    println!(
        "Serving node {} in group {} (socket: {:?})",
        node_number,
        cg_id,
        daemon.path()
    );

    // Shared state for the serving handle (None until hub connects)
    let handle_state: Arc<RwLock<Option<ServingHandle>>> = Arc::new(RwLock::new(None));

    // Spawn hub connection in background
    let connect_handle_state = handle_state.clone();
    let mut connect_task = tokio::spawn(async move {
        let result: Result<(ServingHandle, ServingSession, IncomingResult), anyhow::Error> = match stage {
            NodeStateStage::Pending(_) => unreachable!(),
            NodeStateStage::Registered(r) => {
                r.start_serving()
                    .await
                    .map(|(handle, session, incoming_rx)| (handle, session, incoming_rx))
                    .context("failed to start serving")
            }
            NodeStateStage::Activated(a) => {
                a.start_serving()
                    .await
                    .map(|(handle, session, incoming_rx)| (handle, session, incoming_rx))
                    .context("failed to start serving")
            }
        };

        if let Ok((handle, _session, _)) = &result {
            *connect_handle_state.write().await = Some(handle.clone());
        }
        result
    });

    // Session task (None until hub connects)
    let mut session_task: Option<tokio::task::JoinHandle<Result<(), wispers_connect::ServingError>>> = None;
    // Incoming P2P connections receivers (None until hub connects, stays None for Registered state)
    let mut incoming_udp_rx: Option<tokio::sync::mpsc::Receiver<Result<UdpConnection, P2pError>>> = None;
    let mut incoming_quic_rx: Option<tokio::sync::mpsc::Receiver<Result<QuicConnection, P2pError>>> = None;

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
                        if let Some(inc) = incoming {
                            incoming_udp_rx = Some(inc.udp);
                            incoming_quic_rx = Some(inc.quic);
                            println!("P2P connections enabled (activated node)");
                        }
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
                        tokio::spawn(handle_quic_connection(conn));
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
async fn handle_udp_connection(conn: wispers_connect::UdpConnection) {
    let peer = conn.peer_node_number;
    println!("  UDP connected to node {} (connection already established)", peer);

    // Handle messages
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

/// Handle an incoming QUIC P2P connection (respond to stream pings).
async fn handle_quic_connection(conn: wispers_connect::QuicConnection) {
    let peer = conn.peer_node_number;
    println!("  QUIC connected to node {} (connection already established)", peer);

    // Accept streams and respond to pings
    loop {
        match conn.accept_stream().await {
            Ok(stream) => {
                println!("  Accepted stream {} from node {}", stream.id(), peer);

                // Read message
                let mut buf = [0u8; 1024];
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        println!("  Stream {} closed by peer", stream.id());
                    }
                    Ok(n) => {
                        let data = &buf[..n];
                        if data == b"ping" {
                            println!("  Received ping on stream {}, sending pong", stream.id());
                            if let Err(e) = stream.write_all(b"pong").await {
                                eprintln!("  Failed to send pong: {}", e);
                            }
                            let _ = stream.finish().await;
                        } else {
                            println!("  Received {} bytes on stream {}", n, stream.id());
                        }
                    }
                    Err(e) => {
                        eprintln!("  Stream read error: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  QUIC connection to node {} closed: {}", peer, e);
                break;
            }
        }
    }
}

async fn get_pairing_code(hub_override: Option<&str>) -> Result<()> {
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    let reg = match &stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => r.registration(),
        NodeStateStage::Activated(a) => a.registration(),
    };

    let cg_id = reg.connectivity_group_id.to_string();
    let node_number = reg.node_number;

    // Connect to daemon
    let mut client = daemon::DaemonClient::connect(&cg_id, node_number)
        .await
        .context("Daemon not running. Start it with 'wconnect serve' first.")?;

    // Request pairing code
    let response = client
        .request(&daemon::Request::GetPairingCode)
        .await
        .context("failed to communicate with daemon")?;

    match response {
        daemon::Response::Success { data: daemon::ResponseData::PairingCode(p), .. } => {
            println!("{}", p.pairing_code);
        }
        daemon::Response::Error { error, .. } => {
            anyhow::bail!("{}", error);
        }
        _ => {
            anyhow::bail!("unexpected response from daemon");
        }
    }

    Ok(())
}

async fn ping(hub_override: Option<&str>, target_node: i32, use_quic: bool) -> Result<()> {
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    let activated = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(_) => {
            anyhow::bail!("Not activated. Use 'wconnect activate <pairing_code>' first.");
        }
        NodeStateStage::Activated(a) => a,
    };

    let our_node = activated.registration().node_number;
    if target_node == our_node {
        anyhow::bail!("Cannot ping yourself (node {}).", our_node);
    }

    let transport = if use_quic { "QUIC" } else { "UDP" };
    println!("Pinging node {} via {}...", target_node, transport);

    let start = std::time::Instant::now();

    if use_quic {
        ping_quic(&activated, target_node, start).await
    } else {
        ping_udp(&activated, target_node, start).await
    }
}

async fn ping_udp<S: wispers_connect::NodeStateStore>(
    activated: &wispers_connect::ActivatedNode<S>,
    target_node: i32,
    start: std::time::Instant,
) -> Result<()> {
    // Establish P2P connection
    let conn = activated
        .connect_udp(target_node)
        .await
        .context("failed to connect")?;

    let connect_time = start.elapsed();
    println!("  Connected in {:?}", connect_time);

    // Send ping
    conn.send(b"ping").context("failed to send ping")?;

    // Wait for pong with timeout
    let pong_start = std::time::Instant::now();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.recv(),
    )
    .await
    .context("timeout waiting for pong")?
    .context("failed to receive pong")?;

    let rtt = pong_start.elapsed();

    if response == b"pong" {
        println!("  Pong received in {:?}", rtt);
        println!("Ping successful! Total time: {:?}", start.elapsed());
    } else {
        println!("  Unexpected response: {:?}", String::from_utf8_lossy(&response));
    }

    Ok(())
}

async fn ping_quic<S: wispers_connect::NodeStateStore>(
    activated: &wispers_connect::ActivatedNode<S>,
    target_node: i32,
    start: std::time::Instant,
) -> Result<()> {
    // Establish QUIC connection
    let conn = activated
        .connect_quic(target_node)
        .await
        .context("failed to connect")?;

    let connect_time = start.elapsed();
    println!("  Connected in {:?}", connect_time);

    // Open a stream
    let stream_start = std::time::Instant::now();
    let stream = conn.open_stream().await.context("failed to open stream")?;
    let stream_time = stream_start.elapsed();
    println!("  Stream opened in {:?}", stream_time);

    // Send ping
    stream.write_all(b"ping").await.context("failed to send ping")?;
    stream.finish().await.context("failed to finish stream")?;

    // Wait for pong with timeout
    let pong_start = std::time::Instant::now();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .context("timeout waiting for pong")?
    .context("failed to receive pong")?;

    let rtt = pong_start.elapsed();
    let response = &buf[..n];

    if response == b"pong" {
        println!("  Pong received in {:?}", rtt);
        println!("Ping successful! Total time: {:?}", start.elapsed());
    } else {
        println!("  Unexpected response: {:?}", String::from_utf8_lossy(response));
    }

    Ok(())
}
