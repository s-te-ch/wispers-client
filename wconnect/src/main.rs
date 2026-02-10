mod daemon;
mod p2p;
mod proxy_common;
mod proxy_http;
mod serving;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use wispers_connect::{FileNodeStateStore, NodeState, NodeStorage};

#[derive(Parser)]
#[command(name = "wconnect")]
#[command(about = "CLI for Wispers Connect nodes")]
struct Cli {
    /// Override hub address (for testing)
    #[arg(long, env = "WCONNECT_HUB")]
    hub: Option<String>,

    /// Profile name for storing node state (allows multiple nodes on same machine)
    #[arg(long, short, default_value = "default", env = "WCONNECT_PROFILE")]
    profile: String,

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
    /// Get a pairing code to endorse a new node (requires running daemon)
    GetPairingCode,
    /// Clear stored credentials and state
    Logout,
    /// List nodes in the connectivity group
    Nodes,
    /// Show current registration status
    Status,
    /// Start serving and handle incoming requests
    Serve {
        /// Detach and run as a background daemon
        #[arg(short = 'd', long)]
        daemon: bool,

        /// Stop a running daemon
        #[arg(long)]
        stop: bool,

        /// Allow port forwarding (FORWARD command) from other nodes.
        /// Without value: allow all ports. With value: allow only listed ports.
        /// Examples: --allow-port-forwarding or --allow-port-forwarding=80,443
        #[arg(long, value_name = "PORTS", num_args = 0..=1, default_missing_value = "")]
        allow_port_forwarding: Option<String>,

        /// Allow this node to be used as an egress point for internet traffic.
        /// Other nodes can use CONNECT command to reach arbitrary internet hosts.
        #[arg(long)]
        allow_egress: bool,
    },
    /// Ping another node via P2P connection
    Ping {
        /// The node number to ping
        node_number: i32,

        /// Use QUIC transport (reliable streams) instead of UDP (datagrams)
        #[arg(long)]
        quic: bool,
    },
    /// Forward a local TCP port to a remote node
    Forward {
        /// Local port to listen on
        local_port: u16,

        /// Target node number
        node: i32,

        /// Remote port on target node
        remote_port: u16,
    },
    /// Start HTTP proxy for accessing web servers on remote nodes
    ProxyHttp {
        /// Address to bind the proxy server (default: 127.0.0.111:8080)
        #[arg(long, default_value = "127.0.0.111:8080")]
        bind: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub_override: Option<String> = cli.hub.clone();
    let profile = cli.profile.clone();

    // Parse serve options before daemonizing since we need them after.
    let (allowed_ports, allow_egress) = match &cli.command {
        Command::Serve { allow_port_forwarding, allow_egress, .. } => {
            let ports = match allow_port_forwarding {
                Some(ports) => Some(serving::AllowedPorts::parse(ports)?),
                None => None,
            };
            (ports, *allow_egress)
        }
        _ => (None, false),
    };

    // serve --stop and serve --daemon need to be handled before starting tokio.
    match &cli.command {
        Command::Serve { stop: true, .. } => {
            // Stop the daemon and exit
            return stop_daemon(hub_override.as_deref(), &profile);
        }
        Command::Serve { daemon: true, .. } => {
            // Daemonize the process, then continue to start tokio
            daemonize_serve(hub_override.as_deref(), &profile)?;
        }
        _ => {}
    }

    // Start tokio runtime and run async main
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?
        .block_on(async_main(cli.command, hub_override, profile, allowed_ports, allow_egress))
}

//-- Daemon Control Functions --------------------------------------------------

/// Stop a running daemon by sending shutdown command via socket.
fn stop_daemon(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let (cg_id, node_number) = read_registration_sync(profile)?;
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
fn daemonize_serve(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use daemonize::Daemonize;
    use std::fs::{self, File};

    let (cg_id, node_number) = read_registration_sync(profile)?;

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

//-- Storage -------------------------------------------------------------------

/// Read registration info synchronously (for use before tokio starts).
fn read_registration_sync(profile: &str) -> Result<(String, i32)> {
    let storage = get_storage(None, profile)?;
    let reg = storage
        .read_registration()
        .context("failed to read registration")?
        .context("not registered")?;

    Ok((reg.connectivity_group_id.to_string(), reg.node_number))
}

fn get_storage(hub_override: Option<&str>, profile: &str) -> Result<NodeStorage> {
    let config_dir = dirs::config_dir().context("could not determine config directory")?;
    let store_dir = config_dir.join("wconnect").join(profile);
    let store = FileNodeStateStore::new(store_dir);
    let storage = NodeStorage::new(store);
    if let Some(addr) = hub_override {
        storage.override_hub_addr(addr);
    }
    Ok(storage)
}

//-- Async Main ----------------------------------------------------------------

async fn async_main(
    command: Command,
    hub_override: Option<String>,
    profile: String,
    allowed_ports: Option<serving::AllowedPorts>,
    allow_egress: bool,
) -> Result<()> {
    let hub_override = hub_override.as_deref();
    let profile = profile.as_str();
    match command {
        Command::Register { token } => register(hub_override, profile, &token).await,
        Command::Activate { pairing_code } => activate(hub_override, profile, &pairing_code).await,
        Command::GetPairingCode => get_pairing_code(hub_override, profile).await,
        Command::Logout => logout(hub_override, profile).await,
        Command::Nodes => nodes(hub_override, profile).await,
        Command::Status => status(hub_override, profile).await,
        Command::Serve { .. } => serving::serve(hub_override, profile, allowed_ports, allow_egress).await,
        Command::Ping { node_number, quic } => p2p::ping(hub_override, profile, node_number, quic).await,
        Command::Forward { local_port, node, remote_port } => {
            p2p::forward(hub_override, profile, local_port, node, remote_port).await
        }
        Command::ProxyHttp { bind } => proxy_http::run(hub_override, profile, &bind).await,
    }
}

//-- Node lifecycle ------------------------------------------------------------

async fn register(hub_override: Option<&str>, profile: &str, token: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;

    let mut node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    match node.state() {
        NodeState::Pending => {}
        NodeState::Registered | NodeState::Activated => {
            anyhow::bail!(
                "Already registered as node {} in group {}. Use 'wconnect logout' to clear.",
                node.node_number().unwrap(),
                node.connectivity_group_id().unwrap()
            );
        }
    }

    println!("Registering with token {}...", token);

    node.register(token)
        .await
        .context("registration failed")?;

    println!("Registration successful!");
    println!("  Connectivity group: {}", node.connectivity_group_id().unwrap());
    println!("  Node number: {}", node.node_number().unwrap());
    Ok(())
}

async fn activate(hub_override: Option<&str>, profile: &str, pairing_code: &str) -> Result<()> {
    use wispers_connect::PairingCode;

    let storage = get_storage(hub_override, profile)?;
    let mut node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    match node.state() {
        NodeState::Pending => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeState::Registered => {}
        NodeState::Activated => {
            anyhow::bail!(
                "Already activated as node {} in group {}.",
                node.node_number().unwrap(),
                node.connectivity_group_id().unwrap()
            );
        }
    }

    // Parse pairing code to check for self-endorsement
    let parsed_code = PairingCode::parse(pairing_code)
        .context("invalid pairing code format")?;
    let our_node_number = node.node_number().unwrap();
    if parsed_code.node_number == our_node_number {
        anyhow::bail!(
            "Cannot activate using your own pairing code (self-endorsement). \
             You need a pairing code from a different node."
        );
    }

    println!("Activating with pairing code {}...", pairing_code);
    node.activate(pairing_code)
        .await
        .context("activation failed")?;

    println!("Activation successful!");
    println!("  Connectivity group: {}", node.connectivity_group_id().unwrap());
    println!("  Node number: {}", node.node_number().unwrap());
    Ok(())
}

async fn get_pairing_code(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    if node.state() == NodeState::Pending {
        anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
    }

    let cg_id = node.connectivity_group_id().unwrap().to_string();
    let node_number = node.node_number().unwrap();

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

async fn logout(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    node.logout().await.context("failed to logout")?;
    println!("Logged out.");
    Ok(())
}

//-- Status inspection ---------------------------------------------------------

async fn nodes(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    if node.state() == NodeState::Pending {
        anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
    }

    let cg_id = node.connectivity_group_id().unwrap();
    let nodes = node.list_nodes().await.context("failed to list nodes")?;

    if nodes.is_empty() {
        println!("No nodes in connectivity group.");
        return Ok(());
    }

    println!("Nodes in connectivity group {}:", cg_id);
    for info in nodes {
        let name = if info.name.is_empty() {
            "(unnamed)".to_string()
        } else {
            info.name
        };
        let mut tags = Vec::new();
        if info.is_self {
            tags.push("you");
        }
        if let Some(activated) = info.is_activated {
            if activated {
                tags.push("activated");
            } else {
                tags.push("not activated");
            }
        }
        let last_seen = format_last_seen(info.last_seen_at_millis);
        let tags_str = if tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", tags.join(", "))
        };
        println!("  {}: {}{} - {}", info.node_number, name, tags_str, last_seen);
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

async fn status(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = storage
        .restore_or_init_node()
        .await
        .context("failed to load node state")?;

    match node.state() {
        NodeState::Pending => {
            println!("Not registered.");
        }
        NodeState::Registered => {
            let cg_id = node.connectivity_group_id().unwrap();
            let node_num = node.node_number().unwrap();
            println!("Registered (not yet activated):");
            println!("  Connectivity group: {}", cg_id);
            println!("  Node number: {}", node_num);
            print_daemon_status(&cg_id.to_string(), node_num).await;
        }
        NodeState::Activated => {
            let cg_id = node.connectivity_group_id().unwrap();
            let node_num = node.node_number().unwrap();
            println!("Activated:");
            println!("  Connectivity group: {}", cg_id);
            println!("  Node number: {}", node_num);
            print_daemon_status(&cg_id.to_string(), node_num).await;
        }
    }
    Ok(())
}

async fn print_daemon_status(cg_id: &str, node_number: i32) {
    let Ok(mut client) = daemon::DaemonClient::connect(cg_id, node_number).await else {
        println!("  Daemon: not running");
        return;
    };
    let resp = client.request(&daemon::Request::Status).await;
    let Ok(daemon::Response::Success { data: daemon::ResponseData::Status(s), .. }) = resp else {
        println!("  Daemon: running (status unavailable)");
        return;
    };
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
