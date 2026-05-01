mod daemon;
mod p2p;
mod proxy_common;
mod proxy_http;
mod proxy_socks;
mod serving;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use wispers_connect::{FileNodeStateStore, Node, NodeState, NodeStorage};

#[derive(Parser)]
#[command(name = "wconnect", version)]
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
    /// Activate this node using an activation code from an endorser
    Activate {
        /// The activation code from the endorser (format: "node_number-secret")
        activation_code: String,
    },
    /// Get an activation code to endorse a new node (requires running daemon)
    GetActivationCode,
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
        /// Address to bind the proxy server (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,

        /// Node number to use as egress point for non-wispers.link traffic.
        /// Without this, only *.wispers.link destinations are allowed.
        #[arg(long)]
        egress_node: Option<i32>,
    },
    /// Start SOCKS5 proxy for accessing services on remote nodes
    ProxySocks {
        /// Address to bind the proxy server (default: 127.0.0.1:1080)
        #[arg(long, default_value = "127.0.0.1:1080")]
        bind: String,

        /// Node number to use as egress point for non-wispers.link traffic.
        /// Without this, only *.wispers.link destinations are allowed.
        #[arg(long)]
        egress_node: Option<i32>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub_override = cli.hub.clone();
    let profile = cli.profile.clone();

    // Parse serve options before daemonizing since we need them after.
    let (allowed_ports, allow_egress) = match &cli.command {
        Command::Serve {
            allow_port_forwarding,
            allow_egress,
            ..
        } => {
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
        .block_on(async_main(
            cli.command,
            hub_override,
            profile,
            allowed_ports,
            allow_egress,
        ))
}

//-- Daemon Control Functions --------------------------------------------------

/// Stop a running daemon by sending shutdown command via IPC.
#[cfg(unix)]
fn stop_daemon(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let (cg_id, node_number) = read_registration_sync(profile)?;
    let path = daemon::ipc_path(&cg_id, node_number);

    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("daemon not running (socket {})", path.display()))?;

    writeln!(stream, r#"{{"cmd":"shutdown"}}"#)?;
    stream.flush()?;

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

/// Stop a running daemon by sending shutdown command via TCP.
#[cfg(windows)]
fn stop_daemon(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    let (cg_id, node_number) = read_registration_sync(profile)?;
    let path = daemon::ipc_path(&cg_id, node_number);

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("daemon not running (no port file {:?})", path))?;
    let contents = contents.trim();
    let colon = contents.find(':').context("invalid daemon port file")?;
    let port: u16 = contents[..colon]
        .parse()
        .context("invalid daemon port file")?;
    let password = &contents[colon + 1..];

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("daemon not running (port {})", port))?;

    // Send IPC password first
    writeln!(stream, "{}", password)?;
    writeln!(stream, r#"{{"cmd":"shutdown"}}"#)?;
    stream.flush()?;

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

/// Daemonize the process before starting tokio (Unix only).
#[cfg(unix)]
fn daemonize_serve(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use daemonize::Daemonize;
    use std::fs::{self, File};

    let (cg_id, node_number) = read_registration_sync(profile)?;

    // Create log directory
    let log_dir = dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".wconnect")
        .join("logs");
    fs::create_dir_all(&log_dir).context("failed to create log directory")?;

    let log_path = log_dir.join(format!("{cg_id}-{node_number}.log"));
    let log_file = File::create(&log_path)
        .with_context(|| format!("failed to create log file {}", log_path.display()))?;

    println!("Daemonizing, logging to {}", log_path.display());

    let daemonize = Daemonize::new()
        .stdout(log_file.try_clone()?)
        .stderr(log_file);

    daemonize.start().context("failed to daemonize")?;
    Ok(())
}

/// Daemonize by re-launching as a detached process without a console window.
#[cfg(windows)]
fn daemonize_serve(_hub_override: Option<&str>, profile: &str) -> Result<()> {
    use std::fs::{self, File};
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let (cg_id, node_number) = read_registration_sync(profile)?;

    // Create log directory
    let log_dir = dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".wconnect")
        .join("logs");
    fs::create_dir_all(&log_dir).context("failed to create log directory")?;

    let log_path = log_dir.join(format!("{}-{}.log", cg_id, node_number));
    let log_file = File::create(&log_path)
        .with_context(|| format!("failed to create log file {:?}", log_path))?;

    // Re-launch ourselves with the same args minus --daemon / -d
    let exe = std::env::current_exe().context("failed to get current executable path")?;
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--daemon" && a != "-d")
        .collect();

    std::process::Command::new(exe)
        .args(&args)
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("failed to spawn background process")?;

    println!("Daemonized, logging to {:?}", log_path);
    std::process::exit(0);
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

/// Load node state, replacing unauthenticated hub errors with a helpful message.
async fn load_node(storage: &NodeStorage) -> Result<Node> {
    match storage.restore_or_init_node().await {
        Ok(node) => Ok(node),
        Err(e) if e.is_unauthenticated() || e.is_not_found() => {
            anyhow::bail!(
                "Authentication with the hub failed. If your node was removed \
                 remotely, run `wconnect logout` to clear local state."
            );
        }
        Err(e) => Err(e).context("failed to load node state"),
    }
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
        Command::Activate { activation_code } => {
            activate(hub_override, profile, &activation_code).await
        }
        Command::GetActivationCode => get_activation_code(hub_override, profile).await,
        Command::Logout => logout(hub_override, profile).await,
        Command::Nodes => nodes(hub_override, profile).await,
        Command::Status => status(hub_override, profile).await,
        Command::Serve { .. } => {
            serving::serve(hub_override, profile, allowed_ports, allow_egress).await
        }
        Command::Ping { node_number, quic } => {
            p2p::ping(hub_override, profile, node_number, quic).await
        }
        Command::Forward {
            local_port,
            node,
            remote_port,
        } => p2p::forward(hub_override, profile, local_port, node, remote_port).await,
        Command::ProxyHttp { bind, egress_node } => {
            proxy_http::run(hub_override, profile, &bind, egress_node).await
        }
        Command::ProxySocks { bind, egress_node } => {
            proxy_socks::run(hub_override, profile, &bind, egress_node).await
        }
    }
}

//-- Node lifecycle ------------------------------------------------------------

async fn register(hub_override: Option<&str>, profile: &str, token: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;

    let mut node = load_node(&storage).await?;

    if matches!(node.state(), NodeState::Registered | NodeState::Activated) {
        anyhow::bail!(
            "Already registered as node {} in group {}. Use 'wconnect logout' to clear.",
            node.node_number().unwrap(),
            node.connectivity_group_id().unwrap()
        );
    }

    println!("Registering with token {token}...");

    node.register(token).await.context("registration failed")?;

    println!("Registration successful!");
    println!(
        "  Connectivity group: {}",
        node.connectivity_group_id().unwrap()
    );
    println!("  Node number: {}", node.node_number().unwrap());
    Ok(())
}

async fn activate(hub_override: Option<&str>, profile: &str, activation_code: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let mut node = load_node(&storage).await?;

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

    // Check for self-endorsement (code format is "node_number-secret")
    if let Some(peer_str) = activation_code.split('-').next()
        && let Ok(peer_node) = peer_str.parse::<i32>()
        && peer_node == node.node_number().unwrap()
    {
        anyhow::bail!(
            "Cannot activate using your own activation code (self-endorsement). \
             You need an activation code from a different node."
        );
    }

    println!("Activating with activation code {activation_code}...");
    node.activate(activation_code)
        .await
        .context("activation failed")?;

    println!("Activation successful!");
    println!(
        "  Connectivity group: {}",
        node.connectivity_group_id().unwrap()
    );
    println!("  Node number: {}", node.node_number().unwrap());
    Ok(())
}

async fn get_activation_code(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = load_node(&storage).await?;

    if node.state() == NodeState::Pending {
        anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
    }

    let cg_id = node.connectivity_group_id().unwrap().to_string();
    let node_number = node.node_number().unwrap();

    // Connect to daemon
    let mut client = daemon::DaemonClient::connect(&cg_id, node_number)
        .await
        .context("Daemon not running. Start it with 'wconnect serve' first.")?;

    // Request activation code
    let response = client
        .request(&daemon::Request::GetActivationCode)
        .await
        .context("failed to communicate with daemon")?;

    match response {
        daemon::Response::Success {
            data: daemon::ResponseData::ActivationCode(p),
            ..
        } => {
            println!("{}", p.activation_code);
        }
        daemon::Response::Error { error, .. } => {
            anyhow::bail!("{error}");
        }
        daemon::Response::Success { .. } => {
            anyhow::bail!("unexpected response from daemon");
        }
    }

    Ok(())
}

async fn logout(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    match storage.restore_or_init_node().await {
        Ok(mut node) => {
            node.logout().await.context("failed to logout")?;
        }
        Err(e) if e.is_unauthenticated() || e.is_not_found() => {
            // Node was removed remotely — just delete local state.
            storage
                .delete_state()
                .context("failed to delete local state")?;
        }
        Err(e) => return Err(e).context("failed to load node state"),
    }
    println!("Logged out.");
    Ok(())
}

//-- Status inspection ---------------------------------------------------------

async fn nodes(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = load_node(&storage).await?;

    if node.state() == NodeState::Pending {
        anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
    }

    let cg_id = node.connectivity_group_id().unwrap();
    let info = node
        .group_info()
        .await
        .context("failed to get group info")?;

    if info.nodes.is_empty() {
        println!("No nodes in connectivity group.");
        return Ok(());
    }

    println!(
        "Nodes in connectivity group {} (state: {:?}):",
        cg_id, info.state
    );
    for node_info in info.nodes {
        let name = if node_info.name.is_empty() {
            "(unnamed)"
        } else {
            &node_info.name
        };
        let tags: Vec<&str> = [
            node_info.is_self.then_some("you"),
            node_info
                .is_activated
                .map(|a| if a { "activated" } else { "not activated" }),
        ]
        .into_iter()
        .flatten()
        .collect();
        let status = if node_info.is_online {
            "online".to_string()
        } else {
            format_last_seen(node_info.last_seen_at_millis)
        };
        let tags_str = if tags.is_empty() {
            String::new()
        } else {
            format!(" ({})", tags.join(", "))
        };
        println!(
            "  {}: {}{} - {}",
            node_info.node_number, name, tags_str, status
        );
    }
    Ok(())
}

fn format_last_seen(millis: i64) -> String {
    if millis == 0 {
        return "never connected".to_string();
    }
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let ago_secs = (now - millis) / 1000;
    match ago_secs {
        s if s < 60 => "connected just now".to_string(),
        s if s < 3600 => format!("connected {}m ago", s / 60),
        s if s < 86400 => format!("connected {}h ago", s / 3600),
        s => format!("connected {}d ago", s / 86400),
    }
}

async fn status(hub_override: Option<&str>, profile: &str) -> Result<()> {
    let storage = get_storage(hub_override, profile)?;
    let node = load_node(&storage).await?;

    match node.state() {
        NodeState::Pending => {
            println!("Not registered.");
        }
        state => {
            let label = if state == NodeState::Activated {
                "Activated"
            } else {
                "Registered (not yet activated)"
            };
            let cg_id = node.connectivity_group_id().unwrap();
            let node_num = node.node_number().unwrap();
            println!("{label}:");
            println!("  Connectivity group: {cg_id}");
            println!("  Node number: {node_num}");
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
    let Ok(daemon::Response::Success {
        data: daemon::ResponseData::Status(s),
        ..
    }) = resp
    else {
        println!("  Daemon: running (status unavailable)");
        return;
    };
    println!("  Daemon: running (connected: {})", s.connected);
    if let Some(endorsing) = s.endorsing {
        if endorsing.codes_outstanding > 0 {
            println!(
                "  Endorsing: {} activation code(s) outstanding",
                endorsing.codes_outstanding
            );
        }
        if !endorsing.nodes_awaiting_cosign.is_empty() {
            println!(
                "  Endorsing: awaiting cosign for node(s) {:?}",
                endorsing.nodes_awaiting_cosign
            );
        }
    }
}
