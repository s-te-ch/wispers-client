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
    /// List nodes in the connectivity group
    Nodes,
    /// Show current registration status
    Status,
    /// Clear stored credentials and state
    Logout,
    /// Start serving and handle incoming requests
    Serve,
    /// Get a pairing code to endorse a new node (requires running daemon)
    GetPairingCode,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let hub_override = cli.hub.as_deref();

    match cli.command {
        Command::Register { token } => register(hub_override, &token).await,
        Command::Nodes => nodes(hub_override).await,
        Command::Status => status(hub_override).await,
        Command::Logout => logout(hub_override).await,
        Command::Serve => serve(hub_override).await,
        Command::GetPairingCode => get_pairing_code(hub_override).await,
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

async fn nodes(hub_override: Option<&str>) -> Result<()> {
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    let (reg, nodes) = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => {
            let reg = r.registration().clone();
            let nodes = r.list_nodes().await.context("failed to list nodes")?;
            (reg, nodes)
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration().clone();
            // Convert roster nodes to the Node type used by list_nodes
            let nodes: Vec<_> = a
                .roster()
                .nodes
                .iter()
                .map(|n| wispers_connect::Node {
                    node_number: n.node_number,
                    name: String::new(),
                    last_seen_at_millis: 0,
                })
                .collect();
            (reg, nodes)
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
            let you = if node.node_number == reg.node_number {
                " (you)"
            } else {
                ""
            };
            println!("  {}: {}{}", node.node_number, name, you);
        }
    }
    Ok(())
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
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            println!("Activated:");
            println!("  Connectivity group: {}", reg.connectivity_group_id);
            println!("  Node number: {}", reg.node_number);

            // Check if daemon is running
            match daemon::DaemonClient::connect(&reg.connectivity_group_id.to_string(), reg.node_number).await {
                Ok(mut client) => {
                    match client.request(&daemon::Request::Status).await {
                        Ok(daemon::Response::Success { data: daemon::ResponseData::Status(s), .. }) => {
                            println!("  Daemon: running");
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
    }
    Ok(())
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
    let storage = get_storage(hub_override)?;
    let stage = storage
        .restore_or_init_node_state("unused", None::<String>)
        .await
        .context("failed to load node state")?;

    // Both Registered and Activated nodes can serve (needed for bootstrap)
    let (cg_id, node_number, handle, session) = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(r) => {
            let reg = r.registration();
            let cg_id = reg.connectivity_group_id.to_string();
            let node_number = reg.node_number;
            let (handle, session) = r
                .start_serving()
                .await
                .context("failed to start serving")?;
            (cg_id, node_number, handle, session)
        }
        NodeStateStage::Activated(a) => {
            let reg = a.registration();
            let cg_id = reg.connectivity_group_id.to_string();
            let node_number = reg.node_number;
            let (handle, session) = a
                .start_serving()
                .await
                .context("failed to start serving")?;
            (cg_id, node_number, handle, session)
        }
    };

    // Start UDS daemon server
    let daemon = daemon::DaemonServer::bind(&cg_id, node_number)
        .await
        .context("failed to start daemon")?;

    println!(
        "Serving node {} in group {} (socket: {:?})",
        node_number,
        cg_id,
        daemon.path()
    );

    // Spawn the serving session runner
    let mut session_task = tokio::spawn(async move { session.run().await });

    // Accept daemon client connections until session ends or shutdown
    loop {
        tokio::select! {
            // Session completed (hub disconnected, error, or shutdown via handle)
            result = &mut session_task => {
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

            // New daemon client connection
            result = daemon.accept() => {
                match result {
                    Ok(stream) => {
                        let client_handle = handle.clone();
                        tokio::spawn(async move {
                            daemon::handle_client(stream, client_handle).await;
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
