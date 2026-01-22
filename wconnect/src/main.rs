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
        Command::Activate { pairing_code } => activate(hub_override, &pairing_code).await,
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

async fn activate(hub_override: Option<&str>, pairing_code: &str) -> Result<()> {
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
    use wispers_connect::{ServingHandle, ServingSession};

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
        let result: Result<(ServingHandle, ServingSession), anyhow::Error> = match stage {
            NodeStateStage::Pending(_) => unreachable!(),
            NodeStateStage::Registered(r) => {
                r.start_serving()
                    .await
                    .context("failed to start serving")
            }
            NodeStateStage::Activated(a) => {
                a.start_serving()
                    .await
                    .context("failed to start serving")
            }
        };

        if let Ok((handle, _session)) = &result {
            *connect_handle_state.write().await = Some(handle.clone());
        }
        result
    });

    // Session task (None until hub connects)
    let mut session_task: Option<tokio::task::JoinHandle<Result<(), wispers_connect::ServingError>>> = None;

    // Accept daemon client connections, handle hub connection completing
    loop {
        tokio::select! {
            // Hub connection completed
            result = &mut connect_task, if session_task.is_none() => {
                match result {
                    Ok(Ok((handle, session))) => {
                        println!("Connected to hub");
                        *handle_state.write().await = Some(handle);
                        session_task = Some(tokio::spawn(async move { session.run().await }));
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
