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

    let activated = match stage {
        NodeStateStage::Pending(_) => {
            anyhow::bail!("Not registered. Use 'wconnect register <token>' first.");
        }
        NodeStateStage::Registered(_) => {
            anyhow::bail!("Not activated. Activation required before serving.");
        }
        NodeStateStage::Activated(a) => a,
    };

    let (_handle, session) = activated
        .start_serving()
        .await
        .context("failed to start serving")?;

    // TODO: Add UDS listener and use handle for commands
    // For now, just run the session directly
    session.run().await.context("serve failed")?;
    Ok(())
}
