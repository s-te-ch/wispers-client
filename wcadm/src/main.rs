use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

/// CLI tool for managing Wispers Connect domains.
#[derive(Parser)]
#[command(name = "wcadm", version, about)]
struct Cli {
    /// API key (can also be set via WC_API_KEY env var)
    #[arg(long, env = "WC_API_KEY", hide_env_values = true)]
    api_key: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all connectivity groups
    #[command(name = "list-groups")]
    ListGroups,

    /// Show details of a connectivity group
    #[command(name = "show-group")]
    ShowGroup {
        /// Connectivity group ID
        group_id: String,
    },

    /// Add a new connectivity group
    #[command(name = "add-group")]
    AddGroup {
        /// Optional name for the connectivity group
        #[arg(long)]
        name: Option<String>,
    },

    /// Remove a connectivity group
    #[command(name = "remove-group")]
    RemoveGroup {
        /// Connectivity group ID to remove
        group_id: String,
    },

    /// Create a registration token for a new node
    #[command(name = "create-registration-token")]
    CreateRegistrationToken {
        /// Connectivity group ID
        group_id: String,

        /// Optional name for the node
        #[arg(long)]
        name: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let api_key = ApiKey::parse(&cli.api_key)?;
    let base_url = api_key.base_url();
    let client = Client::new();

    match cli.command {
        Command::ListGroups => list_groups(&client, &base_url, &cli.api_key),
        Command::ShowGroup { group_id } => show_group(&client, &base_url, &cli.api_key, &group_id),
        Command::AddGroup { name } => add_group(&client, &base_url, &cli.api_key, name.as_deref()),
        Command::RemoveGroup { group_id } => {
            remove_group(&client, &base_url, &cli.api_key, &group_id)
        }
        Command::CreateRegistrationToken { group_id, name } => {
            create_registration_token(&client, &base_url, &cli.api_key, &group_id, name.as_deref())
        }
    }
}

/// Parsed API key with extracted environment.
struct ApiKey {
    env: String,
}

impl ApiKey {
    /// Parse an API key in the format `wc_{env}_{id}.{secret}`.
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let rest = raw
            .strip_prefix("wc_")
            .ok_or_else(|| anyhow!("API key must start with 'wc_'"))?;

        let underscore_pos = rest
            .find('_')
            .ok_or_else(|| anyhow!("invalid API key format"))?;

        let env = &rest[..underscore_pos];
        if env.is_empty() {
            bail!("API key environment is empty");
        }

        Ok(Self {
            env: env.to_string(),
        })
    }

    /// Map the environment to a base URL.
    fn base_url(&self) -> String {
        match self.env.as_str() {
            "local" => "http://localhost:3000".to_string(),
            "staging" => "https://staging.connect.wispers.dev".to_string(),
            "prod" => "https://connect.wispers.dev".to_string(),
            other => {
                eprintln!("warning: unknown environment '{other}', assuming staging");
                "https://staging.connect.wispers.dev".to_string()
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupSummary {
    id: String,
    name: Option<String>,
}

fn list_groups(client: &Client, base_url: &str, api_key: &str) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups");

    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("server returned {status}: {body}");
    }

    let groups: Vec<GroupSummary> = resp.json().context("failed to parse response")?;

    if groups.is_empty() {
        println!("No connectivity groups found.");
    } else {
        println!("Connectivity groups:");
        for group in groups {
            match &group.name {
                Some(name) => println!("  {} ({})", group.id, name),
                None => println!("  {}", group.id),
            }
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupResponse {
    id: String,
    name: Option<String>,
    created_at: String,
    #[serde(default)]
    nodes: Vec<NodeResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeResponse {
    node_number: i32,
    name: Option<String>,
    last_seen_at: Option<String>,
    created_at: String,
}

fn show_group(client: &Client, base_url: &str, api_key: &str, group_id: &str) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups/{group_id}");

    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("server returned {status}: {body}");
    }

    let data: GroupResponse = resp.json().context("failed to parse response")?;

    println!("Connectivity group: {}", data.id);
    if let Some(name) = &data.name {
        println!("  Name: {name}");
    }
    println!("  Created: {}", data.created_at);
    if data.nodes.is_empty() {
        println!("  Nodes: (none)");
    } else {
        println!("  Nodes:");
        for node in &data.nodes {
            let name = node.name.as_deref().unwrap_or("(unnamed)");
            let last_seen = node.last_seen_at.as_deref().unwrap_or("never");
            println!(
                "    {} - {} (created: {}, last seen: {})",
                node.node_number, name, node.created_at, last_seen
            );
        }
    }

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

fn add_group(client: &Client, base_url: &str, api_key: &str, name: Option<&str>) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups");

    let body = CreateGroupRequest { name };

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to send request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("server returned {status}: {body}");
    }

    let data: GroupResponse = resp.json().context("failed to parse response")?;

    println!("Created connectivity group:");
    println!("  ID: {}", data.id);
    if let Some(name) = &data.name {
        println!("  Name: {name}");
    }
    println!("  Created: {}", data.created_at);

    Ok(())
}

fn remove_group(client: &Client, base_url: &str, api_key: &str, group_id: &str) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups/{group_id}");

    let resp = client
        .delete(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("server returned {status}: {body}");
    }

    println!("Deleted connectivity group: {group_id}");

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateRegistrationTokenRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    node_name: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationTokenResponse {
    token: String,
    expires_at: String,
}

fn create_registration_token(
    client: &Client,
    base_url: &str,
    api_key: &str,
    group_id: &str,
    name: Option<&str>,
) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups/{group_id}/registration-tokens");

    let body = CreateRegistrationTokenRequest { node_name: name };

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to send request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("server returned {status}: {body}");
    }

    let data: RegistrationTokenResponse = resp.json().context("failed to parse response")?;

    println!("Registration token created:");
    println!("  Token: {}", data.token);
    println!("  Expires: {}", data.expires_at);

    Ok(())
}
