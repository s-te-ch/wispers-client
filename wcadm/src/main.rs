use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};

/// CLI tool for managing Wispers Connect domains.
#[derive(Parser)]
#[command(name = "wcadm", version, about)]
struct Cli {
    /// API key (can also be set via WC_API_KEY env var)
    #[arg(long, env = "WC_API_KEY", hide_env_values = true)]
    api_key: String,

    /// Base URL of the API server, e.g. http://my-hub:2357. Required for
    /// standalone API keys. Can also be set via the WC_URL env var.
    #[arg(long, env = "WC_URL")]
    url: Option<String>,

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

    /// Remove all nodes from a connectivity group and clear its roster.
    #[command(name = "reset-group")]
    ResetGroup {
        /// Connectivity group ID to reset
        group_id: String,
    },

    /// Delete a revoked node's registration, freeing the quota it occupies.
    /// Useful when a node has been revoked by another node in the group. Nodes
    /// that call logout() do both revocation and deletion.
    #[command(name = "remove-node")]
    RemoveNode {
        /// Connectivity group ID
        group_id: String,

        /// Node number within the group
        node_number: i32,
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
    let base_url = api_key.base_url(cli.url.as_deref())?;
    let client = Client::new();

    match cli.command {
        Command::ListGroups => list_groups(&client, &base_url, &cli.api_key),
        Command::ShowGroup { group_id } => show_group(&client, &base_url, &cli.api_key, &group_id),
        Command::AddGroup { name } => add_group(&client, &base_url, &cli.api_key, name.as_deref()),
        Command::RemoveGroup { group_id } => {
            remove_group(&client, &base_url, &cli.api_key, &group_id)
        }
        Command::ResetGroup { group_id } => {
            reset_group(&client, &base_url, &cli.api_key, &group_id)
        }
        Command::RemoveNode {
            group_id,
            node_number,
        } => remove_node(&client, &base_url, &cli.api_key, &group_id, node_number),
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

    /// Map the environment to a base URL. An explicit URL (--url / WC_URL)
    /// wins over the environment-derived default and is mandatory for
    /// standalone keys, whose endpoint could be anywhere.
    fn base_url(&self, url_override: Option<&str>) -> Result<String> {
        if let Some(url) = url_override {
            return Ok(url.trim_end_matches('/').to_string());
        }
        match self.env.as_str() {
            "local" => Ok("http://localhost:3000".to_string()),
            "staging" => Ok("https://staging.connect.wispers.dev".to_string()),
            "prod" => Ok("https://connect.wispers.dev".to_string()),
            "standalone" => bail!(
                "standalone API keys need the hub's URL: pass --url or set WC_URL \
                 (e.g. http://my-hub:2357)"
            ),
            other => bail!("unknown API key environment '{other}'; pass --url or set WC_URL"),
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

    let resp = ok_or_error(resp)?;

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

    // Get stats, degrading gracefully.
    if let Ok(stats) = get_stats(client, base_url, api_key) {
        let groups = stats.connectivity_groups;
        println!("Group quota: {}", fmt_used(groups.count, groups.max));
    }

    Ok(())
}

/// Domain-level usage as returned by `GET /stats`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stats {
    connectivity_groups: GroupsStats,
}

/// The domain's connectivity-group quota usage.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupsStats {
    count: i32,
    /// `None` = unlimited (a backend without plans, e.g. a standalone hub).
    max: Option<i32>,
}

fn get_stats(client: &Client, base_url: &str, api_key: &str) -> Result<Stats> {
    let url = format!("{base_url}/api/v1/stats");

    let resp = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    ok_or_error(resp)?
        .json()
        .context("failed to parse response")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupResponse {
    id: String,
    name: Option<String>,
    created_at: String,
    #[serde(default)]
    nodes: Vec<NodeResponse>,
    /// `None` on backends that predate the field, and on responses that
    /// don't carry it (group creation).
    #[serde(default)]
    node_quota: Option<NodeQuota>,
}

/// A group's node-quota usage. `current` counts registered nodes plus
/// unexpired pending registration tokens, which is what the backend compares
/// against `limit` when minting a token. The quota spent on pending tokens is
/// `current` minus the length of `nodes`.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeQuota {
    /// `None` = unlimited (a backend without plans, e.g. a standalone hub).
    limit: Option<i32>,
    current: i32,
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

    let resp = ok_or_error(resp)?;

    let data: GroupResponse = resp.json().context("failed to parse response")?;

    println!("Connectivity group: {}", data.id);
    if let Some(name) = &data.name {
        println!("  Name: {name}");
    }
    println!("  Created: {}", data.created_at);
    if let Some(quota) = &data.node_quota {
        println!("  Node quota: {}", fmt_quota(quota, data.nodes.len()));
    }
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

/// Renders node-quota usage, e.g. `11 of 12 used (9 nodes + 2 pending
/// registration tokens)`.
fn fmt_quota(quota: &NodeQuota, node_count: usize) -> String {
    let used = fmt_used(quota.current, quota.limit);
    let pending = (quota.current.max(0) as usize).saturating_sub(node_count);
    if pending == 0 {
        return used;
    }
    format!(
        "{} ({} node{} + {} pending registration token{})",
        used,
        node_count,
        if node_count == 1 { "" } else { "s" },
        pending,
        if pending == 1 { "" } else { "s" },
    )
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

    let resp = ok_or_error(resp)
        .map_err(explain_quota)
        .context("cannot create a connectivity group")?;

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

    ok_or_error(resp)?;

    println!("Deleted connectivity group: {group_id}");

    Ok(())
}

fn reset_group(client: &Client, base_url: &str, api_key: &str, group_id: &str) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups/{group_id}/reset");

    let resp = client
        .post(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    ok_or_error(resp)?;

    println!("Reset connectivity group {group_id}: all nodes removed, roster cleared.");

    Ok(())
}

fn remove_node(
    client: &Client,
    base_url: &str,
    api_key: &str,
    group_id: &str,
    node_number: i32,
) -> Result<()> {
    let url = format!("{base_url}/api/v1/connectivity-groups/{group_id}/nodes/{node_number}");

    let resp = client
        .delete(&url)
        .bearer_auth(api_key)
        .send()
        .context("failed to send request")?;

    if resp.status() == StatusCode::NOT_FOUND {
        bail!(
            "node {node_number} is not registered in connectivity group {group_id} \
             (`wcadm show-group {group_id}` lists the group's nodes)"
        );
    }
    if resp.status() == StatusCode::CONFLICT {
        bail!(
            "node {node_number} is still active in the connectivity group's roster. \
             Revoke it from another node in the group first (or let the node itself \
             log out, which deregisters it and frees the quota), then retry."
        );
    }

    ok_or_error(resp)?;

    println!("Deleted node {node_number} from connectivity group {group_id}.");

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

    let resp = ok_or_error(resp)
        .map_err(explain_quota)
        .context("cannot create a registration token")?;

    let data: RegistrationTokenResponse = resp.json().context("failed to parse response")?;

    println!("Registration token created:");
    println!("  Token: {}", data.token);
    println!("  Expires: {}", data.expires_at);

    Ok(())
}

//-- Shared helpers ------------------------------------------------------------

/// A quota rejection (HTTP 429 with a `quota exceeded` body), kept typed so
/// callers can render actionable messages. `Display` is the fallback.
#[derive(Debug)]
struct QuotaExceeded {
    /// Which quota, e.g. `nodes_per_group` or `groups_per_domain`.
    quota: String,
    limit: i32,
    current: i32,
}

impl std::fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} quota exceeded ({} of {} used)",
            self.quota, self.current, self.limit
        )
    }
}

impl std::error::Error for QuotaExceeded {}

/// Passes success responses through, everything else becomes an error —
/// quota 429s as a typed [`QuotaExceeded`], the rest as "server returned…".
fn ok_or_error(resp: Response) -> Result<Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    Err(classify_error(status, &body))
}

/// The backend's rate limiter also answers 429, so quota detection matches
/// on the body's `error` field, not the status alone.
fn classify_error(status: StatusCode, body: &str) -> anyhow::Error {
    #[derive(Deserialize)]
    struct QuotaBody {
        error: String,
        quota: String,
        limit: i32,
        current: i32,
    }
    if status == StatusCode::TOO_MANY_REQUESTS
        && let Ok(q) = serde_json::from_str::<QuotaBody>(body)
        && q.error == "quota exceeded"
    {
        return anyhow::Error::new(QuotaExceeded {
            quota: q.quota,
            limit: q.limit,
            current: q.current,
        });
    }
    anyhow!("server returned {status}: {body}")
}

/// Turns a quota rejection into a message that names the way out. Other
/// errors pass through.
fn explain_quota(e: anyhow::Error) -> anyhow::Error {
    match e.downcast_ref::<QuotaExceeded>() {
        Some(q) if q.quota == "groups_per_domain" => anyhow!(
            "the domain's connectivity-group quota is used up ({} of {}). \
             Delete an unused group with `wcadm remove-group <group-id>` or \
             upgrade your plan.",
            q.current,
            q.limit
        ),
        Some(q) if q.quota == "nodes_per_group" => anyhow!(
            "the connectivity group is full: {} of {} node quota used \
             (registered nodes plus pending registration tokens). Free quota \
             by deleting a revoked node with `wcadm remove-node <group-id> \
             <node-number>`, by waiting for a pending registration token to \
             expire, or by starting the group over with `wcadm reset-group \
             <group-id>` (which also clears the roster). `wcadm show-group \
             <group-id>` shows the usage.",
            q.current,
            q.limit
        ),
        _ => e,
    }
}

/// `11 of 12 used`, or `11 used (no limit)` on an unlimited backend.
fn fmt_used(current: i32, limit: Option<i32>) -> String {
    match limit {
        Some(limit) => format!("{current} of {limit} used"),
        None => format!("{current} used (no limit)"),
    }
}
