//! Local daemon server for wconnect CLI.
//!
//! The daemon listens on a Unix Domain Socket (Unix) or TCP localhost (Windows)
//! and accepts JSON-lines commands that are translated to ServingHandle method calls.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wispers_connect::ServingHandle;

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};

// Type aliases so the rest of the code is platform-agnostic.
#[cfg(unix)]
pub type IpcStream = UnixStream;
#[cfg(windows)]
pub type IpcStream = TcpStream;

#[cfg(unix)]
type ReadHalf = tokio::net::unix::OwnedReadHalf;
#[cfg(unix)]
type WriteHalf = tokio::net::unix::OwnedWriteHalf;

#[cfg(windows)]
type ReadHalf = tokio::net::tcp::OwnedReadHalf;
#[cfg(windows)]
type WriteHalf = tokio::net::tcp::OwnedWriteHalf;

/// Get the IPC file path for a specific node.
///
/// On Unix: path to the Unix domain socket (`.sock`).
/// On Windows: path to a file containing the TCP port number (`.port`).
pub fn ipc_path(connectivity_group_id: &str, node_number: i32) -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
    let dir = base.join(".wconnect").join("sockets");
    #[cfg(unix)]
    return dir.join(format!("{}-{}.sock", connectivity_group_id, node_number));
    #[cfg(windows)]
    return dir.join(format!("{}-{}.port", connectivity_group_id, node_number));
}

/// Request from CLI to daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    GetActivationCode,
    Shutdown,
}

/// Response from daemon to CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Success { ok: bool, data: ResponseData },
    Error { ok: bool, error: String },
}

/// Data payload for successful responses.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    Status(StatusData),
    ActivationCode(ActivationCodeData),
    Empty,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusData {
    pub connected: bool,
    pub node_number: i32,
    pub cg_id: String,
    pub endorsing: Option<EndorsingData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EndorsingData {
    pub codes_outstanding: usize,
    pub nodes_awaiting_cosign: Vec<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivationCodeData {
    pub activation_code: String,
}

impl Response {
    pub fn success(data: ResponseData) -> Self {
        Response::Success { ok: true, data }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Response::Error {
            ok: false,
            error: msg.into(),
        }
    }
}

/// Daemon server that listens for CLI commands.
pub struct DaemonServer {
    #[cfg(unix)]
    listener: UnixListener,
    #[cfg(windows)]
    listener: TcpListener,
    /// Password that Windows clients must send before any request.
    /// Stored in the `.port` file alongside the port, readable only by the user.
    #[cfg(windows)]
    windows_ipc_password: String,
    connectivity_group_id: String,
    node_number: i32,
}

impl DaemonServer {
    /// Bind to the daemon socket (Unix) or a localhost TCP port (Windows).
    ///
    /// Removes stale socket/port-file if it exists and no daemon is running.
    #[cfg(unix)]
    pub async fn bind(connectivity_group_id: &str, node_number: i32) -> Result<Self> {
        let path = ipc_path(connectivity_group_id, node_number);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        // Check for stale socket
        if path.exists() {
            match UnixStream::connect(&path).await {
                Ok(_) => {
                    anyhow::bail!("daemon already running at {:?}", path);
                }
                Err(_) => {
                    // Stale socket, remove it
                    tokio::fs::remove_file(&path)
                        .await
                        .context("failed to remove stale socket")?;
                }
            }
        }

        let listener = UnixListener::bind(&path).context("failed to bind socket")?;

        Ok(Self {
            listener,
            connectivity_group_id: connectivity_group_id.to_string(),
            node_number,
        })
    }

    /// Bind to a localhost TCP port and write the port + password to a file.
    ///
    /// The `.port` file contains `port:password`. Clients must send the password
    /// as the first line before any request, preventing other local users from
    /// talking to the daemon.
    #[cfg(windows)]
    pub async fn bind(connectivity_group_id: &str, node_number: i32) -> Result<Self> {
        use rand::Rng;

        let path = ipc_path(connectivity_group_id, node_number);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("failed to create socket directory")?;
        }

        // Check for stale port file
        if path.exists() {
            if let Ok(contents) = tokio::fs::read_to_string(&path).await
                && let Some((port, _)) = parse_port_file(&contents)
                && TcpStream::connect(("127.0.0.1", port)).await.is_ok()
            {
                anyhow::bail!("daemon already running on port {}", port);
            }
            tokio::fs::remove_file(&path)
                .await
                .context("failed to remove stale port file")?;
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind TCP listener")?;
        let port = listener.local_addr()?.port();

        // Generate a random password for IPC auth
        let password: String = rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        tokio::fs::write(&path, format!("{}:{}", port, password))
            .await
            .context("failed to write port file")?;

        Ok(Self {
            listener,
            windows_ipc_password: password,
            connectivity_group_id: connectivity_group_id.to_string(),
            node_number,
        })
    }

    /// Accept a new connection.
    ///
    /// On Windows, the client must send the IPC password as the first line.
    /// Connections that fail auth are dropped silently.
    pub async fn accept(&self) -> Result<IpcStream> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;

            #[cfg(unix)]
            return Ok(stream);

            #[cfg(windows)]
            {
                // Read the IPC password line before handing the stream off
                let mut buf_stream = BufReader::new(stream);
                let mut password_line = String::new();
                match buf_stream.read_line(&mut password_line).await {
                    Ok(0) => continue,
                    Ok(_) if password_line.trim() == self.windows_ipc_password => {
                        // Auth passed — reconstruct the stream from the BufReader.
                        // The buffer should be empty since we consumed exactly one line.
                        return Ok(buf_stream.into_inner());
                    }
                    _ => {
                        // Wrong token or read error — drop the connection
                        continue;
                    }
                }
            }
        }
    }

    /// Get the IPC path (socket path on Unix, port file on Windows).
    pub fn path(&self) -> PathBuf {
        ipc_path(&self.connectivity_group_id, self.node_number)
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        // Best-effort cleanup
        let _ = std::fs::remove_file(self.path());
    }
}

/// Handle a single client connection.
///
/// Reads JSON-lines requests and sends JSON-lines responses.
#[allow(dead_code)]
pub async fn handle_client(stream: IpcStream, handle: ServingHandle) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let response = process_request(&line, &handle).await;
                let response_json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    serde_json::to_string(&Response::error(format!("serialization error: {}", e)))
                        .unwrap()
                });

                if let Err(e) = writer.write_all(response_json.as_bytes()).await {
                    eprintln!("Failed to write response: {}", e);
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    eprintln!("Failed to write newline: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    eprintln!("Failed to flush: {}", e);
                    break;
                }

                // If this was a shutdown request, signal the caller
                if matches!(
                    serde_json::from_str::<Request>(&line),
                    Ok(Request::Shutdown)
                ) {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to read from client: {}", e);
                break;
            }
        }
    }
}

/// Handle a client connection when the ServingHandle may not be available yet.
pub async fn handle_client_with_optional_handle(
    stream: IpcStream,
    handle_state: std::sync::Arc<tokio::sync::RwLock<Option<ServingHandle>>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let response = {
                    let guard = handle_state.read().await;
                    match &*guard {
                        Some(handle) => process_request(&line, handle).await,
                        None => {
                            // Hub not connected yet
                            let request: Result<Request, _> = serde_json::from_str(&line);
                            match request {
                                Ok(Request::Status) => {
                                    Response::success(ResponseData::Status(StatusData {
                                        connected: false,
                                        node_number: 0, // We don't have this info without the handle
                                        cg_id: String::new(),
                                        endorsing: None,
                                    }))
                                }
                                Ok(_) => Response::error("hub not connected yet"),
                                Err(e) => Response::error(format!("invalid request: {}", e)),
                            }
                        }
                    }
                };
                let response_json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    serde_json::to_string(&Response::error(format!("serialization error: {}", e)))
                        .unwrap()
                });

                if let Err(e) = writer.write_all(response_json.as_bytes()).await {
                    eprintln!("Failed to write response: {}", e);
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    eprintln!("Failed to write newline: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    eprintln!("Failed to flush: {}", e);
                    break;
                }

                if matches!(
                    serde_json::from_str::<Request>(&line),
                    Ok(Request::Shutdown)
                ) {
                    break;
                }
            }
            Err(e) => {
                eprintln!("Failed to read from client: {}", e);
                break;
            }
        }
    }
}

/// Process a single request and return a response.
async fn process_request(line: &str, handle: &ServingHandle) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return Response::error(format!("invalid request: {}", e)),
    };

    match request {
        Request::Status => match handle.status().await {
            Ok(status) => {
                let endorsing = status.endorsing.map(|e| EndorsingData {
                    codes_outstanding: e.codes_outstanding,
                    nodes_awaiting_cosign: e.nodes_awaiting_cosign,
                });
                Response::success(ResponseData::Status(StatusData {
                    connected: status.connected,
                    node_number: status.node_number,
                    cg_id: status.connectivity_group_id.to_string(),
                    endorsing,
                }))
            }
            Err(e) => Response::error(format!("status failed: {}", e)),
        },

        Request::GetActivationCode => match handle.generate_activation_code().await {
            Ok(code) => Response::success(ResponseData::ActivationCode(ActivationCodeData {
                activation_code: code.format(),
            })),
            Err(e) => Response::error(format!("{}", e)),
        },

        Request::Shutdown => {
            let _ = handle.shutdown().await;
            Response::success(ResponseData::Empty)
        }
    }
}

/// Parse a port file (`port:password` format).
#[cfg(windows)]
fn parse_port_file(contents: &str) -> Option<(u16, &str)> {
    let contents = contents.trim();
    let colon = contents.find(':')?;
    let port: u16 = contents[..colon].parse().ok()?;
    let password = &contents[colon + 1..];
    Some((port, password))
}

/// Client for connecting to the daemon.
pub struct DaemonClient {
    reader: BufReader<ReadHalf>,
    writer: WriteHalf,
}

impl DaemonClient {
    /// Connect to the daemon for a specific node (via Unix socket).
    #[cfg(unix)]
    pub async fn connect(connectivity_group_id: &str, node_number: i32) -> Result<Self> {
        let path = ipc_path(connectivity_group_id, node_number);
        let stream = UnixStream::connect(&path).await.with_context(|| {
            format!("failed to connect to daemon at {:?} (is it running?)", path)
        })?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
        })
    }

    /// Connect to the daemon for a specific node (via TCP localhost).
    ///
    /// Reads the port and password from the `.port` file, connects, and
    /// sends the password as the first line for authentication.
    #[cfg(windows)]
    pub async fn connect(connectivity_group_id: &str, node_number: i32) -> Result<Self> {
        let path = ipc_path(connectivity_group_id, node_number);
        let contents = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("daemon not running (no port file {:?})", path))?;
        let (port, password) = parse_port_file(&contents)
            .context("invalid daemon port file")?;
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .with_context(|| format!("daemon not running (port {})", port))?;
        let (reader, mut writer) = stream.into_split();
        // Send IPC password
        writer.write_all(password.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(Self {
            reader: BufReader::new(reader),
            writer,
        })
    }

    /// Send a request and receive a response.
    pub async fn request(&mut self, req: &Request) -> Result<Response> {
        let request_json = serde_json::to_string(req)?;
        self.writer.write_all(request_json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        let mut line = String::new();
        self.reader.read_line(&mut line).await?;

        let response: Response = serde_json::from_str(&line)?;
        Ok(response)
    }
}
