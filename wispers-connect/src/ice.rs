//! Higher-level ICE connection wrappers.
//!
//! Provides `IceCaller` and `IceAnswerer` for establishing P2P connections
//! using the libjuice ICE library.

use std::sync::mpsc;

use thiserror::Error;
use tokio::sync::{Mutex as TokioMutex, mpsc as tokio_mpsc};

use crate::hub::proto::StunTurnConfig;
use crate::juice::{
    IceServersConfig, JuiceAgent, JuiceError, State as JuiceState, TurnServerConfig,
};

/// Error type for ICE operations.
#[derive(Debug, Error)]
pub enum IceError {
    #[error("juice error: {0}")]
    Juice(#[from] JuiceError),

    #[error("channel closed")]
    ChannelClosed,

    #[error("connection failed")]
    ConnectionFailed,

    #[error("invalid port number")]
    InvalidPort,
}

pub type Result<T> = std::result::Result<T, IceError>;

/// Convert hub's `StunTurnConfig` to juice's `IceServersConfig`.
fn build_ice_servers_config(config: &StunTurnConfig) -> Result<IceServersConfig> {
    // Parse STUN server (format: "host:port" or just "host")
    let (stun_host, stun_port) = parse_host_port(&config.stun_server, 3478)?;
    let mut ice_config = IceServersConfig::new(stun_host, stun_port);

    // Add TURN server if configured
    if !config.turn_server.is_empty() {
        let (turn_host, turn_port) = parse_host_port(&config.turn_server, 3478)?;
        let username = (!config.turn_username.is_empty()).then(|| config.turn_username.clone());
        let password = (!config.turn_password.is_empty()).then(|| config.turn_password.clone());

        ice_config.add_turn_server(TurnServerConfig {
            host: turn_host,
            port: turn_port,
            username,
            password,
        });
    }

    Ok(ice_config)
}

fn parse_host_port(addr: &str, default_port: u16) -> Result<(String, u16)> {
    match addr.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse().map_err(|_| IceError::InvalidPort)?;
            Ok((host.to_string(), port))
        }
        None => Ok((addr.to_string(), default_port)),
    }
}

/// ICE caller - gathers candidates first, then connects when remote SDP is provided.
pub struct IceCaller {
    agent: JuiceAgent,
    state_rx: TokioMutex<tokio_mpsc::UnboundedReceiver<JuiceState>>,
    recv_rx: TokioMutex<tokio_mpsc::UnboundedReceiver<Vec<u8>>>,
    local_desc: String,
}

impl IceCaller {
    /// Create a new ICE caller.
    ///
    /// This immediately starts gathering candidates and blocks until gathering is complete.
    pub fn new(config: &StunTurnConfig) -> Result<Self> {
        let (state_tx, state_rx) = tokio_mpsc::unbounded_channel();
        let (gather_tx, gather_rx) = mpsc::channel();
        let (recv_tx, recv_rx) = tokio_mpsc::unbounded_channel();

        let ice_servers_config = build_ice_servers_config(config)?;

        let agent = JuiceAgent::new(
            ice_servers_config,
            move |state| {
                let _ = state_tx.send(state);
            },
            |_sdp| {},
            move || {
                let _ = gather_tx.send(());
            },
            move |data| {
                let _ = recv_tx.send(data);
            },
        )?;

        agent.gather_candidates()?;
        gather_rx.recv().map_err(|_| IceError::ChannelClosed)?;
        let local_desc = agent.get_local_description()?;

        Ok(Self {
            agent,
            state_rx: TokioMutex::new(state_rx),
            recv_rx: TokioMutex::new(recv_rx),
            local_desc,
        })
    }

    /// Get the local SDP description to send to the remote peer.
    pub fn local_description(&self) -> &str {
        &self.local_desc
    }

    /// Connect to the remote peer using their SDP description.
    ///
    /// This sets the remote description and waits for the ICE connection to complete.
    pub async fn connect(&self, remote_desc: &str) -> Result<()> {
        self.agent.set_remote_description(remote_desc)?;
        self.agent.set_remote_gathering_done()?;
        wait_for_connect(&self.state_rx).await
    }

    /// Send data to the remote peer.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.agent.send(data).map_err(IceError::from)
    }

    /// Receive data from the remote peer.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(IceError::ChannelClosed)
    }

    /// Close the connection.
    pub fn close(&self) {
        self.agent.close();
    }

    /// Get the current ICE state.
    pub fn state(&self) -> JuiceState {
        self.agent.get_state()
    }
}

/// ICE answerer - receives remote SDP first, then gathers and connects.
pub struct IceAnswerer {
    agent: JuiceAgent,
    state_rx: TokioMutex<tokio_mpsc::UnboundedReceiver<JuiceState>>,
    recv_rx: TokioMutex<tokio_mpsc::UnboundedReceiver<Vec<u8>>>,
    local_desc: String,
}

impl IceAnswerer {
    /// Create a new ICE answerer with the caller's SDP description.
    ///
    /// This sets the remote description, gathers candidates, and blocks until gathering is complete.
    pub fn new(remote_desc: &str, config: &StunTurnConfig) -> Result<Self> {
        let (state_tx, state_rx) = tokio_mpsc::unbounded_channel();
        let (gather_tx, gather_rx) = mpsc::channel();
        let (recv_tx, recv_rx) = tokio_mpsc::unbounded_channel();

        let ice_servers_config = build_ice_servers_config(config)?;

        let agent = JuiceAgent::new(
            ice_servers_config,
            move |state| {
                let _ = state_tx.send(state);
            },
            |_sdp| {},
            move || {
                let _ = gather_tx.send(());
            },
            move |data| {
                let _ = recv_tx.send(data);
            },
        )?;

        agent.set_remote_description(remote_desc)?;
        agent.set_remote_gathering_done()?;
        agent.gather_candidates()?;
        gather_rx.recv().map_err(|_| IceError::ChannelClosed)?;
        let local_desc = agent.get_local_description()?;

        Ok(Self {
            agent,
            state_rx: TokioMutex::new(state_rx),
            recv_rx: TokioMutex::new(recv_rx),
            local_desc,
        })
    }

    /// Get the local SDP description to send back to the caller.
    pub fn local_description(&self) -> &str {
        &self.local_desc
    }

    /// Wait for the ICE connection to complete.
    pub async fn connect(&self) -> Result<()> {
        wait_for_connect(&self.state_rx).await
    }

    /// Send data to the remote peer.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.agent.send(data).map_err(IceError::from)
    }

    /// Receive data from the remote peer.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(IceError::ChannelClosed)
    }

    /// Close the connection.
    pub fn close(&self) {
        self.agent.close();
    }

    /// Get the current ICE state.
    pub fn state(&self) -> JuiceState {
        self.agent.get_state()
    }
}

/// Wait for the ICE connection to reach Connected or Completed state.
async fn wait_for_connect(
    state_rx: &TokioMutex<tokio_mpsc::UnboundedReceiver<JuiceState>>,
) -> Result<()> {
    let mut rx = state_rx.lock().await;
    while let Some(state) = rx.recv().await {
        match state {
            JuiceState::Connected | JuiceState::Completed => return Ok(()),
            JuiceState::Failed => return Err(IceError::ConnectionFailed),
            _ => {}
        }
    }
    Err(IceError::ChannelClosed)
}
