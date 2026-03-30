//! FFI wrapper for libjuice ICE library.
//!
//! This provides a safe Rust interface to the libjuice C library for ICE
//! (Interactive Connectivity Establishment) NAT traversal.

#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

mod ffi {
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(non_upper_case_globals)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/juice_bindings.rs"));
}

type Result<T> = std::result::Result<T, JuiceError>;

/// TURN server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnServerConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// ICE servers configuration (STUN + optional TURN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceServersConfig {
    pub stun_host: String,
    pub stun_port: u16,
    pub turn_servers: Vec<TurnServerConfig>,
}

impl IceServersConfig {
    pub fn new(stun_host: impl Into<String>, stun_port: u16) -> Self {
        Self {
            stun_host: stun_host.into(),
            stun_port,
            turn_servers: Vec::new(),
        }
    }

    pub fn add_turn_server(&mut self, server: TurnServerConfig) {
        self.turn_servers.push(server);
    }
}

/// ICE agent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected,
    Gathering,
    Connecting,
    Connected,
    Completed,
    Failed,
    Unknown(i32),
}

impl State {
    fn from_raw(raw: ffi::juice_state) -> Self {
        match raw {
            x if x == ffi::juice_state_JUICE_STATE_DISCONNECTED => State::Disconnected,
            x if x == ffi::juice_state_JUICE_STATE_GATHERING => State::Gathering,
            x if x == ffi::juice_state_JUICE_STATE_CONNECTING => State::Connecting,
            x if x == ffi::juice_state_JUICE_STATE_CONNECTED => State::Connected,
            x if x == ffi::juice_state_JUICE_STATE_COMPLETED => State::Completed,
            x if x == ffi::juice_state_JUICE_STATE_FAILED => State::Failed,
            #[allow(clippy::unnecessary_cast)]
            other => State::Unknown(other as i32),
        }
    }

    fn as_raw(self) -> ffi::juice_state {
        match self {
            State::Disconnected => ffi::juice_state_JUICE_STATE_DISCONNECTED,
            State::Gathering => ffi::juice_state_JUICE_STATE_GATHERING,
            State::Connecting => ffi::juice_state_JUICE_STATE_CONNECTING,
            State::Connected => ffi::juice_state_JUICE_STATE_CONNECTED,
            State::Completed => ffi::juice_state_JUICE_STATE_COMPLETED,
            State::Failed => ffi::juice_state_JUICE_STATE_FAILED,
            State::Unknown(other) => other as ffi::juice_state,
        }
    }

    /// Returns true if the connection is established (Connected or Completed).
    pub fn is_connected(self) -> bool {
        matches!(self, State::Connected | State::Completed)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { ffi::juice_state_to_string(self.as_raw()) };
        if ptr.is_null() {
            write!(f, "{:?}", self)
        } else {
            unsafe {
                let s = CStr::from_ptr(ptr);
                write!(f, "{}", s.to_string_lossy())
            }
        }
    }
}

/// Error type for libjuice operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JuiceError {
    Invalid,
    Failed,
    NotAvailable,
    Ignored,
    Again,
    TooLarge,
    Closed,
    CreationFailed,
    InteriorNul,
    Unknown(i32),
}

impl JuiceError {
    fn from_code(code: i32) -> Self {
        match code {
            x if x == ffi::JUICE_ERR_INVALID => JuiceError::Invalid,
            x if x == ffi::JUICE_ERR_FAILED => JuiceError::Failed,
            x if x == ffi::JUICE_ERR_NOT_AVAIL => JuiceError::NotAvailable,
            x if x == ffi::JUICE_ERR_IGNORED => JuiceError::Ignored,
            x if x == ffi::JUICE_ERR_AGAIN => JuiceError::Again,
            x if x == ffi::JUICE_ERR_TOO_LARGE => JuiceError::TooLarge,
            x => JuiceError::Unknown(x),
        }
    }
}

impl fmt::Display for JuiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JuiceError::Invalid => write!(f, "juice: invalid argument"),
            JuiceError::Failed => write!(f, "juice: runtime failure"),
            JuiceError::NotAvailable => write!(f, "juice: element not available"),
            JuiceError::Ignored => write!(f, "juice: ignored"),
            JuiceError::Again => write!(f, "juice: buffer full (try again)"),
            JuiceError::TooLarge => write!(f, "juice: datagram too large"),
            JuiceError::Closed => write!(f, "juice: agent already closed"),
            JuiceError::CreationFailed => write!(f, "juice: failed to create agent"),
            JuiceError::InteriorNul => write!(f, "juice: string contains interior NUL byte"),
            JuiceError::Unknown(code) => write!(f, "juice: error code {}", code),
        }
    }
}

impl std::error::Error for JuiceError {}

/// Owned configuration that keeps strings alive for FFI.
struct OwnedConfig {
    raw: ffi::juice_config,
    _stun_host: CString,
    _turn_servers: Vec<ffi::juice_turn_server>,
    _turn_strings: Vec<CString>,
}

impl OwnedConfig {
    fn new(config: IceServersConfig) -> Result<Self> {
        let IceServersConfig {
            stun_host,
            stun_port,
            turn_servers,
        } = config;

        let stun_host_c = CString::new(stun_host).map_err(|_| JuiceError::InteriorNul)?;

        let mut raw: ffi::juice_config = unsafe { std::mem::zeroed() };
        raw.stun_server_host = stun_host_c.as_ptr();
        raw.stun_server_port = stun_port;

        let mut turn_strings = Vec::with_capacity(turn_servers.len() * 3);
        let mut raw_servers = Vec::with_capacity(turn_servers.len());
        for server in turn_servers {
            let mut raw_server: ffi::juice_turn_server = unsafe { std::mem::zeroed() };

            let host_c = CString::new(server.host).map_err(|_| JuiceError::InteriorNul)?;
            raw_server.host = host_c.as_ptr();
            turn_strings.push(host_c);
            raw_server.port = server.port;

            if let Some(username) = server.username
                && !username.is_empty()
            {
                let username_c = CString::new(username).map_err(|_| JuiceError::InteriorNul)?;
                raw_server.username = username_c.as_ptr();
                turn_strings.push(username_c);
            }

            if let Some(password) = server.password
                && !password.is_empty()
            {
                let password_c = CString::new(password).map_err(|_| JuiceError::InteriorNul)?;
                raw_server.password = password_c.as_ptr();
                turn_strings.push(password_c);
            }

            raw_servers.push(raw_server);
        }

        if !raw_servers.is_empty() {
            raw.turn_servers = raw_servers.as_ptr() as *mut _;
            raw.turn_servers_count = raw_servers.len() as i32;
        }

        Ok(Self {
            raw,
            _stun_host: stun_host_c,
            _turn_servers: raw_servers,
            _turn_strings: turn_strings,
        })
    }

    fn configure_callbacks(&mut self, user_ptr: *mut c_void) {
        self.raw.cb_state_changed = Some(on_state_changed);
        self.raw.cb_candidate = Some(on_candidate_discovered);
        self.raw.cb_gathering_done = Some(on_gathering_done);
        self.raw.cb_recv = Some(on_recv_data);
        self.raw.user_ptr = user_ptr;
    }

    fn as_raw(&self) -> *const ffi::juice_config {
        &self.raw
    }
}

unsafe impl Send for OwnedConfig {}
unsafe impl Sync for OwnedConfig {}

/// A libjuice ICE agent.
pub struct JuiceAgent {
    inner: Arc<JuiceAgentInner>,
    _config: OwnedConfig,
}

struct JuiceAgentInner {
    agent: AtomicPtr<ffi::juice_agent_t>,
    closed: AtomicBool,
    on_state_change: Box<dyn Fn(State) + Send + Sync>,
    on_candidate: Box<dyn Fn(String) + Send + Sync>,
    on_gathering_done: Box<dyn Fn() + Send + Sync>,
    on_recv: Box<dyn Fn(Vec<u8>) + Send + Sync>,
}

impl JuiceAgentInner {
    fn new(
        on_state_change: impl Fn(State) + Send + Sync + 'static,
        on_candidate: impl Fn(String) + Send + Sync + 'static,
        on_gathering_done: impl Fn() + Send + Sync + 'static,
        on_recv: impl Fn(Vec<u8>) + Send + Sync + 'static,
    ) -> Self {
        Self {
            agent: AtomicPtr::new(std::ptr::null_mut()),
            closed: AtomicBool::new(false),
            on_state_change: Box::new(on_state_change),
            on_candidate: Box::new(on_candidate),
            on_gathering_done: Box::new(on_gathering_done),
            on_recv: Box::new(on_recv),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl JuiceAgent {
    /// Create a new ICE agent with the given configuration and callbacks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ice_servers_config: IceServersConfig,
        on_state_change: impl Fn(State) + Send + Sync + 'static,
        on_candidate: impl Fn(String) + Send + Sync + 'static,
        on_gathering_done: impl Fn() + Send + Sync + 'static,
        on_recv: impl Fn(Vec<u8>) + Send + Sync + 'static,
    ) -> Result<Self> {
        let inner = Arc::new(JuiceAgentInner::new(
            on_state_change,
            on_candidate,
            on_gathering_done,
            on_recv,
        ));

        let mut owned_config = OwnedConfig::new(ice_servers_config)?;
        let user_ptr = Arc::as_ptr(&inner) as *mut c_void;
        owned_config.configure_callbacks(user_ptr);

        let agent_ptr = unsafe { ffi::juice_create(owned_config.as_raw()) };
        if agent_ptr.is_null() {
            return Err(JuiceError::CreationFailed);
        }
        inner.agent.store(agent_ptr, Ordering::Release);

        Ok(Self {
            inner,
            _config: owned_config,
        })
    }

    fn agent_ptr(&self) -> Result<*mut ffi::juice_agent_t> {
        let ptr = self.inner.agent.load(Ordering::Acquire);
        if ptr.is_null() {
            Err(JuiceError::Closed)
        } else {
            Ok(ptr)
        }
    }

    /// Close the agent and release resources.
    pub fn close(&self) {
        if self
            .inner
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let ptr = self
                .inner
                .agent
                .swap(std::ptr::null_mut(), Ordering::AcqRel);
            if !ptr.is_null() {
                unsafe { ffi::juice_destroy(ptr) };
            }
        }
    }

    /// Start gathering ICE candidates.
    pub fn gather_candidates(&self) -> Result<()> {
        let agent = self.agent_ptr()?;
        let rc = unsafe { ffi::juice_gather_candidates(agent) };
        to_result(rc)
    }

    /// Get the local SDP description (after gathering).
    pub fn get_local_description(&self) -> Result<String> {
        let agent = self.agent_ptr()?;
        let len = ffi::JUICE_MAX_SDP_STRING_LEN as usize;
        let mut buffer = vec![0u8; len];
        let rc = unsafe {
            ffi::juice_get_local_description(
                agent,
                buffer.as_mut_ptr() as *mut c_char,
                buffer.len(),
            )
        };
        to_result(rc)?;
        Ok(buffer_to_string(&buffer))
    }

    /// Set the remote SDP description.
    pub fn set_remote_description(&self, sdp: &str) -> Result<()> {
        let agent = self.agent_ptr()?;
        let c_sdp = CString::new(sdp).map_err(|_| JuiceError::InteriorNul)?;
        let rc = unsafe { ffi::juice_set_remote_description(agent, c_sdp.as_ptr()) };
        to_result(rc)
    }

    /// Add a remote ICE candidate.
    pub fn add_remote_candidate(&self, sdp: &str) -> Result<()> {
        let agent = self.agent_ptr()?;
        let c_sdp = CString::new(sdp).map_err(|_| JuiceError::InteriorNul)?;
        let rc = unsafe { ffi::juice_add_remote_candidate(agent, c_sdp.as_ptr()) };
        to_result(rc)
    }

    /// Signal that remote candidate gathering is complete.
    pub fn set_remote_gathering_done(&self) -> Result<()> {
        let agent = self.agent_ptr()?;
        let rc = unsafe { ffi::juice_set_remote_gathering_done(agent) };
        to_result(rc)
    }

    /// Send data to the remote peer.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        let agent = self.agent_ptr()?;
        let ptr = if data.is_empty() {
            ptr::null()
        } else {
            data.as_ptr() as *const c_char
        };
        let rc = unsafe { ffi::juice_send(agent, ptr, data.len()) };
        to_result(rc)
    }

    /// Get the current ICE state.
    pub fn get_state(&self) -> State {
        match self.agent_ptr() {
            Ok(agent) => {
                let raw = unsafe { ffi::juice_get_state(agent) };
                State::from_raw(raw)
            }
            Err(_) => State::Disconnected,
        }
    }

    /// Get the selected local and remote candidates.
    pub fn get_selected_candidates(&self) -> Result<(String, String)> {
        let agent = self.agent_ptr()?;
        let len = ffi::JUICE_MAX_CANDIDATE_SDP_STRING_LEN as usize;
        let mut local = vec![0u8; len];
        let mut remote = vec![0u8; len];
        let rc = unsafe {
            ffi::juice_get_selected_candidates(
                agent,
                local.as_mut_ptr() as *mut c_char,
                local.len(),
                remote.as_mut_ptr() as *mut c_char,
                remote.len(),
            )
        };
        to_result(rc)?;
        Ok((buffer_to_string(&local), buffer_to_string(&remote)))
    }

    /// Get the selected local and remote addresses.
    pub fn get_selected_addresses(&self) -> Result<(String, String)> {
        let agent = self.agent_ptr()?;
        let len = ffi::JUICE_MAX_ADDRESS_STRING_LEN as usize;
        let mut local = vec![0u8; len];
        let mut remote = vec![0u8; len];
        let rc = unsafe {
            ffi::juice_get_selected_addresses(
                agent,
                local.as_mut_ptr() as *mut c_char,
                local.len(),
                remote.as_mut_ptr() as *mut c_char,
                remote.len(),
            )
        };
        to_result(rc)?;
        Ok((buffer_to_string(&local), buffer_to_string(&remote)))
    }
}

impl Drop for JuiceAgent {
    fn drop(&mut self) {
        self.close();
    }
}

fn buffer_to_string(buffer: &[u8]) -> String {
    let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..len]).into_owned()
}

fn to_result(code: i32) -> Result<()> {
    if code == ffi::JUICE_ERR_SUCCESS as i32 {
        Ok(())
    } else {
        Err(JuiceError::from_code(code))
    }
}

unsafe fn with_inner(user_ptr: *mut c_void, f: impl FnOnce(&JuiceAgentInner)) {
    if user_ptr.is_null() {
        return;
    }
    // SAFETY: user_ptr was set to Arc::as_ptr in JuiceAgent::new and is valid while agent exists
    let inner = unsafe { &*(user_ptr as *const JuiceAgentInner) };
    if inner.is_closed() {
        return;
    }
    f(inner);
}

unsafe extern "C" fn on_state_changed(
    _agent: *mut ffi::juice_agent_t,
    state: ffi::juice_state,
    user_ptr: *mut c_void,
) {
    // SAFETY: Called from libjuice C code with valid user_ptr
    unsafe {
        with_inner(user_ptr, |inner| {
            (inner.on_state_change)(State::from_raw(state));
        });
    }
}

unsafe extern "C" fn on_candidate_discovered(
    _agent: *mut ffi::juice_agent_t,
    sdp: *const c_char,
    user_ptr: *mut c_void,
) {
    if sdp.is_null() {
        return;
    }
    // SAFETY: Called from libjuice C code with valid user_ptr and sdp
    unsafe {
        with_inner(user_ptr, |inner| {
            let s = CStr::from_ptr(sdp).to_string_lossy().into_owned();
            (inner.on_candidate)(s);
        });
    }
}

unsafe extern "C" fn on_gathering_done(_agent: *mut ffi::juice_agent_t, user_ptr: *mut c_void) {
    // SAFETY: Called from libjuice C code with valid user_ptr
    unsafe {
        with_inner(user_ptr, |inner| {
            (inner.on_gathering_done)();
        });
    }
}

unsafe extern "C" fn on_recv_data(
    _agent: *mut ffi::juice_agent_t,
    data: *const c_char,
    size: usize,
    user_ptr: *mut c_void,
) {
    if data.is_null() {
        return;
    }
    // SAFETY: Called from libjuice C code with valid user_ptr and data buffer
    unsafe {
        with_inner(user_ptr, |inner| {
            let slice = std::slice::from_raw_parts(data as *const u8, size);
            let buf = slice.to_vec();
            (inner.on_recv)(buf);
        });
    }
}
