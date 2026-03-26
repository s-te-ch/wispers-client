//! FFI bindings for the wispers-connect library.
//!
//! Module structure:
//! - `types`: All FFI types, callbacks, handle wrappers, and memory management
//! - `node`: Storage and node lifecycle operations
//! - `serving`: Serving session operations
//! - `p2p`: P2P connection operations
//! - `runtime`: Tokio runtime management

// FFI functions necessarily dereference raw pointers from C callers.
#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::mut_from_ref)]

mod node;
mod p2p;
pub(crate) mod runtime;
mod serving;
mod types;

// Re-export types
pub use types::{
    CallbackContext, WispersCallback, WispersGroupInfo, WispersGroupInfoCallback,
    WispersGroupState, WispersInitCallback, WispersNode, WispersNodeHandle, WispersNodeList,
    WispersNodeState, WispersNodeStorageHandle, WispersRegistrationInfo, wispers_group_info_free,
    wispers_node_list_free, wispers_registration_info_free, wispers_string_free,
};

// Re-export node functions
pub use node::{
    wispers_node_activate_async, wispers_node_free, wispers_node_group_info_async,
    wispers_node_logout_async, wispers_node_register_async, wispers_node_state,
    wispers_storage_delete_state, wispers_storage_free, wispers_storage_new_in_memory,
    wispers_storage_new_with_callbacks, wispers_storage_override_hub_addr,
    wispers_storage_read_registration, wispers_storage_restore_or_init_async,
};

// Re-export serving functions
pub use serving::{
    WispersActivationCodeCallback, WispersIncomingConnections, WispersServingHandle,
    WispersServingSession, WispersStartServingCallback, wispers_incoming_accept_quic_async,
    wispers_incoming_accept_udp_async, wispers_incoming_connections_free,
    wispers_node_start_serving_async, wispers_serving_handle_free,
    wispers_serving_handle_generate_activation_code_async, wispers_serving_handle_shutdown_async,
    wispers_serving_session_free, wispers_serving_session_run_async,
};

// Re-export P2P functions
pub use p2p::{
    WispersDataCallback, WispersQuicConnectionCallback, WispersQuicConnectionHandle,
    WispersQuicStreamCallback, WispersQuicStreamHandle, WispersUdpConnectionCallback,
    WispersUdpConnectionHandle, wispers_node_connect_quic_async, wispers_node_connect_udp_async,
    wispers_quic_connection_accept_stream_async, wispers_quic_connection_close_async,
    wispers_quic_connection_free, wispers_quic_connection_open_stream_async,
    wispers_quic_stream_finish_async, wispers_quic_stream_free, wispers_quic_stream_read_async,
    wispers_quic_stream_shutdown_async, wispers_quic_stream_write_async,
    wispers_udp_connection_close, wispers_udp_connection_free, wispers_udp_connection_recv_async,
    wispers_udp_connection_send,
};

pub use crate::storage::foreign::WispersNodeStorageCallbacks;
