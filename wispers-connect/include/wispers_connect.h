#ifndef WISPERS_CONNECT_H
#define WISPERS_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Status codes returned by the FFI functions.
typedef enum {
    WISPERS_STATUS_SUCCESS = 0,
    WISPERS_STATUS_NULL_POINTER = 1,
    WISPERS_STATUS_INVALID_UTF8 = 2,
    WISPERS_STATUS_STORE_ERROR = 3,
    WISPERS_STATUS_ALREADY_REGISTERED = 4,
    WISPERS_STATUS_NOT_REGISTERED = 5,
    WISPERS_STATUS_UNEXPECTED_STAGE = 6,  // Deprecated, use INVALID_STATE
    WISPERS_STATUS_NOT_FOUND = 7,
    WISPERS_STATUS_BUFFER_TOO_SMALL = 8,
    WISPERS_STATUS_MISSING_CALLBACK = 9,
    WISPERS_STATUS_INVALID_PAIRING_CODE = 10,
    WISPERS_STATUS_ACTIVATION_FAILED = 11,
    WISPERS_STATUS_HUB_ERROR = 12,
    WISPERS_STATUS_CONNECTION_FAILED = 13,
    WISPERS_STATUS_TIMEOUT = 14,
    WISPERS_STATUS_INVALID_STATE = 15,
    WISPERS_STATUS_UNAUTHENTICATED = 16,
    WISPERS_STATUS_PEER_REJECTED = 17,
    WISPERS_STATUS_PEER_UNAVAILABLE = 18,
} WispersStatus;

// Node state values.
typedef enum {
    WISPERS_NODE_STATE_PENDING = 0,
    WISPERS_NODE_STATE_REGISTERED = 1,
    WISPERS_NODE_STATE_ACTIVATED = 2,
} WispersNodeState;

// Activation status values for WispersNode.
typedef enum {
    WISPERS_ACTIVATION_UNKNOWN = 0,       // Caller is not activated, can't see roster
    WISPERS_ACTIVATION_NOT_ACTIVATED = 1, // Node is registered but not in roster
    WISPERS_ACTIVATION_ACTIVATED = 2,     // Node is in roster and not revoked
} WispersActivationStatus;

// Forward declarations for opaque handles.
typedef struct WispersNodeStorageHandle WispersNodeStorageHandle;
typedef struct WispersNodeHandle WispersNodeHandle;
typedef struct WispersServingHandle WispersServingHandle;
typedef struct WispersServingSession WispersServingSession;
typedef struct WispersIncomingConnections WispersIncomingConnections;
typedef struct WispersUdpConnectionHandle WispersUdpConnectionHandle;
typedef struct WispersQuicConnectionHandle WispersQuicConnectionHandle;
typedef struct WispersQuicStreamHandle WispersQuicStreamHandle;

// Host-provided storage callbacks. All functions must be non-null when used.
// The ctx pointer carries all context the host needs, including any namespace
// or isolation information used to keep different node storages separate. The
// library does not manage namespacing.
typedef struct {
    void *ctx;
    WispersStatus (*load_root_key)(void *ctx, uint8_t *out_key, size_t out_key_len);
    WispersStatus (*save_root_key)(void *ctx, const uint8_t *key, size_t key_len);
    WispersStatus (*delete_root_key)(void *ctx);

    // Registration payloads are serialized by Rust (protobuf, see storage.proto).
    WispersStatus (*load_registration)(void *ctx, uint8_t *buffer, size_t buffer_len, size_t *out_len);
    WispersStatus (*save_registration)(void *ctx, const uint8_t *buffer, size_t buffer_len);
    WispersStatus (*delete_registration)(void *ctx);
} WispersNodeStorageCallbacks;

//------------------------------------------------------------------------------
// Callback types for async operations
//------------------------------------------------------------------------------

// Basic completion callback (no result value).
typedef void (*WispersCallback)(void *ctx, WispersStatus status);

// Callback for restore_or_init. Returns a single node handle and its current state.
// The handle can be used for all operations; state-inappropriate operations
// will return WISPERS_STATUS_INVALID_STATE.
typedef void (*WispersInitCallback)(
    void *ctx,
    WispersStatus status,
    WispersNodeHandle *handle,
    WispersNodeState state
);

//------------------------------------------------------------------------------
// Node info (returned by list_nodes)
//------------------------------------------------------------------------------

// Information about a node in the connectivity group.
typedef struct {
    int32_t node_number;
    char *name;                          // Owned, freed by wispers_node_list_free()
    bool is_self;                        // Whether this is the current node
    int32_t activation_status;           // WispersActivationStatus value
    int64_t last_seen_at_millis;
    bool is_online;                      // Whether the node is connected to the hub
} WispersNode;

// List of nodes. Free with wispers_node_list_free().
typedef struct {
    WispersNode *nodes;
    size_t count;
} WispersNodeList;

// Free a node list and all contained strings.
void wispers_node_list_free(WispersNodeList *list);

// Callback that receives a node list.
typedef void (*WispersNodeListCallback)(
    void *ctx,
    WispersStatus status,
    WispersNodeList *list
);

// Callback for start_serving that receives session components.
// serving_handle and session are always provided on success.
// incoming is only provided for activated nodes (NULL for registered nodes).
typedef void (*WispersStartServingCallback)(
    void *ctx,
    WispersStatus status,
    WispersServingHandle *serving_handle,
    WispersServingSession *session,
    WispersIncomingConnections *incoming
);

// Callback that receives a pairing code string.
// The pairing code must be freed with wispers_string_free().
typedef void (*WispersPairingCodeCallback)(
    void *ctx,
    WispersStatus status,
    char *pairing_code
);

// Callback that receives a UDP connection handle.
typedef void (*WispersUdpConnectionCallback)(
    void *ctx,
    WispersStatus status,
    WispersUdpConnectionHandle *connection
);

// Callback that receives data from a UDP connection.
// The data buffer is only valid during the callback invocation.
typedef void (*WispersDataCallback)(
    void *ctx,
    WispersStatus status,
    const uint8_t *data,
    size_t len
);

// Callback that receives a QUIC connection handle.
typedef void (*WispersQuicConnectionCallback)(
    void *ctx,
    WispersStatus status,
    WispersQuicConnectionHandle *connection
);

// Callback that receives a QUIC stream handle.
typedef void (*WispersQuicStreamCallback)(
    void *ctx,
    WispersStatus status,
    WispersQuicStreamHandle *stream
);

//------------------------------------------------------------------------------
// Registration info (returned by read_registration)
//------------------------------------------------------------------------------

// Registration information. Strings are owned and must be freed with wispers_string_free().
typedef struct {
    char *connectivity_group_id;  // Owned, free with wispers_string_free()
    int32_t node_number;
    char *auth_token;             // Owned, free with wispers_string_free()
    char *attestation_jwt;        // Owned, free with wispers_string_free()
} WispersRegistrationInfo;

// Free a registration info struct and its strings.
void wispers_registration_info_free(WispersRegistrationInfo *info);

//------------------------------------------------------------------------------
// Storage lifecycle
//------------------------------------------------------------------------------

WispersNodeStorageHandle *wispers_storage_new_in_memory(void);
WispersNodeStorageHandle *wispers_storage_new_with_callbacks(const WispersNodeStorageCallbacks *callbacks);
void wispers_storage_free(WispersNodeStorageHandle *handle);

// Read registration from local storage (sync, no hub contact).
// Returns SUCCESS with out_info populated if registered, NOT_FOUND if not registered.
// Caller must free out_info with wispers_registration_info_free() on success.
WispersStatus wispers_storage_read_registration(
    WispersNodeStorageHandle *handle,
    WispersRegistrationInfo *out_info
);

// Override the hub address (for testing).
WispersStatus wispers_storage_override_hub_addr(
    WispersNodeStorageHandle *handle,
    const char *hub_addr
);

// Restore or initialize node state asynchronously.
// On success, callback receives a single node handle and its current state.
// The storage handle remains valid and is NOT consumed.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_storage_restore_or_init_async(
    WispersNodeStorageHandle *handle,
    void *ctx,
    WispersInitCallback callback
);

//------------------------------------------------------------------------------
// Node operations (unified handle)
//------------------------------------------------------------------------------

// Free a node handle.
void wispers_node_free(WispersNodeHandle *handle);

// Get the current state of the node.
WispersNodeState wispers_node_state(WispersNodeHandle *handle);

// Register the node with the hub using a registration token.
// Requires: Pending state. Returns INVALID_STATE if not Pending.
// The node handle is NOT consumed - it transitions to Registered state on success.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_register_async(
    WispersNodeHandle *handle,
    const char *token,
    void *ctx,
    WispersCallback callback
);

// Activate the node by pairing with an endorser.
// The pairing code format is "node_number-secret" (e.g., "1-abc123xyz0").
// Requires: Registered state. Returns INVALID_STATE if not Registered.
// The node handle is NOT consumed - it transitions to Activated state on success.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_activate_async(
    WispersNodeHandle *handle,
    const char *pairing_code,
    void *ctx,
    WispersCallback callback
);

// Logout the node (delete local state, deregister from hub if registered,
// revoke from roster if activated).
// The node handle is CONSUMED by this call and must not be used afterward.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_logout_async(
    WispersNodeHandle *handle,
    void *ctx,
    WispersCallback callback
);

// List all nodes in the connectivity group.
// Requires: Registered or Activated state. Returns INVALID_STATE if Pending.
// The node handle is NOT consumed and remains valid after this call.
// On success, callback receives a WispersNodeList that must be freed.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_list_nodes_async(
    WispersNodeHandle *handle,
    void *ctx,
    WispersNodeListCallback callback
);

// Start a serving session.
// Requires: Registered or Activated state. Returns INVALID_STATE if Pending.
// - Registered nodes can serve for bootstrapping but cannot accept P2P connections.
// - Activated nodes can accept P2P connections.
// The node handle is NOT consumed.
// On success, callback receives serving_handle, session, and incoming (NULL for registered).
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_start_serving_async(
    WispersNodeHandle *handle,
    void *ctx,
    WispersStartServingCallback callback
);

// Connect to a peer node using UDP transport.
// Requires: Activated state. Returns INVALID_STATE if not Activated.
// The node handle is NOT consumed.
// On success, callback receives the UDP connection handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_connect_udp_async(
    WispersNodeHandle *handle,
    int32_t peer_node_number,
    void *ctx,
    WispersUdpConnectionCallback callback
);

// Connect to a peer node using QUIC transport.
// Requires: Activated state. Returns INVALID_STATE if not Activated.
// The node handle is NOT consumed.
// On success, callback receives the QUIC connection handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_node_connect_quic_async(
    WispersNodeHandle *handle,
    int32_t peer_node_number,
    void *ctx,
    WispersQuicConnectionCallback callback
);

//------------------------------------------------------------------------------
// P2P UDP Connections
//------------------------------------------------------------------------------

// Send data over a UDP connection.
// This is a synchronous, non-blocking operation.
// The connection handle is NOT consumed.
// Returns SUCCESS if the data was sent, or an error status.
WispersStatus wispers_udp_connection_send(
    WispersUdpConnectionHandle *handle,
    const uint8_t *data,
    size_t len
);

// Receive data from a UDP connection.
// The connection handle is NOT consumed.
// On success, callback receives the data buffer (only valid during callback).
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_udp_connection_recv_async(
    WispersUdpConnectionHandle *handle,
    void *ctx,
    WispersDataCallback callback
);

// Close a UDP connection.
// The connection handle is CONSUMED by this call.
void wispers_udp_connection_close(WispersUdpConnectionHandle *handle);

// Free a UDP connection handle (if not already closed).
void wispers_udp_connection_free(WispersUdpConnectionHandle *handle);

//------------------------------------------------------------------------------
// P2P QUIC Connections
//------------------------------------------------------------------------------

// Open a new bidirectional stream on a QUIC connection.
// The connection handle is NOT consumed.
// On success, callback receives the stream handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_connection_open_stream_async(
    WispersQuicConnectionHandle *handle,
    void *ctx,
    WispersQuicStreamCallback callback
);

// Accept an incoming stream from the peer.
// The connection handle is NOT consumed.
// On success, callback receives the stream handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_connection_accept_stream_async(
    WispersQuicConnectionHandle *handle,
    void *ctx,
    WispersQuicStreamCallback callback
);

// Close a QUIC connection.
// The connection handle is CONSUMED by this call.
// Callback is invoked when the close operation completes.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_connection_close_async(
    WispersQuicConnectionHandle *handle,
    void *ctx,
    WispersCallback callback
);

// Free a QUIC connection handle (if not already closed).
void wispers_quic_connection_free(WispersQuicConnectionHandle *handle);

// Free a QUIC stream handle.
void wispers_quic_stream_free(WispersQuicStreamHandle *stream);

//------------------------------------------------------------------------------
// QUIC Stream Operations
//------------------------------------------------------------------------------

// Write data to a QUIC stream.
// The stream handle is NOT consumed.
// The data is copied before the function returns, so the caller's buffer
// can be freed immediately.
// Callback is invoked when the write completes.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_stream_write_async(
    WispersQuicStreamHandle *handle,
    const uint8_t *data,
    size_t len,
    void *ctx,
    WispersCallback callback
);

// Read data from a QUIC stream.
// The stream handle is NOT consumed.
// On success, callback receives the data buffer (only valid during callback).
// max_len specifies the maximum number of bytes to read.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_stream_read_async(
    WispersQuicStreamHandle *handle,
    size_t max_len,
    void *ctx,
    WispersDataCallback callback
);

// Close the stream for writing (send FIN).
// The stream handle is NOT consumed. The stream can still be read from
// after calling finish.
// Callback is invoked when the finish completes.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_stream_finish_async(
    WispersQuicStreamHandle *handle,
    void *ctx,
    WispersCallback callback
);

// Shutdown the stream (stop sending and receiving).
// The stream handle is NOT consumed.
// Callback is invoked when the shutdown completes.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_quic_stream_shutdown_async(
    WispersQuicStreamHandle *handle,
    void *ctx,
    WispersCallback callback
);

//------------------------------------------------------------------------------
// Serving
//------------------------------------------------------------------------------

// Generate a pairing code for endorsing a new node.
// The serving handle is NOT consumed.
// On success, callback receives the pairing code string (must free with wispers_string_free).
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_serving_handle_generate_pairing_code_async(
    WispersServingHandle *handle,
    void *ctx,
    WispersPairingCodeCallback callback
);

// Run the serving session event loop.
// The session handle is CONSUMED by this call.
// The callback is invoked when the session ends (either by shutdown or error).
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_serving_session_run_async(
    WispersServingSession *session,
    void *ctx,
    WispersCallback callback
);

// Request the serving session to shut down.
// The serving handle is NOT consumed.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_serving_handle_shutdown_async(
    WispersServingHandle *handle,
    void *ctx,
    WispersCallback callback
);

// Free a serving handle.
void wispers_serving_handle_free(WispersServingHandle *handle);

// Free a serving session handle.
void wispers_serving_session_free(WispersServingSession *session);

// Free an incoming connections handle.
void wispers_incoming_connections_free(WispersIncomingConnections *incoming);

// Accept an incoming UDP connection.
// The incoming connections handle is NOT consumed.
// Waits for a peer to connect via UDP and returns the connection handle.
// On success, callback receives the UDP connection handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_incoming_accept_udp_async(
    WispersIncomingConnections *handle,
    void *ctx,
    WispersUdpConnectionCallback callback
);

// Accept an incoming QUIC connection.
// The incoming connections handle is NOT consumed.
// Waits for a peer to connect via QUIC and returns the connection handle.
// On success, callback receives the QUIC connection handle.
// Returns SUCCESS immediately if the async operation was started.
WispersStatus wispers_incoming_accept_quic_async(
    WispersIncomingConnections *handle,
    void *ctx,
    WispersQuicConnectionCallback callback
);

//------------------------------------------------------------------------------
// Utilities
//------------------------------------------------------------------------------

// Free strings allocated by the library.
void wispers_string_free(char *ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // WISPERS_CONNECT_H
