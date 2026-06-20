"""FFI function declarations and callback types for wispers_connect."""

from __future__ import annotations

import ctypes
from ctypes import (
    CFUNCTYPE,
    POINTER,
    c_bool,
    c_char_p,
    c_int,
    c_int32,
    c_int64,
    c_size_t,
    c_uint8,
    c_void_p,
)

from ._structs import (
    WispersNodeStorageCallbacks,
    WispersRegistrationInfo,
)

# ---------------------------------------------------------------------------
# Callback CFUNCTYPE definitions (matching C typedefs)
# ---------------------------------------------------------------------------

# void (*WispersCallback)(void *ctx, WispersStatus status, const char *error_detail)
WispersCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p)

# void (*WispersInitCallback)(void *ctx, WispersStatus, const char *, WispersNodeHandle *, WispersNodeState)
WispersInitCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p, c_int)

# void (*WispersGroupInfoCallback)(void *ctx, WispersStatus, const char *, WispersGroupInfo *)
WispersGroupInfoCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)

# void (*WispersStartServingCallback)(void *ctx, WispersStatus, const char *,
#     WispersServingHandle *, WispersServingSession *, WispersIncomingConnections *)
WispersStartServingCallbackType = CFUNCTYPE(
    None, c_void_p, c_int, c_char_p, c_void_p, c_void_p, c_void_p
)

# void (*WispersServingStatusCallback)(void *ctx, WispersStatus, const char *, WispersServingStatus *)
WispersServingStatusCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)

# void (*WispersActivationCodeCallback)(void *ctx, WispersStatus, const char *, char *activation_code)
# activation_code is c_void_p (not c_char_p) so we can wispers_string_free() it.
WispersActivationCodeCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)

# void (*WispersUdpConnectionCallback)(void *ctx, WispersStatus, const char *, WispersUdpConnectionHandle *)
WispersUdpConnectionCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)

# void (*WispersDataCallback)(void *ctx, WispersStatus, const char *, const uint8_t *data, size_t len)
WispersDataCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, POINTER(c_uint8), c_size_t)

# void (*WispersQuicConnectionCallback)(void *ctx, WispersStatus, const char *, WispersQuicConnectionHandle *)
WispersQuicConnectionCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)

# void (*WispersQuicStreamCallback)(void *ctx, WispersStatus, const char *, WispersQuicStreamHandle *)
WispersQuicStreamCallbackType = CFUNCTYPE(None, c_void_p, c_int, c_char_p, c_void_p)


# ---------------------------------------------------------------------------
# declare_functions — sets argtypes/restype for all C functions
# ---------------------------------------------------------------------------

def declare_functions(lib: ctypes.CDLL) -> None:  # noqa: C901
    """Set argtypes and restype for every FFI function on *lib*."""

    # -- Utilities --
    lib.wispers_string_free.argtypes = [c_void_p]
    lib.wispers_string_free.restype = None

    lib.wispers_group_info_free.argtypes = [c_void_p]
    lib.wispers_group_info_free.restype = None

    # -- Group info / node accessors --
    lib.wispers_group_info_id.argtypes = [c_void_p]
    lib.wispers_group_info_id.restype = c_char_p

    lib.wispers_group_info_name.argtypes = [c_void_p]
    lib.wispers_group_info_name.restype = c_char_p

    lib.wispers_group_info_created_at_millis.argtypes = [c_void_p]
    lib.wispers_group_info_created_at_millis.restype = c_int64

    lib.wispers_group_info_state.argtypes = [c_void_p]
    lib.wispers_group_info_state.restype = c_int

    lib.wispers_group_info_nodes_count.argtypes = [c_void_p]
    lib.wispers_group_info_nodes_count.restype = c_size_t

    lib.wispers_group_info_node_at.argtypes = [c_void_p, c_size_t]
    lib.wispers_group_info_node_at.restype = c_void_p

    lib.wispers_node_number.argtypes = [c_void_p]
    lib.wispers_node_number.restype = c_int32

    lib.wispers_node_name.argtypes = [c_void_p]
    lib.wispers_node_name.restype = c_char_p

    lib.wispers_node_metadata.argtypes = [c_void_p]
    lib.wispers_node_metadata.restype = c_char_p

    lib.wispers_node_is_self.argtypes = [c_void_p]
    lib.wispers_node_is_self.restype = c_bool

    lib.wispers_group_node_state.argtypes = [c_void_p]
    lib.wispers_group_node_state.restype = c_int32

    lib.wispers_node_last_seen_at_millis.argtypes = [c_void_p]
    lib.wispers_node_last_seen_at_millis.restype = c_int64

    lib.wispers_node_is_online.argtypes = [c_void_p]
    lib.wispers_node_is_online.restype = c_bool

    lib.wispers_registration_info_free.argtypes = [POINTER(WispersRegistrationInfo)]
    lib.wispers_registration_info_free.restype = None

    # -- Storage lifecycle --
    lib.wispers_storage_new_in_memory.argtypes = []
    lib.wispers_storage_new_in_memory.restype = c_void_p

    lib.wispers_storage_new_with_callbacks.argtypes = [POINTER(WispersNodeStorageCallbacks)]
    lib.wispers_storage_new_with_callbacks.restype = c_void_p

    lib.wispers_storage_free.argtypes = [c_void_p]
    lib.wispers_storage_free.restype = None

    lib.wispers_storage_read_registration.argtypes = [c_void_p, POINTER(WispersRegistrationInfo)]
    lib.wispers_storage_read_registration.restype = c_int

    lib.wispers_storage_override_hub_addr.argtypes = [c_void_p, c_char_p]
    lib.wispers_storage_override_hub_addr.restype = c_int

    lib.wispers_storage_delete_state.argtypes = [c_void_p]
    lib.wispers_storage_delete_state.restype = c_int

    lib.wispers_storage_restore_or_init_async.argtypes = [c_void_p, c_void_p, WispersInitCallbackType]
    lib.wispers_storage_restore_or_init_async.restype = c_int

    # -- Node operations --
    lib.wispers_node_free.argtypes = [c_void_p]
    lib.wispers_node_free.restype = None

    lib.wispers_node_state.argtypes = [c_void_p]
    lib.wispers_node_state.restype = c_int

    lib.wispers_node_register_async.argtypes = [c_void_p, c_char_p, c_void_p, WispersCallbackType]
    lib.wispers_node_register_async.restype = c_int

    lib.wispers_node_activate_async.argtypes = [c_void_p, c_char_p, c_void_p, WispersCallbackType]
    lib.wispers_node_activate_async.restype = c_int

    lib.wispers_node_logout_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_node_logout_async.restype = c_int

    lib.wispers_node_revoke_node_async.argtypes = [
        c_void_p, c_int32, c_void_p, WispersCallbackType,
    ]
    lib.wispers_node_revoke_node_async.restype = c_int

    lib.wispers_node_refresh_membership_async.argtypes = [
        c_void_p, c_void_p, WispersCallbackType,
    ]
    lib.wispers_node_refresh_membership_async.restype = c_int

    lib.wispers_node_group_info_async.argtypes = [c_void_p, c_void_p, WispersGroupInfoCallbackType]
    lib.wispers_node_group_info_async.restype = c_int

    lib.wispers_node_start_serving_async.argtypes = [
        c_void_p, c_void_p, WispersStartServingCallbackType,
    ]
    lib.wispers_node_start_serving_async.restype = c_int

    lib.wispers_node_connect_udp_async.argtypes = [
        c_void_p, c_int32, c_void_p, WispersUdpConnectionCallbackType,
    ]
    lib.wispers_node_connect_udp_async.restype = c_int

    lib.wispers_node_connect_quic_async.argtypes = [
        c_void_p, c_int32, c_void_p, WispersQuicConnectionCallbackType,
    ]
    lib.wispers_node_connect_quic_async.restype = c_int

    # -- UDP connections --
    lib.wispers_udp_connection_send.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
    lib.wispers_udp_connection_send.restype = c_int

    lib.wispers_udp_connection_recv_async.argtypes = [c_void_p, c_void_p, WispersDataCallbackType]
    lib.wispers_udp_connection_recv_async.restype = c_int

    lib.wispers_udp_connection_close.argtypes = [c_void_p]
    lib.wispers_udp_connection_close.restype = None

    lib.wispers_udp_connection_free.argtypes = [c_void_p]
    lib.wispers_udp_connection_free.restype = None

    # -- QUIC connections --
    lib.wispers_quic_connection_open_stream_async.argtypes = [
        c_void_p, c_void_p, WispersQuicStreamCallbackType,
    ]
    lib.wispers_quic_connection_open_stream_async.restype = c_int

    lib.wispers_quic_connection_accept_stream_async.argtypes = [
        c_void_p, c_void_p, WispersQuicStreamCallbackType,
    ]
    lib.wispers_quic_connection_accept_stream_async.restype = c_int

    lib.wispers_quic_connection_close_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_quic_connection_close_async.restype = c_int

    lib.wispers_quic_connection_free.argtypes = [c_void_p]
    lib.wispers_quic_connection_free.restype = None

    lib.wispers_quic_stream_free.argtypes = [c_void_p]
    lib.wispers_quic_stream_free.restype = None

    # -- QUIC streams --
    lib.wispers_quic_stream_write_async.argtypes = [
        c_void_p, POINTER(c_uint8), c_size_t, c_void_p, WispersCallbackType,
    ]
    lib.wispers_quic_stream_write_async.restype = c_int

    lib.wispers_quic_stream_read_async.argtypes = [
        c_void_p, c_size_t, c_void_p, WispersDataCallbackType,
    ]
    lib.wispers_quic_stream_read_async.restype = c_int

    lib.wispers_quic_stream_finish_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_quic_stream_finish_async.restype = c_int

    lib.wispers_quic_stream_shutdown_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_quic_stream_shutdown_async.restype = c_int

    # -- Serving --
    lib.wispers_serving_handle_generate_activation_code_async.argtypes = [
        c_void_p, c_void_p, WispersActivationCodeCallbackType,
    ]
    lib.wispers_serving_handle_generate_activation_code_async.restype = c_int

    lib.wispers_serving_handle_generate_activation_code_with_ttl_async.argtypes = [
        c_void_p, c_int, c_void_p, WispersActivationCodeCallbackType,
    ]
    lib.wispers_serving_handle_generate_activation_code_with_ttl_async.restype = c_int

    lib.wispers_serving_session_run_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_serving_session_run_async.restype = c_int

    lib.wispers_serving_handle_shutdown_async.argtypes = [c_void_p, c_void_p, WispersCallbackType]
    lib.wispers_serving_handle_shutdown_async.restype = c_int

    lib.wispers_serving_handle_status_async.argtypes = [
        c_void_p, c_void_p, WispersServingStatusCallbackType,
    ]
    lib.wispers_serving_handle_status_async.restype = c_int

    # -- Serving status accessors --
    lib.wispers_serving_status_free.argtypes = [c_void_p]
    lib.wispers_serving_status_free.restype = None

    lib.wispers_serving_status_connected.argtypes = [c_void_p]
    lib.wispers_serving_status_connected.restype = c_bool

    lib.wispers_serving_status_node_number.argtypes = [c_void_p]
    lib.wispers_serving_status_node_number.restype = c_int32

    lib.wispers_serving_status_connectivity_group_id.argtypes = [c_void_p]
    lib.wispers_serving_status_connectivity_group_id.restype = c_char_p

    lib.wispers_serving_status_codes_outstanding.argtypes = [c_void_p]
    lib.wispers_serving_status_codes_outstanding.restype = c_size_t

    lib.wispers_serving_status_nodes_awaiting_cosign_count.argtypes = [c_void_p]
    lib.wispers_serving_status_nodes_awaiting_cosign_count.restype = c_size_t

    lib.wispers_serving_status_node_awaiting_cosign_at.argtypes = [c_void_p, c_size_t]
    lib.wispers_serving_status_node_awaiting_cosign_at.restype = c_int32

    lib.wispers_serving_handle_free.argtypes = [c_void_p]
    lib.wispers_serving_handle_free.restype = None

    lib.wispers_serving_session_free.argtypes = [c_void_p]
    lib.wispers_serving_session_free.restype = None

    lib.wispers_incoming_connections_free.argtypes = [c_void_p]
    lib.wispers_incoming_connections_free.restype = None

    lib.wispers_incoming_accept_udp_async.argtypes = [
        c_void_p, c_void_p, WispersUdpConnectionCallbackType,
    ]
    lib.wispers_incoming_accept_udp_async.restype = c_int

    lib.wispers_incoming_accept_quic_async.argtypes = [
        c_void_p, c_void_p, WispersQuicConnectionCallbackType,
    ]
    lib.wispers_incoming_accept_quic_async.restype = c_int
