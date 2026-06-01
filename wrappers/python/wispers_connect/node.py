"""Node handle — operations on a wispers node."""

from __future__ import annotations

from typing import Any

from ._bridge import (
    BASIC_CB,
    GROUP_INFO_CB,
    QUIC_CONNECTION_CB,
    START_SERVING_CB,
    UDP_CONNECTION_CB,
    call_async,
)
from ._handle import Handle
from .types import GroupInfo, NodeState


class Node(Handle):
    """Wraps a WispersNodeHandle."""

    @property
    def state(self) -> NodeState:
        from ._library import get_lib
        ptr = self._require_open()
        return NodeState(get_lib().wispers_node_state(ptr))

    def register(self, token: str) -> None:
        """Register the node with the hub. Requires PENDING state."""
        from ._library import get_lib
        ptr = self._require_open()
        call_async(get_lib().wispers_node_register_async, ptr, token.encode("utf-8"), cb=BASIC_CB)

    def activate(self, activation_code: str) -> None:
        """Activate the node using an activation code. Requires REGISTERED state."""
        from ._library import get_lib
        ptr = self._require_open()
        call_async(
            get_lib().wispers_node_activate_async, ptr,
            activation_code.encode("utf-8"), cb=BASIC_CB,
        )

    def logout(self) -> None:
        """Logout (deregister + revoke). The handle is consumed."""
        from ._library import get_lib
        ptr = self._consume()
        call_async(get_lib().wispers_node_logout_async, ptr, cb=BASIC_CB)

    def group_info(self) -> GroupInfo:
        """Get group activation state and node list. Requires REGISTERED or ACTIVATED."""
        from ._library import get_lib
        ptr = self._require_open()
        group_id, name, created_at_millis, state, nodes = call_async(
            get_lib().wispers_node_group_info_async, ptr, cb=GROUP_INFO_CB,
        )
        return GroupInfo(
            id=group_id,
            name=name,
            created_at_millis=created_at_millis,
            state=state,
            nodes=nodes,
        )

    def start_serving(self) -> Any:
        """Start a serving session. Returns ServingSession."""
        from ._library import get_lib
        from .serving import ServingSession
        ptr = self._require_open()
        serving_ptr, session_ptr, incoming_ptr = call_async(
            get_lib().wispers_node_start_serving_async, ptr, cb=START_SERVING_CB,
        )
        return ServingSession(serving_ptr, session_ptr, incoming_ptr)

    def connect_udp(self, peer_node_number: int) -> Any:
        """Connect to a peer via UDP. Requires ACTIVATED state."""
        from ._library import get_lib
        from .udp import UdpConnection
        import ctypes
        ptr = self._require_open()
        conn_ptr = call_async(
            get_lib().wispers_node_connect_udp_async, ptr,
            ctypes.c_int32(peer_node_number), cb=UDP_CONNECTION_CB,
        )
        return UdpConnection(conn_ptr)

    def connect_quic(self, peer_node_number: int) -> Any:
        """Connect to a peer via QUIC. Requires ACTIVATED state."""
        from ._library import get_lib
        from .quic import QuicConnection
        import ctypes
        ptr = self._require_open()
        conn_ptr = call_async(
            get_lib().wispers_node_connect_quic_async, ptr,
            ctypes.c_int32(peer_node_number), cb=QUIC_CONNECTION_CB,
        )
        return QuicConnection(conn_ptr)

    def _do_close(self, ptr: Any) -> None:
        from ._library import get_lib
        get_lib().wispers_node_free(ptr)
