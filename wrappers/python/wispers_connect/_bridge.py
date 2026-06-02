"""Callback bridge: maps integer IDs to threading.Events for async C→Python dispatch.

Same pattern as Go bridge.go (sync.Map + channels) and Kotlin CallbackBridge.kt.
"""

from __future__ import annotations

import ctypes
import threading
from typing import Any

from ._ffi import (
    WispersActivationCodeCallbackType,
    WispersCallbackType,
    WispersDataCallbackType,
    WispersGroupInfoCallbackType,
    WispersInitCallbackType,
    WispersQuicConnectionCallbackType,
    WispersQuicStreamCallbackType,
    WispersServingStatusCallbackType,
    WispersStartServingCallbackType,
    WispersUdpConnectionCallbackType,
)
from .exceptions import raise_for_status
from .types import ActivationStatus, GroupState, NodeInfo, NodeState


# ---------------------------------------------------------------------------
# Pending-call bookkeeping
# ---------------------------------------------------------------------------

class _CallbackError:
    """Wraps an error delivered via a C callback (status + detail)."""
    __slots__ = ("status", "detail")

    def __init__(self, status: int, detail: str | None) -> None:
        self.status = status
        self.detail = detail


class _PendingCall:
    """A slot waiting for a C callback to fire."""
    __slots__ = ("event", "result")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: Any = None


_lock = threading.Lock()
_next_id = 0
_pending: dict[int, _PendingCall] = {}


def _new_pending() -> tuple[int, _PendingCall]:
    global _next_id
    with _lock:
        _next_id += 1
        call_id = _next_id
        call = _PendingCall()
        _pending[call_id] = call
    return call_id, call


def _resolve(ctx_int: int | None, result: Any) -> None:
    if ctx_int is None:
        return
    with _lock:
        call = _pending.pop(ctx_int, None)
    if call is not None:
        call.result = result
        call.event.set()


def _detail_str(detail: bytes | None) -> str | None:
    if detail is None:
        return None
    return detail.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Singleton callbacks (module-level → prevent GC)
# ---------------------------------------------------------------------------

@WispersCallbackType  # type: ignore[untyped-decorator]
def BASIC_CB(ctx: int | None, status: int, detail: bytes | None) -> None:  # noqa: N802
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, None)


@WispersInitCallbackType  # type: ignore[untyped-decorator]
def INIT_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
            node_ptr: int | None, state: int) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, (node_ptr, NodeState(state)))


@WispersGroupInfoCallbackType  # type: ignore[untyped-decorator]
def GROUP_INFO_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                  gi_ptr: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
        return
    # gi_ptr is an opaque WispersGroupInfo handle. Walk it via accessors and
    # copy all data into Python objects before freeing.
    from ._library import get_lib
    lib = get_lib()
    id_bytes = lib.wispers_group_info_id(gi_ptr)
    name_bytes = lib.wispers_group_info_name(gi_ptr)
    group_id = id_bytes.decode("utf-8") if id_bytes else ""
    group_name = name_bytes.decode("utf-8") if name_bytes else None
    created_at_millis = lib.wispers_group_info_created_at_millis(gi_ptr)
    state = GroupState(lib.wispers_group_info_state(gi_ptr))
    nodes: list[NodeInfo] = []
    for i in range(lib.wispers_group_info_nodes_count(gi_ptr)):
        n = lib.wispers_group_info_node_at(gi_ptr, i)
        node_name_bytes = lib.wispers_node_name(n)
        metadata_bytes = lib.wispers_node_metadata(n)
        nodes.append(NodeInfo(
            node_number=lib.wispers_node_number(n),
            name=node_name_bytes.decode("utf-8") if node_name_bytes else "",
            metadata=metadata_bytes.decode("utf-8") if metadata_bytes else "",
            is_self=lib.wispers_node_is_self(n),
            activation_status=ActivationStatus(lib.wispers_node_activation_status(n)),
            last_seen_at_millis=lib.wispers_node_last_seen_at_millis(n),
            is_online=lib.wispers_node_is_online(n),
        ))
    lib.wispers_group_info_free(gi_ptr)
    _resolve(ctx, (group_id, group_name, created_at_millis, state, tuple(nodes)))


@WispersStartServingCallbackType  # type: ignore[untyped-decorator]
def START_SERVING_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                     serving: int | None, session: int | None,
                     incoming: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, (serving, session, incoming))


@WispersServingStatusCallbackType  # type: ignore[untyped-decorator]
def SERVING_STATUS_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                      ss_ptr: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
        return
    # ss_ptr is an opaque WispersServingStatus handle. Walk it via accessors and
    # copy all data into Python objects before freeing.
    from ._library import get_lib
    lib = get_lib()
    cg_bytes = lib.wispers_serving_status_connectivity_group_id(ss_ptr)
    awaiting = tuple(
        lib.wispers_serving_status_node_awaiting_cosign_at(ss_ptr, i)
        for i in range(lib.wispers_serving_status_nodes_awaiting_cosign_count(ss_ptr))
    )
    result = (
        bool(lib.wispers_serving_status_connected(ss_ptr)),
        lib.wispers_serving_status_node_number(ss_ptr),
        cg_bytes.decode("utf-8") if cg_bytes else "",
        lib.wispers_serving_status_codes_outstanding(ss_ptr),
        awaiting,
    )
    lib.wispers_serving_status_free(ss_ptr)
    _resolve(ctx, result)


@WispersActivationCodeCallbackType  # type: ignore[untyped-decorator]
def ACTIVATION_CODE_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                       code_ptr: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
        return
    # code_ptr is c_void_p (raw pointer). Read string and free.
    code_str = ctypes.string_at(code_ptr).decode("utf-8") if code_ptr else ""
    from ._library import get_lib
    get_lib().wispers_string_free(code_ptr)
    _resolve(ctx, code_str)


@WispersUdpConnectionCallbackType  # type: ignore[untyped-decorator]
def UDP_CONNECTION_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                      conn: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, conn)


@WispersDataCallbackType  # type: ignore[untyped-decorator]
def DATA_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
            data: Any, length: int) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
        return
    # Copy data out — buffer is only valid during callback invocation.
    if length > 0 and data:
        buf = ctypes.string_at(data, length)
    else:
        buf = b""
    _resolve(ctx, buf)


@WispersQuicConnectionCallbackType  # type: ignore[untyped-decorator]
def QUIC_CONNECTION_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                       conn: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, conn)


@WispersQuicStreamCallbackType  # type: ignore[untyped-decorator]
def QUIC_STREAM_CB(ctx: int | None, status: int, detail: bytes | None,  # noqa: N802
                   stream: int | None) -> None:
    if status != 0:
        _resolve(ctx, _CallbackError(status, _detail_str(detail)))
    else:
        _resolve(ctx, stream)


# ---------------------------------------------------------------------------
# call_async — public helper
# ---------------------------------------------------------------------------

def call_async(c_fn: Any, *args: Any, cb: Any) -> Any:
    """Call a C async function and block until the callback fires.

    c_fn is called as: c_fn(*args, ctx, cb) → status
    Returns the callback result, or raises WispersError on failure.
    """
    call_id, call = _new_pending()
    ctx = ctypes.c_void_p(call_id)
    try:
        status = c_fn(*args, ctx, cb)
        raise_for_status(status)
    except Exception:
        with _lock:
            _pending.pop(call_id, None)
        raise
    call.event.wait()
    result = call.result
    if isinstance(result, _CallbackError):
        raise_for_status(result.status, result.detail)
    return result
