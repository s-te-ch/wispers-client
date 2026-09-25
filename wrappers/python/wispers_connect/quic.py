"""QuicConnection + QuicStream handles."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import Any

from ._bridge import BASIC_CB, DATA_CB, QUIC_STREAM_CB, call_async
from ._handle import Handle
from .types import QuicCloseInfo


class QuicStream(Handle):
    """Wraps a WispersQuicStreamHandle."""

    def write(self, data: bytes) -> None:
        """Write data to the QUIC stream."""
        from ._library import get_lib
        ptr = self._require_open()
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        call_async(
            get_lib().wispers_quic_stream_write_async, ptr, buf, len(data), cb=BASIC_CB,
        )

    def read(self, max_len: int = 65536) -> bytes:
        """Read up to max_len bytes from the QUIC stream."""
        from ._library import get_lib
        ptr = self._require_open()
        result: bytes = call_async(
            get_lib().wispers_quic_stream_read_async, ptr, max_len, cb=DATA_CB,
        )
        return result

    def finish(self) -> None:
        """Close the write side (send FIN). Can still read after this."""
        from ._library import get_lib
        ptr = self._require_open()
        call_async(get_lib().wispers_quic_stream_finish_async, ptr, cb=BASIC_CB)

    def shutdown(self) -> None:
        """Shutdown both sides of the stream."""
        from ._library import get_lib
        ptr = self._require_open()
        call_async(get_lib().wispers_quic_stream_shutdown_async, ptr, cb=BASIC_CB)

    def _do_close(self, ptr: Any) -> None:
        from ._library import get_lib
        get_lib().wispers_quic_stream_free(ptr)


class QuicConnection(Handle):
    """Wraps a WispersQuicConnectionHandle."""

    def open_stream(self) -> QuicStream:
        """Open a new bidirectional QUIC stream."""
        from ._library import get_lib
        ptr = self._require_open()
        stream_ptr = call_async(
            get_lib().wispers_quic_connection_open_stream_async, ptr, cb=QUIC_STREAM_CB,
        )
        return QuicStream(stream_ptr)

    def accept_stream(self) -> QuicStream:
        """Accept an incoming QUIC stream from the peer."""
        from ._library import get_lib
        ptr = self._require_open()
        stream_ptr = call_async(
            get_lib().wispers_quic_connection_accept_stream_async, ptr, cb=QUIC_STREAM_CB,
        )
        return QuicStream(stream_ptr)

    def ping(self, timeout: float) -> None:
        """Check that the peer is still reachable.

        Sends a QUIC PING and waits for the peer's transport to acknowledge it.
        Raises TimeoutError if no acknowledgement arrives within ``timeout``
        seconds (a few seconds is reasonable), and ConnectionFailedError if the
        connection is closed or closing.
        """
        from ._library import get_lib
        ptr = self._require_open()
        timeout_ms = 0 if timeout <= 0 else min(max(1, int(timeout * 1000)), 0xFFFFFFFF)
        call_async(
            get_lib().wispers_quic_connection_ping_async, ptr, timeout_ms, cb=BASIC_CB,
        )

    def close_with_error(self, error_code: int, reason: str = "") -> None:
        """Close the connection, with error code and reason.

        ``error_code`` and ``reason`` are application-defined; the peer reads
        them with peer_close_info(). ``error_code`` must be at most 2**62 - 1
        (QUIC's limit); ``reason`` is truncated to 1024 bytes.
        """
        ptr = self._consume()
        reason_bytes = reason.encode("utf-8")
        self._close_consumed(
            ptr,
            lambda lib, ctx, cb: lib.wispers_quic_connection_close_with_error_async(
                ptr, error_code, reason_bytes, ctx, cb,
            ),
        )

    def peer_close_info(self) -> QuicCloseInfo | None:
        """How the peer closed the connection, or None if it hasn't."""
        from ._library import get_lib
        lib = get_lib()
        ptr = self._require_open()
        info_ptr = lib.wispers_quic_connection_peer_close_info(ptr)
        if not info_ptr:
            return None
        reason = lib.wispers_quic_close_info_reason(info_ptr)
        info = QuicCloseInfo(
            closed_by_app=bool(lib.wispers_quic_close_info_closed_by_app(info_ptr)),
            error_code=lib.wispers_quic_close_info_error_code(info_ptr),
            reason=reason.decode("utf-8") if reason else "",
        )
        lib.wispers_quic_close_info_free(info_ptr)
        return info

    def _do_close(self, ptr: Any) -> None:
        self._close_consumed(
            ptr, lambda lib, ctx, cb: lib.wispers_quic_connection_close_async(ptr, ctx, cb),
        )

    def _close_consumed(self, ptr: Any, start: Callable[[Any, Any, Any], int]) -> None:
        """Run a close call (``start(lib, ctx, cb)``) that consumes ``ptr``."""
        from ._library import get_lib
        lib = get_lib()
        # The close call CONSUMES the handle on SUCCESS.  Only call _free if
        # the initial status indicates the async op was never started.
        from ._bridge import BASIC_CB as _cb, _new_pending, _lock, _pending
        call_id, call = _new_pending()
        ctx = ctypes.c_void_p(call_id)
        status = start(lib, ctx, _cb)
        if status != 0:
            with _lock:
                _pending.pop(call_id, None)
            # Async op not started — handle not consumed, free it.
            lib.wispers_quic_connection_free(ptr)
            return
        # Handle was consumed. Wait for completion, ignore callback errors.
        call.event.wait()
