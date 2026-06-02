"""ServingSession + IncomingConnections handles."""

from __future__ import annotations

import threading
from typing import Any

from ._bridge import (
    ACTIVATION_CODE_CB,
    BASIC_CB,
    QUIC_CONNECTION_CB,
    UDP_CONNECTION_CB,
    call_async,
)
from ._handle import Handle
from .types import TtlProfile


class IncomingConnections(Handle):
    """Wraps WispersIncomingConnections for accepting P2P connections.

    Tracks in-flight accept operations so that close() can wait for their
    callbacks to fire before freeing the C handle.  This prevents a
    use-after-free in the Rust async runtime (the spawned accept tasks hold
    a raw pointer to the IncomingConnections struct).
    """

    def __init__(self, ptr: Any) -> None:
        super().__init__(ptr)
        self._in_flight = 0
        self._in_flight_cv = threading.Condition()

    def accept_udp(self) -> Any:
        """Accept an incoming UDP connection from a peer."""
        from ._library import get_lib
        from .udp import UdpConnection
        ptr = self._require_open()
        with self._in_flight_cv:
            self._in_flight += 1
        try:
            conn_ptr = call_async(
                get_lib().wispers_incoming_accept_udp_async, ptr, cb=UDP_CONNECTION_CB,
            )
        except Exception:
            with self._in_flight_cv:
                self._in_flight -= 1
                self._in_flight_cv.notify_all()
            raise
        with self._in_flight_cv:
            self._in_flight -= 1
            self._in_flight_cv.notify_all()
        return UdpConnection(conn_ptr)

    def accept_quic(self) -> Any:
        """Accept an incoming QUIC connection from a peer."""
        from ._library import get_lib
        from .quic import QuicConnection
        ptr = self._require_open()
        with self._in_flight_cv:
            self._in_flight += 1
        try:
            conn_ptr = call_async(
                get_lib().wispers_incoming_accept_quic_async, ptr, cb=QUIC_CONNECTION_CB,
            )
        except Exception:
            with self._in_flight_cv:
                self._in_flight -= 1
                self._in_flight_cv.notify_all()
            raise
        with self._in_flight_cv:
            self._in_flight -= 1
            self._in_flight_cv.notify_all()
        return QuicConnection(conn_ptr)

    def _do_close(self, ptr: Any) -> None:
        from ._library import get_lib
        # Wait for in-flight accept callbacks to fire before freeing.
        # After the serving session stops, the channel senders drop and
        # pending recv() calls return None, firing callbacks with errors.
        # The accept threads then decrement _in_flight.  We must wait for
        # this to reach zero so the Rust async tasks are no longer
        # dereferencing the raw pointer to this handle.
        with self._in_flight_cv:
            self._in_flight_cv.wait_for(
                lambda: self._in_flight == 0, timeout=5,
            )
        get_lib().wispers_incoming_connections_free(ptr)


class ServingSession:
    """Composite handle: serving handle + session + optional incoming connections.

    Not a Handle subclass — owns multiple C handles with different lifetimes.
    """

    def __init__(
        self,
        serving_ptr: Any,
        session_ptr: Any,
        incoming_ptr: Any | None,
    ) -> None:
        self._serving_ptr = serving_ptr
        self._session_ptr = session_ptr
        self._session_consumed = False
        self._serving_closed = False
        self._run_started = False
        self._run_done = threading.Event()
        self._shutdown_requested = False
        self.incoming: IncomingConnections | None = (
            IncomingConnections(incoming_ptr) if incoming_ptr else None
        )

    def generate_activation_code(
        self, ttl_profile: TtlProfile = TtlProfile.INTERACTIVE,
    ) -> str:
        """Generate an activation code for endorsing a new node.

        ``ttl_profile`` selects the code's lifetime (default
        :attr:`TtlProfile.INTERACTIVE`; use :attr:`TtlProfile.ASYNCHRONOUS` for
        a long-lived code sent out-of-band).
        """
        from ._library import get_lib
        if self._serving_closed:
            raise RuntimeError("wispers: serving handle already closed")
        result: str = call_async(
            get_lib().wispers_serving_handle_generate_activation_code_with_ttl_async,
            self._serving_ptr, int(ttl_profile), cb=ACTIVATION_CODE_CB,
        )
        return result

    def run(self) -> None:
        """Run the serving session event loop. Blocks until shutdown or error.

        The session handle is consumed by this call.
        """
        from ._library import get_lib
        if self._session_consumed:
            raise RuntimeError("wispers: session already consumed")
        self._session_consumed = True
        self._run_started = True
        try:
            call_async(
                get_lib().wispers_serving_session_run_async,
                self._session_ptr, cb=BASIC_CB,
            )
        finally:
            self._run_done.set()

    def shutdown(self) -> None:
        """Request the serving session to shut down. Idempotent."""
        if self._shutdown_requested:
            return
        from ._library import get_lib
        if self._serving_closed:
            raise RuntimeError("wispers: serving handle already closed")
        self._shutdown_requested = True
        call_async(
            get_lib().wispers_serving_handle_shutdown_async,
            self._serving_ptr, cb=BASIC_CB,
        )

    def close(self) -> None:
        """Free all handles. Idempotent.

        If run() is active in another thread, triggers shutdown and waits
        for it to complete before freeing handles.
        """
        # Ensure the session event loop has stopped before freeing anything.
        if self._run_started and not self._run_done.is_set():
            try:
                self.shutdown()
            except Exception:
                pass
            self._run_done.wait(timeout=5)

        from ._library import get_lib
        lib = get_lib()
        if self.incoming is not None:
            self.incoming.close()
            self.incoming = None
        if not self._session_consumed and self._session_ptr is not None:
            lib.wispers_serving_session_free(self._session_ptr)
            self._session_consumed = True
        if not self._serving_closed and self._serving_ptr is not None:
            lib.wispers_serving_handle_free(self._serving_ptr)
            self._serving_closed = True

    def __enter__(self) -> ServingSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
