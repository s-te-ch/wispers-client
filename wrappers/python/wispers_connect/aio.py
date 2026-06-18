"""Asyncio wrappers — thin async layer over the sync API via run_in_executor."""

from __future__ import annotations

import asyncio
from pathlib import Path
from . import node as _node_mod
from . import quic as _quic_mod
from . import serving as _serving_mod
from . import storage as _storage_mod
from . import udp as _udp_mod
from .types import GroupInfo, NodeState, RegistrationInfo, ServingStatus, TtlProfile


class NodeStorage:
    """Async wrapper around storage.NodeStorage."""

    def __init__(self, inner: _storage_mod.NodeStorage) -> None:
        self._inner = inner

    @staticmethod
    def in_memory() -> NodeStorage:
        return NodeStorage(_storage_mod.NodeStorage.in_memory())

    @staticmethod
    def with_callbacks(cb: _storage_mod.StorageCallbacks) -> NodeStorage:
        return NodeStorage(_storage_mod.NodeStorage.with_callbacks(cb))

    @staticmethod
    def with_file_storage(directory: str | Path) -> NodeStorage:
        return NodeStorage(_storage_mod.NodeStorage.with_file_storage(directory))

    async def read_registration(self) -> RegistrationInfo:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._inner.read_registration)

    async def override_hub_addr(self, addr: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.override_hub_addr, addr)

    async def restore_or_init(self) -> tuple[Node, NodeState]:
        loop = asyncio.get_running_loop()
        sync_node, state = await loop.run_in_executor(None, self._inner.restore_or_init)
        return Node(sync_node), state

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> NodeStorage:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class Node:
    """Async wrapper around node.Node."""

    def __init__(self, inner: _node_mod.Node) -> None:
        self._inner = inner

    @property
    def state(self) -> NodeState:
        return self._inner.state

    async def register(self, token: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.register, token)

    async def activate(self, activation_code: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.activate, activation_code)

    async def logout(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.logout)

    async def revoke_node(self, target_node_number: int) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.revoke_node, target_node_number)

    async def refresh_membership(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.refresh_membership)

    async def group_info(self) -> GroupInfo:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._inner.group_info)

    async def start_serving(self) -> ServingSession:
        loop = asyncio.get_running_loop()
        sync_ss = await loop.run_in_executor(None, self._inner.start_serving)
        return ServingSession(sync_ss)

    async def connect_udp(self, peer_node_number: int) -> UdpConnection:
        loop = asyncio.get_running_loop()
        sync_conn = await loop.run_in_executor(None, self._inner.connect_udp, peer_node_number)
        return UdpConnection(sync_conn)

    async def connect_quic(self, peer_node_number: int) -> QuicConnection:
        loop = asyncio.get_running_loop()
        sync_conn = await loop.run_in_executor(None, self._inner.connect_quic, peer_node_number)
        return QuicConnection(sync_conn)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> Node:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class ServingSession:
    """Async wrapper around serving.ServingSession."""

    def __init__(self, inner: _serving_mod.ServingSession) -> None:
        self._inner = inner

    @property
    def incoming(self) -> IncomingConnections | None:
        if self._inner.incoming is None:
            return None
        return IncomingConnections(self._inner.incoming)

    async def generate_activation_code(
        self, ttl_profile: TtlProfile = TtlProfile.INTERACTIVE,
    ) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, self._inner.generate_activation_code, ttl_profile,
        )

    async def status(self) -> ServingStatus:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._inner.status)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.run)

    async def shutdown(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.shutdown)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> ServingSession:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class IncomingConnections:
    """Async wrapper around serving.IncomingConnections."""

    def __init__(self, inner: _serving_mod.IncomingConnections) -> None:
        self._inner = inner

    async def accept_udp(self) -> UdpConnection:
        loop = asyncio.get_running_loop()
        sync_conn = await loop.run_in_executor(None, self._inner.accept_udp)
        return UdpConnection(sync_conn)

    async def accept_quic(self) -> QuicConnection:
        loop = asyncio.get_running_loop()
        sync_conn = await loop.run_in_executor(None, self._inner.accept_quic)
        return QuicConnection(sync_conn)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> IncomingConnections:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class UdpConnection:
    """Async wrapper around udp.UdpConnection."""

    def __init__(self, inner: _udp_mod.UdpConnection) -> None:
        self._inner = inner

    async def send(self, data: bytes) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.send, data)

    async def recv(self) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._inner.recv)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> UdpConnection:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class QuicConnection:
    """Async wrapper around quic.QuicConnection."""

    def __init__(self, inner: _quic_mod.QuicConnection) -> None:
        self._inner = inner

    async def open_stream(self) -> QuicStream:
        loop = asyncio.get_running_loop()
        sync_stream = await loop.run_in_executor(None, self._inner.open_stream)
        return QuicStream(sync_stream)

    async def accept_stream(self) -> QuicStream:
        loop = asyncio.get_running_loop()
        sync_stream = await loop.run_in_executor(None, self._inner.accept_stream)
        return QuicStream(sync_stream)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> QuicConnection:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()


class QuicStream:
    """Async wrapper around quic.QuicStream."""

    def __init__(self, inner: _quic_mod.QuicStream) -> None:
        self._inner = inner

    async def write(self, data: bytes) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.write, data)

    async def read(self, max_len: int = 65536) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._inner.read, max_len)

    async def finish(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.finish)

    async def shutdown(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._inner.shutdown)

    def close(self) -> None:
        self._inner.close()

    async def __aenter__(self) -> QuicStream:
        return self

    async def __aexit__(self, *_: object) -> None:
        self.close()
