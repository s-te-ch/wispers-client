"""wispers-connect Python wrapper.

Public API re-exports. The native library is loaded lazily on first handle use,
so importing types/exceptions works without the shared library present.
"""

from .types import (
    ActivationStatus,
    GroupInfo,
    GroupState,
    NodeInfo,
    NodeState,
    RegistrationInfo,
    ServingStatus,
    Status,
    TtlProfile,
)

from .exceptions import (
    ActivationFailedError,
    AlreadyRegisteredError,
    BufferTooSmallError,
    ConnectionFailedError,
    HubError,
    InvalidActivationCodeError,
    InvalidStateError,
    InvalidUtf8Error,
    MissingCallbackError,
    NotFoundError,
    NotRegisteredError,
    NullPointerError,
    PeerRejectedError,
    PeerUnavailableError,
    RevokedError,
    StoreError,
    TimeoutError,
    UnauthenticatedError,
    WispersError,
    raise_for_status,
)

from .storage import FileStorage, NodeStorage, StorageCallbacks
from .node import Node
from .serving import IncomingConnections, ServingSession
from .udp import UdpConnection
from .quic import QuicConnection, QuicStream

__all__ = [
    # Types
    "ActivationStatus",
    "GroupInfo",
    "GroupState",
    "NodeInfo",
    "NodeState",
    "RegistrationInfo",
    "ServingStatus",
    "Status",
    "TtlProfile",
    # Exceptions
    "ActivationFailedError",
    "AlreadyRegisteredError",
    "BufferTooSmallError",
    "ConnectionFailedError",
    "HubError",
    "InvalidActivationCodeError",
    "InvalidStateError",
    "InvalidUtf8Error",
    "MissingCallbackError",
    "NotFoundError",
    "NotRegisteredError",
    "NullPointerError",
    "PeerRejectedError",
    "PeerUnavailableError",
    "RevokedError",
    "StoreError",
    "TimeoutError",
    "UnauthenticatedError",
    "WispersError",
    "raise_for_status",
    # Storage
    "FileStorage",
    "NodeStorage",
    "StorageCallbacks",
    # Handles
    "Node",
    "IncomingConnections",
    "ServingSession",
    "UdpConnection",
    "QuicConnection",
    "QuicStream",
]
