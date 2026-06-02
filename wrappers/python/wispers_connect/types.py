"""Public types for wispers-connect."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Status(IntEnum):
    SUCCESS = 0
    NULL_POINTER = 1
    INVALID_UTF8 = 2
    STORE_ERROR = 3
    ALREADY_REGISTERED = 4
    NOT_REGISTERED = 5
    NOT_FOUND = 6
    BUFFER_TOO_SMALL = 7
    MISSING_CALLBACK = 8
    INVALID_ACTIVATION_CODE = 9
    ACTIVATION_FAILED = 10
    HUB_ERROR = 11
    CONNECTION_FAILED = 12
    TIMEOUT = 13
    INVALID_STATE = 14
    UNAUTHENTICATED = 15
    PEER_REJECTED = 16
    PEER_UNAVAILABLE = 17


class NodeState(IntEnum):
    PENDING = 0
    REGISTERED = 1
    ACTIVATED = 2


class ActivationStatus(IntEnum):
    UNKNOWN = 0
    NOT_ACTIVATED = 1
    ACTIVATED = 2


class GroupState(IntEnum):
    ALONE = 0
    BOOTSTRAP = 1
    NEED_ACTIVATION = 2
    CAN_ENDORSE = 3
    ALL_ACTIVATED = 4


class TtlProfile(IntEnum):
    """TTL profile for activation codes (mirrors C enum WispersTtlProfile).

    Selects the code's lifetime and entropy. INTERACTIVE is short-lived (for
    live entry); ASYNCHRONOUS is long-lived (for out-of-band delivery, e.g.
    email).
    """

    INTERACTIVE = 0
    ASYNCHRONOUS = 1


@dataclass(frozen=True)
class NodeInfo:
    node_number: int
    name: str
    metadata: str
    is_self: bool
    activation_status: ActivationStatus
    last_seen_at_millis: int
    is_online: bool


@dataclass(frozen=True)
class GroupInfo:
    id: str
    name: str | None
    created_at_millis: int
    state: GroupState
    nodes: tuple[NodeInfo, ...]


@dataclass(frozen=True)
class ServingStatus:
    """Snapshot of a serving session's hub connection and endorsing state."""

    #: Whether the session currently holds a live hub stream. False while it is
    #: reconnecting after a hub disconnect.
    connected: bool
    node_number: int
    connectivity_group_id: str
    #: Number of activation codes awaiting use.
    codes_outstanding: int
    #: Node numbers that have paired and await cosign.
    nodes_awaiting_cosign: tuple[int, ...]


@dataclass(frozen=True)
class RegistrationInfo:
    connectivity_group_id: str
    node_number: int
    auth_token: str
    attestation_jwt: str
