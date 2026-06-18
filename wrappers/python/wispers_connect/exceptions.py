"""Exception hierarchy for wispers-connect."""

from __future__ import annotations

from .types import Status


class WispersError(Exception):
    """Base exception for all wispers-connect errors."""

    status: Status
    detail: str | None

    def __init__(self, status: Status, detail: str | None = None) -> None:
        self.status = status
        self.detail = detail
        msg = f"{status.name}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class NullPointerError(WispersError):
    pass


class InvalidUtf8Error(WispersError):
    pass


class StoreError(WispersError):
    pass


class AlreadyRegisteredError(WispersError):
    pass


class NotRegisteredError(WispersError):
    pass


class NotFoundError(WispersError):
    pass


class BufferTooSmallError(WispersError):
    pass


class MissingCallbackError(WispersError):
    pass


class InvalidActivationCodeError(WispersError):
    pass


class ActivationFailedError(WispersError):
    pass


class HubError(WispersError):
    pass


class ConnectionFailedError(WispersError):
    pass


class TimeoutError(WispersError):
    pass


class InvalidStateError(WispersError):
    pass


class UnauthenticatedError(WispersError):
    pass


class PeerRejectedError(WispersError):
    pass


class PeerUnavailableError(WispersError):
    pass


class RevokedError(WispersError):
    pass


_STATUS_EXCEPTIONS: dict[Status, type[WispersError]] = {
    Status.NULL_POINTER: NullPointerError,
    Status.INVALID_UTF8: InvalidUtf8Error,
    Status.STORE_ERROR: StoreError,
    Status.ALREADY_REGISTERED: AlreadyRegisteredError,
    Status.NOT_REGISTERED: NotRegisteredError,
    Status.NOT_FOUND: NotFoundError,
    Status.BUFFER_TOO_SMALL: BufferTooSmallError,
    Status.MISSING_CALLBACK: MissingCallbackError,
    Status.INVALID_ACTIVATION_CODE: InvalidActivationCodeError,
    Status.ACTIVATION_FAILED: ActivationFailedError,
    Status.HUB_ERROR: HubError,
    Status.CONNECTION_FAILED: ConnectionFailedError,
    Status.TIMEOUT: TimeoutError,
    Status.INVALID_STATE: InvalidStateError,
    Status.UNAUTHENTICATED: UnauthenticatedError,
    Status.PEER_REJECTED: PeerRejectedError,
    Status.PEER_UNAVAILABLE: PeerUnavailableError,
    Status.REVOKED: RevokedError,
}


def raise_for_status(code: int, detail: str | None = None) -> None:
    """Raise a typed WispersError if code is not SUCCESS."""
    if code == Status.SUCCESS:
        return
    try:
        status = Status(code)
    except ValueError:
        raise WispersError(Status(code), detail or f"unknown status {code}")
    cls = _STATUS_EXCEPTIONS.get(status, WispersError)
    raise cls(status, detail)
