"""Registry observation values and refusals, independent of HTTP/client setup.

awid.registry re-exports these identical classes for compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IDTreeEnrollment:
    """A did:aw's identity-tree enrollment as its registry states it.

    enrolled carries the domain fixed at first enrollment; a revoked ID is
    still enrolled. Not enrolled is proven only by a registry that says so.
    """

    enrolled: bool
    domain: str | None


class RegistryError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: str | None = None,
        code: str | None = None,
        body: Any = None,
        body_is_json: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail or message
        # The refusal's machine-readable code, when the registry sent one.
        self.code = code
        # The refusal's parsed JSON body, of whatever type, when body_is_json.
        self.body = body
        self.body_is_json = body_is_json


class RegistryThrottled(RegistryError):
    """A bounded read could not proceed, or its proof cannot be refreshed.

    Fixed text and machine fields only: upstream bodies/identities never enter
    this refusal. A caller may expose an appropriate transient response without
    treating throttling as absence, stale evidence or an operation conflict.
    """

    def __init__(self, *, retry_after_seconds: float | None, attempts: int, reason: str):
        super().__init__(
            "AWID registry rate limit exceeded", status_code=429, code="rate_limited"
        )
        self.retry_after_seconds = retry_after_seconds
        self.attempts = attempts
        self.reason = reason


class DIDKeyNotFoundError(RegistryError):
    """The registry has no key for the did:aw; id_tree says whether it is enrolled.

    id_tree is None (unknown) when the registry did not state it.
    """

    def __init__(
        self, refused: RegistryError, *, id_tree: IDTreeEnrollment | None
    ) -> None:
        super().__init__(
            str(refused),
            status_code=refused.status_code,
            detail=refused.detail,
            code=refused.code,
            body=refused.body,
            body_is_json=refused.body_is_json,
        )
        self.id_tree = id_tree
