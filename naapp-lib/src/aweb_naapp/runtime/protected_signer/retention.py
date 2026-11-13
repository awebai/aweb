"""Private local retention for an exact, service-owned HTTP effect.

These values carry no authority by themselves. Only isolated custody receives
the engine's verified typed operation/signature/current observation. It builds
the final request and attestation locally; the engine commits them together
before a separate, single-claim delivery. Public receipts select safe fields.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from awid.log import require_canonical_server_origin

if TYPE_CHECKING:
    from .types import CatalogOperation, CurrentAuthority


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _aware(value: datetime) -> None:
    if type(value) is not datetime or value.utcoffset() is None:
        raise ValueError("retained effect needs its original aware deadline")


@dataclass(frozen=True)
class FrozenDelivery:
    audience: str
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self):
        require_canonical_server_origin(self.audience)
        if (self.method not in {"POST", "PUT", "PATCH", "DELETE"} or type(self.body) is not bytes
            or type(self.path) is not str or not self.path.startswith("/") or self.path.startswith("//")
            or any(ord(c) <= 32 or ord(c) == 127 or c in "#\\" for c in self.path)
            or not isinstance(self.headers, Mapping)):
            raise ValueError("invalid retained delivery")
        headers = dict(self.headers)
        names = set()
        for name, value in headers.items():
            if (type(name) is not str or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or name.lower() in names or type(value) is not str or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ValueError("invalid retained header")
            names.add(name.lower())
        object.__setattr__(self, "headers", MappingProxyType(headers))

    def fields(self) -> dict[str, Any]:
        return {"audience": self.audience, "method": self.method, "path": self.path,
            "headers": dict(self.headers), "body": base64.b64encode(self.body).decode()}

    @classmethod
    def from_fields(cls, fields: Any) -> FrozenDelivery:
        if type(fields) is not dict or set(fields) != {"audience", "method", "path", "headers", "body"}:
            raise ValueError("invalid retained delivery shape")
        value = cls(fields["audience"], fields["method"], fields["path"], fields["headers"],
            base64.b64decode(fields["body"], validate=True))
        if value.fields() != fields:
            raise ValueError("noncanonical retained delivery")
        return value


@dataclass(frozen=True)
class RetainedEffect:
    operation_id: str
    signing: bytes
    signature: bytes
    artifact_sha256: str
    expires_at: datetime
    delivery: FrozenDelivery
    attestation: str

    def __post_init__(self):
        _aware(self.expires_at)
        if (type(self.operation_id) is not str or str(UUID(self.operation_id)) != self.operation_id
            or type(self.signing) is not bytes or not self.signing or type(self.signature) is not bytes or len(self.signature) != 64
            or type(self.artifact_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256)
            or type(self.delivery) is not FrozenDelivery or type(self.attestation) is not str or not self.attestation
            or any(ord(c) < 32 or ord(c) == 127 for c in self.attestation)):
            raise ValueError("invalid retained effect")
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(UTC))

    def result(self) -> dict[str, str]:
        return {"signing": base64.b64encode(self.signing).decode(), "signature": base64.b64encode(self.signature).decode()}

    def require_matches(self, operation_id: str, signed: Mapping[str, str], expires_at: datetime) -> None:
        _aware(expires_at)
        if self.operation_id != operation_id or self.result() != signed or self.expires_at > expires_at:
            raise ValueError("retention changed the engine's signed effect or original bound")

    def fields(self) -> dict[str, Any]:
        return {"v": 1, "operation_id": self.operation_id, **self.result(), "artifact_sha256": self.artifact_sha256,
            "expires_at": _stamp(self.expires_at), "delivery": self.delivery.fields(), "attestation": self.attestation}

    @classmethod
    def from_fields(cls, fields: Any) -> RetainedEffect:
        if (type(fields) is not dict or set(fields) != {"v", "operation_id", "signing", "signature", "artifact_sha256", "expires_at", "delivery", "attestation"}
            or type(fields["v"]) is not int or fields["v"] != 1):
            raise ValueError("invalid retained effect shape")
        value = cls(fields["operation_id"], base64.b64decode(fields["signing"], validate=True),
            base64.b64decode(fields["signature"], validate=True), fields["artifact_sha256"],
            datetime.fromisoformat(fields["expires_at"].replace("Z", "+00:00")),
            FrozenDelivery.from_fields(fields["delivery"]), fields["attestation"])
        if value.fields() != fields:
            raise ValueError("noncanonical retained effect")
        return value

    def applied_result(self) -> dict[str, Any]:
        """Call only after actual confirmation; never serializes private headers."""
        return {"v": 2, "type": "aweb.protected-delivery", "artifact": self.result(), "delivery": {
            "mode": "service_owned", "state": "applied", "reference": {
                "operation_id": self.operation_id, "artifact_sha256": self.artifact_sha256}}}


@dataclass(frozen=True)
class EffectConfirmation:
    operation_id: str
    artifact_sha256: str
    valid_until: datetime

    def require_matches(self, retained: RetainedEffect, now: datetime) -> None:
        _aware(self.valid_until)
        _aware(now)
        if (self.operation_id != retained.operation_id or self.artifact_sha256 != retained.artifact_sha256
            or now >= self.valid_until):
            raise ValueError("unconfirmed or stale retained effect")


class RetainedEffectCustody(Protocol):
    def retain_authorized_effect(self, *, operation: CatalogOperation, request: Mapping[str, Any],
        artifact: Mapping[str, Any], signing: bytes, signature: bytes, authority: CurrentAuthority,
        expires_at: datetime) -> RetainedEffect | None:
        """Synchronous/local only; None preserves unmarked legacy behavior.

        The trusted definition selects the consumer. Freeze final body and
        authentication envelope before proof signing. No network or exposure
        is allowed here. A protected binding must never return None.
        """
        ...

    async def deliver_retained(self, operation: CatalogOperation, retained: RetainedEffect) -> None:
        """One exact post-commit mutation; never refresh or regenerate bytes."""
        ...

    async def confirm_retained(self, operation: CatalogOperation, retained: RetainedEffect) -> EffectConfirmation | None:
        """Read-only exact-effect confirmation, including after an uncertain send.

        Verify the binding/artifact/proof/reference against the actual named
        consumer; a conflict or signed artifact alone is not confirmation.
        None means unconfirmed. Preserve the observation's original deadline;
        the engine additionally caps it at sixty seconds from this read's start.
        """
        ...
