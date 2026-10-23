"""Value-free commitments for the actual broker response (secrets §11.5).

The response key is independently provisioned producer-private material, never
a signing seed or a request/parameter commitment key. Only the HMACs and safe
counts survive response processing; this module retains neither response bytes
nor a credential. The shared key-file reader owns filesystem checks.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from aweb_naapp.hooks.strictjson import encode_base64url
from aweb_naapp.key_file import KeyFileError, read_key_file

from aweb_secrets.responses import BrokeredResult

_KEY_HEX = re.compile(rb"[0-9a-fA-F]{64}\n?")


class ResponseKeyInvalid(ValueError):
    """Missing, unsafe or malformed response key; never echoes its contents."""


@dataclass(frozen=True)
class ResponseAudit:
    disposition: Literal["returned", "withheld"]
    undeclared_credential: bool
    upstream_response_hmac: str
    upstream_status_code: int
    upstream_bytes: int
    upstream_truncated: bool
    redaction_count: int
    returned_hmac: str | None

    def fields(self) -> dict[str, Any]:
        """A fresh allowlisted completion view for BrokerAudit, with no nulls."""
        return {name: value for name, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class ResponseKey:
    _material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._material, bytes) or len(self._material) != 32:
            raise ResponseKeyInvalid("a response key must be 32 immutable bytes")

    @classmethod
    def from_file(cls, path: Path) -> ResponseKey:
        try:
            content = read_key_file(path)
        except KeyFileError:
            raise ResponseKeyInvalid("response key file unavailable or unsafe") from None
        if not _KEY_HEX.fullmatch(content):
            raise ResponseKeyInvalid(
                "a response key file must hold 64 hex characters and optional LF"
            )
        return cls(bytes.fromhex(content.rstrip(b"\n").decode("ascii")))

    def record(
        self, upstream_body: bytes, *, upstream_truncated: bool, result: BrokeredResult
    ) -> ResponseAudit:
        """Bind raw received bytes before redaction and the handled entity bytes.

        Empty returned bytes have a MAC; a withheld entity has none. Transport
        truncation is distinct from a smaller result/projection bound. The
        caller passes the original egress flag, never the handled cut flag.
        """
        if (
            not isinstance(upstream_body, bytes)
            or type(upstream_truncated) is not bool
            or result.upstream_bytes != len(upstream_body)
            or result.disposition not in ("returned", "withheld")
            or (result.disposition == "returned" and not isinstance(result.body, bytes))
            or (result.disposition == "withheld" and result.body is not None)
        ):
            raise ValueError("response audit requires the original response and handled result")

        def mac(body: bytes) -> str:
            return encode_base64url(hmac.digest(self._material, body, "sha256"))

        return ResponseAudit(
            disposition=result.disposition,
            undeclared_credential=result.undeclared_credential,
            upstream_response_hmac=mac(upstream_body),
            upstream_status_code=result.status,
            upstream_bytes=len(upstream_body),
            upstream_truncated=upstream_truncated,
            redaction_count=result.redaction_count,
            returned_hmac=None if result.body is None else mac(result.body),
        )
