"""Producer-private request commitments (docs/hook-events.md, decisions 70/73).

This module frames bytes and loads purpose-specific keys without importing the
web runtime. The caller supplies authoritative installation/tool context and a
complete, bounded inbound request, before upstream rendering or injection. For
parameters it supplies canonical UTF-8 JSON bytes of already validated typed
input, using B2's integer-only value rules. This helper neither parses a body
nor duplicates the app's parameter coercion or B2's canonical-JSON codec.

Provision each purpose with an independent random key, separate from signing
and response HMAC keys. Persist the resulting MAC/context once with the use;
retries use that value or stored signed outbox bytes. Rotation and destroying
the old configured key are the producer's lifecycle responsibility.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from aweb_naapp.hooks.strictjson import MAX_SAFE_INTEGER, Refused, canonical
from aweb_naapp.signing_key import KeyFileError, read_key_file


class CommitmentError(ValueError):
    """Invalid key/configuration/input; messages never include request or key bytes."""


class Purpose(StrEnum):
    MANIFEST_REQUEST = "manifest_request"
    SECRET_REQUEST = "secret_request"
    SECRET_PARAMS = "secret_params"


_DOMAINS = {
    Purpose.MANIFEST_REQUEST: b"aweb.post-manifest-command.request/1\n",
    Purpose.SECRET_REQUEST: b"aweb.post-secret-use.request/1\n",
    Purpose.SECRET_PARAMS: b"aweb.post-secret-use.params/1\n",
}
_KEY_HEX = re.compile(rb"[0-9a-fA-F]{64}\n?")
_METHOD = re.compile(r"[A-Z]+")


def _frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


@dataclass(frozen=True, slots=True)
class CommitmentContext:
    """The caller resolves these fields from authenticated installation/tool data.

    Validation establishes the canonical encoding, not authority to name an
    installation. There are no user text or request parameter fields here.
    """

    app_id: str
    team_id: str
    installation_id: str
    generation: int
    tool: str

    def __post_init__(self) -> None:
        values = (self.app_id, self.team_id, self.installation_id, self.tool)
        if not all(isinstance(value, str) and value for value in values):
            raise CommitmentError("context identifiers must be nonempty text")
        if type(self.generation) is not int or not 1 <= self.generation <= MAX_SAFE_INTEGER:
            raise CommitmentError("context generation must be a positive safe integer")
        try:
            self.canonical_bytes()
        except Refused:
            raise CommitmentError("context identifiers must be printable ASCII") from None

    def canonical_bytes(self) -> bytes:
        return canonical(
            {
                "app_id": self.app_id,
                "team_id": self.team_id,
                "installation_id": self.installation_id,
                "generation": self.generation,
                "tool": self.tool,
            }
        )


@dataclass(frozen=True, slots=True, repr=False)
class RequestBytes:
    """Complete inbound bytes, with raw external target and ordered header values.

    The body is immutable bytes in both JSON and raw mode. The target includes
    the mount prefix and raw query exactly as reconstructed for authentication.
    Header names are matched case-insensitively by the caller; the values here
    retain their received byte spelling and order. No component is normalized.
    """

    method: str
    raw_target: bytes
    content_types: tuple[bytes, ...]
    body: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not _METHOD.fullmatch(self.method):
            raise CommitmentError("method must be uppercase ASCII")
        if (
            not isinstance(self.raw_target, bytes)
            or not self.raw_target.startswith(b"/")
            or any(not 0x21 <= value <= 0x7E for value in self.raw_target)
        ):
            raise CommitmentError("raw target must be an external ASCII path and query")
        if not isinstance(self.content_types, tuple) or not all(
            isinstance(value, bytes) for value in self.content_types
        ):
            raise CommitmentError("content types must be an ordered tuple of byte values")
        if not isinstance(self.body, bytes):
            raise CommitmentError("body must be complete immutable bytes")

    def framed(self) -> bytes:
        """The unambiguous u64be encoding, including zero counts/lengths."""
        return (
            _frame(self.method.encode("ascii"))
            + _frame(self.raw_target)
            + struct.pack(">Q", len(self.content_types))
            + b"".join(_frame(value) for value in self.content_types)
            + _frame(self.body)
        )


@dataclass(frozen=True, slots=True)
class CommitmentKey:
    """One configured purpose. Raw key material is excluded from representation."""

    purpose: Purpose
    _material: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.purpose, Purpose):
            raise CommitmentError("unknown commitment purpose")
        if not isinstance(self._material, bytes) or len(self._material) != 32:
            raise CommitmentError("a commitment key must be 32 immutable bytes")

    def _mac(self, context: CommitmentContext, framed: bytes) -> str:
        mac = hmac.new(self._material, digestmod=hashlib.sha256)
        mac.update(_DOMAINS[self.purpose])
        mac.update(context.canonical_bytes())
        mac.update(b"\n")
        mac.update(framed)
        return mac.hexdigest()

    def request(self, context: CommitmentContext, request: RequestBytes) -> str:
        if self.purpose not in (Purpose.MANIFEST_REQUEST, Purpose.SECRET_REQUEST):
            raise CommitmentError("a request commitment requires a request-purpose key")
        return self._mac(context, request.framed())

    def params(
        self, context: CommitmentContext, canonical_params_bytes: bytes | None
    ) -> str | None:
        """Commit caller-validated canonical typed params; None means absent.

        No B2 prefix or policy/request wrapper belongs in these bytes. Open
        requests and unparseable refusal inputs pass None, never a fabricated
        empty object. Serialization/coercion remain with the existing caller.
        """
        if self.purpose is not Purpose.SECRET_PARAMS:
            raise CommitmentError("a parameter commitment requires the parameters-purpose key")
        if canonical_params_bytes is None:
            return None
        if not isinstance(canonical_params_bytes, bytes):
            raise CommitmentError("canonical parameters must be immutable bytes or absent")
        return self._mac(context, _frame(canonical_params_bytes))


def load_commitment_key(purpose: Purpose, path: Path) -> CommitmentKey:
    """Read 64 hex characters with an optional LF using the shared file checks.

    A missing, unsafe or malformed file is a startup error. There is no key
    generation or signing-seed fallback, and errors never echo file contents.
    """
    if not isinstance(purpose, Purpose):
        raise CommitmentError("unknown commitment purpose")
    try:
        content = read_key_file(path)
    except KeyFileError as exc:
        raise CommitmentError(str(exc)) from None
    if not _KEY_HEX.fullmatch(content):
        raise CommitmentError("a commitment key file must hold 64 hex characters and optional LF")
    return CommitmentKey(purpose, bytes.fromhex(content.rstrip(b"\n").decode("ascii")))
