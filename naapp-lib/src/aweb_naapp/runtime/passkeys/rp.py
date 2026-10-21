"""The WebAuthn relying party: the app's own origin, nothing wider."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class RelyingParty:
    """`origin` is the scheme, host and optional port the app serves from.
    HTTPS is required except for `localhost` during development."""

    origin: str
    name: str
    rp_id: str = field(init=False)

    def __post_init__(self) -> None:
        parts = urlsplit(self.origin)
        if (
            not parts.hostname
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise ValueError(f"relying party origin must be a bare origin: {self.origin!r}")
        if parts.scheme != "https" and not (
            parts.scheme == "http" and parts.hostname == "localhost"
        ):
            raise ValueError(f"relying party origin must use https: {self.origin!r}")
        object.__setattr__(self, "rp_id", parts.hostname)
