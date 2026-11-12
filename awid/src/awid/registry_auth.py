"""How a client authenticates its requests to its home AWID registry.

A hosted deployment holds AWID's service token, which rides on every request.
Without one, a client holding an ordinary member key of a private team
path-signs that team's gated reads (the team, its certificates, a member and
its revocations) as the CLI does: ``"{timestamp}\\n{METHOD}\\n{path}"`` in a
DIDKey ``Authorization`` header with ``X-AWEB-Timestamp``. No write, identity
read or certificate status read inherits the member's authority, and a key
never signs another team's reads.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType

from awid.did import did_key_from_signing_key
from awid.ratelimit import AWID_SERVICE_TOKEN_HEADER
from awid.signing import sign_message
from awid.team_ids import build_team_id

_GATED_TEAM_READ = re.compile(
    r"/v1/namespaces/([^/]+)/teams/([^/]+)(?:/(?:revocations|certificates|members/[^/]+))?"
)


@dataclass(frozen=True)
class RegistryRequestAuth:
    service_token: str | None = field(default=None, repr=False)
    member_signing_keys: Mapping[str, bytes] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        token = (self.service_token or "").strip() or None
        object.__setattr__(self, "service_token", token)
        object.__setattr__(
            self, "member_signing_keys", MappingProxyType(dict(self.member_signing_keys))
        )

    def headers(self, method: str, path: str, *, signed_by_caller: bool = False) -> dict[str, str]:
        """The authentication headers of one request for ``path`` (its query
        is not signed). A request the caller signs itself keeps that
        signature: only the service token joins it."""
        if self.service_token:
            return {AWID_SERVICE_TOKEN_HEADER: self.service_token}
        if signed_by_caller or method != "GET":
            return {}
        read_path = path.partition("?")[0]
        match = _GATED_TEAM_READ.fullmatch(read_path)
        if match is None:
            return {}
        key = self.member_signing_keys.get(build_team_id(*match.groups()))
        if key is None:
            return {}
        return path_signature_headers(method, read_path, key)


def path_signature_headers(method: str, path: str, signing_key: bytes) -> dict[str, str]:
    """``signing_key``'s signature of one request for exactly ``path``."""
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = f"{timestamp}\n{method}\n{path}".encode("utf-8")
    did_key = did_key_from_signing_key(signing_key)
    return {
        "Authorization": f"DIDKey {did_key} {sign_message(signing_key, payload)}",
        "X-AWEB-Timestamp": timestamp,
    }
