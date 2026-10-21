"""aweb.team-server/1: a team-key-signed binding of a team to its coordination server.

The team controller signs, with the team key, the domain prefix followed by the
canonical JSON of the record. Consumers verify the record against the team's
current key from the registry they already trust for that team; a record signed
by any other key is refused.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlparse

from awid.did import public_key_from_did
from awid.signing import VerifyResult, canonical_json_bytes, verify_signature_with_public_key
from awid.utc_timestamps import parse_utc_seconds

SIGNING_PREFIX = b"aweb.team-server/1\n"
RECORD_TYPE = "aweb.team-server"
RECORD_VERSION = 1
RECORD_FIELDS = frozenset({"v", "type", "team_id", "team_did_key", "server_url", "issued_at"})
MAX_FUTURE_SECONDS = 300
MAX_SERVER_URL_BYTES = 2048
# An Ed25519 signature in unpadded standard base64: 64 bytes, 86 characters.
# The last character carries four spare bits, which must be zero (A, Q, g or w),
# so every signature has exactly one accepted encoding.
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9+/]{85}[AQgw]")


class TeamServerRecordError(ValueError):
    """A refused record; ``code`` is stable and distinct per refusal."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TeamServerRecord:
    team_id: str
    team_did_key: str
    server_url: str
    audience: str
    issued_at: datetime


def record_signing_bytes(record: dict) -> bytes:
    return SIGNING_PREFIX + canonical_json_bytes(record)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def canonical_team_server_url(value: str) -> tuple[str, str]:
    """Return ``(server_url, audience)`` for a canonical team server URL.

    The URL is an https origin with an optional path prefix, in canonical form:
    lower-case scheme and host, no default port, no trailing slash, no
    userinfo, query or fragment. Plain http is accepted only for loopback
    hosts, and literal IP addresses only when they are loopback.
    """

    def refuse(reason: str) -> TeamServerRecordError:
        return TeamServerRecordError("server_url_invalid", f"server_url {reason}")

    if not isinstance(value, str) or not value:
        raise refuse("is required")
    if len(value.encode("utf-8")) > MAX_SERVER_URL_BYTES:
        raise refuse(f"must be at most {MAX_SERVER_URL_BYTES} bytes")
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise refuse("is not a URL") from exc
    scheme = parsed.scheme
    host = parsed.hostname or ""
    if scheme not in {"http", "https"}:
        raise refuse("must use https")
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        raise refuse("must not include userinfo, params, query or fragment")
    if not host:
        raise refuse("must include a host")
    path = parsed.path
    if path.endswith("/") or "//" in path:
        raise refuse("must not end with a slash or contain empty segments")
    default_port = 80 if scheme == "http" else 443
    host_out = f"[{host}]" if ":" in host else host
    audience = f"{scheme}://{host_out}{'' if port in (None, default_port) else f':{port}'}"
    if audience + path != value:
        raise refuse("must be in canonical form")
    loopback = _is_loopback_host(host)
    if scheme == "http" and not loopback:
        raise refuse("must use https outside loopback hosts")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not loopback:
            raise refuse("must not use a literal IP address")
    return value, audience


def _parse_issued_at(value: object) -> datetime:
    try:
        return parse_utc_seconds(value)
    except ValueError as exc:
        raise TeamServerRecordError(
            "record_invalid", "issued_at must be RFC 3339 UTC seconds (YYYY-MM-DDTHH:MM:SSZ)"
        ) from exc


def verify_team_server_record(
    record: object,
    signature: object,
    *,
    team_id: str,
    current_team_did_key: str,
    now: datetime,
    max_future_seconds: int = MAX_FUTURE_SECONDS,
) -> TeamServerRecord:
    """Verify one record for ``team_id`` against the team's current key.

    Raises TeamServerRecordError with one of the codes ``record_invalid``,
    ``team_mismatch``, ``team_server_key_mismatch`` or ``signature_invalid``
    for a record that does not verify, or ``server_url_invalid`` or
    ``issued_at_in_future`` for a verified record that is still refused.
    """

    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise TeamServerRecordError("record_invalid", "record must have exactly the aweb.team-server/1 fields")
    version = record["v"]
    if type(version) is not int or version != RECORD_VERSION or record["type"] != RECORD_TYPE:
        raise TeamServerRecordError("record_invalid", "record must be version 1 of aweb.team-server")
    if not all(isinstance(record[field], str) for field in ("team_id", "team_did_key", "server_url")):
        raise TeamServerRecordError("record_invalid", "record fields must be strings")
    issued_at = _parse_issued_at(record["issued_at"])
    if record["team_id"] != team_id:
        raise TeamServerRecordError("team_mismatch", "record names another team")
    if record["team_did_key"] != current_team_did_key:
        raise TeamServerRecordError("team_server_key_mismatch", "record is not signed by the team's current key")
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        raise TeamServerRecordError("signature_invalid", "signature must be unpadded standard base64 Ed25519")
    try:
        public_key = public_key_from_did(current_team_did_key)
    except ValueError as exc:
        raise TeamServerRecordError("team_server_key_mismatch", "team key is not a did:key") from exc
    if verify_signature_with_public_key(public_key, record_signing_bytes(record), signature) != VerifyResult.VERIFIED:
        raise TeamServerRecordError("signature_invalid", "signature does not verify against the team key")
    server_url, audience = canonical_team_server_url(record["server_url"])
    if issued_at > now + timedelta(seconds=max_future_seconds):
        raise TeamServerRecordError("issued_at_in_future", "issued_at is too far in the future")
    return TeamServerRecord(
        team_id=team_id,
        team_did_key=current_team_did_key,
        server_url=server_url,
        audience=audience,
        issued_at=issued_at,
    )
