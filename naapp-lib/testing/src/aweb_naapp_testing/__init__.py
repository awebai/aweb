"""Test support for naapps: team members and a signer for team-auth v2
requests. AWID itself runs in-process through ``awid_service.testing``.

This is a dev-only distribution: it mints throwaway team keys and
certificates, and no production install depends on it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey


def did_key(key: SigningKey) -> str:
    return did_from_public_key(bytes(key.verify_key))


def utc_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class Member:
    """A team key and one member certificate signed by it."""

    team_id: str
    team_key: SigningKey = field(default_factory=SigningKey.generate)
    member_key: SigningKey = field(default_factory=SigningKey.generate)
    certificate_id: str = "cert-1"
    alias: str = "alice"
    extra_cert_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def team_did_key(self) -> str:
        return did_key(self.team_key)

    @property
    def did_key(self) -> str:
        return did_key(self.member_key)

    def certificate(self) -> dict[str, Any]:
        cert = {
            "version": 1,
            "certificate_id": self.certificate_id,
            "team_id": self.team_id,
            "team_did_key": self.team_did_key,
            "member_did_key": self.did_key,
            "alias": self.alias,
            "lifetime": "persistent",
            "issued_at": "2026-01-01T00:00:00Z",
            **self.extra_cert_fields,
        }
        cert["signature"] = sign_message(bytes(self.team_key), canonical_json_bytes(cert))
        return cert

    def headers(
        self,
        *,
        aud: str,
        method: str,
        path: str,
        body: bytes = b"",
        timestamp: str | None = None,
        payload_changes: dict[str, Any] | None = None,
        cert: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        timestamp = timestamp or utc_timestamp(datetime.now(UTC))
        payload: dict[str, Any] = {
            "v": 2,
            "aud": aud,
            "method": method,
            "path": path,
            "team_id": self.team_id,
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        for name, value in (payload_changes or {}).items():
            if value is None:
                payload.pop(name, None)
            else:
                payload[name] = value
        canonical = canonical_json_bytes(payload)
        return envelope_headers(
            did_key=self.did_key,
            signature=sign_message(bytes(self.member_key), canonical),
            timestamp=timestamp,
            signed_payload=canonical,
            cert=cert if cert is not None else self.certificate(),
        )


def envelope_headers(
    *, did_key: str, signature: str, timestamp: str, signed_payload: bytes, cert: dict[str, Any]
) -> dict[str, str]:
    return {
        "Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed_payload).rstrip(b"=").decode(),
        "X-AWID-Team-Certificate": base64.b64encode(json.dumps(cert).encode()).decode(),
    }
