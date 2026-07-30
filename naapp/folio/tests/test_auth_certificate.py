from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from folio.auth import _verify_certificate_signature


def test_certificate_signature_matches_awid_canonical_json() -> None:
    team_key = SigningKey.generate()
    member_key = SigningKey.generate()
    team_did = did_from_public_key(bytes(team_key.verify_key))
    member_did = did_from_public_key(bytes(member_key.verify_key))

    cert = {
        "version": 1,
        "certificate_id": "00000000-0000-4000-8000-000000000001",
        "team_id": "backend:example.com",
        "team_did_key": team_did,
        "member_did_key": member_did,
        "member_did_aw": "did:aw:test",
        "member_address": "example.com/alice",
        "alias": "alice",
        "lifetime": "persistent",
        "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    cert["signature"] = sign_message(bytes(team_key), canonical_json_bytes(cert))

    _verify_certificate_signature(cert, team_did)


def test_certificate_header_is_standard_base64_json() -> None:
    encoded = base64.b64encode(json.dumps({"team_id": "backend:example.com"}).encode()).decode()
    assert json.loads(base64.b64decode(encoded)) == {"team_id": "backend:example.com"}
