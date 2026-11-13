"""Public self-proof example: actual shared envelope and certificate codecs.

This verifies byte agreement, not freshness or current registry authority.
Those predicates belong to the independently mounted native tests.
"""

import hashlib
import json
from pathlib import Path

from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.team_certificate import check_team_certificate
from starlette.requests import Request

from aweb.team_auth_envelope import team_auth_signature_payload

FIXTURE = Path(__file__).parent / "fixtures" / "protected-self-remove-request.json"


def test_self_remove_example_uses_the_existing_team_auth_and_certificate_encoding():
    example = json.loads(FIXTURE.read_bytes())
    body, payload, headers = example["body"], example["payload"], example["headers"]
    raw = example["body_canonical"].encode()
    assert raw == canonical_json_bytes(body)
    assert payload["body_sha256"] == hashlib.sha256(raw).hexdigest()
    assert payload["scope_sha256"] == hashlib.sha256(canonical_json_bytes(body["scope"])).hexdigest()
    assert payload["operation"] == "protected_operation_prepare"
    assert payload["service_id"] == body["scope"]["service_id"]
    request = Request({"type": "http", "method": "POST", "path": "/protected-operations",
        "raw_path": b"/protected-operations", "query_string": b"",
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()]})
    envelope = team_auth_signature_payload(request, team_id=body["subject"]["team_id"],
        timestamp=headers["X-AWEB-Timestamp"], body_sha256=hashlib.sha256(raw).hexdigest(),
        allowed_audiences=[payload["aud"]])
    assert envelope.version == 2 and envelope.payload == payload
    scheme, key, signature = headers["Authorization"].split()
    assert scheme == "DIDKey"
    verify_did_key_signature(did_key=key, payload=envelope.canonical_payload, signature_b64=signature)
    checked = check_team_certificate(headers["X-AWID-Team-Certificate"], subject_did_key=key,
        team_did_key=example["certificate"]["team_did_key"], revoked_certificate_ids=set(),
        registered_certificate_ids={body["subject"]["certificate_id"]})
    assert checked["identity_scope"] == "local" and checked["member_did_key"] == body["subject"]["member_id"]
    assert checked["certificate_id"] == body["subject"]["certificate_id"]
