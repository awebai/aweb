"""Signed artifact compatibility yields one normalized scope vocabulary."""

import base64
import json
import pytest
from nacl.signing import SigningKey
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from awid.team_certificate import TeamCertificateError
from aweb.identity_scope import IdentityScope
from aweb.team_auth import parse_and_verify_certificate


@pytest.mark.parametrize(
    "artifact_lifetime,scope",
    [("persistent", IdentityScope.GLOBAL), ("ephemeral", IdentityScope.LOCAL)],
)
def test_historical_signed_lifetime_is_accepted_without_duplicate_metadata(
    artifact_lifetime, scope
):
    key = SigningKey(bytes(range(32)))
    did = did_from_public_key(bytes(key.verify_key))
    cert = dict(
        version=1,
        certificate_id="historical",
        team_id="backend:example.test",
        team_did_key=did,
        member_did_key=did,
        alias="worker",
        lifetime=artifact_lifetime,
        issued_at="2026-11-18T00:00:00Z",
    )
    cert["signature"] = sign_message(bytes(key), canonical_json_bytes(cert))

    def parse(value):
        return parse_and_verify_certificate(
            base64.b64encode(json.dumps(value).encode()).decode(),
            request_did_key=did,
            team_did_key=did,
            revoked_certificate_ids=set(),
            registered_certificate_ids=None,
        )

    projected = parse(cert)
    assert projected["identity_scope"] is scope
    assert "lifetime" not in projected
    altered = {
        **cert,
        "lifetime": "ephemeral" if artifact_lifetime == "persistent" else "persistent",
    }
    with pytest.raises(TeamCertificateError) as refused:
        parse(altered)
    assert refused.value.reason == "bad_signature"
