"""Default relying-service credentials must be shapes the typed issuer accepts."""

import pytest
from aweb_naapp_testing import Member
from awid.controller_signing import (
    ControllerDescriptor,
    ControllerObjectRequest,
    ControllerSigningContext,
)
from awid.signing import VerifyResult, verify_signature


@pytest.mark.parametrize("global_member", [False, True])
def test_fixture_certificate_uses_current_scope_and_typed_issuer(global_member):
    fields = {"member_did_aw": "did:aw:fixture"} if global_member else {}
    member = Member("backend:example.test", extra_cert_fields=fields)
    certificate = member.certificate()
    assert certificate.get("identity_scope") == ("global" if global_member else "local")
    assert "lifetime" not in certificate
    unsigned = {key: value for key, value in certificate.items() if key != "signature"}
    context = ControllerSigningContext(
        ControllerObjectRequest("team_certificate_issue", "example.test", {"name": "backend", "certificate": unsigned}),
        ControllerDescriptor("team", "example.test", member.team_did_key, "fixture", 0, team="backend"),
    )
    assert verify_signature(member.team_did_key, context.signing_bytes(), certificate["signature"]) is VerifyResult.VERIFIED
