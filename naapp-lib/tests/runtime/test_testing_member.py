"""Default relying-service credentials must be shapes the typed issuer accepts."""

import pytest
from aweb_naapp_testing import TEAM_CONTROLLER_SCOPE, Member
from awid.contract import IdentityScope
from awid.controller_signing import (
    ControllerDescriptor,
    ControllerObjectRequest,
    ControllerSigningContext,
)
from awid.did import stable_id_from_did_key
from awid.signing import VerifyResult, verify_signature


@pytest.mark.parametrize("scope", [IdentityScope.LOCAL, IdentityScope.GLOBAL])
def test_fixture_certificate_uses_current_scope_and_typed_issuer(scope):
    member = Member("backend:example.test")
    if scope is IdentityScope.GLOBAL:
        member.extra_cert_fields = {"member_did_aw": stable_id_from_did_key(member.did_key)}
    certificate = member.certificate()
    assert certificate.get("identity_scope") == scope.value
    assert "lifetime" not in certificate
    unsigned = {key: value for key, value in certificate.items() if key != "signature"}
    context = ControllerSigningContext(
        request=ControllerObjectRequest(operation="team_certificate_issue", domain="example.test", parameters={"name": "backend", "certificate": unsigned}),
        controller=ControllerDescriptor(scope=TEAM_CONTROLLER_SCOPE, domain="example.test", did_key=member.team_did_key, key_reference="fixture", generation=0, team="backend"),
    )
    assert verify_signature(member.team_did_key, context.signing_bytes(), certificate["signature"]) is VerifyResult.VERIFIED
