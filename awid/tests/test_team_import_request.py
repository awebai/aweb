"""The Python verifier consumes the released aw import request unchanged."""

from dataclasses import replace

import pytest

from awid.team_control_requests import TeamControlSignatureError, TeamImportRequest


def test_released_aw_import_request_preimage_and_signature():
    # The released aw fixture in
    # cli/go/cmd/aw/id_team_test.go::TestBuildTeamImportRequestOutputSignsCanonicalACPayload.
    signer = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
    signature = (
        "wJ9qUNecyxiqSF45ALU6upFloyUPiQW1RXkste671QcTjBM9nGqN9ngTcgGwVX2OO"
        "+s4gQ/yFIXKL7OewHelBw"
    )
    request = TeamImportRequest(
        awid_team_id="research:acme.com",
        dry_run=True,
        organization_id="org-1",
        team_id=None,
        timestamp="2026-05-09T12:00:00Z",
    )
    assert request.signing_bytes() == (
        b'{"awid_team_id":"research:acme.com","dry_run":true,"operation":"byoidt_import",'
        b'"organization_id":"org-1","team_id":"","timestamp":"2026-05-09T12:00:00Z"}'
    )
    request.verify_signature(signer_did_key=signer, signature=signature)
    with pytest.raises(TeamControlSignatureError):
        replace(request, dry_run=False).verify_signature(
            signer_did_key=signer, signature=signature
        )
