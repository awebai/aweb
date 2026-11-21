"""Unit policy boundary: unknown grant authority cannot establish stale deletion."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from fastapi import HTTPException
from awid.registry import RegistryError
from aweb.grant_liveness import (
    GrantLivenessFailurePolicy,
    valid_grant_liveness_by_workspace,
)


class CandidateRows:
    """Stored-candidate stand-in; this test does not establish SQL eligibility."""

    def __init__(self, row):
        self.row = row

    async def fetch_all(self, sql, *values):
        return [self.row]


class UnavailableRevocationReader:
    async def get_team_revocations_for_certificates(
        self, domain, name, certificate_ids, *, fresh=False
    ):
        raise RegistryError("unit upstream unavailable", status_code=503)


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", list(GrantLivenessFailurePolicy))
async def test_unknown_grant_authority_is_omitted_for_display_and_refuses_stale_eligibility(
    policy,
):
    now = datetime.now(timezone.utc)
    row = dict(
        workspace_id=uuid4(),
        grant_id=uuid4(),
        subject_agent_id=uuid4(),
        alias="worker",
        session_did_key="did:key:session",
        last_seen_at=now,
        liveness_expires_at=now + timedelta(minutes=5),
        team_id="backend:example.test",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        revoked_at=None,
        issued_by_certificate_id="current-certificate",
        certificate_id="current-certificate",
        subject_status="active",
        subject_deleted_at=None,
        accepted_team_did_key="did:key:team",
        current_team_did_key="did:key:team",
    )
    kwargs = dict(registry_client=UnavailableRevocationReader(), failure_policy=policy)
    if policy is GrantLivenessFailurePolicy.REQUIRE_KNOWN:
        with pytest.raises(HTTPException) as refused:
            await valid_grant_liveness_by_workspace(
                CandidateRows(row), [str(row["workspace_id"])], **kwargs
            )
        assert refused.value.status_code == 503
        assert "revocation" in str(refused.value.detail)
    else:
        assert (
            await valid_grant_liveness_by_workspace(
                CandidateRows(row), [str(row["workspace_id"])], **kwargs
            )
            == {}
        )
