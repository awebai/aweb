"""Pure eligibility boundary; real certificate/HTTP controls run separately."""

from contextlib import asynccontextmanager

import pytest
from aweb.identity_binding import IdentityBinding
from aweb.member_status import MemberStatus
from aweb.member_team_key import MemberProjection
from aweb.team_auth_deps import resolve_team_identity
from test_native_member_projection import native_json_snapshot as native_json_snapshot

__all__ = ["native_json_snapshot"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", list(MemberStatus))
async def test_checked_certificate_context_still_requires_an_active_native_row(
    native_json_snapshot, status
):
    # These are explicit unit inputs, not admission or identity authority proof.
    native_json_snapshot["status"] = status
    native_json_snapshot["accepted_team_did_key"] = "did:key:unit-team"
    native_json_snapshot["current_team_did_key"] = "did:key:unit-team"
    row = MemberProjection.from_row(native_json_snapshot)
    checked = {
        "team_id": row["team_id"],
        "alias": row["alias"],
        "did_key": row["did_key"],
        "identity_scope": row["identity_scope"],
        "certificate_id": row["certificate_id"],
        "verified_team_did_key": row["accepted_team_did_key"],
        "agent_row": row,
        "identity_binding": IdentityBinding(did_key=row["did_key"]),
    }

    class RowDatabase:
        # Unit-only transaction carrier; actual locking/authority has real controls.
        @asynccontextmanager
        async def transaction(self):
            yield self

        async def fetch_one(self, *args):
            return dict(row)

    if status is MemberStatus.ACTIVE:
        identity = await resolve_team_identity(RowDatabase(), checked)
        assert identity.agent_id == str(row["agent_id"])
    else:
        with pytest.raises(ValueError, match="Reconnect with a certificate"):
            await resolve_team_identity(object(), checked)
