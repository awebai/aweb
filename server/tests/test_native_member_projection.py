"""The embedded native snapshot is complete, immutable and JSON-normalized."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from aweb.member_team_key import MemberProjection


@pytest.fixture
def native_json_snapshot():
    return {
        "agent_id": str(uuid4()),
        "team_id": "backend:example.test",
        "alias": "member",
        "did_key": "did:key:current",
        "did_aw": "did:aw:unverified-claim",
        "address": "example.test/unverified-claim",
        "did_aw_verified_key": None,
        "identity_scope": "global",
        "certificate_id": "member-certificate",
        "accepted_team_did_key": "did:key:admitting-team",
        "current_team_did_key": "did:key:current-team",
        "status": "active",
        "deleted_at": None,
        "agent_type": "agent",
        "human_verified_key": None,
        "inbound_mode": "team_and_contacts",
    }


def test_native_snapshot_normalizes_postgres_json_types(native_json_snapshot):
    deleted_at = datetime(2026, 11, 18, tzinfo=timezone.utc)
    native_json_snapshot["deleted_at"] = deleted_at.isoformat()
    projection = MemberProjection.from_row(native_json_snapshot)

    assert projection["agent_id"] == UUID(native_json_snapshot["agent_id"])
    assert projection["deleted_at"] == deleted_at


@pytest.mark.parametrize(
    "column", ["accepted_team_did_key", "current_team_did_key", "did_aw_verified_key"]
)
def test_omitted_authority_column_is_not_a_null_fact(native_json_snapshot, column):
    del native_json_snapshot[column]
    with pytest.raises(ValueError, match="Incomplete native member projection"):
        MemberProjection.from_row(native_json_snapshot)


def test_snapshot_keeps_raw_policy_claims_without_attributing_them(
    native_json_snapshot,
):
    # Deliberate legacy/tampering state, not a supported authenticated identity.
    projection = MemberProjection.from_row(native_json_snapshot)
    assert projection["did_aw"] == "did:aw:unverified-claim"
    assert projection.verified_identity()["did_aw"] is None
    assert projection.verified_identity()["address"] is None


def test_host_cannot_mutate_a_captured_native_snapshot(native_json_snapshot):
    projection = MemberProjection.from_row(native_json_snapshot)
    native_json_snapshot["did_aw_verified_key"] = native_json_snapshot["did_key"]
    assert projection["did_aw_verified_key"] is None
    assert projection.verified_identity()["did_aw"] is None


def test_native_snapshot_exposes_the_canonical_scope_and_status_types(
    native_json_snapshot,
):
    from aweb.identity_scope import IdentityScope
    from aweb.member_status import MemberStatus

    projection = MemberProjection.from_row(native_json_snapshot)
    assert projection["identity_scope"] is IdentityScope.GLOBAL
    assert projection["status"] is MemberStatus.ACTIVE


@pytest.mark.parametrize("column", ["identity_scope", "status"])
@pytest.mark.parametrize("invalid", [None, "unrecognized"])
def test_invalid_constrained_native_vocabulary_is_not_a_valid_projection(
    native_json_snapshot, column, invalid
):
    native_json_snapshot[column] = invalid
    with pytest.raises(ValueError):
        MemberProjection.from_row(native_json_snapshot)
