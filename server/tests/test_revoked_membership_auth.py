"""aweb-abfn: identity-only messaging auth must not grant team context to a
member whose admitting certificate is revoked.

Identity-only auth proves key possession; the team_id/alias it inherits from
the agents projection is only as current as that row. These tests pin the
enforcement: the projection records the admitting certificate (at connect and
at certificate-authenticated requests), and the identity-only path checks that
certificate against the registry's revocations, stripping team context when it
is revoked — same fail-closed posture as the certificate-presenting path.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from aweb.member_team_key import current_membership, read_member_projection
from aweb.routes.connect import connect_agent
from aweb.team_auth_deps import resolve_team_identity
from awid.registry import RegistryError
from messaging_actor_support import admit_messaging_actor
from test_dashboard_privacy import TEAM, TEAM_NAME
from test_dashboard_privacy import privacy_app as privacy_app

__all__ = ["privacy_app"]

TEAM_ID = "backend:acme.com"
MEMBER_DID_KEY = "did:key:z6MkRevocable"
# A member accepted under its team's current key, as lookup_identity_agent_context reads it.
CURRENT_KEY = {
    "status": "active",
    "deleted_at": None,
    "accepted_team_did_key": "did:key:zTeam",
    "current_team_did_key": "did:key:zTeam",
}


async def _registered_member(env, *, alias="revocable"):
    actor = await admit_messaging_actor(
        env, alias=alias, team_id=TEAM, address="example.test/" + alias
    )
    row = await read_member_projection(env.db, team_id=TEAM, did_key=actor.did_key)
    assert row["certificate_id"]
    assert row["did_aw"] == actor.stable_id
    return actor, row


@pytest.mark.asyncio
async def test_revoked_certificate_strips_team_context(privacy_app):
    env = privacy_app
    actor, row = await _registered_member(env)
    registry = env.app.state.awid_registry_client
    live = await current_membership(registry, row)
    assert live["agent_id"] == row["agent_id"]
    await registry.revoke_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=row["certificate_id"],
    )
    out = await current_membership(registry, row)
    assert out["team_id"] is None
    assert out["alias"] is None
    assert out["agent_id"] is None
    assert out["did_aw"] == actor.stable_id
    assert out["address"] == actor.address


@pytest.mark.asyncio
async def test_live_certificate_keeps_team_context(privacy_app):
    env = privacy_app
    _, row = await _registered_member(env)
    _, other = await _registered_member(env, alias="other-certificate")
    registry = env.app.state.awid_registry_client
    await registry.revoke_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=other["certificate_id"],
    )
    out = await current_membership(registry, row)
    assert out["team_id"] == TEAM
    assert out["alias"] == "revocable"
    assert out["agent_id"] == row["agent_id"]


@pytest.mark.asyncio
async def test_row_without_recorded_certificate_passes_without_registry_call():
    registry = AsyncMock()
    row = {
        "team_id": TEAM_ID,
        "alias": "alice",
        "agent_id": "a",
        "certificate_id": None,
        **CURRENT_KEY,
    }
    out = await current_membership(registry, row)
    assert out is row
    registry.get_team_revocations_for_certificates.assert_not_awaited()
    registry.get_team_revocations.assert_not_awaited()
    assert registry.mock_calls == []


@pytest.mark.asyncio
async def test_row_without_team_context_passes_without_registry_call():
    registry = AsyncMock()
    row = {"team_id": None, "alias": None, "agent_id": None, "certificate_id": "cert-9"}
    out = await current_membership(registry, row)
    assert out is row
    registry.get_team_revocations_for_certificates.assert_not_awaited()
    registry.get_team_revocations.assert_not_awaited()
    assert registry.mock_calls == []


@pytest.mark.asyncio
async def test_registry_unavailable_fails_closed(privacy_app):
    env = privacy_app
    _, row = await _registered_member(env)
    registry = env.app.state.awid_registry_client
    assert (await current_membership(registry, row))["team_id"] == TEAM
    env.registry.transport.down = True
    with pytest.raises(HTTPException) as excinfo:
        await current_membership(registry, row)
    assert excinfo.value.status_code == 503
    assert isinstance(excinfo.value.__cause__, RegistryError)


@pytest.mark.asyncio
async def test_connect_records_certificate_and_lookup_returns_it(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    cert_info = {
        "team_id": TEAM_ID,
        "alias": "revocable",
        "did_key": MEMBER_DID_KEY,
        "identity_scope": "local",
        "certificate_id": "cert-first",
    }
    await connect_agent(
        db=db,
        cert_info=cert_info,
        team_did_key="did:key:zTeam",
        hostname="host",
        workspace_path="/tmp/w",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    row = await read_member_projection(db, team_id=TEAM_ID, did_key=MEMBER_DID_KEY)
    assert row is not None
    assert row["certificate_id"] == "cert-first"
    assert row["team_id"] == TEAM_ID

    # A reconnect with a replacement certificate refreshes the recording.
    await connect_agent(
        db=db,
        cert_info={**cert_info, "certificate_id": "cert-second"},
        team_did_key="did:key:zTeam",
        hostname="host",
        workspace_path="/tmp/w",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    row = await read_member_projection(db, team_id=TEAM_ID, did_key=MEMBER_DID_KEY)
    assert row["certificate_id"] == "cert-second"


@pytest.mark.asyncio
async def test_certificate_authenticated_request_refreshes_recorded_certificate(
    aweb_cloud_db,
):
    db = aweb_cloud_db.aweb_db
    cert_info = {
        "team_id": TEAM_ID,
        "alias": "refresher",
        "did_key": "did:key:z6MkRefresher",
        "identity_scope": "local",
        "certificate_id": "cert-old",
        # Unit owner input: the key the certificate verifier checked.
        "verified_team_did_key": "did:key:zTeam",
    }
    await connect_agent(
        db=db,
        cert_info=cert_info,
        team_did_key="did:key:zTeam",
        hostname="host",
        workspace_path="/tmp/w2",
        repo_origin="",
        role="",
        human_name="",
        agent_type="agent",
    )
    # The per-request agent resolution sees the replacement certificate and
    # updates the projection, so identity-only enforcement checks the current
    # certificate rather than the one from the original connect.
    await resolve_team_identity(db, {**cert_info, "certificate_id": "cert-new"})
    row = await read_member_projection(db, team_id=TEAM_ID, did_key="did:key:z6MkRefresher")
    assert row["certificate_id"] == "cert-new"
