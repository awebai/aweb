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

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException

from aweb.identity_auth_deps import (
    _enforce_current_membership,
    lookup_identity_agent_context,
)
from aweb.routes.connect import connect_agent
from aweb.team_auth_deps import resolve_team_identity

TEAM_ID = "backend:acme.com"
MEMBER_DID_KEY = "did:key:z6MkRevocable"


def _request_with_revocations(result):
    registry = AsyncMock()
    if isinstance(result, Exception):
        registry.get_team_revocations = AsyncMock(side_effect=result)
    else:
        registry.get_team_revocations = AsyncMock(return_value=result)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(awid_registry_client=registry))), registry


@pytest.mark.asyncio
async def test_revoked_certificate_strips_team_context():
    request, _ = _request_with_revocations({"cert-9"})
    row = {
        "agent_id": "agent-1",
        "team_id": TEAM_ID,
        "alias": "alice",
        "did_aw": "did:aw:alice",
        "address": "acme.com/alice",
        "identity_scope": "global",
        "certificate_id": "cert-9",
    }
    out = await _enforce_current_membership(request, row)
    assert out["team_id"] is None
    assert out["alias"] is None
    assert out["agent_id"] is None
    # Revocation ends membership, not the identity.
    assert out["did_aw"] == "did:aw:alice"
    assert out["address"] == "acme.com/alice"


@pytest.mark.asyncio
async def test_live_certificate_keeps_team_context():
    request, _ = _request_with_revocations({"cert-other"})
    row = {"team_id": TEAM_ID, "alias": "alice", "agent_id": "a", "certificate_id": "cert-9"}
    out = await _enforce_current_membership(request, row)
    assert out["team_id"] == TEAM_ID and out["alias"] == "alice"


@pytest.mark.asyncio
async def test_row_without_recorded_certificate_passes_without_registry_call():
    request, registry = _request_with_revocations(set())
    row = {"team_id": TEAM_ID, "alias": "alice", "agent_id": "a", "certificate_id": None}
    out = await _enforce_current_membership(request, row)
    assert out is row
    registry.get_team_revocations.assert_not_awaited()


@pytest.mark.asyncio
async def test_row_without_team_context_passes_without_registry_call():
    request, registry = _request_with_revocations(set())
    row = {"team_id": None, "alias": None, "agent_id": None, "certificate_id": "cert-9"}
    out = await _enforce_current_membership(request, row)
    assert out is row
    registry.get_team_revocations.assert_not_awaited()


@pytest.mark.asyncio
async def test_registry_unavailable_fails_closed():
    request, _ = _request_with_revocations(httpx.ConnectError("registry down"))
    row = {"team_id": TEAM_ID, "alias": "alice", "agent_id": "a", "certificate_id": "cert-9"}
    with pytest.raises(HTTPException) as excinfo:
        await _enforce_current_membership(request, row)
    assert excinfo.value.status_code == 503


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
    row = await lookup_identity_agent_context(db, did_key=MEMBER_DID_KEY)
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
    row = await lookup_identity_agent_context(db, did_key=MEMBER_DID_KEY)
    assert row["certificate_id"] == "cert-second"


@pytest.mark.asyncio
async def test_certificate_authenticated_request_refreshes_recorded_certificate(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    cert_info = {
        "team_id": TEAM_ID,
        "alias": "refresher",
        "did_key": "did:key:z6MkRefresher",
        "identity_scope": "local",
        "certificate_id": "cert-old",
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
    row = await lookup_identity_agent_context(db, did_key="did:key:z6MkRefresher")
    assert row["certificate_id"] == "cert-new"
