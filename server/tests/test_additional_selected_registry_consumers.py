"""Actual admitted-membership and signed-controller neighbors on resource-only roots."""

import json
from datetime import datetime, timezone

import pytest

from awid.signing import sign_message
from aweb.application_state import RegistryClientUnavailable
from aweb.routes.service_registration import (
    TeamServiceRegisterRequest,
    _team_service_register_signature_payload,
    register_team_with_service,
)
from aweb.routes.status import status
from aweb.team_auth_deps import resolve_team_identity
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _signed_team_headers
from test_selected_registry_consumers import root_app, root_request
from test_team_auth_deps import _admitted_cert_info

__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [False, True])
async def test_status_grant_presence_uses_selected_registry_on_resource_only_root(
    privacy_app, missing
):
    env = privacy_app
    actor, cert_info = await _admitted_cert_info(env, alias="alice")
    identity = await resolve_team_identity(
        env.db, cert_info, request=root_request(env.app)
    )
    session_key, session_did = _session_keypair()
    body = json.dumps(
        {"grant_did_key": session_did, "scopes": ["presence.write"], "ttl_seconds": 600}
    ).encode()
    minted = await env.client.post(
        "/v1/identity-grants",
        content=body,
        headers={
            **_signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body),
            "Content-Type": "application/json",
        },
    )
    assert minted.status_code == 200, minted.text
    heartbeat = await env.client.post(
        "/v1/agents/heartbeat",
        headers=_grant_headers(
            signing_key=session_key,
            did_key=session_did,
            grant_id=minted.json()["grant_id"],
            method="POST",
            path="/v1/agents/heartbeat",
            aud=env.app.state.public_origin,
        ),
    )
    assert heartbeat.status_code == 200, heartbeat.text
    registry = env.app.state.awid_registry_client
    root = root_app(env.app, None if missing else registry)
    if missing:
        root.state.awid_registry_client = registry
        with pytest.raises(RegistryClientUnavailable) as refused:
            await status(
                root_request(root),
                workspace_id=str(actor.workspace),
                repo_id=None,
                redis=env.redis,
                db_infra=env.infra,
                identity=identity,
            )
        assert refused.value.code == "registry_client_unavailable"
    else:
        assert not hasattr(root.state, "awid_registry_client")
        result = await status(
            root_request(root),
            workspace_id=str(actor.workspace),
            repo_id=None,
            redis=env.redis,
            db_infra=env.infra,
            identity=identity,
        )
        assert len(result["agents"]) == 1
        assert result["agents"][0]["workspace_id"] == str(actor.workspace)
        assert result["agents"][0]["status"] == "active"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [False, True])
async def test_controller_service_registration_uses_selected_root_registry(
    privacy_app, monkeypatch, missing
):
    env = privacy_app
    origin = "https://aweb.example.test"
    monkeypatch.setenv("AWEB_DISCOVERY_ORIGIN", origin)
    body = TeamServiceRegisterRequest(
        awid_team_id=TEAM,
        service_url=origin,
        dry_run=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
        controller_signature="pending",
    )
    body.controller_signature = sign_message(
        env.team_sk, _team_service_register_signature_payload(body)
    )
    registry = env.app.state.awid_registry_client
    root = root_app(env.app, None if missing else registry)
    if missing:
        root.state.awid_registry_client = registry
        with pytest.raises(RegistryClientUnavailable) as refused:
            await register_team_with_service(body, root_request(root), db=env.infra)
        assert refused.value.status_code == 503
        assert refused.value.code == "registry_client_unavailable"
    else:
        assert not hasattr(root.state, "awid_registry_client")
        result = await register_team_with_service(
            body, root_request(root), db=env.infra
        )
        assert result.status == "dry-run"
        assert result.team_did_key == env.team_did
        assert result.awid_team_id == TEAM
