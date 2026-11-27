"""A designated status host must retain current team membership."""

import pytest
from test_agent_health_http import _document, _health, _publish
from test_agent_status_host_http import _team_request
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _certificate, _change_key, _connect
from test_team_auth_deps import _admitted_cert_info
from test_team_key_pinning import pinning as pinning

__all__ = ["pinning"]


@pytest.mark.asyncio
async def test_superseded_status_host_is_inactive_until_it_reconnects(pinning):
    # agent-health.md:43-44,78-99: delegation does not outlive membership.
    env = pinning
    await _admitted_cert_info(env, alias="alice")
    host, _ = await _admitted_cert_info(env, alias="bob")
    designated = await _team_request(
        env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": host.did}
    )
    assert designated.status_code == 200, designated.text
    assert designated.json()["host_active"] is True
    published = await _publish(env, "bob", "alice", _document(env, "alice", "bob"))
    assert published.status_code == 200, published.text
    assert (await _health(env, "alice"))["source"] == "host"

    next_key, next_did = await _change_key(env)
    alice = env.actors["alice"]
    member = (alice.sk, alice.did, "alice")
    alice.certificate = _certificate(next_key, next_did, member, "alice-status-current")
    reconnected = await _connect(env, member, alice.certificate)
    assert reconnected.status_code == 200, reconnected.text
    shown = await _team_request(env, "alice", "GET", "/v1/agents/me/status-host")
    assert shown.status_code == 200, shown.text
    assert shown.json()["host_did"] == host.did
    assert shown.json()["host_active"] is False
    assert (await _health(env, "alice"))["source"] == "aweb"
    refused = await _team_request(
        env, "alice", "PUT", "/v1/agents/me/status-host", {"host_did": host.did}
    )
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"] == (
        "host_not_member: host_did is not a current member of this team. "
        "Check the host name; if it exists, ask it to reconnect with a current team certificate."
    )

    host_member = (host.sk, host.did, "bob")
    host.certificate = _certificate(
        next_key, next_did, host_member, "bob-status-current"
    )
    restored = await _connect(env, host_member, host.certificate)
    assert restored.status_code == 200, restored.text
    shown = await _team_request(env, "alice", "GET", "/v1/agents/me/status-host")
    assert shown.status_code == 200, shown.text
    assert shown.json()["host_active"] is True
