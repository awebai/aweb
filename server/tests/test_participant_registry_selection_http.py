"""Actual participant discovery borrows the root's selected native registry."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request

from aweb.identity_auth_deps import MessagingAuth
from aweb.routes.messaging import participant
from test_mcp_mail_conversation_parity import (
    _publish_hosted_key,
    mail_server as mail_server,
)

__all__ = ["mail_server"]


@pytest.mark.asyncio
@pytest.mark.parametrize("subject", ["human-membership", "agent-encryption-key"])
async def test_participant_discovery_reads_selected_root_registry(mail_server, subject):
    env = mail_server
    with_key = subject == "agent-encryption-key"
    if with_key:
        await _publish_hosted_key(
            env,
            agent_id=env.pilot,
            signing_key=env.pilot_key,
            did_key=env.pilot_did,
            did_aw=env.pilot_stable,
            public_key=b"s" * 32,
        )
    actor = env.actors[env.pilot]
    root = FastAPI()
    root.state.native_resources = SimpleNamespace(
        api_app=env.fixture.app, registry_client=env.registry
    )
    root.state.awid_registry_client = None
    # Auth is the already admitted fixture actor, not a serving-ref proof.
    auth = MessagingAuth(
        did_key=env.pilot_did,
        did_aw=env.pilot_stable,
        address=actor.address,
        team_id=actor.team_id,
        verified_team_id=actor.team_id,
        agent_id=env.pilot,
        alias="pilot",
    )
    result = await participant(
        "pilot" if with_key else "human",
        Request({"type": "http", "app": root, "headers": []}),
        db=env.fixture.infra,
        auth=auth,
    )
    assert result["did_aw"] == (env.pilot_stable if with_key else env.human_stable)
    if with_key:
        assert result["encryption_key"]["identity_did"] == env.pilot_did
        assert result["encryption_key"]["identity_stable_id"] == env.pilot_stable
        assert result["encryption_key"]["custody"] == "hosted_custodial"
    else:
        assert result["agent_type"] == "human"
