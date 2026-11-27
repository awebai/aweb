"""Admit a reconnected member while its archived row shares the same key."""

import json
from dataclasses import replace
from uuid import UUID

import pytest

from aweb.application_state import application_registry_client
from messaging_actor_support import (
    admit_messaging_actor,
    archive_messaging_actor,
    messaging_actor_headers,
)
from test_certificate_preferred_identity_http import mount_policy
from test_dashboard_privacy import TEAM, privacy_app


__all__ = ["privacy_app"]


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["enforce", "prefer-live"])
async def test_reconnected_member_is_admitted_beside_its_archived_row(
    privacy_app, monkeypatch, policy,
):
    env = privacy_app
    registry = application_registry_client(env.app.state)
    archived = await admit_messaging_actor(
        env, alias="returning", team_id=TEAM, address="returning.test/returning"
    )
    receiver = await admit_messaging_actor(env, alias="receiver", team_id=TEAM, local=True)
    await archive_messaging_actor(
        env.db, env.redis, team_id=TEAM, agent_id=archived.agent_id, registry_client=registry,
    )
    # The same identity reconnects with its certificate: connect inserts a
    # new live row beside the archived one.
    connect = await env.client.post(
        "/v1/connect",
        content=b"{}",
        headers=messaging_actor_headers(archived, body=b"{}"),
    )
    assert connect.status_code == 200, connect.text
    sender = replace(archived, agent_id=str(UUID(connect.json()["agent_id"])))
    assert sender.agent_id != archived.agent_id
    rows = await env.db.fetch_all(
        """
        SELECT agent_id, deleted_at IS NOT NULL AS archived FROM {{tables.agents}}
        WHERE team_id=$1 AND did_key=$2 ORDER BY ctid
        """,
        TEAM,
        sender.did_key,
    )
    # The archived row comes first in heap order, where an unordered read finds it.
    assert [(str(row["agent_id"]), row["archived"]) for row in rows] == [
        (archived.agent_id, True),
        (sender.agent_id, False),
    ]
    if policy == "prefer-live":
        mount_policy(env, monkeypatch, include_reads=True)

    body = json.dumps(
        {"to_did": receiver.did_key, "subject": "back again", "body": "hello"}
    ).encode()
    sent = await env.client.post(
        "/v1/messages", content=body, headers=messaging_actor_headers(sender, body=body)
    )
    assert sent.status_code == 200, sent.text
    inbox = await env.client.get("/v1/messages/inbox", headers=messaging_actor_headers(sender))
    assert inbox.status_code == 200, inbox.text
    tasks = await env.client.get("/v1/tasks", headers=messaging_actor_headers(sender))
    assert tasks.status_code == 200, tasks.text
    received = await env.client.get(
        f"/v1/messages/{sent.json()['message_id']}", headers=messaging_actor_headers(receiver)
    )
    assert received.status_code == 200, received.text
    assert received.json()["from_stable_id"] == sender.stable_id
    assert await env.db.fetch_value(
        "SELECT from_agent_id FROM {{tables.messages}} WHERE message_id=$1",
        UUID(sent.json()["message_id"]),
    ) == UUID(sender.agent_id)
