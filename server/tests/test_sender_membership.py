"""Read-time sender membership through the real OSS/AWID/PG/Redis apps."""

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from aweb.messaging.sender_membership import sender_memberships
from awid.identity_observation import IdentityKind
from awid.registry import CachedRegistryClient
from messaging_actor_support import admit_privacy_actor
from starlette.requests import Request
from test_cli_never_grants import registry_listener
from test_current_member_review_regressions import _archive_global_member
from test_dashboard_privacy import TEAM, TEAM_NAME, _request, _seed_mail, privacy_app  # noqa: F401
from test_team_room import admit_room_member, headers

__all__ = ["privacy_app"]


_STANDING_VECTOR = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "test-vectors/trust/sender-standing-v1.json"
    ).read_text()
)
_REQUIRED_CASES = {case["id"]: case for case in _STANDING_VECTOR["cases"]}


@pytest.mark.asyncio
async def test_sender_standing_sees_registration_after_a_warm_list(
    privacy_app, monkeypatch
):
    env = privacy_app
    sender, reader = env.actors["alice"], env.actors["bob"]
    certificate = json.loads(base64.b64decode(sender.certificate))
    certificate_id = certificate["certificate_id"]

    async def assert_admission(alias, case):
        response = await env.client.post(
            "/v1/connect", content=b"{}", headers=headers(env.actors[alias], b"{}")
        )
        refusal = case["certificate_refusal"]
        assert response.status_code == (200 if refusal is None else 401), response.text
        if refusal == "revoked":
            assert response.json()["detail"]["code"] == "certificate_revoked"
        elif refusal is not None:
            assert response.json()["detail"] == refusal

    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "false")
    await admit_room_member(env, alias="bob")
    paths = {}
    for alias in ("alice", "carol"):
        actor = env.actors[alias]
        connected = await env.client.post(
            "/v1/connect", content=b"{}", headers=headers(actor, b"{}")
        )
        assert connected.status_code == 200, connected.text
        body = json.dumps(
            {"to_did": reader.did, "subject": "standing", "body": "one message"}
        ).encode()
        sent = await env.client.post(
            "/v1/messages", content=body, headers=headers(actor, body)
        )
        assert sent.status_code == 200, sent.text
        paths[alias] = f"/v1/messages/{sent.json()['message_id']}"
    message_path = paths["alice"]
    initial = await env.client.get(message_path, headers=headers(reader))
    assert initial.status_code == 200, initial.text
    assert initial.json()["sender_membership"] == {
        "team_id": TEAM,
        "member_did_aw": None,
        "state": "active",
    }

    async with registry_listener(env) as (writer, origin):
        cache = CachedRegistryClient(
            origin, env.redis, service_token=writer.service_token
        )
        try:
            before = await cache.list_team_certificates(
                "example.test", TEAM_NAME, active_only=False
            )
            assert {row.certificate_id for row in before} == {"privacy-bob"}
            await writer.register_team_certificate(
                "example.test",
                TEAM_NAME,
                team_controller_signing_key=env.team_sk,
                certificate_id=certificate_id,
                member_did_key=sender.did,
                member_did_aw=None,
                member_address=None,
                alias=certificate["alias"],
                identity_scope="local",
                certificate=sender.certificate,
            )
            still_cached = await cache.list_team_certificates(
                "example.test", TEAM_NAME, active_only=False
            )
            assert still_cached == before
            monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")
            env.app.state.awid_registry_client = cache
            response = await env.client.get(message_path, headers=headers(reader))
            assert response.status_code == 200, response.text
            assert response.json()["sender_membership"] == {
                "team_id": TEAM,
                "member_did_aw": None,
                "state": _REQUIRED_CASES["registered"]["state"],
            }
            await assert_admission("alice", _REQUIRED_CASES["registered"])
            unregistered = await env.client.get(paths["carol"], headers=headers(reader))
            assert unregistered.status_code == 200, unregistered.text
            assert (
                unregistered.json()["sender_membership"]["state"]
                == _REQUIRED_CASES["unregistered"]["state"]
            )
            await assert_admission("carol", _REQUIRED_CASES["unregistered"])

            await writer.revoke_team_certificate(
                "example.test",
                TEAM_NAME,
                team_controller_signing_key=env.team_sk,
                certificate_id=certificate_id,
            )
            env.app.state.awid_registry_client = writer
            revoked = await env.client.get(message_path, headers=headers(reader))
            assert revoked.status_code == 200, revoked.text
            assert (
                revoked.json()["sender_membership"]["state"]
                == _REQUIRED_CASES["revoked"]["state"]
            )
            await assert_admission("alice", _REQUIRED_CASES["revoked"])
        finally:
            env.app.state.awid_registry_client = writer
            await cache.aclose()


@pytest.mark.asyncio
async def test_sender_membership_mail_and_chat_is_current_and_participant_scoped(
    privacy_app,
):
    env = privacy_app
    sender = await admit_privacy_actor(env, "alice", kind=IdentityKind.HUMAN)
    stable_id = sender.stable_id
    await admit_privacy_actor(env, "bob", local=True)
    mail_id = await _seed_mail(env)
    chat = await _request(
        env,
        "alice",
        "POST",
        "/v1/chat/sessions",
        {
            "to_dids": [env.actors["bob"].did],
            "message": "membership control",
        },
    )
    assert chat.status_code == 200, chat.text
    paths = [
        f"/v1/messages/{mail_id}",
        f"/v1/chat/sessions/{chat.json()['session_id']}/messages",
    ]
    for state in ("active", "inactive"):
        if state == "inactive":
            await _archive_global_member(env, sender)
        for path in paths:
            response = await _request(env, "bob", "GET", path)
            assert response.status_code == 200, response.text
            data = response.json()
            message = data["messages"][0] if "messages" in data else data
            assert message["sender_membership"] == {
                "team_id": TEAM,
                "member_did_aw": stable_id,
                "state": state,
            }
    query = urlencode(
        {
            "after": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "deadline": (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat(),
        }
    )
    streamed = await _request(
        env,
        "bob",
        "GET",
        f"/v1/chat/sessions/{chat.json()['session_id']}/stream?{query}",
    )
    assert streamed.status_code == 200, streamed.text
    events = [
        json.loads(line[6:])
        for line in streamed.text.splitlines()
        if line.startswith("data: ")
    ]
    message = next(event for event in events if event.get("type") == "message")
    assert message["sender_membership"]["state"] == "inactive"
    assert message["sender_membership"]["member_did_aw"] == stable_id
    for path in paths:
        response = await _request(env, "carol", "GET", path)
        assert response.status_code in (403, 404)


@pytest.mark.asyncio
async def test_sender_membership_revocation_without_archiving(privacy_app):
    env = privacy_app
    sender = await admit_privacy_actor(env, "alice", local=True)
    await admit_privacy_actor(env, "bob", local=True)
    mail_id = await _seed_mail(env)
    certificate_id = json.loads(base64.b64decode(sender.certificate))["certificate_id"]
    await env.app.state.awid_registry_client.revoke_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate_id,
    )
    response = await _request(env, "bob", "GET", f"/v1/messages/{mail_id}")
    assert response.status_code == 200, response.text
    assert response.json()["sender_membership"]["state"] == "inactive"


@pytest.mark.asyncio
async def test_missing_sender_certificate_provenance_is_unknown(privacy_app):
    env = privacy_app
    sender = await admit_privacy_actor(env, "alice", local=True)
    row = await env.db.fetch_one(
        """SELECT a.agent_id, a.team_id, a.did_aw, a.status, a.deleted_at,
                  a.accepted_team_did_key, t.team_did_key AS current_team_did_key
           FROM {{tables.agents}} AS a JOIN {{tables.teams}} AS t ON t.team_id=a.team_id
           WHERE a.agent_id=$1""",
        sender.id,
    )
    evidence = dict(row, certificate_id=None)
    key = (TEAM, str(sender.id))
    projected = await sender_memberships(
        Request({"type": "http", "app": env.app}),
        env.infra,
        [{"team_id": TEAM, "from_agent_id": sender.id}],
        member_rows=[evidence],
    )
    assert projected[key].state == "unknown"
