"""A member is a member under the team's current key.

The server records, for each member, the team key under which it last accepted
that member's certificate, and refuses the member wherever it is looked up when
that key is not the team's current key (the admitted pin). Rotation goes
through the real AWID route with a namespace-controller act; every request goes
through the real server.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.requests import Request
from aweb.member_team_key import read_member_projection

from aweb.application_state import application_registry_client
from aweb.member_team_key import current_membership
from aweb.messaging.delivery_policy import has_current_shared_team
from aweb.messaging.participants import messaging_participants_by_aliases
from aweb.messaging.sender_membership import sender_memberships
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)
from test_team_key_pinning import (
    _substitute_registry_team_key,
    pinning as pinning,
    register_namespace_controller,
    rotate_team_key,
)  # noqa: F401

__all__ = ["pinning"]

MIGRATIONS = (
    Path(__file__).resolve().parents[1] / "src" / "aweb" / "migrations" / "aweb"
)


def _certificate(team_sk, team_did, member, certificate_id):
    sk, did, alias = member
    return _encode_certificate(
        _make_certificate(
            team_sk,
            team_did,
            did,
            team_id=TEAM,
            alias=alias,
            identity_scope="local",
            certificate_id=certificate_id,
        )
    )


def _new_member(alias):
    sk, _, did = _make_keypair()
    return sk, did, alias


async def _connect(env, member, certificate):
    sk, did, _ = member
    body = json.dumps(
        {
            "hostname": "host",
            "workspace_path": f"/work/{did[-8:]}",
            "repo_origin": "",
            "role": "developer",
            "human_name": "member",
            "agent_type": "agent",
        }
    ).encode()
    headers = _signed_team_headers(sk, did, TEAM, certificate, body)
    headers["Content-Type"] = "application/json"
    response = await env.client.post("/v1/connect", content=body, headers=headers)
    return response


async def _roster(env, member, certificate):
    sk, did, _ = member
    return await env.client.get(
        "/v1/agents", headers=_signed_team_headers(sk, did, TEAM, certificate)
    )


async def _row(env, member):
    return await env.db.fetch_one(
        "SELECT agent_id, certificate_id, accepted_team_did_key FROM {{tables.agents}} "
        "WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL",
        TEAM,
        member[1],
    )


async def _identity_membership(env, member):
    row = await read_member_projection(env.db, team_id=TEAM, did_key=member[1])
    return await current_membership(env.app.state.awid_registry_client, row)


async def _change_key(env):
    """Rotate the team key with the controller's act, and let the server
    admit it: a member reissued under the new key connects."""
    await register_namespace_controller(env, env.namespace_did)
    next_sk, _, next_did = _make_keypair()
    await rotate_team_key(env, env.namespace_sk, env.namespace_did, next_did)
    reissued = _new_member("reissued")
    connected = await _connect(
        env, reissued, _certificate(next_sk, next_did, reissued, "after-change")
    )
    assert connected.status_code == 200, connected.text
    pin = await env.db.fetch_value(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1", TEAM
    )
    assert pin == next_did
    return next_sk, next_did


async def _mint_grant(env, member, certificate):
    sk, did, _ = member
    session_sk, session_did = _session_keypair()
    body = json.dumps(
        {"grant_did_key": session_did, "scopes": ["mail.read"], "ttl_seconds": 600}
    ).encode()
    headers = _signed_team_headers(sk, did, TEAM, certificate, body)
    headers["Content-Type"] = "application/json"
    minted = await env.client.post("/v1/identity-grants", content=body, headers=headers)
    assert minted.status_code == 200, minted.text
    return session_sk, session_did, minted.json()["grant_id"]


async def _use_grant(env, grant):
    session_sk, session_did, grant_id = grant
    return await env.client.get(
        "/v1/messages/inbox",
        headers=_grant_headers(
            signing_key=session_sk,
            did_key=session_did,
            grant_id=grant_id,
            method="GET",
            path="/v1/messages/inbox",
            aud=env.app.state.public_origin,
        ),
    )


# --- Every writer records the key -------------------------------------------


@pytest.mark.asyncio
async def test_connect_records_the_team_key_it_accepted_the_certificate_under(pinning):
    env = pinning
    member = _new_member("writer")

    connected = await _connect(
        env, member, _certificate(env.team_sk, env.team_did, member, "writer-1")
    )

    assert connected.status_code == 200, connected.text
    row = await _row(env, member)
    assert (row["certificate_id"], row["accepted_team_did_key"]) == (
        "writer-1",
        env.team_did,
    )


@pytest.mark.asyncio
async def test_a_request_under_a_new_key_records_it_even_with_the_same_certificate_id(
    pinning,
):
    env = pinning
    member = _new_member("sameid")
    assert (
        await _connect(
            env, member, _certificate(env.team_sk, env.team_did, member, "same-id")
        )
    ).status_code == 200
    next_sk, next_did = await _change_key(env)

    roster = await _roster(
        env, member, _certificate(next_sk, next_did, member, "same-id")
    )

    assert roster.status_code == 200, roster.text
    row = await _row(env, member)
    assert (row["certificate_id"], row["accepted_team_did_key"]) == (
        "same-id",
        next_did,
    )


@pytest.mark.asyncio
async def test_the_fill_records_the_pin_for_every_existing_member_and_they_keep_passing(
    pinning,
):
    env = pinning
    member = _new_member("existing")
    assert (
        await _connect(
            env, member, _certificate(env.team_sk, env.team_did, member, "existing-1")
        )
    ).status_code == 200
    alice = env.actors["alice"]
    without_certificate = (alice.sk, alice.did, "alice")
    # As every member row stood before the key was recorded, with or without a certificate.
    await env.db.execute(
        "UPDATE {{tables.agents}} SET accepted_team_did_key = NULL WHERE did_key = ANY($1::text[])",
        [member[1], alice.did],
    )
    [fill] = MIGRATIONS.glob("*_member_accepted_team_key.sql")

    await env.db.execute(fill.read_text())

    for each in (member, without_certificate):
        assert (await _row(env, each))["accepted_team_did_key"] == env.team_did
        assert (await _identity_membership(env, each))["team_id"] == TEAM


@pytest.mark.asyncio
async def test_a_member_row_written_without_the_key_takes_the_teams_key_of_that_moment(
    pinning,
):
    env = pinning
    did = _make_keypair()[2]

    await env.db.execute(
        "INSERT INTO {{tables.agents}} (team_id, did_key, alias, identity_scope, inbound_mode) VALUES ($1, $2, 'written', 'local', 'open')",
        TEAM,
        did,
    )

    assert (
        await env.db.fetch_value(
            "SELECT accepted_team_did_key FROM {{tables.agents}} WHERE did_key = $1",
            did,
        )
        == env.team_did
    )


# --- A member under the current key passes; under a superseded key it is refused


@pytest.mark.asyncio
async def test_a_superseded_certificate_is_refused_with_its_own_code(pinning):
    env = pinning
    member = _new_member("stale")
    certificate = _certificate(env.team_sk, env.team_did, member, "stale-1")
    assert (await _connect(env, member, certificate)).status_code == 200
    await _change_key(env)

    roster = await _roster(env, member, certificate)

    assert roster.status_code == 401, roster.text
    assert roster.json()["detail"]["code"] == "team_key_not_current"


@pytest.mark.asyncio
async def test_identity_only_membership_ends_with_the_key_and_returns_with_a_new_certificate(
    pinning,
):
    env = pinning
    member = _new_member("identity")
    assert (
        await _connect(
            env, member, _certificate(env.team_sk, env.team_did, member, "identity-1")
        )
    ).status_code == 200
    assert (await _identity_membership(env, member))["team_id"] == TEAM

    next_sk, next_did = await _change_key(env)
    assert (await _identity_membership(env, member))["team_id"] is None

    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "identity-2")
        )
    ).status_code == 200
    assert (await _identity_membership(env, member))["team_id"] == TEAM


@pytest.mark.asyncio
async def test_a_grant_ends_with_its_issuing_certificate_and_does_not_return(pinning):
    env = pinning
    member = _new_member("granter")
    certificate = _certificate(env.team_sk, env.team_did, member, "granter-1")
    assert (await _connect(env, member, certificate)).status_code == 200
    grant = await _mint_grant(env, member, certificate)
    assert (await _use_grant(env, grant)).status_code == 200

    next_sk, next_did = await _change_key(env)
    refused = await _use_grant(env, grant)
    assert refused.status_code == 403, refused.text
    assert (
        refused.json()["detail"]
        == "grant issuing certificate revoked. This grant was issued from a certificate that is no longer current. Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
    )

    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "granter-2")
        )
    ).status_code == 200
    assert (await _use_grant(env, grant)).status_code == 403
    assert (
        await _use_grant(
            env,
            await _mint_grant(
                env,
                member,
                _certificate(next_sk, next_did, member, "granter-2"),
            ),
        )
    ).status_code == 200


@pytest.mark.asyncio
async def test_a_grant_status_reports_the_superseded_issuer(pinning):
    env = pinning
    member = _new_member("status")
    certificate = _certificate(env.team_sk, env.team_did, member, "status-1")
    assert (await _connect(env, member, certificate)).status_code == 200
    _, _, grant_id = await _mint_grant(env, member, certificate)
    next_sk, next_did = await _change_key(env)
    current = _certificate(next_sk, next_did, member, "status-2")
    assert (await _connect(env, member, current)).status_code == 200

    shown = await env.client.get(
        f"/v1/identity-grants/{grant_id}/status",
        headers=_signed_team_headers(member[0], member[1], TEAM, current),
    )

    assert shown.status_code == 200, shown.text
    assert shown.json()["effective_status"] == "issuer_revoked"


@pytest.mark.asyncio
async def test_sender_membership_is_inactive_under_a_superseded_key(pinning):
    env = pinning
    member = _new_member("sender")
    assert (
        await _connect(
            env, member, _certificate(env.team_sk, env.team_did, member, "sender-1")
        )
    ).status_code == 200
    agent_id = str((await _row(env, member))["agent_id"])
    rows = [{"team_id": TEAM, "from_agent_id": agent_id}]
    request = Request({"type": "http", "app": env.app, "headers": []})
    assert (await sender_memberships(request, env.infra, rows))[
        (TEAM, agent_id)
    ].state == "active"

    await _change_key(env)

    assert (await sender_memberships(request, env.infra, rows))[
        (TEAM, agent_id)
    ].state == "inactive"


@pytest.mark.asyncio
async def test_participants_resolve_only_members_under_the_current_key(pinning):
    env = pinning
    member = _new_member("participant")
    assert (
        await _connect(
            env,
            member,
            _certificate(env.team_sk, env.team_did, member, "participant-1"),
        )
    ).status_code == 200

    async def resolved():
        rows = await messaging_participants_by_aliases(
            env.infra,
            team_id=TEAM,
            aliases=["participant"],
            selected_team_id=TEAM,
            registry_client=env.app.state.awid_registry_client,
        )
        return [row["alias"] for row in rows]

    assert await resolved() == ["participant"]
    await _change_key(env)
    assert await resolved() == []


@pytest.mark.asyncio
async def test_same_team_delivery_needs_the_sender_under_the_current_key(pinning):
    env = pinning
    sender = _new_member("teamsender")
    recipient = _new_member("teamrecipient")
    for member, cert_id in ((sender, "teamsender-1"), (recipient, "teamrecipient-1")):
        assert (
            await _connect(
                env, member, _certificate(env.team_sk, env.team_did, member, cert_id)
            )
        ).status_code == 200

    async def same_team():
        return await has_current_shared_team(
            env.infra,
            registry_client=application_registry_client(env.app.state),
            recipient={"did_key": recipient[1]},
            sender_dids=[sender[1]],
        )

    assert await same_team()
    next_sk, next_did = await _change_key(env)
    assert (
        await _connect(
            env,
            recipient,
            _certificate(next_sk, next_did, recipient, "teamrecipient-2"),
        )
    ).status_code == 200
    assert not await same_team()


@pytest.mark.asyncio
async def test_a_member_row_written_with_a_certificate_but_no_key_is_not_a_member(
    pinning,
):
    env = pinning
    sk, _, did = _make_keypair()
    member = (sk, did, "unverified")

    # Nothing verified this certificate under the team's key, so no key is recorded for it.
    await env.db.execute(
        "INSERT INTO {{tables.agents}} (team_id, did_key, alias, identity_scope, certificate_id, inbound_mode) "
        "VALUES ($1, $2, 'unverified', 'local', 'unverified-1', 'open')",
        TEAM,
        did,
    )

    assert (await _row(env, member))["accepted_team_did_key"] is None
    assert (await _identity_membership(env, member))["team_id"] is None


@pytest.mark.asyncio
async def test_a_member_without_a_certificate_on_file_is_a_member_until_the_key_changes(
    pinning,
):
    env = pinning
    alice = env.actors["alice"]
    member = (alice.sk, alice.did, "alice")
    assert (await _row(env, member))["certificate_id"] is None
    assert (await _identity_membership(env, member))["team_id"] == TEAM

    next_sk, next_did = await _change_key(env)
    assert (await _identity_membership(env, member))["team_id"] is None

    assert (
        await _connect(
            env, member, _certificate(next_sk, next_did, member, "alice-after")
        )
    ).status_code == 200
    assert (await _identity_membership(env, member))["team_id"] == TEAM


@pytest.mark.asyncio
async def test_before_enforcement_a_member_under_the_registrys_key_keeps_its_grant_and_team_context(
    pinning, monkeypatch
):
    env = pinning
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "false")
    await register_namespace_controller(env, env.namespace_did)
    served_sk, _, served_did = _make_keypair()
    # The registry serves another key with no namespace-controller act.
    await _substitute_registry_team_key(env, served_did)
    member = _new_member("tolerated")
    certificate = _certificate(served_sk, served_did, member, "tolerated-1")

    assert (await _connect(env, member, certificate)).status_code == 200
    grant = await _mint_grant(env, member, certificate)

    assert (await _use_grant(env, grant)).status_code == 200
    assert (await _identity_membership(env, member))["team_id"] == TEAM
    assert (
        await env.db.fetch_value(
            "SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1", TEAM
        )
        == served_did
    )
