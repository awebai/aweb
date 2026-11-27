"""Signed reads of a private team: the covering read_team envelope and the
measured path signature, through AWID, real PostgreSQL and real Redis."""

from __future__ import annotations

import logging

import pytest
from awid.controller_request import (
    COVERING_CONTROLLER_AUTH_EVENT,
    LEGACY_CONTROLLER_AUTH_EVENT,
    MAX_TRACKED_AW_VERSIONS,
    PATH_SIGNED_READ_EVENT,
    client_family,
)
from awid.registry_auth import path_signature_headers
from conftest import (
    controller_keypair as keypair,
)
from conftest import (
    controller_request_headers as headers,
)
from conftest import (
    send_controller_request as send,
)
from test_controller_request_v2_http import certificate_body

TEAM = "/v1/namespaces/local/teams/base"


async def _private_team(env):
    """Make the fixture's team private with one active and one revoked member."""
    changed = await send(
        env,
        "POST",
        TEAM + "/visibility",
        {
            "domain": "local",
            "team_name": "base",
            "operation": "set_team_visibility",
            "visibility": "private",
        },
        {"visibility": "private"},
        signer=env.team,
    )
    assert changed.status_code == 200, changed.text
    members = {}
    for alias in ("member", "gone"):
        member = keypair()
        body = certificate_body(env, alias=alias, member=member)
        claims = {
            "domain": "local",
            "team_name": "base",
            "operation": "register_certificate",
            "certificate_id": body["certificate_id"],
        }
        registered = await send(
            env, "POST", TEAM + "/certificates", claims, body, signer=env.team
        )
        assert registered.status_code == 200, registered.text
        members[alias] = (member, body["certificate_id"])
    gone_id = members["gone"][1]
    revoked = await send(
        env,
        "POST",
        TEAM + "/certificates/revoke",
        {
            "domain": "local",
            "team_name": "base",
            "operation": "revoke_certificate",
            "certificate_id": gone_id,
        },
        {"certificate_id": gone_id},
        signer=env.team,
    )
    assert revoked.status_code == 200, revoked.text
    return members


def _routes(members, reader):
    """Every gated team read, with the claims its covering envelope carries.

    The single certificate fetch reads the reader's own certificate: only the
    certificate's member may fetch its blob.
    """
    team_claims = {"domain": "local", "name": "base", "operation": "read_team"}
    return [
        ("/v1/namespaces/local/teams", {"domain": "local", "operation": "read_team"}),
        (TEAM, team_claims),
        (TEAM + "/members/member", team_claims),
        (TEAM + "/certificates?active_only=true", team_claims),
        (TEAM + "/revocations", team_claims),
        (TEAM + "/certificates/" + members[reader][1], team_claims),
    ]


def _signed(form, signer, path, claims, **kwargs):
    key, did = signer
    if form == "covering":
        return headers(key, did, claims, "GET", path, **kwargs)
    return path_signature_headers("GET", path.partition("?")[0], key)


def _counted(env, event, operation):
    counts = getattr(env.app.state, "controller_auth_counts", {})
    return sum(n for (e, o, _), n in counts.items() if (e, o) == (event, operation))


def _lists_base(response):
    return any(team["name"] == "base" for team in response.json()["teams"])


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["covering", "path"])
async def test_member_key_reads_every_gated_route(controller_app, form):
    env = controller_app
    members = await _private_team(env)
    event = (
        COVERING_CONTROLLER_AUTH_EVENT if form == "covering" else PATH_SIGNED_READ_EVENT
    )
    for path, claims in _routes(members, "member"):
        before = _counted(env, event, "read_team")
        response = await env.client.get(
            path, headers=_signed(form, members["member"][0], path, claims)
        )
        assert response.status_code == 200, (path, response.text)
        assert _counted(env, event, "read_team") == before + 1, path
        if path.endswith("/teams"):
            assert _lists_base(response)


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["covering", "path"])
async def test_revoked_member_key_is_refused_on_every_gated_route(controller_app, form):
    env = controller_app
    members = await _private_team(env)
    for path, claims in _routes(members, "gone"):
        response = await env.client.get(
            path, headers=_signed(form, members["gone"][0], path, claims)
        )
        if path.endswith("/teams"):
            assert response.status_code == 200, response.text
            assert not _lists_base(response)
        elif "/certificates/" in path:
            assert response.status_code == 409, (path, response.text)
        else:
            assert response.status_code == 403, (path, response.text)
            assert response.json()["detail"]["code"] == "team_private"


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["covering", "path"])
async def test_team_key_reads_and_stranger_key_is_refused(controller_app, form):
    env = controller_app
    members = await _private_team(env)
    stranger = keypair()
    for path, claims in _routes(members, "member")[:5]:
        response = await env.client.get(
            path, headers=_signed(form, env.team, path, claims)
        )
        assert response.status_code == 200, (path, response.text)
        response = await env.client.get(
            path, headers=_signed(form, stranger, path, claims)
        )
        if path.endswith("/teams"):
            assert response.status_code == 200 and not _lists_base(response), (
                response.text
            )
        else:
            assert response.status_code == 403, (path, response.text)
    fetch, claims = _routes(members, "member")[5]
    response = await env.client.get(
        fetch, headers=_signed(form, env.team, fetch, claims)
    )
    assert response.status_code == 403, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims_change",
    [
        {"name": "other"},
        {"domain": "elsewhere"},
        {"operation": "register_certificate"},
        {"name": None},
    ],
)
async def test_covering_read_claims_must_match_the_route(controller_app, claims_change):
    env = controller_app
    members = await _private_team(env)
    path = TEAM + "/members/member"
    claims = {
        "domain": "local",
        "name": "base",
        "operation": "read_team",
        **claims_change,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    response = await env.client.get(
        path, headers=_signed("covering", members["member"][0], path, claims)
    )
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_covering_read_is_bound_to_its_route(controller_app):
    env = controller_app
    members = await _private_team(env)
    claims = {"domain": "local", "name": "base", "operation": "read_team"}
    signed = _signed("covering", members["member"][0], TEAM + "/members/member", claims)
    response = await env.client.get(TEAM + "/revocations", headers=signed)
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_covering_read_is_bound_to_its_query(controller_app):
    env = controller_app
    members = await _private_team(env)
    claims = {"domain": "local", "name": "base", "operation": "read_team"}
    signed = _signed(
        "covering",
        members["member"][0],
        TEAM + "/certificates?active_only=true",
        claims,
    )
    for changed in (
        TEAM + "/certificates?active_only=false",
        TEAM + "/certificates",
        TEAM + "/certificates?active_only=true&limit=1",
    ):
        response = await env.client.get(changed, headers=signed)
        assert response.status_code == 401, (changed, response.text)
    response = await env.client.get(
        TEAM + "/certificates?active_only=true", headers=signed
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_path_signed_read_does_not_bind_its_query(controller_app):
    """The measured path-signature form is accepted with a changed query; the
    covering form exists to close this."""
    env = controller_app
    members = await _private_team(env)
    signed = path_signature_headers(
        "GET", TEAM + "/certificates", members["member"][0][0]
    )
    response = await env.client.get(
        TEAM + "/certificates?active_only=false", headers=signed
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_covering_read_names_this_registry(controller_app):
    env = controller_app
    members = await _private_team(env)
    path = TEAM + "/members/member"
    claims = {"domain": "local", "name": "base", "operation": "read_team"}
    signed = _signed(
        "covering",
        members["member"][0],
        path,
        claims,
        overrides={"aud": "https://registry.example.com"},
    )
    response = await env.client.get(path, headers=signed)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "AWID controller audience is not allowed"


@pytest.mark.asyncio
async def test_invalid_signed_read_is_refused_not_read_anonymously(controller_app):
    env = controller_app
    members = await _private_team(env)
    path = "/v1/namespaces/local/teams"
    claims = {"domain": "local", "operation": "read_team"}
    signed = _signed("covering", members["member"][0], path, claims)
    signed["Authorization"] = signed["Authorization"][:-4] + "AAAA"
    response = await env.client.get(path, headers=signed)
    assert response.status_code == 401, response.text
    unsigned_envelope = {
        k: v
        for k, v in _signed("covering", members["member"][0], path, claims).items()
        if k != "Authorization"
    }
    response = await env.client.get(path, headers=unsigned_envelope)
    assert response.status_code == 401, response.text


def test_client_family_is_one_of_three_and_never_the_raw_user_agent():
    assert client_family("aw/1.36.58 (darwin/arm64)") == "aw/1.36.58"
    assert client_family("aw/1.36.59-rc.2 (linux/amd64)") == "aw/1.36.59-rc.2"
    assert client_family("python-httpx/0.28.1") == "python-httpx"
    for other in (
        None,
        "",
        "curl/8.0",
        "aw/dev",
        "aw/1.2.3",
        "aw/1.2.3 trailing",
        "aw/1.2.3 (linux/amd64) extra",
        "aw/1.2.3\n(linux/amd64)",
        "Mozilla/5.0 aw/1.2.3",
        "aw/" + "1" * 40 + ".0.0",
    ):
        assert client_family(other) == "other", other


@pytest.mark.asyncio
async def test_accepted_auth_is_logged_by_form_operation_and_client(
    controller_app, caplog
):
    env = controller_app
    members = await _private_team(env)
    caplog.set_level(logging.INFO, logger="awid.controller_request")
    agent = {"User-Agent": "aw/9.8.7 (plan9/arm)"}
    legacy = await env.client.post(
        "/v1/namespaces/local/teams",
        content=b'{"name":"logged","team_did_key":"' + keypair()[1].encode() + b'"}',
        headers={
            **headers(
                *env.controller,
                {"domain": "local", "operation": "create_team", "name": "logged"},
                "POST",
                "/v1/namespaces/local/teams",
                covering=False,
            ),
            "Content-Type": "application/json",
            **agent,
        },
    )
    assert legacy.status_code == 200, legacy.text
    path = TEAM + "/members/member"
    claims = {"domain": "local", "name": "base", "operation": "read_team"}
    covering = await env.client.get(
        path,
        headers={**_signed("covering", members["member"][0], path, claims), **agent},
    )
    assert covering.status_code == 200, covering.text
    signed = await env.client.get(
        path,
        headers={
            **_signed("path", members["member"][0], path, claims),
            "User-Agent": "python-httpx/0.28.1",
        },
    )
    assert signed.status_code == 200, signed.text
    lines = [r.getMessage() for r in caplog.records]
    assert (
        f"event={LEGACY_CONTROLLER_AUTH_EVENT} metric={LEGACY_CONTROLLER_AUTH_EVENT} value=1 operation=create_team client=aw/9.8.7 form=legacy"
        in lines
    )
    assert (
        f"event={COVERING_CONTROLLER_AUTH_EVENT} metric={COVERING_CONTROLLER_AUTH_EVENT} value=1 operation=read_team client=aw/9.8.7 form=covering"
        in lines
    )
    assert (
        f"event={PATH_SIGNED_READ_EVENT} metric={PATH_SIGNED_READ_EVENT} value=1 operation=read_team client=python-httpx form=path"
        in lines
    )
    assert not any("plan9" in line for line in lines)


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["covering", "path"])
async def test_signed_records_read_only_by_the_team_key_in_both_forms(
    controller_app, form
):
    """Every refusal on this route is the same 404, including a proof that does
    not verify."""
    env = controller_app
    members = await _private_team(env)
    path = TEAM + "/signed-records?limit=5"
    claims = {"domain": "local", "name": "base", "operation": "read_team"}
    response = await env.client.get(path, headers=_signed(form, env.team, path, claims))
    assert response.status_code == 200, response.text
    for reader in ("member", "gone"):
        response = await env.client.get(
            path, headers=_signed(form, members[reader][0], path, claims)
        )
        assert response.status_code == 404, (reader, response.text)
    if form == "covering":
        changed = await env.client.get(
            TEAM + "/signed-records?limit=6",
            headers=_signed(form, env.team, path, claims),
        )
        assert changed.status_code == 404, changed.text
        elsewhere = _signed(
            form,
            env.team,
            path,
            claims,
            overrides={"aud": "https://registry.example.com"},
        )
        response = await env.client.get(path, headers=elsewhere)
        assert response.status_code == 404, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["covering", "path"])
async def test_distinct_aw_versions_tracked_are_bounded(controller_app, form):
    """Any fresh key may sign a team list read (it sees public teams), so the
    per-client counter must not grow with each new aw version a caller claims."""
    env = controller_app
    path = "/v1/namespaces/local/teams"
    claims = {"domain": "local", "operation": "read_team"}
    for n in range(MAX_TRACKED_AW_VERSIONS + 20):
        agent = {"User-Agent": f"aw/0.0.{n} (linux/amd64)"}
        response = await env.client.get(
            path, headers={**_signed(form, keypair(), path, claims), **agent}
        )
        assert response.status_code == 200, response.text
    versions = {
        client
        for (_, _, client) in env.app.state.controller_auth_counts
        if client.startswith("aw/")
    }
    assert len(versions - {"aw/other"}) == MAX_TRACKED_AW_VERSIONS
    event = (
        COVERING_CONTROLLER_AUTH_EVENT if form == "covering" else PATH_SIGNED_READ_EVENT
    )
    assert env.app.state.controller_auth_counts[(event, "read_team", "aw/other")] == 20
    size = len(env.app.state.controller_auth_counts)
    response = await env.client.get(
        path,
        headers={
            **_signed(form, keypair(), path, claims),
            "User-Agent": "aw/9.9.9 (linux/amd64)",
        },
    )
    assert response.status_code == 200, response.text
    assert len(env.app.state.controller_auth_counts) == size
