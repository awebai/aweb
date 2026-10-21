"""The remote GrantSource reads real aweb routes through real AWID discovery."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from aweb.app_registry import install_app
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.authorization import (
    DeclaredTools,
    GrantUnavailable,
    authorize_request,
)
from aweb_naapp.runtime.team_auth import Principal
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from awid.did import did_from_public_key
from fastapi import FastAPI, HTTPException, Request
from nacl.signing import SigningKey

TEAM = "backend:grants.example"
IDENTITY = AppIdentity(
    app_id="notebook", origin="https://notebook.example", digest="sha256:" + "a" * 64
)
pytestmark = pytest.mark.asyncio


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


@pytest_asyncio.fixture
async def team_controller(real_stack):
    team_key = await real_stack.add_team(TEAM)
    await real_stack.publish_server(TEAM, team_key)
    return team_key


@pytest_asyncio.fixture
async def installed(real_stack, team_controller):
    db = real_stack.aweb_db
    await install_app(
        db,
        team_id=TEAM,
        app_id=IDENTITY.app_id,
        origin=IDENTITY.origin,
        digest=IDENTITY.digest,
        app_version="1.0",
        manifest_version=2,
        granted_scopes=["notebook:read"],
    )
    key = SigningKey.generate()
    did = did_from_public_key(bytes(key.verify_key))
    # G1-b2b owns deriving this registration from pinned v2 bytes. These tests
    # exercise the reader and the real verifier against that registration.
    await db.execute(
        """INSERT INTO {{tables.team_app_keys}}
           (team_id, app_id, origin, digest, key_id, did_key, purposes)
           VALUES ($1, $2, $3, $4, 'read', $5, $6::TEXT[])""",
        TEAM,
        IDENTITY.app_id,
        IDENTITY.origin,
        IDENTITY.digest,
        did,
        [APP_GRANT_READ],
    )
    clock = Clock()
    signer = AppCredentialSigner(
        app_id=IDENTITY.app_id,
        key=AppKey(kid="read", did_key=did, signing_key=key),
        purpose=APP_GRANT_READ,
    )
    source = TeamGrantSource(
        identity=IDENTITY,
        signer=signer,
        discovery=real_stack.directory(clock=clock),
        transport=real_stack.aweb,
        monotonic=clock,
    )
    return real_stack, source, clock, signer


def change_answer(stack, **fields):
    def fault(request, response):
        body = response.json()
        body.update(fields)
        return httpx.Response(200, json=body)

    stack.aweb.fault = fault


async def test_reads_only_its_own_grant_and_shares_status_cache(installed):
    stack, source, clock, _ = installed
    status = await source.status_for(TEAM)
    grant = await source.grant_for(TEAM)
    assert status.team_id == grant.team_id == TEAM
    assert status.app_id == IDENTITY.app_id
    assert status.digest == IDENTITY.digest
    assert status.origin == IDENTITY.origin
    assert status.state == "active"
    assert status.granted_scopes == grant.scopes == frozenset({"notebook:read"})
    assert status.installation_id is grant.installation_id is None
    assert status.generation is grant.generation is None
    assert status.origin_verified is None
    assert status.fresh_until == grant.fresh_until == clock.now + 60
    assert len(stack.aweb.calls) == 1
    request = stack.aweb.calls[0]
    assert request.url.path == "/v1/apps/self/grant"
    assert request.headers["Authorization"].startswith("AWEB-App-Grant-Read DIDKey ")


@pytest.mark.parametrize(
    "field,value",
    [
        ("team_id", "other:grants.example"),
        ("app_id", "another"),
        ("origin", "https://another.example"),
        ("digest", "sha256:" + "b" * 64),
        ("granted_scopes", "notebook:read"),
        ("granted_scopes", [3]),
        ("state", None),
        ("installation_id", 3),
        ("generation", True),
        ("generation", 0),
        ("generation", 1.0),
        ("origin_verified", 1),
        ("max_age_seconds", True),
        ("max_age_seconds", 0),
        ("max_age_seconds", 1.0),
        ("as_of", "yesterday"),
        ("manifest_version", True),
    ],
)
async def test_malformed_or_wrong_identity_answer_is_unavailable(
    installed, field, value
):
    stack, source, _, _ = installed
    change_answer(stack, **{field: value})
    with pytest.raises(GrantUnavailable):
        await source.status_for(TEAM)
    stack.aweb.fault = None
    assert await source.grant_for(TEAM) is not None  # a failure was not cached


@pytest.mark.parametrize(
    "state", ["pending_origin_verification", "uninstalled", "future_state"]
)
async def test_nonactive_status_is_typed_but_never_grants(installed, state):
    stack, source, _, _ = installed
    change_answer(
        stack,
        state=state,
        installation_id="installation-1",
        generation=8,
        origin_verified=False,
    )
    status = await source.status_for(TEAM)
    assert (status.state, status.installation_id, status.generation) == (
        state,
        "installation-1",
        8,
    )
    assert await source.grant_for(TEAM) is None
    assert len(stack.aweb.calls) == 1


async def test_generation_refresh_and_scope_change_share_one_answer(installed):
    stack, source, clock, _ = installed
    change_answer(stack, installation_id="installation-1", generation=1)
    assert (await source.status_for(TEAM)).generation == 1
    clock.now += 60
    change_answer(
        stack, installation_id="installation-2", generation=2, granted_scopes=[]
    )
    status, grant = await asyncio.gather(
        source.status_for(TEAM), source.grant_for(TEAM)
    )
    assert (status.installation_id, status.generation) == ("installation-2", 2)
    assert (grant.installation_id, grant.generation, grant.scopes) == (
        "installation-2",
        2,
        frozenset(),
    )
    assert len(stack.aweb.calls) == 2


async def test_revoked_key_means_no_grant_without_claiming_uninstall(installed):
    stack, source, _, _ = installed
    await stack.aweb_db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE team_id = $1",
        TEAM,
    )
    assert await source.status_for(TEAM) is None
    assert await source.grant_for(TEAM) is None


async def test_install_retry_refreshes_a_missing_key_denial_after_five_seconds(installed):
    stack, source, clock, _ = installed
    # The key's registry entry alone grants nothing before the team installs.
    await stack.aweb_db.execute(
        "DELETE FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = $2",
        TEAM, IDENTITY.app_id,
    )
    assert await source.grant_for(TEAM) is None
    assert await source.status_for(TEAM) is None
    assert len(stack.aweb.calls) == 1

    await install_app(
        stack.aweb_db,
        team_id=TEAM, app_id=IDENTITY.app_id, origin=IDENTITY.origin,
        digest=IDENTITY.digest, app_version="1.0", manifest_version=2,
        granted_scopes=["notebook:read"],
    )
    clock.now += 4
    assert await source.grant_for(TEAM) is None
    assert len(stack.aweb.calls) == 1

    clock.now += 1
    grant = await source.grant_for(TEAM)
    assert grant is not None
    assert grant.scopes == frozenset({"notebook:read"})
    assert len(stack.aweb.calls) == 2
    assert (await source.status_for(TEAM)).state == "active"
    assert len(stack.aweb.calls) == 2


async def test_expired_grant_never_survives_failed_refresh(installed):
    stack, source, clock, _ = installed
    assert await source.grant_for(TEAM) is not None
    clock.now += 60
    stack.aweb.down = True
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)
    stack.aweb.down = False
    assert await source.grant_for(TEAM) is not None


@pytest.mark.parametrize("status", [301, 307, 401, 403, 404, 429, 500, 503])
async def test_http_failures_are_unavailable_not_empty_grants(installed, status):
    stack, source, _, _ = installed
    stack.aweb.fault = lambda request, response: httpx.Response(
        status,
        headers={"Location": "https://untrusted.example"},
        json={"detail": "another_error"},
    )
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)
    assert len(stack.aweb.calls) == 1  # redirects are never followed


async def test_unpublished_discovery_and_registry_outage_are_unavailable(installed):
    stack, source, _, _ = installed
    await stack.add_team("unpublished:grants.example")
    with pytest.raises(GrantUnavailable):
        await source.grant_for("unpublished:grants.example")
    stack.awid.down = True
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)
    assert not stack.aweb.calls


async def test_bounded_timeout_covers_discovery_and_read(installed):
    stack, _, clock, signer = installed
    source = TeamGrantSource(
        identity=IDENTITY,
        signer=signer,
        discovery=stack.directory(clock=clock),
        transport=stack.aweb,
        monotonic=clock,
        timeout=0.02,
    )
    stack.awid.delay = 0.1
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)
    assert not stack.aweb.calls


async def test_slow_answer_does_not_gain_freshness(installed):
    stack, source, clock, _ = installed

    def slow(request, response):
        clock.now += 4

    stack.aweb.fault = slow
    status = await source.status_for(TEAM)
    assert status.fresh_until == 1060
    assert status.fresh_until - clock.now == 56


async def test_answer_already_expired_on_arrival_is_unavailable(installed):
    stack, source, clock, _ = installed

    def expired(request, response):
        clock.now += 2
        return httpx.Response(200, json={**response.json(), "max_age_seconds": 1})

    stack.aweb.fault = expired
    with pytest.raises(GrantUnavailable):
        await source.status_for(TEAM)


async def test_b1_maps_missing_to_403_and_unavailable_to_503(installed):
    stack, source, clock, _ = installed
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/items",
            "raw_path": b"/items",
            "headers": [],
            "query_string": b"",
        }
    )
    principal = Principal(
        team_id=TEAM,
        did_key="unused",
        did_aw=None,
        address=None,
        alias="member",
        certificate_id="unused",
        team_did_key="unused",
    )
    manifest = load_manifest(
        json.dumps({
            "manifest_version": 1,
            "app": {"id": IDENTITY.app_id, "version": "1.0", "origin": IDENTITY.origin},
            "tools": [
                {
                    "name": "list",
                    "method": "GET",
                    "path": "/items",
                    "scopes": ["notebook:read"],
                }
            ]
        }).encode()
    )
    tools = DeclaredTools.from_manifest(manifest)

    async def allow(*args):
        return True

    async def authorize():
        return await authorize_request(
            request,
            principal=principal,
            caller="agent",
            tools=tools,
            grants=source,
            policy=allow,
            monotonic=clock,
        )

    assert (await authorize()).grant.scopes == frozenset({"notebook:read"})
    clock.now += 60
    stack.aweb.down = True
    with pytest.raises(HTTPException) as refused:
        await authorize()
    assert refused.value.status_code == 503
    stack.aweb.down = False
    await stack.aweb_db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE team_id = $1",
        TEAM,
    )
    with pytest.raises(HTTPException) as refused:
        await authorize()
    assert refused.value.status_code == 403


@pytest.mark.parametrize("purpose", ["app-event", "hook-resolve"])
async def test_another_purpose_is_refused_at_construction(installed, purpose):
    stack, _, _, signer = installed
    other = AppCredentialSigner(app_id=IDENTITY.app_id, key=signer._key, purpose=purpose)
    with pytest.raises(ValueError):
        TeamGrantSource(identity=IDENTITY, signer=other, discovery=stack.directory())
    assert not stack.aweb.calls


@pytest.mark.parametrize("content", [b"not json", b"[]", b"{}", b"x" * ((1 << 20) + 1)])
async def test_malformed_or_oversize_body_fails_closed(installed, content):
    stack, source, _, _ = installed
    stack.aweb.fault = lambda request, response: httpx.Response(200, content=content)
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)


@pytest.mark.parametrize("max_age,window", [(1, 1), (120, 60)])
async def test_server_window_is_honored_and_capped(installed, max_age, window):
    stack, source, clock, _ = installed
    change_answer(stack, max_age_seconds=max_age)
    assert (await source.status_for(TEAM)).fresh_until == clock.now + window
    clock.now += window
    stack.aweb.down = True
    with pytest.raises(GrantUnavailable):
        await source.grant_for(TEAM)


async def test_server_move_discards_cached_grant_and_signs_the_mount_prefix(installed, team_controller):
    stack, _, clock, signer = installed
    source = TeamGrantSource(
        identity=IDENTITY,
        signer=signer,
        discovery=stack.directory(clock=clock, ttl_seconds=0),
        transport=stack.aweb,
        monotonic=clock,
    )
    assert await source.grant_for(TEAM) is not None
    # Move the real app under a prefix; republish through AWID's real route.
    mounted = FastAPI()
    mounted.mount("/api", stack.aweb._inner.app)
    stack.aweb._inner = httpx.ASGITransport(app=mounted)
    await stack.publish_server(
        TEAM,
        team_controller,
        server_url="https://aweb.example/api",
        issued_at=datetime.now(UTC) + timedelta(seconds=1),
    )
    assert await source.grant_for(TEAM) is not None
    assert len(stack.aweb.calls) == 2
    assert stack.aweb.calls[-1].url.path == "/api/v1/apps/self/grant"
    signed = stack.aweb.calls[-1].headers["X-AWEB-Signed-Payload"]

    assert (
        json.loads(base64.urlsafe_b64decode(signed + "=" * (-len(signed) % 4)))["path"]
        == "/api/v1/apps/self/grant"
    )
