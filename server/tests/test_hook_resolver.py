"""The naapp HookResolver against this server's real routes, reached through real discovery.

Bindings are written by the install path's own writer and made active through
the row values a real owner activation must satisfy (owner activation is not
built yet). A response is changed only after the real handler produced it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.app_credentials import HOOK_RESOLVE
from aweb.app_registry import install_app
from aweb.hook_bindings import PRODUCTION, REGISTRATION, HookBindingDeclaration, write_pending_bindings
from aweb_naapp.runtime.app_credentials import AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.hook_resolver import (
    HookBindingRequired,
    HookResolutionUnavailable,
    HookResolver,
)
from tests.real_stack import AWEB_URL

TEAM = "backend:resolve.example"
HOOK = ("aweb.hooks", 1, "post-secret-use-hook")
LOGS = {"app_id": "logs", "origin": "https://logs.example", "digest": "sha256:" + "1" * 64}
SECRETS = {"app_id": "secrets", "origin": "https://secrets.example", "digest": "sha256:" + "2" * 64}
INGEST = HookBindingDeclaration(
    kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK[2],
    tool="ingest", method="POST", path="/hooks/ingest", scopes=("logs:ingest",),
)
SECRET_USE = HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK[2])


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def _install(db, app: dict, installation_id: str, declarations) -> dict:
    await install_app(
        db, team_id=TEAM, app_id=app["app_id"], origin=app["origin"], app_version="1.0.0",
        manifest_version=2, digest=app["digest"], granted_scopes=[],
    )
    async with db.transaction() as tx:
        written = await write_pending_bindings(
            tx, team_id=TEAM, app_id=app["app_id"], origin=app["origin"], digest=app["digest"],
            installation_id=installation_id, generation=1, declarations=list(declarations),
        )
    return {binding.kind: binding for binding in written}


async def _activate(db, binding_id: UUID) -> None:
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'active', activated_at = date_trunc('milliseconds', NOW()),
            active_from = date_trunc('milliseconds', NOW()) + INTERVAL '60 seconds',
            activation_act_sha256 = $2
        WHERE binding_id = $1
        """,
        binding_id, "ab" * 32,
    )


async def _key(db, app: dict, *, kid: str, purposes: list[str]) -> AppKey:
    signing_key = SigningKey.generate()
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    await db.execute(
        """
        INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
        VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[])
        """,
        TEAM, app["app_id"], app["origin"], app["digest"], kid, did_key, purposes,
    )
    return AppKey(kid=kid, did_key=did_key, signing_key=signing_key)


@pytest_asyncio.fixture
async def team(real_stack):
    team_key = await real_stack.add_team(TEAM)
    await real_stack.publish_server(TEAM, team_key)
    db = real_stack.aweb_db
    logs = await _install(db, LOGS, "inst-logs", [INGEST])
    secrets = await _install(db, SECRETS, "inst-secrets", [SECRET_USE])
    await _activate(db, logs[REGISTRATION].binding_id)
    await _activate(db, secrets[PRODUCTION].binding_id)
    clock = Clock()

    async def resolver_for(
        app: dict, *, refresh_timeout: float = 5.0, directory_ttl: int | None = None
    ) -> HookResolver:
        key = await _key(db, app, kid=f"resolve-{app['app_id']}", purposes=[HOOK_RESOLVE])
        return HookResolver(
            directory=real_stack.directory(clock=clock, ttl_seconds=directory_ttl),
            signer=AppCredentialSigner(app_id=app["app_id"], key=key, purpose=HOOK_RESOLVE),
            app_origin=app["origin"],
            transport=real_stack.aweb,
            refresh_timeout=refresh_timeout,
            monotonic=clock,
        )

    return {
        "stack": real_stack, "db": db, "clock": clock, "resolver_for": resolver_for,
        "team_key": team_key, "registration": logs[REGISTRATION], "production": secrets[PRODUCTION],
    }


def _aweb_calls(team) -> int:
    return len(team["stack"].aweb.calls)


@pytest.mark.asyncio
async def test_a_producer_resolves_where_to_deliver(team):
    resolver = await team["resolver_for"](SECRETS)
    resolution = await resolver.registrations(TEAM, *HOOK)
    [binding] = resolution.items
    registration = team["registration"]
    assert binding.binding_id == registration.binding_id
    assert (binding.kind, binding.app_id, binding.installation_id, binding.generation) == (
        "registration", "logs", "inst-logs", 1,
    )
    assert (binding.origin, binding.method, binding.path, binding.digest) == (
        LOGS["origin"], "POST", "/hooks/ingest", LOGS["digest"],
    )
    stored = await team["db"].fetch_value(
        "SELECT active_from FROM {{tables.app_hook_bindings}} WHERE binding_id = $1", registration.binding_id
    )
    assert binding.active_from == stored
    assert resolution.server_url == AWEB_URL
    assert resolution.fresh_until == team["clock"].now + 60


@pytest.mark.asyncio
async def test_a_target_resolves_who_may_produce_and_with_which_keys(team):
    await _key(team["db"], SECRETS, kid="hook-1", purposes=["hook-delivery", "hook-event"])
    await _key(team["db"], SECRETS, kid="emit-1", purposes=["app-event"])
    resolver = await team["resolver_for"](LOGS)
    [production] = (await resolver.productions(TEAM, *HOOK)).items
    assert production.app_id == "secrets"
    assert [(key.kid, key.purposes) for key in production.keys] == [("hook-1", ("hook-delivery", "hook-event"))]


@pytest.mark.asyncio
async def test_own_bindings_are_read_in_every_state(team):
    resolver = await team["resolver_for"](LOGS)
    registration = team["registration"]
    by_id = await resolver.own_bindings(TEAM, binding_id=registration.binding_id)
    [binding] = by_id.items
    assert (binding.state, binding.ended_by, binding.hook) == ("active", None, HOOK[2])
    assert binding.activated_at is not None and binding.revoked_at is None
    by_hook = await resolver.own_bindings(TEAM, hook=HOOK)
    assert [b.binding_id for b in by_hook.items] == [registration.binding_id]


@pytest.mark.asyncio
async def test_the_core_producers_keys_come_from_the_teams_server(team, monkeypatch):
    signing_key = SigningKey.generate()
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    monkeypatch.setenv(
        "AWEB_HOOK_PRODUCER_KEYS",
        json.dumps([{"kid": "hook-2026-10", "did_key": did_key, "valid_from": "2026-10-01T00:00:00Z", "valid_until": None}]),
    )
    resolver = await team["resolver_for"](LOGS)
    [key] = (await resolver.core_producer_keys(TEAM)).items
    assert (key.kid, key.did_key, key.valid_until) == ("hook-2026-10", did_key, None)
    assert key.valid_from == datetime(2026, 10, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_an_answer_is_reused_while_fresh_and_refetched_after(team):
    resolver = await team["resolver_for"](SECRETS)
    await resolver.registrations(TEAM, *HOOK)
    calls = _aweb_calls(team)
    await resolver.registrations(TEAM, *HOOK)
    assert _aweb_calls(team) == calls
    team["clock"].now += 61
    await resolver.registrations(TEAM, *HOOK)
    assert _aweb_calls(team) == calls + 1


@pytest.mark.asyncio
async def test_an_expired_answer_is_never_served_when_the_server_is_down(team):
    resolver = await team["resolver_for"](SECRETS)
    await resolver.registrations(TEAM, *HOOK)
    team["clock"].now += 61
    team["stack"].aweb.down = True
    with pytest.raises(HookResolutionUnavailable):
        await resolver.registrations(TEAM, *HOOK)


@pytest.mark.asyncio
async def test_a_refresh_that_takes_too_long_fails_closed(team):
    resolver = await team["resolver_for"](SECRETS, refresh_timeout=0.05)
    team["stack"].aweb.delay = 0.3
    with pytest.raises(HookResolutionUnavailable):
        await resolver.registrations(TEAM, *HOOK)


@pytest.mark.asyncio
async def test_without_the_complementary_binding_the_answer_is_binding_required(team):
    resolver = await team["resolver_for"](SECRETS)
    with pytest.raises(HookBindingRequired):
        await resolver.productions(TEAM, *HOOK)


@pytest.mark.asyncio
async def test_a_moved_install_fails_closed_not_empty(team):
    resolver = await team["resolver_for"](SECRETS)
    moved = {**SECRETS, "digest": "sha256:" + "3" * 64}
    await _install(team["db"], moved, "inst-secrets", [SECRET_USE])
    with pytest.raises(HookResolutionUnavailable) as caught:
        await resolver.registrations(TEAM, *HOOK)
    assert caught.value.code == "server_status_403"


@pytest.mark.asyncio
async def test_a_changed_team_server_record_is_followed_even_while_an_answer_is_fresh(team):
    # Discovery refreshes sooner than the answer expires, so the moved record
    # is seen while the old server's answer is still fresh: it must not be reused.
    resolver = await team["resolver_for"](SECRETS, directory_ttl=10)
    await resolver.registrations(TEAM, *HOOK)
    await team["stack"].publish_server(
        TEAM, team["team_key"], server_url="https://aweb.moved.example",
        issued_at=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1),
    )
    team["clock"].now += 11
    with pytest.raises(HookResolutionUnavailable):
        # The moved record names a server this in-process app is not the
        # audience of, so it refuses the credential: the point is where the
        # request went.
        await resolver.registrations(TEAM, *HOOK)
    assert team["stack"].aweb.calls[-1].url.host == "aweb.moved.example"


def _rewrite(change):
    def fault(request, response):
        body = json.loads(response.content)
        change(body)
        content = json.dumps(body).encode()
        response._content = content
        response.headers["content-length"] = str(len(content))

    return fault


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body.update(team_id="other:resolve.example"),
        lambda body: body.update(hook="post-governance-hook"),
        lambda body: body.update(catalog={"id": "aweb.hooks", "version": 2}),
        lambda body: body["bindings"][0].update(kind="production"),
        lambda body: body["bindings"][0].pop("active_from"),
        lambda body: body["bindings"][0].update(path=None),
        lambda body: body["bindings"][0].update(binding_id="not-a-uuid"),
        lambda body: body.update(max_age_seconds=0),
        lambda body: body.pop("bindings"),
    ],
)
async def test_a_malformed_registrations_answer_fails_closed(team, change):
    resolver = await team["resolver_for"](SECRETS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.registrations(TEAM, *HOOK)


@pytest.mark.asyncio
async def test_a_production_key_without_a_hook_purpose_fails_closed(team):
    await _key(team["db"], SECRETS, kid="hook-1", purposes=["hook-event"])
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(lambda body: body["bindings"][0]["keys"][0].update(purposes=["app-event"]))
    with pytest.raises(HookResolutionUnavailable):
        await resolver.productions(TEAM, *HOOK)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body["bindings"][0].update(app_id="secrets"),
        lambda body: body["bindings"][0].update(origin="https://other.example"),
        lambda body: body["bindings"][0].update(state="unknown"),
    ],
)
async def test_an_own_binding_of_another_app_or_origin_fails_closed(team, change):
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.own_bindings(TEAM, binding_id=team["registration"].binding_id)


@pytest.mark.asyncio
async def test_an_answer_that_is_not_json_fails_closed(team):
    resolver = await team["resolver_for"](SECRETS)

    def not_json(request, response):
        response._content = b"<html>"
        response.headers["content-length"] = "6"

    team["stack"].aweb.fault = not_json
    with pytest.raises(HookResolutionUnavailable):
        await resolver.registrations(TEAM, *HOOK)


@pytest.mark.asyncio
async def test_an_answer_past_the_size_bound_is_not_read(team):
    import httpx

    from aweb_naapp.runtime.hook_resolver import MAX_ANSWER_BYTES

    resolver = await team["resolver_for"](SECRETS)

    def oversized(request, response):
        return httpx.Response(200, stream=httpx.ByteStream(b" " * (MAX_ANSWER_BYTES + 1)))

    team["stack"].aweb.fault = oversized
    with pytest.raises(HookResolutionUnavailable) as caught:
        await resolver.registrations(TEAM, *HOOK)
    assert caught.value.code == "answer_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hook",
    [
        ("aweb.hooks", 1, "../registrations"),
        ("aweb.hooks", 1, "post?x=1"),
        ("aweb.hooks", 1, "post#x"),
        ("aweb.hooks", 1, "post\nx"),
        ("aweb.hooks", 1, "Post-secret-use-hook"),
        ("aweb.hooks", 1, "h" * 65),
        ("..", 1, "post-secret-use-hook"),
        ("a" * 65, 1, "post-secret-use-hook"),
        ("aweb.hooks", True, "post-secret-use-hook"),
        ("aweb.hooks", 0, "post-secret-use-hook"),
        ("aweb.hooks", 10**9, "post-secret-use-hook"),
        ("aweb.hooks", "1", "post-secret-use-hook"),
    ],
)
async def test_a_hook_no_binding_could_name_is_refused_before_anything_is_sent(team, hook):
    resolver = await team["resolver_for"](SECRETS)
    calls = _aweb_calls(team)
    with pytest.raises(HookBindingRequired):
        await resolver.registrations(TEAM, *hook)
    with pytest.raises(HookBindingRequired):
        await resolver.productions(TEAM, *hook)
    with pytest.raises(ValueError):
        await resolver.own_bindings(TEAM, hook=hook)
    assert _aweb_calls(team) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body["keys"][0].update(note="x"),
        lambda body: body["keys"][0].update(valid_from="2026-10-01T00:00:00.000Z"),
        lambda body: body["keys"][0].pop("valid_until"),
        lambda body: body["keys"][0].update(kid=""),
        lambda body: body.update(max_age_seconds=True),
    ],
)
async def test_a_malformed_producer_keys_answer_fails_closed(team, monkeypatch, change):
    monkeypatch.setenv(
        "AWEB_HOOK_PRODUCER_KEYS",
        json.dumps([{"kid": "hook-1", "did_key": did_from_public_key(bytes(SigningKey.generate().verify_key)),
                     "valid_from": "2026-10-01T00:00:00Z", "valid_until": None}]),
    )
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.core_producer_keys(TEAM)


@pytest.mark.asyncio
async def test_producer_keys_fail_closed_with_the_server_down(team):
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.down = True
    with pytest.raises(HookResolutionUnavailable):
        await resolver.core_producer_keys(TEAM)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body.update(team_id="other:resolve.example"),
        lambda body: body.update(catalog={"id": "other.hooks", "version": 1}),
        lambda body: body.update(catalog={"id": "aweb.hooks", "version": True}),
        lambda body: body.update(hook="post-governance-hook"),
        lambda body: body["bindings"][0].update(kind="registration"),
        lambda body: body.update(max_age_seconds=True),
        lambda body: body["bindings"][0].update(binding_id=body["bindings"][0]["binding_id"].upper()),
    ],
)
async def test_a_malformed_productions_answer_fails_closed(team, change):
    await _key(team["db"], SECRETS, kid="hook-1", purposes=["hook-event"])
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.productions(TEAM, *HOOK)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body["bindings"][0].update(keys=[]),
        lambda body: body.update(catalog={"id": "aweb.hooks", "version": True}),
    ],
)
async def test_a_registration_with_keys_or_a_bool_version_fails_closed(team, change):
    resolver = await team["resolver_for"](SECRETS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.registrations(TEAM, *HOOK)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        lambda body: body["bindings"][0]["catalog"].update(version="1"),
        lambda body: body["bindings"][0]["catalog"].update(version=True),
        lambda body: body["bindings"][0]["catalog"].update(version=0),
    ],
)
async def test_an_own_binding_with_a_malformed_catalog_version_fails_closed(team, change):
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(change)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.own_bindings(TEAM, binding_id=team["registration"].binding_id)
    with pytest.raises(HookResolutionUnavailable):
        await resolver.own_bindings(TEAM, hook=HOOK)


@pytest.mark.asyncio
async def test_an_own_answer_must_answer_its_selector(team):
    resolver = await team["resolver_for"](LOGS)
    team["stack"].aweb.fault = _rewrite(
        lambda body: body["bindings"][0].update(binding_id="00000000-0000-4000-8000-000000000000")
    )
    with pytest.raises(HookResolutionUnavailable):
        await resolver.own_bindings(TEAM, binding_id=team["registration"].binding_id)
    team["stack"].aweb.fault = _rewrite(lambda body: body["bindings"][0].update(hook="post-governance-hook"))
    with pytest.raises(HookResolutionUnavailable):
        await resolver.own_bindings(TEAM, hook=HOOK)


@pytest.mark.asyncio
async def test_each_selection_has_its_own_answer(team):
    db = team["db"]
    relay = {"app_id": "relay", "origin": "https://relay.example", "digest": "sha256:" + "6" * 64}
    relay_ingest = HookBindingDeclaration(
        kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK[2],
        tool="relay-ingest", method="POST", path="/hooks/relay", scopes=("relay:ingest",),
    )
    bindings = await _install(db, relay, "inst-relay", [relay_ingest, SECRET_USE])
    await _activate(db, bindings[REGISTRATION].binding_id)
    await _activate(db, bindings[PRODUCTION].binding_id)
    resolver = await team["resolver_for"](relay)

    registrations = await resolver.registrations(TEAM, *HOOK)
    productions = await resolver.productions(TEAM, *HOOK)
    assert {b.app_id for b in registrations.items} == {"logs", "relay"}
    assert {b.app_id for b in productions.items} == {"secrets", "relay"}

    calls = _aweb_calls(team)
    with pytest.raises(HookBindingRequired):
        await resolver.registrations(TEAM, "aweb.hooks", 1, "post-governance-hook")
    assert _aweb_calls(team) == calls + 1

    by_id = await resolver.own_bindings(TEAM, binding_id=bindings[REGISTRATION].binding_id)
    by_hook = await resolver.own_bindings(TEAM, hook=HOOK)
    assert len(by_id.items) == 1 and len(by_hook.items) == 2
    assert _aweb_calls(team) == calls + 3


@pytest.mark.asyncio
async def test_an_unpublished_team_or_a_down_registry_fails_closed(team):
    unpublished = "quiet:resolve.example"
    await team["stack"].add_team(unpublished)
    resolver = await team["resolver_for"](SECRETS)
    with pytest.raises(HookResolutionUnavailable) as caught:
        await resolver.registrations(unpublished, *HOOK)
    assert caught.value.code == "team_server_unpublished"

    team["stack"].awid.down = True
    fresh_resolver = await team["resolver_for"](LOGS)
    with pytest.raises(HookResolutionUnavailable) as caught:
        await fresh_resolver.registrations(TEAM, *HOOK)
    assert caught.value.code == "authority_unavailable"
