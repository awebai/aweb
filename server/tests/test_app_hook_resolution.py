"""Hook resolution against the real verifier, routes and database (design app-team-server-api.md §4).

Bindings are written by the install path's own writer. Owner activation is not
built yet, so a binding is made active here through the row values a real
activation must satisfy, which the schema checks.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from aweb.app_credentials import APP_GRANT_READ, HOOK_RESOLVE, PURPOSES
from aweb.hook_bindings import (
    PRODUCTION,
    REGISTRATION,
    HookBindingDeclaration,
    revoke_uninstalled_bindings,
    write_pending_bindings,
)
from aweb.routes.app_hooks import router as app_hooks_router
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey
from tests.installation_fixtures import seed_hook_installation
from tests.test_app_events_http import (
    _build_events_app,
    _make_app_keypair,
    _seed_team_and_agent,
)
from tests.test_events_http import _encode_certificate, _make_certificate

TEAM = "backend:acme.com"
OTHER_TEAM = "frontend:acme.com"
HOOK = "post-secret-use-hook"
HOOK_PATH = f"aweb.hooks/1/{HOOK}"
LOGS = {"app_id": "logs", "origin": "https://logs.example", "digest": "sha256:" + "1" * 64}
SECRETS = {"app_id": "secrets", "origin": "https://secrets.example", "digest": "sha256:" + "2" * 64}

INGEST = HookBindingDeclaration(
    kind=REGISTRATION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK,
    tool="ingest", method="POST", path="/hooks/ingest", scopes=("logs:ingest",),
)
SECRET_USE = HookBindingDeclaration(kind=PRODUCTION, catalog_id="aweb.hooks", catalog_version=1, hook=HOOK)


async def _install(db, app: dict, *, team_id: str = TEAM, installation_id: str, declarations) -> dict:
    await seed_hook_installation(db, app, team_id=team_id, installation_id=installation_id)
    async with db.transaction() as tx:
        written = await write_pending_bindings(
            tx, team_id=team_id, app_id=app["app_id"], origin=app["origin"], digest=app["digest"],
            installation_id=installation_id, generation=1, declarations=list(declarations),
        )
    return {binding.kind: binding for binding in written}


async def _register_key(db, app: dict, *, kid: str, purposes: list[str], team_id: str = TEAM) -> tuple[bytes, str]:
    key, did = _make_app_keypair()
    await db.execute(
        """
        INSERT INTO {{tables.team_app_keys}} (team_id, app_id, origin, digest, key_id, did_key, purposes)
        VALUES ($1, $2, $3, $4, $5, $6, $7::TEXT[])
        """,
        team_id, app["app_id"], app["origin"], app["digest"], kid, did, purposes,
    )
    return key, did


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


async def _revoke(db, binding_id: UUID) -> None:
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'revoked', ended_by = 'owner_act', revoked_at = date_trunc('milliseconds', NOW()),
            revocation_act_sha256 = $2
        WHERE binding_id = $1
        """,
        binding_id, "cd" * 32,
    )


def _headers(app: dict, key: tuple[bytes, str], kid: str, path: str, *, team_id: str = TEAM,
             purpose: str = HOOK_RESOLVE) -> dict[str, str]:
    signing_key, did_key = key
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical = canonical_json_bytes(
        {
            "v": 1, "auth": purpose, "aud": "http://test", "method": "GET", "path": path,
            "team_id": team_id, "app_id": app["app_id"], "kid": kid, "did_key": did_key,
            "body_sha256": hashlib.sha256(b"").hexdigest(), "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"{PURPOSES[purpose].prefix}{did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-App-ID": app["app_id"],
        "X-AWEB-App-Key-ID": kid,
        "X-AWEB-Team-ID": team_id,
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("="),
    }


@pytest_asyncio.fixture
async def team(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team_and_agent(db, team_id=TEAM)
    await _seed_team_and_agent(db, team_id=OTHER_TEAM)
    logs = await _install(db, LOGS, installation_id="inst-logs", declarations=[INGEST])
    secrets = await _install(db, SECRETS, installation_id="inst-secrets", declarations=[SECRET_USE])
    logs_key = await _register_key(db, LOGS, kid="resolve-1", purposes=[HOOK_RESOLVE])
    secrets_key = await _register_key(db, SECRETS, kid="resolve-1", purposes=[HOOK_RESOLVE])
    app = _build_events_app(db)
    app.include_router(app_hooks_router)
    return {
        "db": db, "app": app,
        "registration": logs[REGISTRATION], "production": secrets[PRODUCTION],
        "logs_key": logs_key, "secrets_key": secrets_key,
    }


async def _get(team: dict, caller: dict, key_name: str, path: str, *, kid: str = "resolve-1", **header_options):
    headers = _headers(caller, team[key_name], kid, path, **header_options)
    async with AsyncClient(transport=ASGITransport(app=team["app"]), base_url="http://test") as client:
        return await client.get(path, headers=headers)


def _resolution(kind: str, hook_path: str = HOOK_PATH) -> str:
    return f"/v1/apps/self/hooks/{hook_path}/{kind}"


@pytest.mark.asyncio
async def test_a_producer_resolves_registrations_only_while_its_production_is_active(team):
    path = _resolution("registrations")
    await _activate(team["db"], team["registration"].binding_id)
    refused = await _get(team, SECRETS, "secrets_key", path)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "hook_binding_required"

    await _activate(team["db"], team["production"].binding_id)
    response = await _get(team, SECRETS, "secrets_key", path)
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["team_id"], body["catalog"], body["hook"]) == (TEAM, {"id": "aweb.hooks", "version": 1}, HOOK)
    assert body["max_age_seconds"] == 60
    [binding] = body["bindings"]
    registration = team["registration"]
    assert binding["binding_id"] == str(registration.binding_id)
    assert (binding["kind"], binding["app_id"], binding["installation_id"], binding["generation"]) == (
        "registration", "logs", "inst-logs", 1,
    )
    assert (binding["origin"], binding["method"], binding["path"], binding["digest"]) == (
        LOGS["origin"], "POST", "/hooks/ingest", LOGS["digest"],
    )
    assert binding["active_from"]


@pytest.mark.asyncio
async def test_a_consumer_resolves_productions_only_while_its_registration_is_active(team):
    path = _resolution("productions")
    await _activate(team["db"], team["production"].binding_id)
    refused = await _get(team, LOGS, "logs_key", path)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "hook_binding_required"

    await _activate(team["db"], team["registration"].binding_id)
    response = await _get(team, LOGS, "logs_key", path)
    assert response.status_code == 200, response.text
    [binding] = response.json()["bindings"]
    assert (binding["binding_id"], binding["kind"], binding["app_id"]) == (
        str(team["production"].binding_id), "production", "secrets",
    )


@pytest.mark.asyncio
async def test_productions_list_only_the_producers_unrevoked_hook_keys(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    _, event_did = await _register_key(db, SECRETS, kid="hook-event-1", purposes=["hook-event"])
    _, both_did = await _register_key(db, SECRETS, kid="hook-both-1", purposes=["hook-delivery", "hook-event"])
    await _register_key(db, SECRETS, kid="emit-1", purposes=["app-event"])
    await _register_key(db, SECRETS, kid="usage-1", purposes=["app-usage"])
    await _register_key(db, SECRETS, kid="hook-old", purposes=["hook-event"])
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET revoked_at = NOW() WHERE app_id = 'secrets' AND key_id = 'hook-old'"
    )
    await _register_key(db, SECRETS, kid="other-team-hook", purposes=["hook-event"], team_id=OTHER_TEAM)

    response = await _get(team, LOGS, "logs_key", _resolution("productions"))
    assert response.status_code == 200, response.text
    [binding] = response.json()["bindings"]
    assert binding["keys"] == [
        {"kid": "hook-both-1", "did_key": both_did, "purposes": ["hook-delivery", "hook-event"]},
        {"kid": "hook-event-1", "did_key": event_did, "purposes": ["hook-event"]},
    ]


@pytest.mark.asyncio
async def test_a_binding_of_the_same_kind_authorizes_nothing(team):
    await _activate(team["db"], team["production"].binding_id)
    await _activate(team["db"], team["registration"].binding_id)
    assert (await _get(team, SECRETS, "secrets_key", _resolution("productions"))).status_code == 403
    assert (await _get(team, LOGS, "logs_key", _resolution("registrations"))).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hook_path",
    ["aweb.hooks/1/post-unknown-hook", "aweb.hooks/2/post-secret-use-hook", "other.hooks/1/post-secret-use-hook"],
)
async def test_an_unknown_catalog_version_or_hook_resolves_to_nothing(team, hook_path):
    await _activate(team["db"], team["production"].binding_id)
    await _activate(team["db"], team["registration"].binding_id)
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations", hook_path))
    assert response.status_code == 403
    assert response.json()["detail"] == "hook_binding_required"


@pytest.mark.asyncio
async def test_pending_and_ended_bindings_are_not_listed_but_a_padding_one_is(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    path = _resolution("registrations")
    pending = await _get(team, SECRETS, "secrets_key", path)
    assert pending.status_code == 200 and pending.json()["bindings"] == []

    await _activate(db, team["registration"].binding_id)
    padding = await _get(team, SECRETS, "secrets_key", path)
    assert [b["binding_id"] for b in padding.json()["bindings"]] == [str(team["registration"].binding_id)]

    await _revoke(db, team["registration"].binding_id)
    revoked = await _get(team, SECRETS, "secrets_key", path)
    assert revoked.status_code == 200 and revoked.json()["bindings"] == []


@pytest.mark.asyncio
async def test_a_revoked_production_stops_authorizing_on_the_next_read(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    path = _resolution("registrations")
    assert (await _get(team, SECRETS, "secrets_key", path)).status_code == 200
    await _revoke(db, team["production"].binding_id)
    assert (await _get(team, SECRETS, "secrets_key", path)).status_code == 403


@pytest.mark.asyncio
async def test_resolution_takes_only_a_hook_resolve_credential(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET purposes = $1::TEXT[] WHERE app_id = 'secrets' AND key_id = 'resolve-1'",
        [HOOK_RESOLVE, APP_GRANT_READ],
    )
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations"), purpose=APP_GRANT_READ)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_another_teams_bindings_never_answer(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    other = await _install(db, LOGS, team_id=OTHER_TEAM, installation_id="inst-logs-other", declarations=[INGEST])
    await _activate(db, other[REGISTRATION].binding_id)
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    assert [b["binding_id"] for b in response.json()["bindings"]] == [str(team["registration"].binding_id)]


@pytest.mark.asyncio
async def test_own_bindings_are_read_in_every_state_by_id_or_by_hook(team):
    db = team["db"]
    registration = team["registration"]
    await _activate(db, registration.binding_id)
    await _revoke(db, registration.binding_id)

    by_id = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings?binding_id={registration.binding_id}")
    assert by_id.status_code == 200, by_id.text
    [binding] = by_id.json()["bindings"]
    assert (binding["state"], binding["ended_by"]) == ("revoked", "owner_act")
    assert binding["activated_at"] and binding["active_from"] and binding["revoked_at"]

    by_hook = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings?hook={HOOK_PATH}")
    assert [b["binding_id"] for b in by_hook.json()["bindings"]] == [str(registration.binding_id)]


@pytest.mark.asyncio
async def test_own_bindings_never_show_another_apps_binding(team):
    production = team["production"]
    response = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings?binding_id={production.binding_id}")
    assert response.status_code == 200
    assert response.json()["bindings"] == []
    pending = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings?binding_id={uuid4()}")
    assert pending.json()["bindings"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query",
    ["", f"?binding_id={uuid4()}&hook={HOOK_PATH}", "?binding_id=not-a-uuid", "?hook=aweb.hooks/one/x", "?hook=x"],
)
async def test_own_bindings_need_exactly_one_well_formed_selector(team, query):
    response = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings{query}")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_binding_times_are_milliseconds_and_active_from_never_reads_early(team):
    db = team["db"]
    registration = team["registration"]
    await db.execute(
        """
        UPDATE {{tables.app_hook_bindings}}
        SET state = 'active', activated_at = '2026-10-20T12:00:00.123456Z',
            active_from = '2026-10-20T12:01:00.123456Z', activation_act_sha256 = $2
        WHERE binding_id = $1
        """,
        registration.binding_id, "ab" * 32,
    )
    response = await _get(team, LOGS, "logs_key", f"/v1/apps/self/hooks/bindings?binding_id={registration.binding_id}")
    [binding] = response.json()["bindings"]
    assert binding["activated_at"] == "2026-10-20T12:00:00.123Z"
    assert binding["active_from"] == "2026-10-20T12:01:00.124Z"
    assert binding["revoked_at"] is None


@pytest.mark.asyncio
async def test_a_member_envelope_is_refused_like_any_other_credential(team):
    await _activate(team["db"], team["production"].binding_id)
    await _activate(team["db"], team["registration"].binding_id)
    path = _resolution("registrations")
    member_key = SigningKey.generate()
    member_did = did_from_public_key(bytes(member_key.verify_key))
    team_key = SigningKey.generate()
    certificate = _make_certificate(
        bytes(team_key), did_from_public_key(bytes(team_key.verify_key)), member_did, team_id=TEAM
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signed = canonical_json_bytes(
        {
            "v": 2, "aud": "http://test", "method": "GET", "path": path, "team_id": TEAM,
            "timestamp": timestamp, "body_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    headers = {
        "Authorization": f"DIDKey {member_did} {sign_message(bytes(member_key), signed)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(signed).decode().rstrip("="),
        "X-AWID-Team-Certificate": _encode_certificate(certificate),
    }
    for route in (path, _resolution("productions"), f"/v1/apps/self/hooks/bindings?hook={HOOK_PATH}"):
        async with AsyncClient(transport=ASGITransport(app=team["app"]), base_url="http://test") as client:
            response = await client.get(route, headers={**headers})
        assert response.status_code == 401, route


@pytest.mark.asyncio
async def test_registrations_carry_no_keys(team):
    await _activate(team["db"], team["production"].binding_id)
    await _activate(team["db"], team["registration"].binding_id)
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    [binding] = response.json()["bindings"]
    assert "keys" not in binding


@pytest.mark.asyncio
async def test_a_key_of_an_earlier_digest_reads_nothing(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    moved = {**SECRETS, "digest": "sha256:" + "3" * 64}
    await _install(db, moved, installation_id="inst-secrets", declarations=[SECRET_USE])
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    assert response.status_code == 403
    assert response.json()["detail"] == "app_key_not_registered"


@pytest.mark.asyncio
async def test_a_productions_keys_are_only_those_of_its_own_installed_digest(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    other_digest = {**SECRETS, "digest": "sha256:" + "4" * 64}
    await _install(db, other_digest, team_id=OTHER_TEAM, installation_id="inst-elsewhere", declarations=[SECRET_USE])
    await _register_key(db, other_digest, kid="hook-other-digest", purposes=["hook-event"])
    _, own_did = await _register_key(db, SECRETS, kid="hook-own", purposes=["hook-event"])
    response = await _get(team, LOGS, "logs_key", _resolution("productions"))
    [binding] = response.json()["bindings"]
    assert binding["keys"] == [{"kid": "hook-own", "did_key": own_did, "purposes": ["hook-event"]}]


@pytest.mark.asyncio
async def test_own_bindings_never_show_an_earlier_origins_history(team):
    db = team["db"]
    # Server-side uninstall is not built yet (the installation model owns it):
    # revoke the bindings as uninstall will, and remove the install record.
    async with db.transaction() as tx:
        await revoke_uninstalled_bindings(tx, team_id=TEAM, app_id="logs")
        await tx.execute(
            "DELETE FROM {{tables.team_app_installs}} WHERE team_id = $1 AND app_id = 'logs'", TEAM
        )
    moved = {"app_id": "logs", "origin": "https://logs.other.example", "digest": "sha256:" + "5" * 64}
    current = await _install(db, moved, installation_id="inst-logs-moved", declarations=[INGEST])
    # Key identity survives an origin move: a fresh keypair needs a fresh kid.
    moved_key = await _register_key(db, moved, kid="resolve-moved", purposes=[HOOK_RESOLVE])
    team["moved_key"] = moved_key
    response = await _get(team, moved, "moved_key", f"/v1/apps/self/hooks/bindings?hook={HOOK_PATH}", kid="resolve-moved")
    assert response.status_code == 200, response.text
    assert [b["binding_id"] for b in response.json()["bindings"]] == [str(current[REGISTRATION].binding_id)]
    assert {b["origin"] for b in response.json()["bindings"]} == {moved["origin"]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hook_path",
    [
        f"aweb.hooks/{2**31}/{HOOK}",
        f"aweb.hooks/99999999999/{HOOK}",
        "aweb.hooks/01/post-secret-use-hook",
        f"abc!!!/1/{HOOK}",
        f"ABCa/1/{HOOK}",
        f"{'a' * 200}/1/{HOOK}",
        "aweb.hooks/1/Post-Secret",
        f"aweb.hooks/1/{'h' * 200}",
    ],
)
async def test_a_hook_no_binding_could_name_resolves_to_nothing(team, hook_path):
    await _activate(team["db"], team["production"].binding_id)
    await _activate(team["db"], team["registration"].binding_id)
    response = await _get(team, LOGS, "logs_key", _resolution("registrations", hook_path))
    assert response.status_code == 403
    assert response.json()["detail"] == "hook_binding_required"


@pytest.mark.asyncio
async def test_own_bindings_authenticate_before_reading_the_query(team):
    async with AsyncClient(transport=ASGITransport(app=team["app"]), base_url="http://test") as client:
        response = await client.get("/v1/apps/self/hooks/bindings")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_another_apps_or_teams_binding_authorizes_nothing(team):
    db = team["db"]
    await _activate(db, team["registration"].binding_id)
    other_app = {"app_id": "relay", "origin": "https://relay.example", "digest": "sha256:" + "6" * 64}
    relay = await _install(db, other_app, installation_id="inst-relay", declarations=[SECRET_USE])
    await _activate(db, relay[PRODUCTION].binding_id)
    other_team = await _install(db, SECRETS, team_id=OTHER_TEAM, installation_id="inst-secrets-other",
                                declarations=[SECRET_USE])
    await _activate(db, other_team[PRODUCTION].binding_id)
    response = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    assert response.status_code == 403
    assert response.json()["detail"] == "hook_binding_required"


@pytest.mark.asyncio
async def test_a_superseded_binding_is_neither_listed_nor_authorizing(team):
    db = team["db"]
    await _activate(db, team["production"].binding_id)
    await _activate(db, team["registration"].binding_id)
    moved_logs = {**LOGS, "digest": "sha256:" + "7" * 64}
    await _install(db, moved_logs, installation_id="inst-logs", declarations=[INGEST])
    listed = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    assert listed.status_code == 200 and listed.json()["bindings"] == []
    moved_secrets = {**SECRETS, "digest": "sha256:" + "8" * 64}
    await _install(db, moved_secrets, installation_id="inst-secrets", declarations=[SECRET_USE])
    await db.execute(
        "UPDATE {{tables.team_app_keys}} SET digest = $1 WHERE app_id = 'secrets' AND key_id = 'resolve-1'",
        moved_secrets["digest"],
    )
    refused = await _get(team, SECRETS, "secrets_key", _resolution("registrations"))
    assert refused.status_code == 403
    assert refused.json()["detail"] == "hook_binding_required"
