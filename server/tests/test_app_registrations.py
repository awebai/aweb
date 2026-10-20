from __future__ import annotations

import hashlib
import json

import pytest

from aweb.app_registry import (
    AppEmitKey,
    AppEventType,
    get_active_app_emit_key,
    get_installed_app_event_type,
    install_app,
    list_installed_apps,
    manifest_registration,
    reseed_app_registrations,
)
from aweb.service_errors import ValidationError
from tests.test_app_events_http import _make_app_keypair, _seed_team_and_agent

ORIGIN = "https://notes.example"
TEAM_A = "backend:acme.com"
TEAM_B = "frontend:acme.com"
TEAM_C = "ops:acme.com"


def _manifest(*, did_key: str, version: str = "1.2.0", app_id: str = "notes", origin: str = ORIGIN) -> bytes:
    return json.dumps(
        {
            "manifest_version": 1,
            "app": {"id": app_id, "version": version, "origin": origin},
            "tools": [],
            "events": [
                {"type": "notes/note.saved", "default_delivery_intent": "wake", "description": "Saved."},
                {"type": "note.deleted"},
            ],
            "event_emitters": [{"kid": "notes:emit-1", "did_key": did_key}],
        },
        separators=(",", ":"),
    ).encode()


def _digest(manifest: bytes) -> str:
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


async def _install_without_registrations(db, *, team_id: str, digest: str) -> None:
    await install_app(
        db,
        team_id=team_id,
        app_id="notes",
        origin=ORIGIN,
        app_version="1.2.0",
        manifest_version=1,
        digest=digest,
        granted_scopes=["notes:read"],
    )


def test_manifest_registration_reads_declarations_and_keys_from_the_pinned_bytes():
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)

    registration = manifest_registration(manifest, app_id="notes", origin=ORIGIN, digest=_digest(manifest))

    assert registration.app_version == "1.2.0"
    assert registration.manifest_version == 1
    assert registration.event_types == [
        AppEventType(type="note.saved", default_delivery_intent="wake", description="Saved."),
        AppEventType(type="note.deleted", default_delivery_intent="ambient", description=""),
    ]
    assert registration.emit_keys == [AppEmitKey(kid="notes:emit-1", did_key=did_key)]


@pytest.mark.parametrize(
    "app_id, origin, digest_of",
    [
        ("notes", ORIGIN, b"other bytes"),
        ("other", ORIGIN, None),
        ("notes", "https://other.example", None),
    ],
)
def test_manifest_registration_refuses_bytes_that_do_not_match_the_install(app_id, origin, digest_of):
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    digest = _digest(digest_of if digest_of is not None else manifest)

    with pytest.raises(ValidationError):
        manifest_registration(manifest, app_id=app_id, origin=origin, digest=digest)


def test_manifest_registration_refuses_an_unsupported_manifest_version():
    manifest = json.dumps({"manifest_version": 2, "app": {"id": "notes", "origin": ORIGIN, "version": "1"}}).encode()

    with pytest.raises(ValidationError):
        manifest_registration(manifest, app_id="notes", origin=ORIGIN, digest=_digest(manifest))


@pytest.mark.asyncio
async def test_reseed_registers_keys_and_declarations_for_every_team_at_the_digest(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    stale = _manifest(did_key=did_key, version="1.1.0")
    for team_id in (TEAM_A, TEAM_B, TEAM_C):
        await _seed_team_and_agent(db, team_id=team_id)
    await _install_without_registrations(db, team_id=TEAM_A, digest=_digest(manifest))
    await _install_without_registrations(db, team_id=TEAM_B, digest=_digest(manifest))
    await _install_without_registrations(db, team_id=TEAM_C, digest=_digest(stale))

    report = await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    assert report.reseeded == [TEAM_A, TEAM_B]
    assert report.digest_mismatch == [TEAM_C]
    assert report.key_conflict == []
    for team_id in (TEAM_A, TEAM_B):
        key = await get_active_app_emit_key(db, team_id=team_id, app_id="notes", kid="notes:emit-1", did_key=did_key)
        declared = await get_installed_app_event_type(db, team_id=team_id, app_id="notes", local_event_type="note.saved")
        assert key is not None
        assert declared["default_delivery_intent"] == "wake"
    assert await get_active_app_emit_key(db, team_id=TEAM_C, app_id="notes", kid="notes:emit-1", did_key=did_key) is None
    assert await get_installed_app_event_type(db, team_id=TEAM_C, app_id="notes", local_event_type="note.saved") is None


@pytest.mark.asyncio
async def test_reseed_replaces_declarations_and_projection_with_the_bytes(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    await _seed_team_and_agent(db, team_id=TEAM_A)
    await install_app(
        db,
        team_id=TEAM_A,
        app_id="notes",
        origin=ORIGIN,
        app_version="9.9.9",
        manifest_version=1,
        digest=_digest(manifest),
        granted_scopes=["notes:read"],
        event_types=[AppEventType(type="note.saved", default_delivery_intent="steer")],
    )

    await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    declared = await get_installed_app_event_type(db, team_id=TEAM_A, app_id="notes", local_event_type="note.saved")
    apps = await list_installed_apps(db, team_id=TEAM_A)
    assert declared["default_delivery_intent"] == "wake"
    assert apps[0].app_version == "1.2.0"


@pytest.mark.asyncio
async def test_reseed_leaves_subscriptions_unchanged_and_is_idempotent(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, did_key = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    await _seed_team_and_agent(db, team_id=TEAM_A)
    await _install_without_registrations(db, team_id=TEAM_A, digest=_digest(manifest))
    await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)
    agent = await db.fetch_one("SELECT agent_id FROM {{tables.agents}} WHERE team_id = $1", TEAM_A)
    await db.execute(
        """
        INSERT INTO {{tables.app_event_subscriptions}} (team_id, agent_id, event_type, delivery_intent)
        VALUES ($1, $2, 'notes/note.saved', 'steer')
        """,
        TEAM_A,
        agent["agent_id"],
    )

    again = await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    subscriptions = await db.fetch_all(
        "SELECT event_type, delivery_intent FROM {{tables.app_event_subscriptions}} WHERE team_id = $1",
        TEAM_A,
    )
    assert again.reseeded == [TEAM_A]
    assert [dict(row) for row in subscriptions] == [{"event_type": "notes/note.saved", "delivery_intent": "steer"}]
    key = await get_active_app_emit_key(db, team_id=TEAM_A, app_id="notes", kid="notes:emit-1", did_key=did_key)
    assert key is not None


@pytest.mark.asyncio
async def test_reseed_refuses_a_team_whose_key_id_holds_another_key(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    _, did_key = _make_app_keypair()
    _, other_did = _make_app_keypair()
    manifest = _manifest(did_key=did_key)
    await _seed_team_and_agent(db, team_id=TEAM_A)
    await _seed_team_and_agent(db, team_id=TEAM_B)
    await install_app(
        db,
        team_id=TEAM_A,
        app_id="notes",
        origin=ORIGIN,
        app_version="1.2.0",
        manifest_version=1,
        digest=_digest(manifest),
        granted_scopes=["notes:read"],
        emit_keys=[AppEmitKey(kid="notes:emit-1", did_key=other_did)],
    )
    await _install_without_registrations(db, team_id=TEAM_B, digest=_digest(manifest))

    report = await reseed_app_registrations(db, origin=ORIGIN, manifest=manifest)

    assert report.key_conflict == [TEAM_A]
    assert report.reseeded == [TEAM_B]
    assert await get_active_app_emit_key(db, team_id=TEAM_A, app_id="notes", kid="notes:emit-1", did_key=did_key) is None
    assert await get_installed_app_event_type(db, team_id=TEAM_A, app_id="notes", local_event_type="note.saved") is None
