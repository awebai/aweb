"""Pinned-byte setup for registry/credential unit tests.

These tests exercise the transaction writer or downstream credentials, not an
origin fetch. Network installation journeys use the real TLS origin fixtures.
``digest`` in old fixture call sites is a byte-variant label; this helper always
computes the real digest of the constructed manifest, never a fabricated pin.
"""

import hashlib
import json

from aweb.app_manifests import FetchedManifest
from aweb.app_registry import (
    AppInstall,
    _write_team_registrations,
    get_installation_on,
    normalize_event_types,
    reserved_app_ids,
)
from aweb.installations import install_verified_manifest_on
from aweb_naapp.manifest import load_manifest


async def install_fixture_app(
    db, *, team_id, app_id, origin, app_version="1.0.0", manifest_version=1,
    digest=None, granted_scopes=(), event_types=(), emit_keys=(), manifest=None,
    installed_by_agent_id=None,
):
    if manifest is None:
        assert manifest_version == 1
        manifest = json.dumps({
            "manifest_version": 1, "app": {"id": app_id, "version": app_version, "origin": origin},
            "tools": [{"name": "fixture-read", "method": "GET", "path": "/fixture",
                       "description": digest or "Registry test fixture", "scopes": list(granted_scopes)}],
            "events": [{"type": event.type, "default_delivery_intent": event.default_delivery_intent,
                        "description": event.description} for event in event_types],
            "event_emitters": [{"kid": key.kid, "did_key": key.did_key} for key in emit_keys],
        }).encode()
    parsed = load_manifest(manifest, reserved_names=reserved_app_ids())
    assert parsed.app_id == app_id
    assert parsed.manifest_version == manifest_version
    assert parsed.document["app"]["version"] == app_version
    evidence = FetchedManifest(origin=origin, url=origin+"/.well-known/aweb-app.json",
                               digest="sha256:"+hashlib.sha256(manifest).hexdigest(), data=manifest, manifest=parsed)
    async with db.transaction() as tx:
        before = await get_installation_on(tx, team_id=team_id, app_id=app_id)
        row = await install_verified_manifest_on(
            tx, team_id=team_id, fetched=evidence, granted_scopes=list(granted_scopes),
            expected_generation=before["generation"] if before else None, installed_by_agent_id=installed_by_agent_id,
        )
    return AppInstall(**{key: value for key, value in row.items() if key != "team_id"})


async def seed_pending_installation(
    db, *, team_id, app_id, origin, app_version, manifest_version, digest,
    granted_scopes, event_types=(), emit_keys=(),
):
    """Seed pre-F6 metadata for legacy repair and hook-storage tests.

    This supplies no origin evidence and never grants active app authority.
    It is fixture SQL, not a production installation ingress.
    """
    async with db.transaction() as tx:
        await tx.execute(
            "INSERT INTO {{tables.app_registry_apps}} (app_id,origin) VALUES ($1,$2) ON CONFLICT DO NOTHING",
            app_id, origin,
        )
        await tx.execute(
            "INSERT INTO {{tables.app_registry_entries}} (app_id,origin,digest,app_version,manifest_version) "
            "VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", app_id, origin, digest, app_version, manifest_version,
        )
        await tx.execute(
            "INSERT INTO {{tables.team_app_installs}} (team_id,app_id,origin,digest,app_version,manifest_version,granted_scopes) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7::TEXT[]) ON CONFLICT (team_id,app_id) DO UPDATE SET "
            "origin=EXCLUDED.origin,digest=EXCLUDED.digest,app_version=EXCLUDED.app_version,manifest_version=EXCLUDED.manifest_version,"
            "granted_scopes=EXCLUDED.granted_scopes,state='pending_origin_verification',origin_verified=FALSE,manifest_bytes=NULL",
            team_id, app_id, origin, digest, app_version, manifest_version, list(granted_scopes),
        )
        await _write_team_registrations(
            tx, team_id=team_id, app_id=app_id, origin=origin, digest=digest,
            event_types=normalize_event_types(list(event_types)), emit_keys=list(emit_keys), app_keys=[],
        )
