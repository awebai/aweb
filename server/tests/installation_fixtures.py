"""Pinned-byte setup for registry/credential unit tests.

These tests exercise the transaction writer or downstream credentials, not an
origin fetch. Network installation journeys use the real TLS origin fixtures.
``digest`` in old fixture call sites is a byte-variant label; this helper always
computes the real digest of the constructed manifest, never a fabricated pin.
"""

import hashlib
import json

from aweb_naapp.manifest import load_manifest

from aweb.app_manifests import FetchedManifest
from aweb.app_registry import AppInstall, get_installation_on, reserved_app_ids
from aweb.installations import install_verified_manifest_on


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
