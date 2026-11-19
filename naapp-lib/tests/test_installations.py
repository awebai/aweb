"""aweb_naapp_testing.installations: a naapp installed, uninstalled and reinstalled
through the coordination server's public routes, and read back by the naapp's
own runtime over real HTTP, DNS and AWID (``listening_coordination``)."""

from __future__ import annotations

import asyncio
import time
from uuid import uuid4

import pytest
from aweb_naapp_testing import SERVICE_TOKEN, Member
from aweb_naapp_testing.installations import Installations, InstallRefused, app_origin
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ
from tests.runtime.test_served_manifest import ExampleSettings, _key_file, _v2_template

SCOPES = ["example:write"]
# This deployment's own app id; the template's hosted id belongs to its hosted origin.
APP_ID = "example-local"


def _member() -> Member:
    # Team keys are cached in the Redis other runs share; a fresh team per test.
    return Member(team_id=f"t{uuid4().hex[:12]}:naapp.example", alias="alice")


def _runtime(tmp_path, *, origin: str, registry_url: str, database_url: str) -> NaappRuntime:
    keys = (("grants", [APP_GRANT_READ]),)
    files = {kid: _key_file(tmp_path, kid, bytes(SigningKey.generate()).hex()) for kid, _ in keys}
    manifest = tmp_path / "manifest.json"
    template = _v2_template(*keys)
    # An installed app names its release; the server pins it with the manifest.
    template["app"]["version"] = "1.0.0"
    manifest.write_bytes(canonical_bytes(template))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    # Only settings a deployment sets: no transport or resolver is handed in.
    return NaappRuntime(
        ExampleSettings(
            _env_file=None,
            app_key_files=files,
            public_origin=origin,
            app_id=APP_ID,
            database_url=database_url,
            awid_registry_url=registry_url,
            awid_service_token=SERVICE_TOKEN,
        ),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
    )


async def _status_after_freshness(runtime: NaappRuntime, team_id: str, previous):
    # The grant answer is reused until its max age passes; wait that out.
    if previous is not None:
        await asyncio.sleep(max(0.0, (previous.fresh_until - time.monotonic_ns()) / 1e9) + 0.05)
    return await runtime.installation_grants().status_for(team_id)


async def test_install_uninstall_and_reinstall_reach_the_naapp(
    listening_coordination, test_db_factory, tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", "1")
    member = _member()
    installations = Installations(listening_coordination, member)
    await installations.admit()
    database = await test_db_factory.create_db(suffix="installations_app")
    async with app_origin(tmp_path / "origin") as origin:
        runtime = _runtime(
            tmp_path / "app",
            origin=origin.url,
            registry_url=listening_coordination.registry_url,
            database_url=database.config.get_dsn(),
        )
        app = FastAPI(lifespan=runtime.lifespan)
        mount_manifest_routes(app, runtime=runtime)
        origin.serve(app)
        async with app.router.lifespan_context(app):
            installed = await installations.install(
                origin, app_id=APP_ID, manifest=runtime.manifest_bytes, granted_scopes=SCOPES
            )
            assert (installed["state"], installed["generation"]) == ("active", 1)

            active = await runtime.installation_grants().status_for(member.team_id)
            assert active is not None
            assert (active.state, active.installation_id, active.generation) == (
                "active",
                installed["installation_id"],
                1,
            )
            assert active.granted_scopes == frozenset(SCOPES)

            removed = await installations.uninstall(app_id=APP_ID, expected_generation=1)
            assert removed["state"] == "uninstalled"
            gone = await _status_after_freshness(runtime, member.team_id, active)
            assert gone is not None and gone.state == "uninstalled"

            again = await installations.install(
                origin,
                app_id=APP_ID,
                manifest=runtime.manifest_bytes,
                granted_scopes=SCOPES,
                expected_generation=removed["generation"],
            )
            assert again["state"] == "active" and again["generation"] > removed["generation"]
            back = await _status_after_freshness(runtime, member.team_id, gone)
            assert back is not None
            assert (back.state, back.generation) == ("active", again["generation"])


async def test_a_member_who_is_not_an_install_admin_is_refused(
    listening_coordination, tmp_path
) -> None:
    admin = _member()
    installations = Installations(listening_coordination, admin)
    await installations.admit()
    other = Member(
        team_id=admin.team_id, team_key=admin.team_key, alias="bob", certificate_id="cert-bob"
    )
    await listening_coordination.add_member(other)
    await listening_coordination.connect(other)
    async with app_origin(tmp_path / "origin") as origin:
        with pytest.raises(InstallRefused) as refused:
            await Installations(listening_coordination, other).install(
                origin, app_id=APP_ID, manifest=b"{}", granted_scopes=SCOPES
            )
    assert refused.value.status == 403
