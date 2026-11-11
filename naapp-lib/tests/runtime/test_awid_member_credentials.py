"""A customer-hosted naapp configured with an ordinary member certificate for
its private team, in the files ``aw`` writes: the runtime signs that team's
AWID reads with it, refuses a credential whose files do not belong together,
and refuses to start on one AWID does not currently publish. Real AWID on
real PostgreSQL; no service token anywhere."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, Member

from aweb_naapp.runtime.app import NaappRuntime
from tests.runtime.test_naapp_runtime import (
    CREATE,
    ORIGIN,
    ExampleSettings,
    InstalledTeams,
    _app,
    _manifest,
    _migrations,
    _signed,
)

TEAM_ID = "backend:example.com"


@pytest.fixture
async def app_database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_member_reads")
    return database.config.get_dsn()


async def private_team(registry) -> tuple[Member, Member]:
    caller = Member(team_id=TEAM_ID, certificate_id="caller", alias="caller")
    service = Member(team_id=TEAM_ID, team_key=caller.team_key, certificate_id="service", alias="logs")
    await registry.add_team(TEAM_ID, caller.team_did_key, visibility="private")
    await registry.add_certificate(caller.certificate())
    await registry.add_certificate(service.certificate())
    return caller, service


def aw_files(directory: Path, member: Member, *, certificate: dict | None = None) -> dict[str, str]:
    """The member's signing key and team certificate as ``aw`` writes them."""
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "signing.key"
    key.write_text(
        "-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(bytes(member.member_key)).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n"
    )
    os.chmod(key, 0o600)
    cert = directory / "team.pem"
    cert.write_text(json.dumps(certificate or member.certificate(), indent=2))
    return {"signing_key_file": str(key), "certificate_file": str(cert)}


def settings_for(app_database_url: str, credentials: dict) -> ExampleSettings:
    return ExampleSettings(
        _env_file=None,
        database_url=app_database_url,
        awid_registry_url=REGISTRY_URL,
        awid_member_credentials=credentials,
    )


def runtime_for(registry, settings: ExampleSettings, tmp_path: Path) -> NaappRuntime:
    return NaappRuntime(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        manifest_path=_manifest(tmp_path, CREATE),
        awid_transport=registry.transport,
    )


async def running(runtime: NaappRuntime) -> AsyncIterator[httpx.AsyncClient]:
    app = _app(runtime, InstalledTeams({TEAM_ID: frozenset({"example:write"})}))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield client


async def test_a_private_teams_member_is_authenticated_with_the_apps_own_certificate(
    registry, app_database_url, tmp_path
):
    caller, service = await private_team(registry)
    settings = settings_for(app_database_url, {TEAM_ID: aw_files(tmp_path / "aw", service)})
    async for client in running(runtime_for(registry, settings, tmp_path / "app")):
        response = await client.post("/v1/things", **_signed(caller, "/v1/things"))
    assert response.status_code == 200, response.text
    gated = [r for r in registry.transport.calls if r.url.path.endswith(("/teams/backend", "/certificates"))]
    assert gated
    assert all(r.headers["Authorization"].startswith(f"DIDKey {service.did_key} ") for r in gated)


def test_the_credentials_come_from_the_apps_own_environment(tmp_path, monkeypatch):
    service = Member(team_id=TEAM_ID)
    files = aw_files(tmp_path, service)
    monkeypatch.setenv("EXAMPLE_AWID_MEMBER_CREDENTIALS", json.dumps({TEAM_ID: files}))
    settings = ExampleSettings(_env_file=None, database_url="postgresql://unused/db")
    assert {
        team: (str(paths.signing_key_file), str(paths.certificate_file))
        for team, paths in settings.awid_member_credentials.items()
    } == {TEAM_ID: (files["signing_key_file"], files["certificate_file"])}


@pytest.mark.parametrize("mismatch", ["certificate of another team", "certificate of another key"])
async def test_a_credential_whose_files_do_not_belong_together_is_refused(
    registry, app_database_url, tmp_path, mismatch
):
    service = Member(team_id=TEAM_ID)
    if mismatch == "certificate of another team":
        certificate = Member(team_id="frontend:example.com", member_key=service.member_key).certificate()
    else:
        certificate = Member(team_id=TEAM_ID).certificate()
    settings = settings_for(
        app_database_url, {TEAM_ID: aw_files(tmp_path / "aw", service, certificate=certificate)}
    )
    with pytest.raises(ValueError) as refused:
        runtime_for(registry, settings, tmp_path / "app")
    assert TEAM_ID in str(refused.value)


@pytest.mark.parametrize("state", ["revoked", "never published"])
async def test_the_app_does_not_start_on_a_credential_awid_does_not_publish(
    registry, app_database_url, tmp_path, state
):
    _, service = await private_team(registry)
    if state == "revoked":
        await registry.revoke("service")
    else:
        service = Member(team_id=TEAM_ID, team_key=service.team_key, certificate_id="unpublished")
    settings = settings_for(app_database_url, {TEAM_ID: aw_files(tmp_path / "aw", service)})
    with pytest.raises(RuntimeError) as refused:
        async for _ in running(runtime_for(registry, settings, tmp_path / "app")):
            pass
    assert TEAM_ID in str(refused.value)
    assert service.certificate_id in str(refused.value)
