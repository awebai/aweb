"""Runtime-owned SDK lifecycle and read authority on real AWID/PostgreSQL."""

from __future__ import annotations

import pytest
from awid.registry import RegistryClient
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import FastAPI

from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.runtime.app import NaappRuntime
from tests.runtime.test_awid_member_credentials import TEAM_ID, aw_files, private_team
from tests.runtime.test_served_manifest import ExampleSettings, _v2_template

pytest_plugins = ("tests.runtime.test_human_member",)


async def make_runtime(
    tmp_path, test_db_factory, registry, *, credentials=None, token=SERVICE_TOKEN, verifier=None
):
    database = await test_db_factory.create_db(suffix="runtime_registry", schema="app")
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template()))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    settings = ExampleSettings(
        _env_file=None,
        database_url=database.config.get_dsn(),
        db_schema=database.config.schema_name,
        awid_registry_url=REGISTRY_URL,
        awid_service_token=token,
        awid_member_credentials=credentials or {},
    )
    return NaappRuntime(
        settings,
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        awid_transport=registry.transport,
        awid_domain_verifier=verifier,
    )


@pytest.mark.parametrize("profile", ["service_token", "member_files"])
async def test_one_ready_sdk_client_reads_private_team_fresh_and_closes(
    tmp_path, test_db_factory, registry, profile
):
    caller, member = await private_team(registry)
    credentials = (
        {TEAM_ID: aw_files(tmp_path / "service-member", member)}
        if profile == "member_files"
        else {}
    )
    runtime = await make_runtime(
        tmp_path,
        test_db_factory,
        registry,
        credentials=credentials,
        token=None if profile == "member_files" else SERVICE_TOKEN,
    )
    with pytest.raises(RuntimeError, match="not initialized"):
        runtime.registry_client()
    app = FastAPI()
    async with runtime.lifespan(app):
        client = runtime.registry_client()
        assert type(client) is RegistryClient
        assert runtime.registry_client() is client
        assert client._domain_verifier is None
        team = await client.get_team("example.com", "backend")
        assert team is not None and team.name == "backend"
        assert caller.certificate_id not in await client.get_team_revocations(
            "example.com", "backend"
        )
        await registry.revoke(caller.certificate_id)
        assert caller.certificate_id in await client.get_team_revocations("example.com", "backend")
    assert client._http_client.is_closed
    assert runtime.connected_db() is None
    with pytest.raises(RuntimeError, match="not initialized"):
        runtime.registry_client()


async def test_later_app_startup_failure_closes_ready_client_and_database(
    tmp_path, test_db_factory, registry
):
    await private_team(registry)
    runtime = await make_runtime(tmp_path, test_db_factory, registry)
    client = None
    with pytest.raises(RuntimeError, match="later app startup failed"):
        async with runtime.lifespan(FastAPI()):
            client = runtime.registry_client()
            assert await client.get_team("example.com", "backend") is not None
            raise RuntimeError("later app startup failed")
    assert client is not None and client._http_client.is_closed
    assert runtime.connected_db() is None
    with pytest.raises(RuntimeError, match="not initialized"):
        runtime.registry_client()


async def test_library_verifier_and_owned_plain_sdk_preserve_real_h2_admission(
    tmp_path, test_db_factory, registry, human
):
    from tests.runtime.test_human_member import TEAM

    member, identity, caller_client, _, _ = human
    verifier = caller_client._domain_verifier
    runtime = await make_runtime(tmp_path, test_db_factory, registry, verifier=verifier)
    # Team authentication reads the app's team-key pins, so it runs in the lifespan.
    async with runtime.lifespan(FastAPI()):
        # The caller-owned client is used when the caller injects it.
        before = await runtime.check_human_member(
            TEAM, principal=identity, certificate=member.certificate(), identity_client=caller_client
        )
        owned = runtime.registry_client()
        assert owned is not caller_client and owned._domain_verifier is verifier
        current = await runtime.check_human_member(
            TEAM, principal=identity, certificate=member.certificate()
        )
        assert current.principal == before.principal == identity
        assert current.did_key == before.did_key == member.did_key
    assert owned._http_client.is_closed and not caller_client._http_client.is_closed
