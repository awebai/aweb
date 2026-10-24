"""One production directory and resolver, using real AWID and database fixtures."""

import hashlib
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member, did_key
from fastapi import Depends, FastAPI, HTTPException
from nacl.signing import SigningKey

from aweb_naapp.runtime import team_auth
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, HOOK_RESOLVE, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKeyError, load_app_key
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from tests.runtime.conftest import relying_app
from tests.runtime.test_naapp_runtime import allow_all
from tests.runtime.test_served_manifest import ExampleSettings, _key_file, _v2_template
from tests.runtime.test_team_server_directory import SERVER_URL, TEAM_ID


def _runtime(tmp_path, *, keys=(), registry=None, team_server_transport=None, **settings):
    from aweb_naapp.manifest import canonical_bytes

    files = {kid: _key_file(tmp_path, kid, bytes(SigningKey.generate()).hex()) for kid, _ in keys}
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template(*keys)))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    return NaappRuntime(
        ExampleSettings(
            _env_file=None,
            app_key_files=files,
            awid_registry_url=REGISTRY_URL,
            awid_service_token=SERVICE_TOKEN,
            **settings,
        ),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        awid_transport=registry.transport if registry else None,
        team_server_transport=team_server_transport,
    )


async def test_one_directory_can_be_wired_before_startup_and_resolves_real_awid(
    tmp_path,
    registry,
    test_db_factory,
):
    database = await test_db_factory.create_db(suffix="runtime_services")
    runtime = _runtime(
        tmp_path,
        registry=registry,
        database_url=database.config.get_dsn(),
        keys=(("hooks", [HOOK_RESOLVE]), ("grants", [APP_GRANT_READ])),
    )
    cache = runtime.team_cache()
    directory = runtime.team_server_directory()
    resolver = runtime.hook_resolver()
    source = TeamGrantSource(
        identity=AppIdentity(
            app_id=runtime.manifest.app_id,
            origin=runtime.settings.public_origin,
            digest="sha256:" + hashlib.sha256(runtime.manifest_bytes).hexdigest(),
        ),
        signer=AppCredentialSigner(
            app_id=runtime.manifest.app_id,
            key=load_app_key(runtime.settings, runtime.manifest, APP_GRANT_READ),
            purpose=APP_GRANT_READ,
        ),
        discovery=directory,
    )
    # Registering guards must precede the existing lifespan route validation.
    guard = runtime.authorized(grants=source, policy=allow_all)
    assert resolver._directory is directory
    assert directory._team_cache is cache
    assert not registry.transport.calls
    team_key = SigningKey.generate()
    await registry.add_team(TEAM_ID, did_key(team_key))
    await registry.publish_team_server(
        TEAM_ID,
        team_key,
        server_url=SERVER_URL,
        issued_at=datetime.now(UTC) - timedelta(minutes=1),
    )

    async def no_dns_override(domain):
        return None

    directory._registry_override = no_dns_override
    app = FastAPI(lifespan=runtime.lifespan)

    @app.post("/v1/things", dependencies=[Depends(guard)])
    async def create():
        return {}

    async with app.router.lifespan_context(app):
        assert runtime.team_cache() is cache
        assert runtime.team_server_directory() is directory
        assert runtime.hook_resolver() is resolver
        assert (await directory.resolve(TEAM_ID)).server_url == SERVER_URL
    assert runtime.team_server_directory() is directory
    assert runtime.team_cache() is cache
    assert runtime.connected_db() is None


def test_hook_key_is_loaded_at_construction_and_resolver_is_cached(tmp_path):
    transport = httpx.ASGITransport(app=FastAPI())
    runtime = _runtime(tmp_path, keys=(("hooks", [HOOK_RESOLVE]),), team_server_transport=transport)
    runtime.settings.app_key_files["hooks"].unlink()
    resolver = runtime.hook_resolver()
    assert resolver is runtime.hook_resolver()
    assert resolver._transport is transport
    assert resolver._directory._transport is None
    assert resolver._signer.purpose == HOOK_RESOLVE
    credential = resolver._signer.sign(method="GET", target=SERVER_URL, team_id=TEAM_ID)
    assert credential.did_key == runtime.manifest.app_keys_for(HOOK_RESOLVE)["hooks"]


def test_ambiguous_hook_keys_stop_construction(tmp_path):
    with pytest.raises(AppKeyError):
        _runtime(tmp_path, keys=(("one", [HOOK_RESOLVE]), ("two", [HOOK_RESOLVE])))


@pytest.mark.parametrize("keys", [(), (("grants", [APP_GRANT_READ]),)])
def test_no_hook_purpose_is_valid_but_cannot_obtain_a_resolver(tmp_path, keys):
    runtime = _runtime(tmp_path, keys=keys)
    with pytest.raises(AppKeyError):
        runtime.hook_resolver()


@pytest.mark.parametrize("service_token", [None, SERVICE_TOKEN], ids=["status", "history"])
@pytest.mark.parametrize("state", ["active", "revoked", "unpublished"])
async def test_shared_publication_check_and_request_authentication_agree(
    registry, service_token, state
):
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    if state != "unpublished":
        await registry.add_certificate(member.certificate())
    if state == "revoked":
        await registry.revoke(member.certificate_id)
    cache = team_auth.AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token=service_token,
        transport=registry.transport,
    )
    if state == "active":
        facts = await team_auth.require_active_certificate(
            cache, team_id=TEAM_ID, certificate_id=member.certificate_id
        )
        assert facts.team_did_key == member.team_did_key
    else:
        with pytest.raises(HTTPException) as refused:
            await team_auth.require_active_certificate(
                cache, team_id=TEAM_ID, certificate_id=member.certificate_id
            )
        assert refused.value.status_code == 401
    origin = "https://example.aweb.ai"
    async with relying_app(registry, public_origin=origin, cache=cache) as (client, _):
        response = await client.get(
            "/who", headers=member.headers(aud=origin, method="GET", path="/who")
        )
    assert response.status_code == (200 if state == "active" else 401)


def test_a_declared_hook_key_cannot_be_replaced_by_another_configured_kid(tmp_path):
    from aweb_naapp.manifest import canonical_bytes

    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template(("hooks", [HOOK_RESOLVE]))))
    other = _key_file(tmp_path, "other", bytes(SigningKey.generate()).hex())
    with pytest.raises(AppKeyError):
        NaappRuntime(
            ExampleSettings(_env_file=None, app_key_files={"other": other}),
            module_name="example",
            migrations_path=tmp_path / "migrations",
            manifest_path=manifest,
        )


@pytest.mark.parametrize("service_token", [None, SERVICE_TOKEN], ids=["status", "history"])
async def test_shared_publication_check_preserves_authority_outages(registry, service_token):
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    await registry.add_certificate(member.certificate())

    def outage(request, response):
        response.status_code = 503

    registry.transport.fault = outage
    cache = team_auth.AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token=service_token,
        transport=registry.transport,
    )
    with pytest.raises(HTTPException) as refused:
        await team_auth.require_active_certificate(
            cache, team_id=TEAM_ID, certificate_id=member.certificate_id
        )
    assert refused.value.status_code == 503


async def test_shared_publication_check_preserves_invalid_team_refusal(registry):
    cache = team_auth.AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport
    )
    with pytest.raises(HTTPException) as refused:
        await team_auth.require_active_certificate(cache, team_id="invalid", certificate_id="cert")
    assert refused.value.status_code == 401
    assert isinstance(refused.value.__cause__, ValueError)
    assert not registry.transport.calls
