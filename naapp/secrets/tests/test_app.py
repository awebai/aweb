"""The secrets service on the shared runtime: its two origins, its tools behind
team-auth, its manifest and its health. Real AWID routes, real PostgreSQL."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
import pytest
from aweb_naapp.manifest import canonical_bytes, fill_manifest, load_manifest
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.app_keys import AppKeyError
from aweb_naapp.runtime.authorization import DeclaredTool, Grant
from aweb_naapp.runtime.health import CheckResult, HealthCheck
from aweb_naapp.runtime.team_auth import Principal
from aweb_naapp_testing import REGISTRY_URL, Member, attested
from awid.did import did_from_public_key
from fastapi import Request
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME, SecretsService, create_app
from aweb_secrets.config import SecretsSettings
from aweb_secrets.manifest import MANIFEST, MANIFEST_PATH

API = "https://api.secrets.test"
CONSOLE = "https://console.secrets.test"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TOOLS = MANIFEST["tools"]
EXAMPLE_PATH_VALUES = {
    "secret": "stripe-test",
    "job": "deploy-staging",
    "ref": "req-1",
    "request_id": "req-1",
}


class InstalledTeams:
    """The teams that installed secrets, with their granted scopes."""

    def __init__(self, scopes_by_team: dict[str, frozenset[str]]) -> None:
        self.scopes_by_team = scopes_by_team

    async def grant_for(self, team_id: str) -> Grant | None:
        scopes = self.scopes_by_team.get(team_id)
        if scopes is None:
            return None
        return Grant(
            team_id=team_id,
            scopes=scopes,
            fresh_until=time.monotonic() + 60,
            installation_id=None,
            generation=None,
        )


async def allow_all(request: Request, principal: Principal, tool: DeclaredTool) -> bool:
    return True


def kms_check(ok: bool) -> HealthCheck:
    async def check() -> CheckResult:
        return CheckResult(ok=ok)

    return check


ALL_SCOPES = frozenset(scope for tool in TOOLS for scope in tool["scopes"])


@dataclass
class Running:
    service: SecretsService
    api: httpx.AsyncClient
    console: httpx.AsyncClient


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id="backend:example.com")
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


@pytest.fixture
async def database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="secrets_app")
    return database.config.get_dsn()


KEY_PURPOSES = {
    "secrets:hook-event-1": ["hook-event"],
    "secrets:hook-delivery-1": ["hook-delivery"],
    "secrets:grant-read-1": ["app-grant-read"],
    "secrets:hook-resolve-1": ["hook-resolve"],
}


def _key_files(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    keys = {}
    for number, kid in enumerate(KEY_PURPOSES):
        path = directory / f"key-{number}"
        path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
        path.chmod(0o600)
        keys[kid] = path
    return keys


def _settings(database_url: str, directory: Path) -> SecretsSettings:
    return SecretsSettings(
        _env_file=None,
        database_url=database_url,
        public_origin=API,
        app_id="secrets-test",
        console_origin=CONSOLE,
        awid_registry_url=REGISTRY_URL,
        app_key_files=_key_files(directory),
    )


@asynccontextmanager
async def running(
    registry, database_url: str, *, grants: InstalledTeams, kms_ok: bool = True, tool_routers=()
) -> AsyncIterator[Running]:
    with TemporaryDirectory() as directory:
        settings = _settings(database_url, Path(directory))
        service = create_app(
            settings,
            grants=grants,
            policy=allow_all,
            kms=kms_check(kms_ok),
            awid_transport=registry.transport,
            tool_routers=tool_routers,
        )
        async with service.api_app.router.lifespan_context(service.api_app):
            async with (
                httpx.AsyncClient(transport=httpx.ASGITransport(app=service), base_url=API) as api,
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=service), base_url=CONSOLE
                ) as console,
            ):
                yield Running(service, api, console)


async def test_the_database_holds_every_table_admission_reads(registry, database_url) -> None:
    async with running(registry, database_url, grants=InstalledTeams({})) as running_app:
        db = running_app.service.runtime.db()
        for table in (
            "secrets",
            "grants",
            "intents",
            "role_assignments",
            "idempotency_keys",
            "installation_fences",
            "config_revisions",
        ):
            assert await db.fetch_value(f"SELECT to_regclass('{table}') IS NOT NULL"), table


async def test_records_migrations_leave_rate_buckets_to_the_shared_store(test_db_factory) -> None:
    db = await test_db_factory.create_db(suffix="records_without_buckets")
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    assert not await db.fetch_value("SELECT to_regclass('rate_buckets') IS NOT NULL")


async def _rate_bucket_shape(db: AsyncDatabaseManager) -> tuple[list[dict], list[dict]]:
    columns = await db.fetch_all(
        """
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'rate_buckets'
        ORDER BY ordinal_position
        """
    )
    constraints = await db.fetch_all(
        """
        SELECT contype, pg_get_constraintdef(oid) AS definition FROM pg_constraint
        WHERE conrelid = 'rate_buckets'::regclass ORDER BY contype, definition
        """
    )
    return [dict(row) for row in columns], [dict(row) for row in constraints]


async def test_startup_has_exactly_the_shared_rate_bucket_shape(
    registry, database_url, test_db_factory
) -> None:
    reference = await test_db_factory.create_db(suffix="shared_rate_bucket_shape")
    await apply_ratelimit_migrations(reference)
    expected = await _rate_bucket_shape(reference)
    assert expected[0]
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        assert await _rate_bucket_shape(app.service.runtime.db()) == expected


def _path(tool: dict) -> str:
    path = tool["path"]
    for name, value in EXAMPLE_PATH_VALUES.items():
        path = path.replace("{" + name + "}", value)
    assert "{" not in path, path
    return path


def _signed(member: Member, tool: dict, *, aud: str = API) -> dict:
    body = b"{}" if tool["method"] != "GET" else b""
    return dict(
        method=tool["method"],
        url=_path(tool),
        content=body,
        headers=member.headers(aud=aud, method=tool["method"], path=_path(tool), body=body),
    )


# --- The manifest -------------------------------------------------------------


def test_the_committed_manifest_is_the_authoring_manifest() -> None:
    assert MANIFEST_PATH.read_bytes() == canonical_bytes(MANIFEST)


def test_every_tool_is_signed_with_team_auth_and_declares_its_scopes() -> None:
    assert TOOLS
    for tool in TOOLS:
        assert tool.get("auth") != "none", tool["name"]
        assert tool["scopes"], tool["name"]


def test_no_tool_handles_a_secret_value() -> None:
    names = {tool["name"] for tool in TOOLS}
    assert names == {
        "list",
        "describe",
        "request",
        "run",
        "status",
        "cancel",
        "contain",
        "propose-change",
        "activity",
    }


async def test_the_manifest_is_served_on_the_api_origin_only(registry, database_url) -> None:
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        for path in ("/manifests/v2.json", "/aweb-app.json"):
            response = await app.api.get(path)
            assert response.status_code == 200
            assert response.json()["tools"] == TOOLS
            assert response.json()["app"]["origin"] == API
            assert (await app.console.get(path)).status_code == 404
        assert (await app.api.get("/.well-known/aweb-app.json")).status_code == 404
        catalog = await app.api.get("/.well-known/aweb-app-versions.json")
        assert catalog.status_code == 200
        manifest = await app.api.get("/aweb-app.json")
        assert catalog.json() == {
            "catalog_version": 1,
            "app_id": "secrets-test",
            "variants": [
                {
                    "manifest_version": 2,
                    "url": "/manifests/v2.json",
                    "digest": "sha256:" + hashlib.sha256(manifest.content).hexdigest(),
                }
            ],
        }
        assert (await app.console.get("/.well-known/aweb-app-versions.json")).status_code == 404


# --- Every tool is admitted only through team-auth ----------------------------


@pytest.mark.parametrize("tool", TOOLS, ids=[tool["name"] for tool in TOOLS])
async def test_a_tool_admits_a_signed_installed_member_and_refuses_an_unsigned_request(
    registry, database_url, member, tool
) -> None:
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants) as app:
        unsigned = await app.api.request(tool["method"], _path(tool))
        assert unsigned.status_code == 401
        admitted = await app.api.request(**_signed(member, tool))
        if tool["invocation_contexts"] == ["surface"]:
            assert admitted.status_code == 403
            assert admitted.json()["detail"]["code"] == "tool_context_denied"
        else:
            assert admitted.status_code == 501, admitted.text
            assert admitted.json()["detail"]["code"] == "not_implemented"


async def test_a_member_whose_team_has_not_installed_secrets_is_refused(
    registry, database_url, member
) -> None:
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        response = await app.api.request(**_signed(member, TOOLS[0]))
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "scope_denied"


# --- The API origin: a cookie gains nothing -----------------------------------


async def test_a_cookie_alone_is_refused_like_no_credential(registry, database_url, member) -> None:
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants) as app:
        tool = TOOLS[0]
        bare = await app.api.request(tool["method"], _path(tool))
        with_cookie = await app.api.request(
            tool["method"], _path(tool), headers={"Cookie": "__Host-console=a-console-session"}
        )
        assert (with_cookie.status_code, with_cookie.json()) == (bare.status_code, bare.json())
        assert with_cookie.status_code == 401


async def test_a_cookie_on_a_signed_request_changes_nothing(registry, database_url, member) -> None:
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants) as app:
        tool = TOOLS[0]
        signed = _signed(member, tool)
        plain = await app.api.request(**signed)
        signed["headers"] = {**signed["headers"], "Cookie": "__Host-console=a-console-session"}
        with_cookie = await app.api.request(**signed)
        assert (with_cookie.status_code, with_cookie.json()) == (plain.status_code, plain.json())
        assert "set-cookie" not in with_cookie.headers


# --- The console origin refuses team-auth -------------------------------------


async def test_a_signed_team_auth_request_to_the_console_is_refused(
    registry, database_url, member
) -> None:
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants) as app:
        for tool in TOOLS:
            response = await app.console.request(**_signed(member, tool, aud=CONSOLE))
            assert response.status_code == 403
            assert response.json()["code"] == "team_auth_refused"
        assert (await app.console.get("/live")).status_code == 200


async def test_no_tool_is_reachable_on_the_console(registry, database_url, member) -> None:
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        for tool in TOOLS:
            response = await app.console.request(tool["method"], _path(tool))
            assert response.status_code == 404, tool["name"]


# --- Health --------------------------------------------------------------------


async def test_health_reports_the_commit_the_database_kms_and_the_outbox(
    registry, database_url, monkeypatch
) -> None:
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.setenv("SECRETS_GIT_SHA", COMMIT)
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        response = await app.api.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["service"] == "secrets-test"
        assert body["build"] == {"git_sha": COMMIT}
        assert body["checks"] == {
            "database": {"ok": True},
            "outbox": {"ok": True, "oldest_undelivered_age_seconds": None},
            "kms": {"ok": True},
        }
        assert (await app.api.get("/ready")).status_code == 200


async def test_the_service_is_not_ready_without_kms(registry, database_url) -> None:
    async with running(registry, database_url, grants=InstalledTeams({}), kms_ok=False) as app:
        ready = await app.api.get("/ready")
        assert ready.status_code == 503
        assert ready.json()["checks"]["kms"] == {"ok": False}
        assert (await app.console.get("/ready")).status_code == 503


async def test_a_failing_check_serves_no_error_detail(registry, database_url, tmp_path) -> None:
    async def failing_kms() -> CheckResult:
        raise RuntimeError("KMSInvalidStateException: arn:aws:kms:eu-west-1:000000000000:key/x")

    settings = _settings(database_url, tmp_path)
    service = create_app(
        settings,
        grants=InstalledTeams({}),
        policy=allow_all,
        kms=failing_kms,
        awid_transport=registry.transport,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service), base_url=API) as api:
        # Outside the lifespan the database is down too.
        for client_path in ("/ready", "/health"):
            response = await api.get(client_path)
            assert "KMSInvalidState" not in response.text
            assert "arn:" not in response.text
            assert response.json()["checks"]["kms"] == {"ok": False}
            assert response.json()["checks"]["database"] == {"ok": False}
        assert set((await api.get("/ready")).json()["checks"]) == {"database", "outbox", "kms"}


async def test_the_served_v2_bytes_come_from_the_template_and_configured_keys(
    registry, database_url
) -> None:
    async with running(registry, database_url, grants=InstalledTeams({})) as app:
        runtime = app.service.runtime
        keys = {
            kid: did_from_public_key(
                bytes(SigningKey(bytes.fromhex(path.read_text().strip())).verify_key)
            )
            for kid, path in runtime.settings.app_key_files.items()
        }
        expected = fill_manifest(MANIFEST, app_id="secrets-test", origin=API, did_keys=keys)
        response = await app.api.get("/aweb-app.json")
        assert response.content == expected == runtime.manifest_bytes
        resolved = load_manifest(response.content)
        assert resolved.manifest_version == 2
        assert {kid: list(purposes) for kid, _, purposes in resolved.app_keys} == KEY_PURPOSES
        assert {kid: did for kid, did, _ in resolved.app_keys} == keys
        # Producing secrets runtimes must have the purpose-specific resolver
        # needed by K4, rather than substituting an event or delivery key.
        assert resolved.app_keys_for("hook-resolve") == {
            "secrets:hook-resolve-1": keys["secrets:hook-resolve-1"]
        }
        assert runtime.hook_resolver() is runtime.hook_resolver()
        assert runtime.hook_registrations() is runtime.hook_registrations()
        producer = runtime.hook_producer(
            installation_id="1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b", generation=1
        )
        assert producer.producer.did_key == keys["secrets:hook-event-1"]
        assert producer.producer.did_key != keys["secrets:hook-resolve-1"]


async def test_a_verified_dashboard_member_reaches_every_declared_tool(
    registry, database_url, member
) -> None:
    issuer = SigningKey.generate()
    custodian = "console.secrets.test"
    await registry.add_custody(member, custodian_id=custodian, issuer=issuer)
    async with running(
        registry, database_url, grants=InstalledTeams({member.team_id: ALL_SCOPES})
    ) as app:
        for tool in TOOLS:
            signed = _signed(member, tool)
            signed["headers"] = attested(
                member,
                signed["headers"],
                issuer=issuer,
                custodian_id=custodian,
                channel="dashboard",
            )
            response = await app.api.request(**signed)
            assert response.status_code == 501
            assert response.json()["detail"]["code"] == "not_implemented"


def test_the_template_declares_only_signed_tools_and_the_two_hook_productions() -> None:
    assert MANIFEST["manifest_version"] == 2
    assert {key["kid"]: key["purposes"] for key in MANIFEST["app_keys"]} == KEY_PURPOSES
    assert all("did_key" not in key for key in MANIFEST["app_keys"])
    for tool in TOOLS:
        assert tool.get("auth", "") == ""
        assert tool["invocation_contexts"] == (
            ["surface"] if tool["name"] in {"propose-change", "activity"} else ["agent", "surface"]
        )
    hooks = MANIFEST["hooks"]
    assert hooks["registration_version"] == 1
    assert hooks.get("registrations", []) == []
    assert {item["hook"] for item in hooks["productions"]} == {
        "post-secret-use-hook",
        "post-governance-hook",
    }
    assert all(
        item["catalog"] == {"id": "aweb.hooks", "version": 1} for item in hooks["productions"]
    )


def test_app_key_configuration_is_taken_from_the_secrets_environment(tmp_path, monkeypatch) -> None:
    keys = _key_files(tmp_path)
    monkeypatch.setenv(
        "SECRETS_APP_KEY_FILES", json.dumps({kid: str(path) for kid, path in keys.items()})
    )
    assert SecretsSettings(_env_file=None).app_key_files == keys


def test_an_undeclared_configured_key_is_refused_before_startup(tmp_path) -> None:
    settings = _settings("postgresql://localhost/unused", tmp_path)
    settings.app_key_files["secrets:undeclared"] = next(iter(settings.app_key_files.values()))
    with pytest.raises(AppKeyError):
        create_app(settings, grants=InstalledTeams({}), policy=allow_all, kms=kms_check(True))


@pytest.mark.parametrize("kid", KEY_PURPOSES)
def test_every_declared_key_must_be_configured(tmp_path, kid: str) -> None:
    settings = _settings("postgresql://localhost/unused", tmp_path)
    settings.app_key_files.pop(kid)
    with pytest.raises(AppKeyError):
        create_app(settings, grants=InstalledTeams({}), policy=allow_all, kms=kms_check(True))


def test_the_hosted_identity_is_refused_at_another_reachable_origin(tmp_path) -> None:
    settings = _settings("postgresql://localhost/unused", tmp_path)
    settings.app_id = "secrets"
    with pytest.raises(ValueError):
        create_app(settings, grants=InstalledTeams({}), policy=allow_all, kms=kms_check(True))


async def test_composed_tool_router_keeps_the_exact_runtime_guard_and_other_tools_unavailable(
    registry, database_url, member
):
    from fastapi import APIRouter, Depends

    def routes(runtime, authorized):
        router = APIRouter()
        dependency = Depends(authorized)

        @router.get("/v1/secrets")
        async def listed(auth=dependency):
            assert runtime.db is not None
            return {"state": "completed", "request_id": None, "tool": auth.tool.name}

        return router

    tool = next(t for t in TOOLS if t["name"] == "list")
    unmounted = next(t for t in TOOLS if t["name"] == "describe")
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants, tool_routers=(routes,)) as app:
        assert (await app.api.request(tool["method"], _path(tool))).status_code == 401
        accepted = await app.api.request(**_signed(member, tool))
        assert accepted.status_code == 200
        assert accepted.json()["tool"] == "list"
        assert (await app.api.request(**_signed(member, unmounted))).status_code == 501
        assert (await app.console.request(**_signed(member, tool, aud=CONSOLE))).status_code == 403


async def test_composition_guards_a_router_even_when_its_endpoint_omits_the_dependency(
    registry, database_url, member
):
    from fastapi import APIRouter

    def routes(runtime, authorized):
        router = APIRouter()

        @router.get("/v1/secrets")
        async def listed():
            return {"state": "completed", "request_id": None}

        return router

    tool = next(t for t in TOOLS if t["name"] == "list")
    grants = InstalledTeams({member.team_id: ALL_SCOPES})
    async with running(registry, database_url, grants=grants, tool_routers=(routes,)) as app:
        assert (await app.api.request(tool["method"], _path(tool))).status_code == 401
        assert (await app.api.request(**_signed(member, tool))).status_code == 200
