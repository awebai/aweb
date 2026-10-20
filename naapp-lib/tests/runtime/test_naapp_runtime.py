"""The shared naapp wiring on a real database and real AWID routes.

No ``from __future__ import annotations``: FastAPI resolves the routes'
``Depends(runtime.authorized(...))`` annotations at definition time.
"""

import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from awid.did import stable_id_from_did_key
from fastapi import Depends, FastAPI, Request
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import Authorization, DeclaredTool, DeclaredTools, Grant
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import Principal

from .conftest import REGISTRY_URL, Member, did_key

ORIGIN = "https://app.example"
TOOLS = DeclaredTools.from_manifest(
    {
        "tools": [
            {"name": "create", "method": "POST", "path": "/v1/things", "scopes": ["example:write"]}
        ]
    }
)


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    public_origin: str = ORIGIN
    app_id: str = "example"


class InstalledTeams:
    """A local grant source: the teams that installed the app, with their scopes."""

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


def _migrations(tmp_path: Path) -> Path:
    path = tmp_path / "migrations"
    path.mkdir(parents=True)
    (path / "001_initial.sql").write_text(
        "CREATE TABLE {{tables.things}} (id integer PRIMARY KEY);\n"
    )
    return path


def _app(runtime: NaappRuntime, grants: InstalledTeams) -> FastAPI:
    app = FastAPI(lifespan=runtime.lifespan)
    authorized = runtime.authorized(tools=TOOLS, grants=grants, policy=allow_all)

    @app.post("/v1/things")
    async def create_thing(
        auth: Annotated[Authorization, Depends(authorized)],
        db: Annotated[AsyncDatabaseManager, Depends(runtime.db)],
    ) -> dict[str, object]:
        await db.execute("INSERT INTO {{tables.things}} (id) VALUES (1)")
        return {
            "team_id": auth.principal.team_id,
            "alias": auth.principal.alias,
            "tool": auth.tool.name,
        }

    @app.post("/v1/whoami")
    async def whoami(actor: Annotated[Principal, Depends(runtime.principal)]) -> dict[str, str]:
        return {"alias": actor.alias}

    return app


@pytest.fixture
async def app_database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_app")
    return database.config.get_dsn()


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id="backend:example.com")
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


async def _running(
    registry, app_database_url: str, tmp_path: Path, grants: InstalledTeams, **settings_values: object
) -> AsyncIterator[tuple[NaappRuntime, httpx.AsyncClient]]:
    settings = ExampleSettings(
        _env_file=None, database_url=app_database_url, awid_registry_url=REGISTRY_URL,
        **settings_values,
    )
    runtime = NaappRuntime(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        awid_transport=registry.transport,
    )
    app = _app(runtime, grants)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN
        ) as client:
            yield runtime, client


def _signed(member: Member, path: str, body: bytes = b"{}") -> dict[str, object]:
    return dict(
        content=body,
        headers=member.headers(aud=ORIGIN, method="POST", path=path, body=body),
    )


async def _observed(runtime: NaappRuntime) -> tuple[int, int]:
    db = runtime.db()
    return (
        await db.fetch_value("SELECT count(*) FROM teams"),
        await db.fetch_value("SELECT count(*) FROM agents"),
    )


async def test_an_installed_team_member_is_authorized_and_then_recorded(
    registry, member: Member, app_database_url: str, tmp_path: Path
) -> None:
    grants = InstalledTeams({member.team_id: frozenset({"example:write"})})
    async for runtime, client in _running(registry, app_database_url, tmp_path, grants):
        response = await client.post("/v1/things", **_signed(member, "/v1/things"))
        assert response.status_code == 200, response.text
        assert response.json() == {"team_id": member.team_id, "alias": "alice", "tool": "create"}
        db = runtime.db()
        assert await db.fetch_value("SELECT count(*) FROM things") == 1
        assert await db.fetch_value("SELECT team_did_key FROM teams") == member.team_did_key
        assert await db.fetch_value("SELECT did_key FROM agents") == member.did_key
    assert runtime.connected_db() is None


@pytest.mark.parametrize(
    ("scopes_by_team", "status"),
    [({}, 403), ({"backend:example.com": frozenset({"example:read"})}, 403)],
    ids=["not-installed", "missing-scope"],
)
async def test_a_member_without_the_grant_is_refused_and_not_recorded(
    registry, member: Member, app_database_url: str, tmp_path: Path, scopes_by_team, status
) -> None:
    async for runtime, client in _running(
        registry, app_database_url, tmp_path, InstalledTeams(scopes_by_team)
    ):
        response = await client.post("/v1/things", **_signed(member, "/v1/things"))
        assert response.status_code == status, response.text
        assert response.json()["detail"]["code"] == "scope_denied"
        assert await runtime.db().fetch_value("SELECT count(*) FROM things") == 0
        assert await _observed(runtime) == (0, 0)


async def test_an_unsigned_request_is_refused_and_not_recorded(
    registry, member: Member, app_database_url: str, tmp_path: Path
) -> None:
    grants = InstalledTeams({member.team_id: frozenset({"example:write"})})
    async for runtime, client in _running(registry, app_database_url, tmp_path, grants):
        assert (await client.post("/v1/things", content=b"{}")).status_code == 401
        assert await _observed(runtime) == (0, 0)


async def test_principal_authenticates_only_and_records_nothing(
    registry, member: Member, app_database_url: str, tmp_path: Path
) -> None:
    async for runtime, client in _running(registry, app_database_url, tmp_path, InstalledTeams({})):
        response = await client.post("/v1/whoami", **_signed(member, "/v1/whoami"))
        assert response.status_code == 200, response.text
        assert response.json() == {"alias": "alice"}
        assert await _observed(runtime) == (0, 0)


@pytest.mark.parametrize(("settings_values", "status"), [({}, 401), ({"did_aw_profile": "observe"}, 200)],
                         ids=["required-by-default", "observed"])
async def test_the_runtime_applies_the_configured_did_aw_profile(
    registry, app_database_url: str, tmp_path: Path, settings_values, status
) -> None:
    unregistered = stable_id_from_did_key(did_key(SigningKey.generate()))
    member = Member(team_id="backend:example.com", extra_cert_fields={"member_did_aw": unregistered})
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    async for _, client in _running(registry, app_database_url, tmp_path, InstalledTeams({}), **settings_values):
        response = await client.post("/v1/whoami", **_signed(member, "/v1/whoami"))
        assert response.status_code == status, response.text


async def test_the_database_is_unavailable_outside_the_lifespan(tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, database_url="postgresql://localhost/unused")
    runtime = NaappRuntime(settings, module_name="example", migrations_path=_migrations(tmp_path))
    assert runtime.connected_db() is None
    with pytest.raises(RuntimeError):
        runtime.db()
    with pytest.raises(RuntimeError):
        runtime.team_cache()


# --- Every authorized route must be exactly a declared tool ---------------------

GET_THING = DeclaredTools.from_manifest(
    {
        "tools": [
            {
                "name": "get-thing",
                "method": "GET",
                "path": "/v1/things/{id}",
                "scopes": ["things:read"],
            }
        ]
    }
)


def _guarded_app(
    tmp_path: Path, register, *, tools: DeclaredTools = GET_THING, root_path: str = ""
) -> tuple[NaappRuntime, FastAPI]:
    settings = ExampleSettings(_env_file=None, database_url="postgresql://localhost/unused")
    runtime = NaappRuntime(
        settings, module_name="example", migrations_path=_migrations(tmp_path), root_path=root_path
    )
    app = FastAPI(lifespan=runtime.lifespan)
    register(app, runtime.authorized(tools=tools, grants=InstalledTeams({}), policy=allow_all))
    return runtime, app


def _purge_shadowing_get_thing(app: FastAPI, authorized) -> None:
    @app.get("/v1/things/purge")
    async def purge(auth: Annotated[Authorization, Depends(authorized)]) -> dict[str, str]:
        return {"purged": "everything"}

    @app.get("/v1/things/{id}")
    async def get_thing(
        id: str, auth: Annotated[Authorization, Depends(authorized)]
    ) -> dict[str, str]:
        return {"id": id}


async def test_an_app_whose_route_shadows_a_declared_tool_fails_to_start(tmp_path: Path) -> None:
    runtime, app = _guarded_app(tmp_path, _purge_shadowing_get_thing)
    with pytest.raises(RuntimeError, match="/v1/things/purge"):
        async with app.router.lifespan_context(app):
            pass
    assert runtime.connected_db() is None


def _renamed_placeholder(app: FastAPI, authorized) -> None:
    @app.get("/v1/things/{thing_id}")
    async def get_thing(thing_id: str, auth: Annotated[Authorization, Depends(authorized)]) -> dict:
        return {}


def _route_level_dependency(app: FastAPI, authorized) -> None:
    @app.get("/v1/things/{id}", dependencies=[Depends(authorized)])
    async def get_thing(id: str) -> dict:
        return {}


def _unguarded_extra_route(app: FastAPI, authorized) -> None:
    _renamed_placeholder(app, authorized)

    @app.get("/v1/things/public/list")
    async def listing() -> dict:
        return {}


@pytest.mark.parametrize(
    "register", [_renamed_placeholder, _route_level_dependency, _unguarded_extra_route]
)
def test_routes_that_are_exactly_declared_tools_pass(tmp_path: Path, register) -> None:
    runtime, app = _guarded_app(tmp_path, register)
    runtime.check_authorized_routes(app)


def _wrong_method(app: FastAPI, authorized) -> None:
    @app.post("/v1/things/{id}")
    async def change(id: str, auth: Annotated[Authorization, Depends(authorized)]) -> dict:
        return {}


def _extra_method(app: FastAPI, authorized) -> None:
    @app.api_route("/v1/things/{id}", methods=["GET", "DELETE"])
    async def either(id: str, auth: Annotated[Authorization, Depends(authorized)]) -> dict:
        return {}


def _path_converter(app: FastAPI, authorized) -> None:
    @app.get("/v1/things/{id:path}")
    async def anything(id: str, auth: Annotated[Authorization, Depends(authorized)]) -> dict:
        return {}


def _nested_dependency(app: FastAPI, authorized) -> None:
    async def actor(auth: Annotated[Authorization, Depends(authorized)]) -> str:
        return auth.principal.alias

    @app.get("/v1/things/{id}/purge")
    async def purge(id: str, who: Annotated[str, Depends(actor)]) -> dict:
        return {}


@pytest.mark.parametrize(
    "register",
    [_purge_shadowing_get_thing, _wrong_method, _extra_method, _path_converter, _nested_dependency],
)
def test_routes_that_are_not_exactly_declared_tools_are_refused(tmp_path: Path, register) -> None:
    runtime, app = _guarded_app(tmp_path, register)
    with pytest.raises(RuntimeError):
        runtime.check_authorized_routes(app)


def test_the_root_path_is_part_of_the_declared_path(tmp_path: Path) -> None:
    runtime, app = _guarded_app(tmp_path / "unprefixed", _renamed_placeholder, root_path="/mounted")
    with pytest.raises(RuntimeError):
        runtime.check_authorized_routes(app)
    prefixed = DeclaredTools.from_manifest(
        {
            "tools": [
                {
                    "name": "get-thing",
                    "method": "GET",
                    "path": "/mounted/v1/things/{id}",
                    "scopes": ["r"],
                }
            ]
        }
    )
    runtime, app = _guarded_app(
        tmp_path / "prefixed", _renamed_placeholder, tools=prefixed, root_path="/mounted/"
    )
    runtime.check_authorized_routes(app)


def _mounted(sub_path: str, mount_at: str):
    def register(app: FastAPI, authorized) -> None:
        sub = FastAPI()

        @sub.get(sub_path)
        async def handler(auth: Annotated[Authorization, Depends(authorized)]) -> dict:
            return {}

        app.mount(mount_at, sub)

    return register


def test_a_guarded_route_in_a_mounted_app_is_refused(tmp_path: Path) -> None:
    for name, register in (
        ("declared", _mounted("/things/{id}", "/v1")),
        ("shadow", _mounted("/things/purge", "/v1")),
    ):
        runtime, app = _guarded_app(tmp_path / name, register)
        with pytest.raises(RuntimeError, match="mounted"):
            runtime.check_authorized_routes(app)


def test_a_mounted_app_without_guarded_routes_is_allowed(tmp_path: Path) -> None:
    def register(app: FastAPI, authorized) -> None:
        _renamed_placeholder(app, authorized)
        sub = FastAPI()

        @sub.get("/status")
        async def status() -> dict:
            return {}

        app.mount("/public", sub)

    runtime, app = _guarded_app(tmp_path, register)
    runtime.check_authorized_routes(app)


def test_a_guarded_route_under_a_host_route_is_refused(tmp_path: Path) -> None:
    from starlette.routing import Host

    def register(app: FastAPI, authorized) -> None:
        sub = FastAPI()

        @sub.get("/v1/things/{id}")
        async def handler(id: str, auth: Annotated[Authorization, Depends(authorized)]) -> dict:
            return {}

        app.router.routes.append(Host("api.example", app=sub))

    runtime, app = _guarded_app(tmp_path, register)
    with pytest.raises(RuntimeError):
        runtime.check_authorized_routes(app)
