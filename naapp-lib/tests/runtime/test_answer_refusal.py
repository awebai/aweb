"""Answers reach a naapp only through a surface's answer tool, on real requests.

The manifest is the shared v2 vectors' base manifest: a surface whose invoke
tool performs page actions, and whose answer tool alone takes answers.

No ``from __future__ import annotations``: FastAPI resolves the routes'
``Depends(...)`` annotations at definition time.
"""

import copy
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, Member, attested
from fastapi import Depends, FastAPI, Request
from nacl.signing import SigningKey
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import canonical_bytes, write_manifest_file
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.authorization import ActionKind, Authorization, DeclaredTool, Grant
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import Principal

from ..test_manifest_v2_vectors import V2
from .test_runtime_manifest_vectors import _as_template

MANIFEST = V2["base_manifests"]["v2"]
ORIGIN = MANIFEST["app"]["origin"]
SCOPES = frozenset(scope for tool in MANIFEST["tools"] for scope in tool["scopes"])
CUSTODIAN = "custodian.example"

# The app's page action definitions: action_id to kind.
PAGE_ACTIONS = {"refresh": "command", "approve": "answer"}


class FixtureSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="FIXTURE_")

    public_origin: str = ORIGIN
    app_id: str = "fixture"


class AllGranted:
    async def grant_for(self, team_id: str) -> Grant | None:
        return Grant(team_id=team_id, scopes=SCOPES, fresh_until=time.monotonic() + 60,
                     installation_id=None, generation=None)


async def allow_all(request: Request, principal: Principal, tool: DeclaredTool) -> bool:
    return True


async def page_action_kind(request: Request, principal: Principal, tool: DeclaredTool) -> str | None:
    """The kind of the page action named by the body's ``request.action_id``."""
    body = json.loads(await request.body() or b"{}")
    invocation = body.get("request") if isinstance(body, dict) else None
    action_id = invocation.get("action_id") if isinstance(invocation, dict) else None
    return PAGE_ACTIONS.get(action_id) if isinstance(action_id, str) else None


@pytest.fixture
async def app_database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_answers")
    return database.config.get_dsn()


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id="backend:example.com")
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


ROUTES = ("/v1/workspaces/{page_id}/invoke", "/v1/workspaces/{page_id}/answers", "/v1/export")


async def _running(
    registry, app_database_url: str, tmp_path: Path, *, action_kind: ActionKind | None,
    manifest: dict[str, Any] = MANIFEST, routes: tuple[str, ...] = ROUTES,
) -> AsyncIterator[httpx.AsyncClient]:
    manifest_path = tmp_path / "aweb-app.json"
    template, key_files, _ = _as_template(canonical_bytes(manifest), tmp_path / "keys")
    write_manifest_file(manifest_path, template)
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    runtime = NaappRuntime(
        FixtureSettings(
            _env_file=None, database_url=app_database_url, awid_registry_url=REGISTRY_URL,
            app_key_files=key_files,
        ),
        module_name="fixture",
        migrations_path=migrations,
        manifest_path=manifest_path,
        awid_transport=registry.transport,
    )
    app = FastAPI(lifespan=runtime.lifespan)
    authorized = runtime.authorized(grants=AllGranted(), policy=allow_all, action_kind=action_kind)

    async def admitted(auth: Annotated[Authorization, Depends(authorized)]) -> dict[str, str]:
        return {"tool": auth.tool.name}

    for path in routes:
        app.add_api_route(path, admitted, methods=["POST"])
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield client


async def _post(client, member, path: str, body: dict[str, Any], **attestation: Any) -> tuple[int, str | None]:
    content = json.dumps(body).encode()
    headers = member.headers(aud=ORIGIN, method="POST", path=path, body=content)
    if attestation:
        headers = attested(member, headers, **attestation)
    response = await client.post(path, content=content, headers={**headers, "Content-Type": "application/json"})
    if response.status_code == 200:
        return 200, None
    return response.status_code, response.json()["detail"]["code"]


INVOKE = "/v1/workspaces/w1/invoke"
ANSWER = "/v1/workspaces/w1/answers"
EXPORT = "/v1/export"


async def test_an_invoke_action_that_is_not_an_answer_is_admitted(registry, app_database_url, tmp_path, member):
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        assert await _post(client, member, INVOKE, {"request": {"action_id": "refresh"}}) == (200, None)


async def test_an_answer_kind_action_through_the_invoke_tool_is_refused(
    registry, app_database_url, tmp_path, member
):
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        outcome = await _post(client, member, INVOKE, {"request": {"action_id": "approve"}})
    assert outcome == (403, "answer_action_refused")


async def test_an_answer_kind_action_through_another_agent_tool_is_refused(
    registry, app_database_url, tmp_path, member
):
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        assert await _post(client, member, EXPORT, {"page_id": "w1"}) == (200, None)
        outcome = await _post(client, member, EXPORT, {"page_id": "w1", "request": {"action_id": "approve"}})
    assert outcome == (403, "answer_action_refused")


async def test_an_invoke_action_whose_kind_cannot_be_resolved_is_refused(
    registry, app_database_url, tmp_path, member
):
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        unknown = await _post(client, member, INVOKE, {"request": {"action_id": "no-such-action"}})
        unnamed = await _post(client, member, INVOKE, {"request": {}})
    assert unknown == unnamed == (403, "action_unresolved")


async def test_an_app_guarding_its_invoke_tool_without_an_action_kind_does_not_start(
    registry, app_database_url, tmp_path, member
):
    with pytest.raises(RuntimeError, match="workspace-invoke"):
        async for _client in _running(registry, app_database_url, tmp_path, action_kind=None):
            pass


async def test_an_app_that_does_not_route_its_invoke_tool_needs_no_action_kind(
    registry, app_database_url, tmp_path, member
):
    async for client in _running(
        registry, app_database_url, tmp_path, action_kind=None, routes=("/v1/export",)
    ):
        assert await _post(client, member, EXPORT, {"page_id": "w1"}) == (200, None)


async def test_a_body_carrying_an_answer_member_is_refused_outside_the_answer_tool(
    registry, app_database_url, tmp_path, member
):
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        top_level = await _post(client, member, EXPORT, {"page_id": "w1", "answer": "x"})
        nested = await _post(client, member, INVOKE, {"request": {"action_id": "refresh", "answer": None}})
    assert top_level == nested == (403, "answer_payload_refused")


async def test_the_answer_tool_takes_answers_from_a_surface(registry, app_database_url, tmp_path, member):
    issuer = SigningKey.generate()
    await registry.add_custody(member, custodian_id=CUSTODIAN, issuer=issuer)
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind):
        outcome = await _post(
            client, member, ANSWER, {"request": {"action_id": "approve", "answer": {"choice": "accept"}}},
            issuer=issuer, custodian_id=CUSTODIAN, channel="dashboard",
        )
    assert outcome == (200, None)


async def test_a_raw_body_is_not_inspected_for_answer_members(registry, app_database_url, tmp_path, member):
    manifest = copy.deepcopy(MANIFEST)
    export = next(t for t in manifest["tools"] if t["name"] == "workspace-export")
    export["params"] = [{"name": "document", "in": "body"}]
    export["input_schema"] = {"type": "object", "properties": {"document": {"type": "string"}},
                              "required": ["document"], "additionalProperties": False}
    export["body"] = {"mode": "raw", "raw_param": "document", "content_type": "application/json"}
    async for client in _running(registry, app_database_url, tmp_path, action_kind=page_action_kind,
                                 manifest=manifest):
        assert await _post(client, member, EXPORT, {"answer": "a field in an uploaded document"}) == (200, None)


async def test_an_invoke_tool_is_known_by_the_name_the_manifest_resolves(
    registry, app_database_url, tmp_path, member
):
    # U+001F is not whitespace to the manifest's reader, so it is part of the name.
    manifest = copy.deepcopy(MANIFEST)
    renamed = "workspace-invoke\x1f"
    next(t for t in manifest["tools"] if t["name"] == "workspace-invoke")["name"] = renamed
    manifest["surfaces"][0]["invoke_tool"] = renamed
    with pytest.raises(RuntimeError, match="workspace-invoke"):
        async for _client in _running(registry, app_database_url, tmp_path, action_kind=None, manifest=manifest):
            pass
