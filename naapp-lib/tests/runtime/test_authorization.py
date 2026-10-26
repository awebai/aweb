"""Authorization after authentication: declared tool, installed grant, app policy.

Requests are signed for real and authenticated against real AWID. The grant
source here is an app-supplied implementation of the seam, as a naapp would
supply one; it holds explicit grant records rather than imitating a service.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
import pytest
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL
from fastapi import FastAPI, HTTPException, Request

from aweb_naapp.manifest import canonical_bytes, load_manifest
from aweb_naapp.runtime.authorization import (
    DeclaredTools,
    Grant,
    GrantUnavailable,
    authorize_request,
)
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from tests.runtime.conftest import relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"

def in_path(name: str) -> dict:
    """The params and input_schema a tool needs to take ``name`` from its path."""
    return {
        "params": [{"name": name, "in": "path"}],
        "input_schema": {"type": "object", "properties": {name: {"type": "string"}}, "required": [name]},
    }


MANIFEST = {
    "app": {"id": "fixture", "origin": ORIGIN, "version": "1"},
    "manifest_version": 1,
    "tools": [
        {"name": "list", "method": "GET", "path": "/v1/items", "scopes": ["fixture:read"]},
        {"name": "get", "method": "GET", "path": "/v1/items/{item_id}",
         **in_path("item_id"), "scopes": ["fixture:read"]},
        {"name": "create", "method": "POST", "path": "/v1/items", "scopes": ["fixture:write"]},
        {"name": "archive", "method": "POST", "path": "/v1/items/{item_id}/archive",
         **in_path("item_id"), "scopes": ["fixture:read", "fixture:write"]},
        {"name": "catalog", "method": "GET", "path": "/v1/catalog", "auth": "none", "scopes": ["fixture:read"]},
    ],
}


def declared(*tools: dict, version: int = 1) -> DeclaredTools:
    """The tools of an app manifest declaring ``tools``, read as the runtime reads it."""
    manifest = {"manifest_version": version, "app": {"id": "fixture", "origin": ORIGIN}, "tools": list(tools)}
    return DeclaredTools.from_manifest(load_manifest(canonical_bytes(manifest)))


@dataclass
class InstalledGrants:
    """The app's grant source: explicit records per team, or an outage."""

    grants: dict[str, Grant] = field(default_factory=dict)
    unavailable: bool = False
    asked: list[str] = field(default_factory=list)

    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        self.asked.append(team_id)
        if self.unavailable:
            raise GrantUnavailable("grant authority unreachable")
        return self.grants.get(team_id)


def fresh(*scopes: str, team_id: str = TEAM_ID, installation_id: str | None = None,
          generation: int | None = None) -> Grant:
    return Grant(team_id=team_id, scopes=frozenset(scopes), fresh_until=time.monotonic_ns() + seconds_to_ns(60),
                 installation_id=installation_id, generation=generation)


@dataclass
class Policy:
    """App policy: only the item's owner alias may archive it."""

    owners: dict[str, str] = field(default_factory=dict)
    seen: list[tuple[str, str]] = field(default_factory=list)

    async def __call__(self, request, principal, tool) -> bool:
        self.seen.append((principal.alias, tool.name))
        if tool.name != "archive":
            return True
        return self.owners.get(request.path_params["route"].split("/")[2]) == principal.alias


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


def serve(grants, policy, tools=None, caller="agent"):
    tools = tools or DeclaredTools.from_manifest(load_manifest(canonical_bytes(MANIFEST)))

    async def on_principal(request, principal):
        authorization = await authorize_request(
            request, principal=principal, caller=caller, tools=tools, grants=grants, policy=policy,
        )
        return {
            "tool": authorization.tool.name,
            "alias": authorization.principal.alias,
            "installation_id": authorization.grant.installation_id,
        }

    return on_principal


async def call(registry, member, grants, policy, method, path, *, tools=None, caller="agent"):
    on_principal = serve(grants, policy, tools, caller)
    async with relying_app(registry, public_origin=ORIGIN, on_principal=on_principal) as (client, _):
        return await client.request(method, path, headers=member.headers(aud=ORIGIN, method=method, path=path))


def detail_code(response) -> str:
    return response.json()["detail"]["code"]


async def test_granted_declared_tool_reaches_the_policy_and_is_authorized(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", installation_id="inst-1", generation=3)})
    policy = Policy()
    response = await call(registry, member, grants, policy, "GET", "/v1/items/abc?view=full")
    assert response.status_code == 200, response.text
    assert response.json() == {"tool": "get", "alias": "alice", "installation_id": "inst-1"}
    assert policy.seen == [("alice", "get")]


async def test_grant_lacking_the_tools_scope_is_scope_denied(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    policy = Policy()
    response = await call(registry, member, grants, policy, "POST", "/v1/items")
    assert response.status_code == 403
    assert detail_code(response) == "scope_denied"
    assert policy.seen == []


async def test_every_scope_of_the_tool_is_required(registry, member):
    policy = Policy(owners={"abc": "alice"})
    partial = InstalledGrants({TEAM_ID: fresh("fixture:write")})
    assert detail_code(await call(registry, member, partial, policy, "POST", "/v1/items/abc/archive")) == "scope_denied"
    full = InstalledGrants({TEAM_ID: fresh("fixture:write", "fixture:read")})
    assert (await call(registry, member, full, policy, "POST", "/v1/items/abc/archive")).status_code == 200


async def test_team_without_an_installation_is_scope_denied(registry, member):
    grants = InstalledGrants({"other:example.com": fresh("fixture:read", team_id="other:example.com")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items")
    assert response.status_code == 403
    assert detail_code(response) == "scope_denied"
    assert grants.asked == [TEAM_ID]


async def test_policy_refusal_is_action_denied_while_the_owner_is_allowed(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", "fixture:write")})
    policy = Policy(owners={"abc": "alice", "xyz": "bob"})
    assert (await call(registry, member, grants, policy, "POST", "/v1/items/abc/archive")).status_code == 200
    refused = await call(registry, member, grants, policy, "POST", "/v1/items/xyz/archive")
    assert refused.status_code == 403
    assert detail_code(refused) == "action_denied"


@pytest.mark.parametrize("method,path", [
    ("DELETE", "/v1/items/abc"), ("GET", "/v1/other"), ("GET", "/v1/items/abc/extra"),
    ("GET", "/v1/items/"), ("POST", "/v1/items/abc"),
])
async def test_undeclared_operation_is_refused_before_the_grant_is_read(registry, member, method, path):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", "fixture:write")})
    policy = Policy()
    response = await call(registry, member, grants, policy, method, path)
    assert response.status_code == 403
    assert detail_code(response) == "operation_undeclared"
    assert grants.asked == [] and policy.seen == []


async def test_unavailable_grant_authority_is_503_without_fallback(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")}, unavailable=True)
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items")
    assert response.status_code == 503
    assert detail_code(response) == "authority_unavailable"


async def test_stale_grant_is_503_even_when_it_would_allow(registry, member):
    stale = Grant(team_id=TEAM_ID, scopes=frozenset({"fixture:read"}), fresh_until=time.monotonic_ns() - seconds_to_ns(1),
                  installation_id=None, generation=None)
    response = await call(registry, member, InstalledGrants({TEAM_ID: stale}), Policy(), "GET", "/v1/items")
    assert response.status_code == 503
    assert detail_code(response) == "authority_unavailable"


async def test_grant_for_another_team_is_never_used(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", team_id="other:example.com")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items")
    assert response.status_code == 503
    assert detail_code(response) == "authority_unavailable"


async def test_scope_names_are_compared_exactly(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:*", "FIXTURE:READ", "fixture:read ")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items")
    assert response.status_code == 403
    assert detail_code(response) == "scope_denied"


@pytest.mark.parametrize("path", [
    "/v1/items/a%2Fb", "/v1/items/a%2fb", "/v1/items/a%5Cb", "/v1/items/a%5cb", "/v1/items/a%00",
    "/v1/items/%2E", "/v1/items/%2e%2E",
])
async def test_non_canonical_target_is_refused_before_matching(registry, member, path):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", "fixture:write")})
    policy = Policy()
    response = await call(registry, member, grants, policy, "GET", path)
    assert response.status_code == 400, response.text
    assert detail_code(response) == "target_not_canonical"
    assert grants.asked == [] and policy.seen == []


async def asgi_get(app: FastAPI, raw_path: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    """Deliver one request with this exact raw path, as a proxy may; clients normalize dot segments away."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "https",
             "server": ("app.example.com", 443), "client": ("127.0.0.1", 1), "root_path": "",
             "path": raw_path.decode(), "raw_path": raw_path, "query_string": b"",
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    await app(scope, receive, send)
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent[1:])


@pytest.mark.parametrize("path", ["/v1/items/.", "/v1/items/..", "/v1/./items", "/v1/items/abc/../x"])
async def test_raw_dot_segments_are_refused_before_matching(registry, member, path):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read", "fixture:write")})
    tools = DeclaredTools.from_manifest(load_manifest(canonical_bytes(MANIFEST)))
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    app = FastAPI()

    @app.get("/{route:path}")
    async def anything(route: str, request: Request):
        principal = await authenticate_request(request, public_origin=ORIGIN, team_cache=cache)
        await authorize_request(
            request, principal=principal, caller="agent", tools=tools, grants=grants, policy=Policy()
        )
        return {}

    status, body = await asgi_get(app, path.encode(), member.headers(aud=ORIGIN, method="GET", path=path))
    assert status == 400, body
    assert b"target_not_canonical" in body
    assert grants.asked == []


async def test_ordinary_percent_encoding_in_a_segment_is_still_authorized(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items/caf%C3%A9")
    assert response.status_code == 200, response.text
    assert response.json()["tool"] == "get"


async def test_encoded_slash_cannot_reach_a_second_declared_route(registry, member):
    """Real per-route dispatch: the tool that is checked is the route that runs."""
    tools = declared(
        {"name": "get-thing", "method": "GET", "path": "/v1/things/{id}", **in_path("id"),
         "scopes": ["things:read"]},
        {"name": "get-secret", "method": "GET", "path": "/v1/things/{id}/secret", **in_path("id"),
         "scopes": ["things:admin"]},
    )
    grants = InstalledGrants({TEAM_ID: fresh("things:read")})
    cache = AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)
    app = FastAPI()
    ran: list[str] = []

    async def admit(request: Request) -> str:
        principal = await authenticate_request(request, public_origin=ORIGIN, team_cache=cache)
        authorization = await authorize_request(request, principal=principal, caller="agent", tools=tools,
                                                grants=grants,
                                                policy=Policy())
        return authorization.tool.name

    @app.get("/v1/things/{id}")
    async def get_thing(id: str, request: Request):
        ran.append("get-thing")
        return {"checked": await admit(request)}

    @app.get("/v1/things/{id}/secret")
    async def get_secret(id: str, request: Request):
        ran.append("get-secret")
        return {"checked": await admit(request)}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        async def get(path):
            return await client.get(path, headers=member.headers(aud=ORIGIN, method="GET", path=path))

        assert (await get("/v1/things/x")).json() == {"checked": "get-thing"}
        assert detail_code(await get("/v1/things/x/secret")) == "scope_denied"
        encoded = await get("/v1/things/x%2Fsecret")
    assert encoded.status_code == 400
    assert detail_code(encoded) == "target_not_canonical"
    assert ran == ["get-thing", "get-secret", "get-secret"]


async def test_signed_request_to_a_public_tool_still_needs_the_grant(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:write")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/catalog")
    assert detail_code(response) == "scope_denied"


@pytest.mark.parametrize("declared_path,matches", [("/mounted/v1/items", True), ("/v1/items", False)])
async def test_mounted_app_matches_the_external_path_its_manifest_declares(
    registry, member, declared_path, matches
):
    # A manifest path is relative to the app origin, so a mounted app declares its prefix.
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    tools = declared({"name": "list", "method": "GET", "path": declared_path, "scopes": ["fixture:read"]})
    async with relying_app(
        registry, public_origin=ORIGIN, root_path="/mounted", on_principal=serve(grants, Policy(), tools)
    ) as (client, _):
        headers = member.headers(aud=ORIGIN, method="GET", path="/mounted/v1/items")
        response = await client.get("/mounted/v1/items", headers=headers)
    if matches:
        assert response.status_code == 200, response.text
        assert response.json()["tool"] == "list"
    else:
        assert detail_code(response) == "operation_undeclared"


@pytest.mark.parametrize("tools,reason", [
    ([{"name": "a", "method": "GET", "path": "/v1/x"}], "signed tool without scopes"),
    ([{"name": "a", "method": "GET", "path": "/v1/x", "scopes": []}], "signed tool with empty scopes"),
    ([{"name": "a", "method": "GET", "path": "/v1/x", "scopes": ["s", 1]}], "non-string scope"),
    ([{"name": "a", "method": "GET", "path": "https://evil.example/v1/x", "scopes": ["s"]}], "absolute path"),
    ([{"name": "a", "method": "GET", "path": "/v1/x?y=1", "scopes": ["s"]}], "query in path"),
    ([{"name": "a", "method": "FETCH", "path": "/v1/x", "scopes": ["s"]}], "unknown method"),
    ([{"name": "a", "method": "GET", "path": "/v1/{}", "scopes": ["s"]}], "empty placeholder"),
    ([{"name": "a", "method": "GET", "path": "/v1/{x}", **in_path("x"), "scopes": ["s"]},
      {"name": "b", "method": "GET", "path": "/v1/fixed", "scopes": ["t"]}], "ambiguous routes"),
])
def test_manifest_that_cannot_be_enforced_is_rejected(tools, reason):
    with pytest.raises(ValueError):
        declared(*tools)


def test_same_path_with_different_methods_is_not_ambiguous():
    tools = DeclaredTools.from_manifest(load_manifest(canonical_bytes(MANIFEST)))
    assert tools.match("GET", "/v1/items").name == "list"
    assert tools.match("POST", "/v1/items").name == "create"
    assert tools.match("get", "/v1/items") is None


async def test_authorization_requires_explicit_installation_fields():
    with pytest.raises(TypeError):
        Grant(team_id=TEAM_ID, scopes=frozenset({"fixture:read"}), fresh_until=time.monotonic_ns() + seconds_to_ns(60))  # type: ignore[call-arg]


async def test_policy_http_refusal_from_the_app_propagates(registry, member):
    async def refuse(request, principal, tool):
        raise HTTPException(status_code=404, detail={"code": "resource_not_found"})

    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    response = await call(registry, member, grants, refuse, "GET", "/v1/items/abc")
    assert response.status_code == 404


@pytest.mark.parametrize("caller,contexts,admitted", [
    ("agent", ["agent"], True),
    ("agent", ["surface"], False),
    ("agent", ["hook"], False),
    ("surface", ["surface"], True),
    ("surface", ["agent"], False),
    ("surface", ["hook"], False),
])
async def test_a_tool_admits_only_the_caller_contexts_it_declares(registry, member, caller, contexts, admitted):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    tools = declared(
        {"name": "list", "method": "GET", "path": "/v1/items", "scopes": ["fixture:read"],
         "invocation_contexts": contexts},
        version=2,
    )
    response = await call(registry, member, grants, Policy(), "GET", "/v1/items", tools=tools, caller=caller)
    if admitted:
        assert response.status_code == 200, response.text
    else:
        assert detail_code(response) == "tool_context_denied"
        assert grants.asked == []
