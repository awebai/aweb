"""Authorization after authentication: declared tool, installed grant, app policy.

Requests are signed for real and authenticated against real AWID. The grant
source here is an app-supplied implementation of the seam, as a naapp would
supply one; it holds explicit grant records rather than imitating a service.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import pytest
from fastapi import HTTPException

from aweb_naapp.runtime.authorization import (
    DeclaredTools,
    Grant,
    GrantUnavailable,
    authorize_request,
)
from tests.runtime.conftest import Member, relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"

MANIFEST = {
    "app": {"id": "fixture", "origin": ORIGIN, "version": "1"},
    "manifest_version": 1,
    "tools": [
        {"name": "list", "method": "GET", "path": "/v1/items", "scopes": ["fixture:read"]},
        {"name": "get", "method": "GET", "path": "/v1/items/{item_id}", "scopes": ["fixture:read"]},
        {"name": "create", "method": "POST", "path": "/v1/items", "scopes": ["fixture:write"]},
        {"name": "archive", "method": "POST", "path": "/v1/items/{item_id}/archive",
         "scopes": ["fixture:read", "fixture:write"]},
        {"name": "catalog", "method": "GET", "path": "/v1/catalog", "auth": "none", "scopes": ["fixture:read"]},
    ],
}


@dataclass
class InstalledGrants:
    """The app's grant source: explicit records per team, or an outage."""

    grants: dict[str, Grant] = field(default_factory=dict)
    unavailable: bool = False
    asked: list[str] = field(default_factory=list)

    async def grant_for(self, team_id: str) -> Grant | None:
        self.asked.append(team_id)
        if self.unavailable:
            raise GrantUnavailable("grant authority unreachable")
        return self.grants.get(team_id)


def fresh(*scopes: str, team_id: str = TEAM_ID, installation_id: str | None = None,
          generation: int | None = None) -> Grant:
    return Grant(team_id=team_id, scopes=frozenset(scopes), fresh_until=time.monotonic() + 60,
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


def serve(grants, policy, tools=None):
    tools = tools or DeclaredTools.from_manifest(MANIFEST)

    async def on_principal(request, principal):
        authorization = await authorize_request(
            request, principal=principal, tools=tools, grants=grants, policy=policy,
        )
        return {
            "tool": authorization.tool.name,
            "alias": authorization.principal.alias,
            "installation_id": authorization.grant.installation_id,
        }

    return on_principal


async def call(registry, member, grants, policy, method, path, *, tools=None):
    async with relying_app(registry, public_origin=ORIGIN, on_principal=serve(grants, policy, tools)) as (client, _):
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
    stale = Grant(team_id=TEAM_ID, scopes=frozenset({"fixture:read"}), fresh_until=time.monotonic() - 1,
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


async def test_raw_path_segments_are_matched_without_decoding(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    assert (await call(registry, member, grants, Policy(), "GET", "/v1/items/a%2Fb")).status_code == 200


async def test_signed_request_to_a_public_tool_still_needs_the_grant(registry, member):
    grants = InstalledGrants({TEAM_ID: fresh("fixture:write")})
    response = await call(registry, member, grants, Policy(), "GET", "/v1/catalog")
    assert detail_code(response) == "scope_denied"


@pytest.mark.parametrize("declared,matches", [("/api/v1/items", True), ("/v1/items", False)])
async def test_mounted_app_matches_the_external_path_its_manifest_declares(registry, member, declared, matches):
    # A manifest path is relative to the app origin, so a mounted app declares its prefix.
    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    tools = DeclaredTools.from_manifest(
        {"tools": [{"name": "list", "method": "GET", "path": declared, "scopes": ["fixture:read"]}]}
    )
    async with relying_app(
        registry, public_origin=ORIGIN, root_path="/api", on_principal=serve(grants, Policy(), tools)
    ) as (client, _):
        headers = member.headers(aud=ORIGIN, method="GET", path="/api/v1/items")
        response = await client.get("/api/v1/items", headers=headers)
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
    ([{"name": "a", "method": "GET", "path": "/v1/{x}", "scopes": ["s"]},
      {"name": "b", "method": "GET", "path": "/v1/fixed", "scopes": ["t"]}], "ambiguous routes"),
])
def test_manifest_that_cannot_be_enforced_is_rejected(tools, reason):
    with pytest.raises(ValueError):
        DeclaredTools.from_manifest({"tools": tools})


def test_same_path_with_different_methods_is_not_ambiguous():
    tools = DeclaredTools.from_manifest(MANIFEST)
    assert tools.match("GET", "/v1/items").name == "list"
    assert tools.match("POST", "/v1/items").name == "create"
    assert tools.match("get", "/v1/items") is None


async def test_authorization_requires_explicit_installation_fields():
    with pytest.raises(TypeError):
        Grant(team_id=TEAM_ID, scopes=frozenset({"fixture:read"}), fresh_until=time.monotonic() + 60)  # type: ignore[call-arg]


async def test_policy_http_refusal_from_the_app_propagates(registry, member):
    async def refuse(request, principal, tool):
        raise HTTPException(status_code=404, detail={"code": "resource_not_found"})

    grants = InstalledGrants({TEAM_ID: fresh("fixture:read")})
    response = await call(registry, member, grants, refuse, "GET", "/v1/items/abc")
    assert response.status_code == 404
