"""Owner acts on an embedded root use its selected serving registry.

The existing real world enrolls the team and admits the member through native
connect. A host-style auth adapter delegates the actual signed request to the
native verifier on its initialized state; no principal is manufactured. This
isolates the owner-act registry consumer from R2's separately tested root-auth
adapter. Membership only scopes the request; the controller's signed owner act
authorizes the change (owner-act.md, design/audit-substrate.md A3).
"""

import base64
import json
from contextlib import aclosing
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from awid.registry import RegistryClient
from awid.signing import sign_message
from awid.team_certificate import decode_team_certificate
from fastapi import FastAPI, Request

from aweb.api import RequestBodyCacheMiddleware
from aweb.hook_bindings import list_app_bindings
from aweb.routes.hook_bindings import router
from aweb.routes import hook_bindings as hook_routes
from aweb_naapp.hooks.owner_act import hook_binding_subject, owner_act_signing_bytes
from aweb_naapp_testing.network import make_certificates
from test_hook_binding_activation import _bindings, _install
from test_dashboard_privacy import TEAM, privacy_stack
from test_team_room import headers


@pytest_asyncio.fixture
async def admitted_world(shared_test_pool, monkeypatch, tmp_path_factory):
    host = "127.0.0.1"
    certificates = make_certificates(
        tmp_path_factory.mktemp("hook-root-tls"), ["hook-root.test"], [host]
    )
    async with privacy_stack(
        shared_test_pool, monkeypatch, tls=(host, certificates)
    ) as env:
        actor = env.actors["alice"]
        certificate = decode_team_certificate(actor.certificate)
        name, domain = TEAM.split(":", 1)
        await env.app.state.awid_registry_client.register_team_certificate(
            domain,
            name,
            team_controller_signing_key=env.team_sk,
            certificate_id=certificate["certificate_id"],
            member_did_key=actor.did,
            member_did_aw=certificate.get("member_did_aw"),
            member_address=certificate.get("member_address"),
            alias="alice",
            identity_scope="local",
            certificate=actor.certificate,
        )
        admitted = await env.client.post(
            "/v1/connect", content=b"{}", headers=headers(actor, b"{}")
        )
        assert admitted.status_code == 200, admitted.text
        assert admitted.json()["agent_id"] == str(actor.id)
        authenticate = hook_routes.get_team_identity

        async def member_auth(request, db_infra):
            # The lower R5 auth owner takes its native State. Forward the real
            # signed request, keeping its cached body and all signed headers.
            scope = {**request.scope, "app": env.app}
            identity = await authenticate(
                Request(scope, receive=request.receive), db_infra
            )
            assert identity.agent_id == str(actor.id)
            assert identity.team_id == TEAM
            assert identity.did_key == actor.did
            return identity

        monkeypatch.setattr(hook_routes, "get_team_identity", member_auth)
        yield env


def _root(env, selected):
    # Configuration carries the actual borrowed services, not startup or proof.
    resources = SimpleNamespace(
        api_app=env.app,
        db_infra=env.infra,
        redis=env.redis,
        registry_client=selected,
        public_origin=env.app.state.public_origin,
        on_mutation=env.app.state.on_mutation,
    )
    root = FastAPI()
    root.state.native_resources = resources
    root.state.db = resources.db_infra
    root.state.public_origin = resources.public_origin
    root.include_router(router)
    root.add_middleware(RequestBodyCacheMiddleware, max_body_bytes=1 << 20)
    return root


def _body(env, act, binding, audience):
    now = datetime.now(UTC).replace(microsecond=0)
    signing = owner_act_signing_bytes(
        {
            "v": 1,
            "type": "aweb.owner-act",
            "act": act,
            "team_id": TEAM,
            "aud": audience,
            "team_key_did": env.team_did,
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": uuid4().hex,
            "subject": hook_binding_subject(
                binding_id=str(binding.binding_id),
                installation_id=binding.installation_id,
                generation=binding.generation,
                app_id=binding.app_id,
                origin=binding.origin,
                digest=binding.digest,
                kind=binding.kind,
                catalog_id=binding.catalog_id,
                catalog_version=binding.catalog_version,
                hook=binding.hook,
                tool=binding.tool,
                method=binding.method,
                path=binding.path,
                scopes=binding.scopes,
            ),
        }
    )
    return {
        "act": base64.b64encode(signing).decode(),
        "signature": sign_message(env.team_sk, signing),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("shadow", [False, True])
async def test_selected_root_activates_and_revokes_actual_owner_act(
    admitted_world, monkeypatch, shadow
):
    env = admitted_world
    selected = env.app.state.awid_registry_client
    root = _root(env, selected)
    await _install(env.db, team_id=TEAM)
    binding, _ = await _bindings(env, team_id=TEAM)
    async with aclosing(
        RegistryClient(registry_url="http://unselected.invalid")
    ) as unselected:
        if shadow:
            root.state.awid_registry_client = unselected
        else:
            assert not hasattr(root.state, "awid_registry_client")
        async with AsyncClient(
            transport=ASGITransport(root), base_url=root.state.public_origin
        ) as client:
            for act, expected in (("activate", "active"), ("revoke", "revoked")):
                content = json.dumps(
                    _body(env, f"hook-binding.{act}", binding, root.state.public_origin)
                ).encode()
                response = await client.post(
                    f"/v1/apps/hook-bindings/{binding.binding_id}/{act}",
                    content=content,
                    headers=headers(env.actors["alice"], content),
                )
                assert response.status_code == 200, response.text
                assert response.json()["state"] == expected
                assert response.json()["binding_id"] == str(binding.binding_id)
    rows = await list_app_bindings(env.db, team_id=TEAM, app_id="logs")
    assert (
        next(row for row in rows if row.binding_id == binding.binding_id).state
        == "revoked"
    )
    assert (
        await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}")
        == 2
    )


@pytest.mark.asyncio
async def test_missing_selected_root_refuses_without_using_outer_registry(
    admitted_world,
):
    env = admitted_world
    root = _root(env, None)
    root.state.awid_registry_client = env.app.state.awid_registry_client
    await _install(env.db, team_id=TEAM)
    binding, _ = await _bindings(env, team_id=TEAM)
    content = json.dumps(
        _body(env, "hook-binding.activate", binding, root.state.public_origin)
    ).encode()
    async with AsyncClient(
        transport=ASGITransport(root), base_url=root.state.public_origin
    ) as client:
        response = await client.post(
            f"/v1/apps/hook-bindings/{binding.binding_id}/activate",
            content=content,
            headers=headers(env.actors["alice"], content),
        )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "registry_client_unavailable"
    assert detail["message"].endswith(
        "Configure the serving registry client and start the application before retrying."
    )
    rows = await list_app_bindings(env.db, team_id=TEAM, app_id="logs")
    assert all(row.state == "pending" for row in rows)
    assert (
        await env.db.fetch_value("SELECT COUNT(*) FROM {{tables.owner_act_nonces}}")
        == 0
    )
