from __future__ import annotations

from contextlib import asynccontextmanager

import hashlib
import json
from datetime import datetime, timezone

import pytest

from awid.external_authority import OriginContext
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.lookup_policy import SENDER_LOOKUP
from aweb.federation.activation import (
    FederationAuthorityActivation,
    build_federation_authority_activation,
)
from aweb.federation.authority import FederationAuthorityCore
from aweb.federation.authority_state import AuthorityRepository
from aweb.federation.authority_work import AuthorityWorkRepository, AuthorityWorkResult
from aweb.identity_auth_deps import IDENTITY_DID_AW_HEADER
from identity_binding_support import register_global_identity
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import privacy_app as privacy_app
from test_federation_preactivation_harness import (
    _LoopbackHosts,
    _RecordedDNS,
    _TLSRegistry,
    _identity_registry_responses,
)

__all__ = ["privacy_app"]


class _ContactRegistry(_TLSRegistry):
    async def _handle(self, reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        self.requests.append(request)
        path = request.split(b" ", 2)[1].decode()
        status = b"200 OK" if path in self.responses else b"404 Not Found"
        body = json.dumps(
            self.responses.get(path, {"detail": "target.not_found"})
        ).encode()
        writer.write(
            b"HTTP/1.1 "
            + status
            + b"\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()


def _signed_identity_headers(agent_sk, agent_did_key, did_aw: str, body_bytes=b""):
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes(
        {
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "did_aw": did_aw,
            "timestamp": timestamp,
        }
    )
    sig = sign_message(agent_sk, payload)
    return {
        "Authorization": f"DIDKey {agent_did_key} {sig}",
        IDENTITY_DID_AW_HEADER: did_aw,
        "X-AWEB-Timestamp": timestamp,
    }


@asynccontextmanager
async def _contact_authority(env, monkeypatch):
    """Resolve through the actual disposable AWID service and shared database."""
    async with registry_listener(env) as (registry, origin):
        monkeypatch.setenv("APP_ENV", "development")
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", origin)
        authority = build_federation_authority_activation(
            env.infra, public_origin=str(env.client.base_url).rstrip("/")
        )
        env.app.state.federation_authority = authority
        try:
            yield registry
        finally:
            await authority.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["namespace", "address", "key", "log"])
async def test_contact_add_unregistered_cross_namespace_target(privacy_app, missing):
    env = privacy_app
    owner = env.actors["bob"]
    owner_stable = await register_global_identity(env, owner)
    db, app = env.db, env.app
    # External missing-evidence controls retain the signed conformance-vector
    # responses; the authenticated owner uses the real serving registry.
    target = "juan.aweb.ai/aweb-expert-secrets-root"
    mapping, responses = _identity_registry_responses(
        "juan.aweb.ai", "aweb-expert-secrets-root", "https://target.test"
    )
    controller_key = mapping["initial_did_key"]
    missing_path = next(
        path
        for path in responses
        if (missing == "namespace" and path == "/v1/namespaces/juan.aweb.ai")
        or (missing == "address" and "/addresses/" in path)
        or (missing in {"key", "log"} and path.endswith("/" + missing))
    )
    del responses[missing_path]
    if missing == "log":
        key_row = next(
            value for path, value in responses.items() if path.endswith("/key")
        )
        key_row["status"] = "OK_DEGRADED"
    async with _ContactRegistry("registry.test", responses) as external:
        dns = _RecordedDNS("juan.aweb.ai", controller_key, external.origin)
        resolver = StrictExternalRegistry(
            txt_resolver=dns,
            host_resolver=_LoopbackHosts(),
            origin_context=OriginContext(
                app_env="development",
                federation_test_enabled=True,
                listener_origin="https://jro.test",
            ),
            ssl_context=external.client_context,
        )
        app.state.federation_authority = FederationAuthorityActivation(
            core=FederationAuthorityCore(AuthorityRepository(db)),
            work=AuthorityWorkRepository(db),
            resolver=resolver,
            txt_resolver=dns,
        )
        body = json.dumps(
            {"contact_address": target, "label": "ho6-secrets-root"}
        ).encode()
        headers = {
            **_signed_identity_headers(owner.sk, owner.did, owner_stable, body),
            "Content-Type": "application/json",
        }
        try:
            response = await env.client.post(
                "/v1/contacts", content=body, headers=headers
            )
        finally:
            await resolver.aclose()
        assert any(
            missing_path.encode() + b" " in request for request in external.requests
        ), response.text
    assert response.status_code == (503 if missing == "log" else 404), response.text
    expected_reason = (
        "sender_identity_unverifiable"
        if missing == "log"
        else "recipient_identity_not_found"
    )
    assert response.json()["reason"] == expected_reason
    assert response.json()["retryable"] is (missing == "log")
    assert await db.fetch_val("SELECT COUNT(*) FROM {{tables.contacts}}") == 0


@pytest.mark.asyncio
async def test_contacts_routes_accept_equivalent_identity_owner_did(privacy_app):
    env = privacy_app
    bob = env.actors["bob"]
    stable = await register_global_identity(env, bob)
    contact_id = await env.db.fetch_val(
        """INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, 'acme.com/alice', 'Alice') RETURNING contact_id""",
        bob.did,
    )
    headers = _signed_identity_headers(bob.sk, bob.did, stable)
    listed = await env.client.get("/v1/contacts", headers=headers)
    assert listed.status_code == 200, listed.text
    assert [c["contact_address"] for c in listed.json()["contacts"]] == [
        "acme.com/alice"
    ]
    deleted = await env.client.delete(f"/v1/contacts/{contact_id}", headers=headers)
    assert deleted.status_code == 200, deleted.text
    assert (
        await env.db.fetch_val(
            "SELECT COUNT(*) FROM {{tables.contacts}} WHERE owner_did = $1", bob.did
        )
        == 0
    )


@pytest.mark.asyncio
async def test_contacts_route_normalizes_hosted_handle_address(
    privacy_app, monkeypatch
):
    env = privacy_app
    alice, target = env.actors["alice"], env.actors["carol"]
    stable = await register_global_identity(env, alice)
    target_stable = await register_global_identity(env, target, "jane.aweb.ai/c3po")
    controller = await env.registry.ensure_namespace(domain="jane.aweb.ai")
    await env.app.state.awid_registry_client.update_namespace_delivery_origin(
        "jane.aweb.ai", bytes(controller), "https://aweb.jane.example"
    )
    body = json.dumps({"contact_address": "@jane/c3po", "label": "C-3PO"}).encode()
    headers = {
        **_signed_identity_headers(alice.sk, alice.did, stable, body),
        "Content-Type": "application/json",
    }
    async with _contact_authority(env, monkeypatch):
        response = await env.client.post("/v1/contacts", content=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["contact_address"] == "jane.aweb.ai/c3po"
    assert response.json()["contact_did_aw"] == target_stable
    stored = await env.db.fetch_val(
        "SELECT contact_address FROM {{tables.contacts}} WHERE owner_did = $1", stable
    )
    assert stored == "jane.aweb.ai/c3po"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "published_reason", ["sender_identity_not_found", "recipient_identity_not_found"]
)
@pytest.mark.parametrize("contact", [False, True])
async def test_shared_not_found_result_uses_current_lookup_role(
    published_reason, contact
):
    # Sender authorization and contact resolution share the same singleflight key.
    activation = FederationAuthorityActivation(
        core=None, work=None, resolver=None, txt_resolver=None
    )
    result = AuthorityWorkResult(
        scope_key="discovery:juan.aweb.ai/missing",
        fence=1,
        status="failed",
        evidence={"reason": published_reason},
        expires_at=datetime.now(timezone.utc),
    )
    with pytest.raises(FederationAuthorityError) as raised:
        if contact:
            await activation._contact_from_result("juan.aweb.ai/missing", result)
        else:
            await activation._contact_from_result(
                "juan.aweb.ai/missing",
                result,
                lookup=SENDER_LOOKUP,
            )
    expected_reason = (
        "recipient_identity_not_found" if contact else "sender_identity_not_found"
    )
    assert raised.value.reason == expected_reason
