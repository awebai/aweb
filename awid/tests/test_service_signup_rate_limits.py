"""Real signed signup writes retain public IP budgets and exempt trusted services."""

from __future__ import annotations

import base64
import json

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.ratelimit import MemoryFixedWindowRateLimiter
import awid.ratelimit as ratelimit_module

from conftest import build_signed_headers
from test_certificates import _setup_team, _signed_certificate_blob, _register_member_address
from test_team_routes import _register_identity, _register_namespace

TOKEN = "signup-service-token-with-at-least-32-bytes"
WRONG_TOKEN = "wrong-signup-service-token-at-least-32-bytes"
OPERATIONS = ("team_create", "certificate_local", "certificate_global", "address_register")


async def _signup_operation(client, controller_identity, operation):
    """Provision prerequisites through real routes, then build distinct signed writes."""
    ns_key, ns_did = controller_identity
    domain = "signup.example.com"
    team_name = "staff"
    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    member_key, member_pub = generate_keypair()
    member_did = did_from_public_key(member_pub)
    member_did_aw = None

    if operation.startswith("certificate_"):
        team_key, team_did, _ = await _setup_team(client, ns_key, ns_did, domain, team_name)
        if operation == "certificate_global":
            member_did_aw = await _register_member_address(
                client, ns_key, ns_did, domain, "member", member_key, member_did,
            )
    else:
        await _register_namespace(client, ns_key, ns_did, domain)
        if operation == "address_register":
            member_did_aw = await _register_identity(client, member_key, member_did)

    def build(attempt, *, wrong_controller=False, bad_certificate=False, unregistered_did=False):
        name = f"member-{attempt}"
        if operation == "team_create":
            headers = build_signed_headers(
                member_key if wrong_controller else ns_key,
                member_did if wrong_controller else ns_did,
                domain=domain, operation="create_team", name=name,
            )
            return f"/v1/namespaces/{domain}/teams", {"name": name, "team_did_key": team_did}, headers
        if operation == "address_register":
            headers = build_signed_headers(
                member_key if wrong_controller else ns_key,
                member_did if wrong_controller else ns_did,
                domain=domain, operation="register_address", name=name,
            )
            body = {"name": name, "did_aw": member_did_aw, "current_did_key": member_did}
            if unregistered_did:
                _, other_public = generate_keypair()
                other_did = did_from_public_key(other_public)
                body.update(did_aw=stable_id_from_did_key(other_did), current_did_key=other_did)
            return f"/v1/namespaces/{domain}/addresses", body, headers

        # Namespace control is not team-controller authority, even with a token.
        headers = build_signed_headers(
            ns_key if wrong_controller else team_key,
            ns_did if wrong_controller else team_did,
            domain=domain, operation="register_certificate",
            team_name=team_name, certificate_id=name,
        )
        body = {"certificate_id": name, "member_did_key": member_did, "alias": name}
        global_member = operation == "certificate_global"
        body["identity_scope"] = "global" if global_member else "local"
        if global_member:
            body.update(member_did_aw=member_did_aw, member_address=f"{domain}/member")
        certificate = _signed_certificate_blob(
            team_key, certificate_id=name, team_id=f"{team_name}:{domain}",
            team_did_key=team_did, member_did_key=member_did, alias=name,
            lifetime="persistent" if global_member else "ephemeral",
            member_did_aw=body.get("member_did_aw"), member_address=body.get("member_address"),
        )
        if bad_certificate:
            document = json.loads(base64.b64decode(certificate))
            document["signature"] = "invalid"
            certificate = base64.b64encode(json.dumps(document).encode()).decode()
        body["certificate"] = certificate
        return f"/v1/namespaces/{domain}/teams/{team_name}/certificates", body, headers

    table = (
        "teams" if operation == "team_create"
        else "public_addresses" if operation == "address_register"
        else "team_certificates"
    )
    return build, table, 10 if operation == "team_create" else 30


async def _post(client, build, attempt, service_headers, **changes):
    path, body, headers = build(attempt, **changes)
    return await client.post(path, json=body, headers={**headers, **service_headers})


def _limited(response, limit):
    assert response.status_code == 429, response.text
    assert response.json()["detail"] == "rate limit exceeded"
    assert response.headers["X-RateLimit-Limit"] == str(limit)
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert int(response.headers["Retry-After"]) == 3600


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("credential", ["valid", "missing", "wrong", "unconfigured"])
async def test_signup_writes_exempt_only_matching_service_token(
    client, controller_identity, awid_db_infra, monkeypatch, operation, credential,
):
    build, table, limit = await _signup_operation(client, controller_identity, operation)
    app = client._transport.app
    monkeypatch.setattr(app.state, "awid_service_token", None if credential == "unconfigured" else TOKEN)
    monkeypatch.setattr(app.state, "rate_limiter", MemoryFixedWindowRateLimiter())
    monkeypatch.setattr(ratelimit_module.time, "time", lambda: 1800000000.0)
    headers = {} if credential == "missing" else {
        "X-AWID-Service-Token": WRONG_TOKEN if credential == "wrong" else TOKEN,
    }
    db = awid_db_infra.get_manager()
    before = await db.fetch_value(f"SELECT COUNT(*) FROM {{{{tables.{table}}}}}")

    for attempt in range(limit + 1):
        response = await _post(client, build, attempt, headers)
        if credential == "valid" or attempt < limit:
            assert response.status_code == 200, response.text
            if credential == "valid" and attempt == limit:
                assert "X-RateLimit-Limit" not in response.headers
            elif credential != "valid":
                assert response.headers["X-RateLimit-Remaining"] == str(limit - attempt - 1)
        else:
            _limited(response, limit)
    count = await db.fetch_value(f"SELECT COUNT(*) FROM {{{{tables.{table}}}}}")
    assert count - before == limit + (credential == "valid")

    # Exempt calls neither consume nor reset the ordinary public IP window.
    if credential == "valid":
        for attempt in range(100, 100 + limit):
            response = await _post(client, build, attempt, {})
            assert response.status_code == 200, response.text
    monkeypatch.setattr(app.state, "awid_service_token", TOKEN)
    trusted = await _post(client, build, 200, {"X-AWID-Service-Token": TOKEN})
    assert trusted.status_code == 200, trusted.text
    assert "X-RateLimit-Limit" not in trusted.headers
    for service_headers in ({}, {"X-AWID-Service-Token": WRONG_TOKEN}):
        _limited(await _post(client, build, 201, service_headers), limit)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", OPERATIONS)
async def test_service_allowance_does_not_authorize_signup_writes(
    client, controller_identity, awid_db_infra, monkeypatch, operation,
):
    build, table, _ = await _signup_operation(client, controller_identity, operation)
    app = client._transport.app
    monkeypatch.setattr(app.state, "awid_service_token", TOKEN)
    monkeypatch.setattr(app.state, "rate_limiter", MemoryFixedWindowRateLimiter())
    headers = {"X-AWID-Service-Token": TOKEN}
    db = awid_db_infra.get_manager()
    before = await db.fetch_value(f"SELECT COUNT(*) FROM {{{{tables.{table}}}}}")
    wrong = await _post(client, build, 0, headers, wrong_controller=True)
    assert wrong.status_code == 403, wrong.text
    path, body, _ = build(0)
    missing_signature = await client.post(path, json=body, headers=headers)
    assert missing_signature.status_code == 401, missing_signature.text
    if operation.startswith("certificate_"):
        invalid = await _post(client, build, 0, headers, bad_certificate=True)
        assert invalid.status_code == 422, invalid.text
        assert invalid.json()["detail"] == "certificate signature verification failed"
    if operation == "address_register":
        unregistered = await _post(client, build, 0, headers, unregistered_did=True)
        assert unregistered.status_code == 409, unregistered.text
        assert unregistered.json()["detail"] == "did_aw must be registered before address assignment"
    assert await db.fetch_value(f"SELECT COUNT(*) FROM {{{{tables.{table}}}}}") == before
    neighbor = await _post(client, build, 0, headers)
    assert neighbor.status_code == 200, neighbor.text
    assert await db.fetch_value(f"SELECT COUNT(*) FROM {{{{tables.{table}}}}}") == before + 1
