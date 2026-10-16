"""Controller-signed team writes retain public IP budgets and exempt trusted services."""

from __future__ import annotations

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.ratelimit import MemoryFixedWindowRateLimiter
import awid.ratelimit as ratelimit_module

from conftest import build_signed_headers as _sign
from test_certificate_lifecycle import _register_cert, _setup_team

TOKEN = "controller-service-token-with-at-least-32-bytes"
WRONG_TOKEN = "wrong-controller-service-token-at-least-32-b"
OPERATIONS = ("team_update", "team_delete", "certificate_revoke")
# A short budget in the real fixed-window limiter, so exhaustion needs few
# targets; the published hourly limits are pinned separately below.
LIMITS = {"team_update": 4, "team_delete": 4, "certificate_revoke": 4}
DOMAIN = "controller.example.com"


async def _controller_operation(client, controller_identity, operation):
    """Provision the targets through real routes, then build distinct signed writes.

    Every attempt has its own target: a visibility to flip, a team to delete or
    a certificate to revoke. Setup runs before the test installs its limiter.
    """
    ns_key, ns_did = controller_identity
    team_key, team_did = await _setup_team(client, ns_key, ns_did, DOMAIN, "staff")
    targets = 2 * LIMITS[operation] + 4
    certificates = []
    if operation == "team_delete":
        for attempt in range(targets):
            _, public = generate_keypair()
            headers = _sign(ns_key, ns_did, domain=DOMAIN, operation="create_team", name=f"gone-{attempt}")
            response = await client.post(
                f"/v1/namespaces/{DOMAIN}/teams",
                json={"name": f"gone-{attempt}", "team_did_key": did_from_public_key(public)},
                headers=headers,
            )
            assert response.status_code == 200, response.text
    if operation == "certificate_revoke":
        for attempt in range(targets):
            certificate_id, _ = await _register_cert(client, team_key, team_did, DOMAIN, "staff", f"member-{attempt}")
            certificates.append(certificate_id)

    def build(attempt, *, wrong_controller=False):
        index = attempt % targets if attempt < 100 else LIMITS[operation] + 1 + attempt % 100
        if operation == "team_update":
            visibility = "private" if attempt % 2 == 0 else "public"
            key, did = (ns_key, ns_did) if wrong_controller else (team_key, team_did)
            headers = _sign(key, did, domain=DOMAIN, operation="set_team_visibility", team_name="staff", visibility=visibility)
            return f"/v1/namespaces/{DOMAIN}/teams/staff/visibility", {"visibility": visibility}, headers
        if operation == "team_delete":
            name = f"gone-{index}"
            key, did = (team_key, team_did) if wrong_controller else (ns_key, ns_did)
            headers = _sign(key, did, domain=DOMAIN, operation="delete_team", team_name=name)
            return f"/v1/namespaces/{DOMAIN}/teams/{name}", None, headers
        certificate_id = certificates[index]
        key, did = (ns_key, ns_did) if wrong_controller else (team_key, team_did)
        headers = _sign(key, did, domain=DOMAIN, operation="revoke_certificate", team_name="staff", certificate_id=certificate_id)
        return f"/v1/namespaces/{DOMAIN}/teams/staff/certificates/revoke", {"certificate_id": certificate_id}, headers

    effect = {
        "team_update": f"SELECT visibility FROM {{{{tables.teams}}}} WHERE domain = '{DOMAIN}' AND name = 'staff' AND deleted_at IS NULL",
        "team_delete": "SELECT COUNT(*) FROM {{tables.teams}} WHERE deleted_at IS NOT NULL",
        "certificate_revoke": "SELECT COUNT(*) FROM {{tables.team_certificates}} WHERE revoked_at IS NOT NULL",
    }[operation]
    return build, effect


async def _send(client, build, attempt, service_headers, **changes):
    path, body, headers = build(attempt, **changes)
    headers = {**headers, **service_headers}
    if body is None:
        return await client.delete(path, headers=headers)
    return await client.post(path, json=body, headers=headers)


def _limited(response, limit):
    assert response.status_code == 429, response.text
    assert response.json()["detail"] == "rate limit exceeded"
    assert response.headers["X-RateLimit-Limit"] == str(limit)
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert int(response.headers["Retry-After"]) == 3600


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("credential", ["valid", "missing", "wrong", "unconfigured"])
async def test_controller_writes_exempt_only_matching_service_token(
    client, controller_identity, awid_db_infra, monkeypatch, operation, credential,
):
    build, effect = await _controller_operation(client, controller_identity, operation)
    limit = LIMITS[operation]
    monkeypatch.setitem(ratelimit_module._BUCKET_DEFAULTS, operation, (limit, 3600))
    app = client._transport.app
    monkeypatch.setattr(app.state, "awid_service_token", None if credential == "unconfigured" else TOKEN)
    monkeypatch.setattr(app.state, "rate_limiter", MemoryFixedWindowRateLimiter())
    monkeypatch.setattr(ratelimit_module.time, "time", lambda: 1800000000.0)
    headers = {} if credential == "missing" else {
        "X-AWID-Service-Token": WRONG_TOKEN if credential == "wrong" else TOKEN,
    }
    db = awid_db_infra.get_manager()
    before = await db.fetch_value(effect)

    for attempt in range(limit + 1):
        response = await _send(client, build, attempt, headers)
        if credential == "valid" or attempt < limit:
            assert response.status_code == 200, response.text
            if credential == "valid" and attempt == limit:
                assert "X-RateLimit-Limit" not in response.headers
            elif credential != "valid":
                assert response.headers["X-RateLimit-Remaining"] == str(limit - attempt - 1)
        else:
            _limited(response, limit)
    after = await db.fetch_value(effect)
    if operation == "team_update":
        # Even attempts set private: attempt `limit` (even) does, attempt `limit - 1` set public.
        assert after == ("private" if credential == "valid" else "public")
    else:
        assert after - before == limit + (credential == "valid")

    # Exempt calls neither consume nor reset the ordinary public IP window.
    if credential == "valid":
        for attempt in range(100, 100 + limit):
            response = await _send(client, build, attempt, {})
            assert response.status_code == 200, response.text
    monkeypatch.setattr(app.state, "awid_service_token", TOKEN)
    trusted = await _send(client, build, 100 + limit, {"X-AWID-Service-Token": TOKEN})
    assert trusted.status_code == 200, trusted.text
    assert "X-RateLimit-Limit" not in trusted.headers
    for service_headers in ({}, {"X-AWID-Service-Token": WRONG_TOKEN}):
        _limited(await _send(client, build, 100 + limit + 1, service_headers), limit)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", OPERATIONS)
async def test_service_allowance_does_not_authorize_controller_writes(
    client, controller_identity, awid_db_infra, monkeypatch, operation,
):
    build, effect = await _controller_operation(client, controller_identity, operation)
    app = client._transport.app
    monkeypatch.setattr(app.state, "awid_service_token", TOKEN)
    monkeypatch.setattr(app.state, "rate_limiter", MemoryFixedWindowRateLimiter())
    headers = {"X-AWID-Service-Token": TOKEN}
    db = awid_db_infra.get_manager()
    before = await db.fetch_value(effect)
    wrong = await _send(client, build, 0, headers, wrong_controller=True)
    assert wrong.status_code == 403, wrong.text
    path, body, _ = build(0)
    missing_signature = (
        await client.delete(path, headers=headers) if body is None
        else await client.post(path, json=body, headers=headers)
    )
    assert missing_signature.status_code == 401, missing_signature.text
    assert await db.fetch_value(effect) == before
    neighbor = await _send(client, build, 0, headers)
    assert neighbor.status_code == 200, neighbor.text
    assert await db.fetch_value(effect) != before


def test_controller_write_limits_bound_only_a_runaway_client():
    """Visibility, deletion and revocation already need the controller's
    signature, so the public per-IP budget only stops a runaway client."""
    assert ratelimit_module._BUCKET_DEFAULTS["team_update"] == (300, 3600)
    assert ratelimit_module._BUCKET_DEFAULTS["team_delete"] == (300, 3600)
    assert ratelimit_module._BUCKET_DEFAULTS["certificate_revoke"] == (1000, 3600)
