"""Read-side enforcement of team visibility (hosted-certificate-anchoring).

Juan's 2026-08-17 ruling: private by default, existing values preserved,
public is explicit opt-in. "Private" is only a fact if the read routes
enforce it: team get, certificate list, member resolve, and revocation list
require a same-team path-signature (the blob-fetch scheme) or the trusted
service token; domain enumeration hides private teams from anonymous and
unprivileged signed callers. Unauthorized reads return 403 with the stable
machine-readable code "team_private" (the CLI branches on it).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from awid.did import did_from_public_key, generate_keypair
from awid.signing import sign_message

from awid_service.deps import get_domain_verifier
from awid_service.main import create_app

from conftest import build_signed_headers as _sign

SERVICE_TOKEN = "trusted-service-token-with-at-least-32-bytes"


def _path_signed_headers(signing_key, did_key, *, method: str, path: str):
    """Path-signature auth: the exact scheme the certificate blob fetch uses."""
    ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = f"{ts}\n{method}\n{path}".encode("utf-8")
    sig = sign_message(signing_key, payload)
    return {
        "Authorization": f"DIDKey {did_key} {sig}",
        "X-AWEB-Timestamp": ts,
    }


async def _setup_namespace(client, ns_key, ns_did, domain):
    headers = _sign(ns_key, ns_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text


async def _create_team(client, ns_key, ns_did, domain, team_name, *, visibility=None):
    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name=team_name)
    body = {"name": team_name, "team_did_key": team_did}
    if visibility is not None:
        body["visibility"] = visibility
    resp = await client.post(f"/v1/namespaces/{domain}/teams", json=body, headers=headers)
    assert resp.status_code == 200, resp.text
    return team_key, team_did, resp.json()


async def _register_member(client, team_key, team_did, domain, team_name, alias):
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    cert_id = str(uuid4())
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json={
            "certificate_id": cert_id,
            "member_did_key": member_did_key,
            "alias": alias,
            "identity_scope": "local",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return member_key, member_did_key, cert_id


async def _revoke_member(client, team_key, team_did, domain, team_name, cert_id):
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="revoke_certificate",
        team_name=team_name, certificate_id=cert_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates/revoke",
        json={"certificate_id": cert_id},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def _assert_team_private(resp):
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == "team_private"


@pytest_asyncio.fixture
async def service_client(awid_db_infra, fake_redis, fake_domain_verifier, monkeypatch):
    """Client against an app configured with AWID_SERVICE_TOKEN."""
    monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: fake_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            yield test_client


# ---------------------------------------------------------------------------
# Route matrix: anonymous callers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_private_team_reads_reject_anonymous_with_team_private(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "priv-anon.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    # Default visibility is private.
    team_key, team_did, team = await _create_team(client, ns_key, ns_did, domain, "ops")
    assert team["visibility"] == "private"
    await _register_member(client, team_key, team_did, domain, "ops", "alice")

    _assert_team_private(await client.get(f"/v1/namespaces/{domain}/teams/ops"))
    _assert_team_private(await client.get(f"/v1/namespaces/{domain}/teams/ops/certificates"))
    _assert_team_private(await client.get(f"/v1/namespaces/{domain}/teams/ops/members/alice"))
    _assert_team_private(await client.get(f"/v1/namespaces/{domain}/teams/ops/revocations"))

    # A nonexistent team stays 404: 404 means the name is free, 403 means it
    # exists and is private (the availability contract depends on this split).
    resp = await client.get(f"/v1/namespaces/{domain}/teams/nope")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_public_team_reads_allow_anonymous(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "pub-anon.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(
        client, ns_key, ns_did, domain, "ops", visibility="public",
    )
    _, _, cert_id = await _register_member(client, team_key, team_did, domain, "ops", "alice")

    resp = await client.get(f"/v1/namespaces/{domain}/teams/ops")
    assert resp.status_code == 200, resp.text
    assert resp.json()["visibility"] == "public"

    resp = await client.get(f"/v1/namespaces/{domain}/teams/ops/certificates")
    assert resp.status_code == 200, resp.text
    assert {c["certificate_id"] for c in resp.json()["certificates"]} == {cert_id}

    resp = await client.get(f"/v1/namespaces/{domain}/teams/ops/members/alice")
    assert resp.status_code == 200, resp.text

    resp = await client.get(f"/v1/namespaces/{domain}/teams/ops/revocations")
    assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# Route matrix: same-team path-signature callers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_private_team_member_path_signature_reads(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "priv-member.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    member_key, member_did_key, cert_id = await _register_member(
        client, team_key, team_did, domain, "ops", "alice",
    )

    for path in (
        f"/v1/namespaces/{domain}/teams/ops",
        f"/v1/namespaces/{domain}/teams/ops/certificates",
        f"/v1/namespaces/{domain}/teams/ops/members/alice",
        f"/v1/namespaces/{domain}/teams/ops/revocations",
    ):
        headers = _path_signed_headers(member_key, member_did_key, method="GET", path=path)
        resp = await client.get(path, headers=headers)
        assert resp.status_code == 200, (path, resp.text)

    # The team controller key passes the same gate.
    path = f"/v1/namespaces/{domain}/teams/ops"
    headers = _path_signed_headers(team_key, team_did, method="GET", path=path)
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["visibility"] == "private"


@pytest.mark.asyncio
async def test_private_team_rejects_non_member_and_revoked_member_signatures(
    client, controller_identity,
):
    ns_key, ns_did = controller_identity
    domain = "priv-outsider.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "ops")
    member_key, member_did_key, cert_id = await _register_member(
        client, team_key, team_did, domain, "ops", "alice",
    )

    # A validly-signed caller who is not a member gets team_private.
    outsider_key, outsider_pub = generate_keypair()
    outsider_did = did_from_public_key(outsider_pub)
    path = f"/v1/namespaces/{domain}/teams/ops"
    headers = _path_signed_headers(outsider_key, outsider_did, method="GET", path=path)
    _assert_team_private(await client.get(path, headers=headers))

    # A revoked member's signature no longer passes the gate.
    await _revoke_member(client, team_key, team_did, domain, "ops", cert_id)
    headers = _path_signed_headers(member_key, member_did_key, method="GET", path=path)
    _assert_team_private(await client.get(path, headers=headers))

    # A malformed signature is a 401 from the signature scheme itself.
    bad = _path_signed_headers(outsider_key, outsider_did, method="GET", path="/some/other/path")
    resp = await client.get(path, headers=bad)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Route matrix: trusted service token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_private_team_service_token_reads(service_client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "priv-service.com"
    await _setup_namespace(service_client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(service_client, ns_key, ns_did, domain, "ops")
    _, _, cert_id = await _register_member(service_client, team_key, team_did, domain, "ops", "alice")
    await _revoke_member(service_client, team_key, team_did, domain, "ops", cert_id)
    await _register_member(service_client, team_key, team_did, domain, "ops", "bob")

    token_headers = {"X-AWID-Service-Token": SERVICE_TOKEN}
    for path in (
        f"/v1/namespaces/{domain}/teams/ops",
        f"/v1/namespaces/{domain}/teams/ops/certificates",
        f"/v1/namespaces/{domain}/teams/ops/members/bob",
        f"/v1/namespaces/{domain}/teams/ops/revocations",
    ):
        resp = await service_client.get(path, headers=token_headers)
        assert resp.status_code == 200, (path, resp.text)

    # aweb-abfn enforcement path: the server-to-server revocation fetch keeps
    # working with the token for a private team...
    resp = await service_client.get(
        f"/v1/namespaces/{domain}/teams/ops/revocations", headers=token_headers,
    )
    assert resp.status_code == 200, resp.text
    assert {r["certificate_id"] for r in resp.json()["revocations"]} == {cert_id}

    # ...and is refused without it, or with a wrong token.
    _assert_team_private(await service_client.get(f"/v1/namespaces/{domain}/teams/ops/revocations"))
    _assert_team_private(
        await service_client.get(
            f"/v1/namespaces/{domain}/teams/ops/revocations",
            headers={"X-AWID-Service-Token": "wrong-service-token-with-at-least-32-bytes"},
        )
    )


@pytest.mark.asyncio
async def test_unconfigured_service_token_grants_nothing(client, controller_identity):
    """The default `client` app has no AWID_SERVICE_TOKEN configured: a
    presented token must not open private teams."""
    ns_key, ns_did = controller_identity
    domain = "priv-notoken.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "ops")

    _assert_team_private(
        await client.get(
            f"/v1/namespaces/{domain}/teams/ops",
            headers={"X-AWID-Service-Token": SERVICE_TOKEN},
        )
    )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enumeration_excludes_private_teams_for_anonymous_callers(
    client, controller_identity,
):
    ns_key, ns_did = controller_identity
    domain = "enum.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "pub", visibility="public")
    priv_team_key, priv_team_did, _ = await _create_team(client, ns_key, ns_did, domain, "priv")
    member_key, member_did_key, _ = await _register_member(
        client, priv_team_key, priv_team_did, domain, "priv", "alice",
    )

    path = f"/v1/namespaces/{domain}/teams"

    # Anonymous: public only.
    resp = await client.get(path)
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub"}

    # A member of the private team sees both.
    headers = _path_signed_headers(member_key, member_did_key, method="GET", path=path)
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub", "priv"}

    # The private team's controller key sees both.
    headers = _path_signed_headers(priv_team_key, priv_team_did, method="GET", path=path)
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub", "priv"}

    # A signed non-member sees public only.
    outsider_key, outsider_pub = generate_keypair()
    outsider_did = did_from_public_key(outsider_pub)
    headers = _path_signed_headers(outsider_key, outsider_did, method="GET", path=path)
    resp = await client.get(path, headers=headers)
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub"}


@pytest.mark.asyncio
async def test_enumeration_includes_private_teams_for_trusted_service(
    service_client, controller_identity,
):
    ns_key, ns_did = controller_identity
    domain = "enum-svc.com"
    await _setup_namespace(service_client, ns_key, ns_did, domain)
    await _create_team(service_client, ns_key, ns_did, domain, "pub", visibility="public")
    await _create_team(service_client, ns_key, ns_did, domain, "priv")

    resp = await service_client.get(
        f"/v1/namespaces/{domain}/teams",
        headers={"X-AWID-Service-Token": SERVICE_TOKEN},
    )
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub", "priv"}

    resp = await service_client.get(f"/v1/namespaces/{domain}/teams")
    assert resp.status_code == 200, resp.text
    assert {t["name"] for t in resp.json()["teams"]} == {"pub"}


# ---------------------------------------------------------------------------
# Visibility persistence: no write path may reset an existing team's value
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_visibility_survives_team_writes(client, controller_identity):
    """Regression: registration, key rotation, certificate register/revoke,
    and duplicate-create attempts must never reset an existing team's
    visibility; only the controller-signed setter changes it."""
    ns_key, ns_did = controller_identity
    domain = "vis-keep.com"
    await _setup_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, team = await _create_team(
        client, ns_key, ns_did, domain, "ops", visibility="public",
    )
    assert team["visibility"] == "public"

    # Duplicate create (a backfill-style re-registration) with a different
    # visibility conflicts and must not overwrite the stored value.
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name="ops")
    _, other_pub = generate_keypair()
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={
            "name": "ops",
            "team_did_key": did_from_public_key(other_pub),
            "visibility": "private",
        },
        headers=headers,
    )
    assert resp.status_code == 409

    # Certificate register + revoke touch the team's certificate rows only.
    _, _, cert_id = await _register_member(client, team_key, team_did, domain, "ops", "alice")
    await _revoke_member(client, team_key, team_did, domain, "ops", cert_id)

    # Key rotation must not touch visibility.
    _, new_pub = generate_keypair()
    new_did = did_from_public_key(new_pub)
    headers = _sign(
        ns_key, ns_did, domain=domain, operation="rotate_team_key",
        name="ops", new_team_did_key=new_did,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/ops/rotate",
        json={"new_team_did_key": new_did},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["visibility"] == "public"

    resp = await client.get(f"/v1/namespaces/{domain}/teams/ops")
    assert resp.status_code == 200, resp.text
    assert resp.json()["visibility"] == "public"


@pytest.mark.asyncio
async def test_visibility_is_persisted_with_database_default_private(awid_db_infra):
    """The private default is a schema fact (001_registry.sql: NOT NULL
    DEFAULT 'private' with a CHECK), not just a Pydantic default: a row
    inserted without visibility is stored private."""
    db = awid_db_infra.get_manager("aweb")
    _, pub = generate_keypair()
    team_uuid = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_uuid, domain, name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_uuid,
        "schema-default.com",
        "ops",
        did_from_public_key(pub),
    )
    row = await db.fetch_one(
        "SELECT visibility FROM {{tables.teams}} WHERE team_uuid = $1", team_uuid,
    )
    assert row["visibility"] == "private"
