from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient, MockTransport, Response

import awid_service.routes.dns_namespace_reverify as dns_namespace_reverify_routes
import awid_service.routes.dns_namespaces as dns_namespaces_routes
import awid_service.routes.dns_addresses as dns_addresses_routes
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.dns_verify import DnsVerificationError, DomainAuthority
from awid.log import identity_state_hash, log_entry_payload
from awid.registry import AddressAlreadyBoundError, RegistryClient
from awid.signing import canonical_json_bytes, sign_message

from conftest import build_signed_headers as _sign
from awid_service.deps import get_domain_verifier
from awid_service.main import create_app


@pytest.mark.asyncio
async def test_require_registered_did_locks_mapping_row_for_share():
    class RecordingTx:
        query = ""

        async def fetch_one(self, query, *args):
            self.query = query
            return {"current_did_key": "did:key:z6MkCurrent"}

    tx = RecordingTx()

    await dns_addresses_routes._require_registered_did(
        tx,
        did_aw="did:aw:test",
        current_did_key="did:key:z6MkCurrent",
    )

    assert "FOR SHARE" in tx.query


async def _register_namespace(client, signing_key, controller_did, domain):
    headers = _sign(signing_key, controller_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _register_identity(client, signing_key, did_key):
    did_aw = stable_id_from_did_key(did_key)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=did_key)
    proof = sign_message(
        signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="register_did",
            previous_did_key=None,
            new_did_key=did_key,
            prev_entry_hash=None,
            state_hash=state_hash,
            authorized_by=did_key,
            timestamp=timestamp,
        ),
    )
    resp = await client.post(
        "/v1/did",
        json={
            "did_aw": did_aw,
            "new_did_key": did_key,
            "operation": "register_did",
            "previous_did_key": None,
            "prev_entry_hash": None,
            "seq": 1,
            "state_hash": state_hash,
            "authorized_by": did_key,
            "timestamp": timestamp,
            "proof": proof,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _rotate_identity(client, old_signing_key, did_aw, old_did_key, new_did_key):
    key_resp = await client.get(f"/v1/did/{did_aw}/key")
    assert key_resp.status_code == 200, key_resp.text
    head = key_resp.json()["log_head"]

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    state_hash = identity_state_hash(did_aw=did_aw, current_did_key=new_did_key)
    seq = head["seq"] + 1
    signature = sign_message(
        old_signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=seq,
            operation="rotate_key",
            previous_did_key=old_did_key,
            new_did_key=new_did_key,
            prev_entry_hash=head["entry_hash"],
            state_hash=state_hash,
            authorized_by=old_did_key,
            timestamp=timestamp,
        ),
    )
    resp = await client.put(
        f"/v1/did/{did_aw}",
        json={
            "operation": "rotate_key",
            "new_did_key": new_did_key,
            "seq": seq,
            "prev_entry_hash": head["entry_hash"],
            "state_hash": state_hash,
            "authorized_by": old_did_key,
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _create_team(client, signing_key, controller_did, domain, team_name):
    team_signing_key, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="create_team", name=team_name,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": team_name, "team_did_key": team_did_key},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return team_signing_key, team_did_key, resp.json()


async def _register_address(client, signing_key, controller_did, domain, name):
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    await _register_identity(client, member_key, member_did_key)
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="register_address", name=name,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": name,
            "did_aw": stable_id_from_did_key(member_did_key),
            "current_did_key": member_did_key,
            "reachability": "public",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _register_address_for_identity(
    client,
    signing_key,
    controller_did,
    domain,
    name,
    *,
    member_signing_key: bytes | None = None,
    member_did_key: str | None = None,
    reachability: str,
    visible_to_team_id: str | None = None,
):
    if member_did_key is None:
        member_signing_key, member_pub = generate_keypair()
        member_did_key = did_from_public_key(member_pub)
    if member_signing_key is None:
        raise AssertionError("member_signing_key is required when member_did_key is supplied")
    await _register_identity(client, member_signing_key, member_did_key)
    headers = _sign(
        signing_key, controller_did, domain=domain, operation="register_address", name=name,
    )
    payload = {
        "name": name,
        "did_aw": stable_id_from_did_key(member_did_key),
        "current_did_key": member_did_key,
        "reachability": reachability,
    }
    if visible_to_team_id is not None:
        payload["visible_to_team_id"] = visible_to_team_id
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _active_address_count(awid_db_infra, domain: str, name: str) -> int:
    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT COUNT(*) AS count
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        WHERE ns.domain = $1
          AND pa.name = $2
          AND pa.deleted_at IS NULL
        """,
        domain,
        name,
    )
    return row["count"]


def _signed_certificate_header(
    team_key,
    team_did,
    domain,
    team_name,
    certificate_id,
    *,
    member_did_key: str,
    member_did_aw: str | None = None,
    member_address: str | None = None,
    alias: str = "alice",
    lifetime: str = "persistent",
) -> str:
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    certificate = {
        "version": 1,
        "certificate_id": certificate_id,
        "team_id": f"{team_name}:{domain}",
        "team_did_key": team_did,
        "member_did_key": member_did_key,
        "alias": alias,
        "lifetime": lifetime,
        "issued_at": issued_at,
    }
    if member_did_aw is not None:
        certificate["member_did_aw"] = member_did_aw
    if member_address is not None:
        certificate["member_address"] = member_address
    certificate["signature"] = sign_message(
        team_key,
        canonical_json_bytes(certificate),
    )
    return base64.b64encode(
        json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


async def _register_certificate(
    client,
    team_key,
    team_did,
    domain,
    team_name,
    certificate_id,
    *,
    member_did_key: str | None = None,
    member_did_aw: str | None = None,
    member_address: str | None = None,
    alias: str = "alice",
    lifetime: str = "persistent",
):
    if member_did_key is None:
        _, member_pub = generate_keypair()
        member_did_key = did_from_public_key(member_pub)
    encoded_certificate = _signed_certificate_header(
        team_key,
        team_did,
        domain,
        team_name,
        certificate_id,
        member_did_key=member_did_key,
        member_did_aw=member_did_aw,
        member_address=member_address,
        alias=alias,
        lifetime=lifetime,
    )
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    payload = {
        "certificate_id": certificate_id,
        "member_did_key": member_did_key,
        "alias": alias,
        "lifetime": lifetime,
        "certificate": encoded_certificate,
    }
    if member_did_aw is not None:
        payload["member_did_aw"] = member_did_aw
    if member_address is not None:
        payload["member_address"] = member_address
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return {
        "certificate_id": certificate_id,
        "member_did_key": member_did_key,
        "member_did_aw": member_did_aw,
        "member_address": member_address,
        "alias": alias,
        "lifetime": lifetime,
        "certificate_header": encoded_certificate,
    }


async def _register_persistent_certificate_for_address(
    client,
    team_key,
    team_did,
    domain,
    team_name,
    certificate_id,
    member_address,
):
    address_domain, address_name = member_address.split("/", 1)
    address_resp = await client.get(f"/v1/namespaces/{address_domain}/addresses/{address_name}")
    assert address_resp.status_code == 200, address_resp.text
    address_body = address_resp.json()
    member_did_key = address_body["current_did_key"]
    member_did_aw = address_body["did_aw"]
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="register_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates",
        json={
            "certificate_id": certificate_id,
            "member_did_key": member_did_key,
            "member_did_aw": member_did_aw,
            "member_address": member_address,
            "alias": "alice",
            "lifetime": "persistent",
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


async def _revoke_certificate(client, team_key, team_did, domain, team_name, certificate_id):
    headers = _sign(
        team_key, team_did,
        domain=domain, operation="revoke_certificate",
        team_name=team_name, certificate_id=certificate_id,
    )
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams/{team_name}/certificates/revoke",
        json={"certificate_id": certificate_id},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


def _bad_signature_headers(signing_key, header_did, *, domain, operation, **extra):
    payload = {"domain": domain, "operation": operation, **extra}
    headers = _sign(signing_key, header_did, domain=domain, operation=operation, **extra)
    headers["Authorization"] = f"DIDKey {header_did} {sign_message(signing_key, canonical_json_bytes(payload | {'timestamp': headers['X-AWEB-Timestamp']}))}"
    return headers


@pytest.mark.asyncio
async def test_register_namespace_local_skips_dns_verification(client):
    signing_key, public_key = generate_keypair()
    controller_did = did_from_public_key(public_key)

    headers = _sign(signing_key, controller_did, domain="local", operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": "local"}, headers=headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["domain"] == "local"
    assert body["controller_did"] == controller_did


@pytest.mark.asyncio
async def test_register_namespace_notlocal_still_requires_dns_verification(client):
    signing_key, public_key = generate_keypair()
    controller_did = did_from_public_key(public_key)

    headers = _sign(signing_key, controller_did, domain="notlocal", operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": "notlocal"}, headers=headers)

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Signing key does not match DNS controller"


@pytest.mark.asyncio
async def test_rotate_local_namespace_controller_skips_dns_verification(client):
    signing_key, public_key = generate_keypair()
    controller_did = did_from_public_key(public_key)
    await _register_namespace(client, signing_key, controller_did, "local")

    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)
    headers = _sign(
        new_signing_key,
        new_controller_did,
        domain="local",
        operation="rotate_controller",
        new_controller_did=new_controller_did,
    )
    resp = await client.put(
        "/v1/namespaces/local",
        json={"new_controller_did": new_controller_did},
        headers=headers,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["controller_did"] == new_controller_did


@pytest.mark.asyncio
async def test_rotate_namespace_controller_recovers_lost_old_key_via_dns(
    client, awid_db_infra, fake_redis, controller_identity, monkeypatch,
):
    old_signing_key, old_controller_did = controller_identity
    domain = "recover.example"
    await _register_namespace(client, old_signing_key, old_controller_did, domain)

    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)

    async def _rotated_domain_verifier(queried_domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=new_controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{queried_domain}",
        )

    logged: list[tuple[str, tuple[object, ...]]] = []

    def _capture_warning(message: str, *args) -> None:
        logged.append((message, args))

    monkeypatch.setattr(dns_namespaces_routes.logger, "warning", _capture_warning)

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _rotated_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            headers = _sign(
                new_signing_key,
                new_controller_did,
                domain=domain,
                operation="rotate_controller",
                new_controller_did=new_controller_did,
            )
            resp = await recovery_client.put(
                f"/v1/namespaces/{domain}",
                json={"new_controller_did": new_controller_did},
                headers=headers,
            )

            assert resp.status_code == 200, resp.text
            assert resp.json()["controller_did"] == new_controller_did
            assert resp.json()["verification_status"] == "verified"

            team_signing_key, team_pub = generate_keypair()
            team_did_key = did_from_public_key(team_pub)
            old_headers = _sign(
                old_signing_key,
                old_controller_did,
                domain=domain,
                operation="create_team",
                name="backend",
            )
            old_resp = await recovery_client.post(
                f"/v1/namespaces/{domain}/teams",
                json={"name": "backend", "team_did_key": team_did_key},
                headers=old_headers,
            )
            assert old_resp.status_code == 403
            assert old_resp.json()["detail"] == "Only the namespace controller can manage teams"

    assert logged == [
        (
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            (domain, old_controller_did, new_controller_did),
        )
    ]


@pytest.mark.asyncio
async def test_rotate_namespace_controller_rejects_when_dns_still_points_to_old_did(
    client, awid_db_infra, fake_redis, controller_identity,
):
    old_signing_key, old_controller_did = controller_identity
    domain = "recover-mismatch.example"
    await _register_namespace(client, old_signing_key, old_controller_did, domain)

    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)

    async def _stale_domain_verifier(queried_domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=old_controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{queried_domain}",
        )

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _stale_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            headers = _sign(
                new_signing_key,
                new_controller_did,
                domain=domain,
                operation="rotate_controller",
                new_controller_did=new_controller_did,
            )
            resp = await recovery_client.put(
                f"/v1/namespaces/{domain}",
                json={"new_controller_did": new_controller_did},
                headers=headers,
            )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "DNS controller does not match new_controller_did"


@pytest.mark.asyncio
async def test_reverify_namespace_updates_controller_from_dns(
    client, awid_db_infra, fake_redis, controller_identity, monkeypatch,
):
    old_signing_key, old_controller_did = controller_identity
    domain = "reverify.example"
    await _register_namespace(client, old_signing_key, old_controller_did, domain)

    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)

    async def _rotated_domain_verifier(queried_domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=new_controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{queried_domain}",
        )

    logged: list[tuple[str, tuple[object, ...]]] = []

    def _capture_warning(message: str, *args) -> None:
        logged.append((message, args))

    monkeypatch.setattr(dns_namespace_reverify_routes.logger, "warning", _capture_warning)

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _rotated_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            resp = await recovery_client.post(f"/v1/namespaces/{domain}/reverify")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["controller_did"] == new_controller_did
            assert body["old_controller_did"] == old_controller_did
            assert body["new_controller_did"] == new_controller_did
            assert body["verification_status"] == "verified"

            team_signing_key, team_pub = generate_keypair()
            team_did_key = did_from_public_key(team_pub)
            old_headers = _sign(
                old_signing_key,
                old_controller_did,
                domain=domain,
                operation="create_team",
                name="backend",
            )
            old_resp = await recovery_client.post(
                f"/v1/namespaces/{domain}/teams",
                json={"name": "backend", "team_did_key": team_did_key},
                headers=old_headers,
            )
            assert old_resp.status_code == 403
            assert old_resp.json()["detail"] == "Only the namespace controller can manage teams"

            new_headers = _sign(
                new_signing_key,
                new_controller_did,
                domain=domain,
                operation="create_team",
                name="backend",
            )
            new_resp = await recovery_client.post(
                f"/v1/namespaces/{domain}/teams",
                json={"name": "backend", "team_did_key": team_did_key},
                headers=new_headers,
            )
            assert new_resp.status_code == 200, new_resp.text

    assert logged == [
        (
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            (domain, old_controller_did, new_controller_did),
        )
    ]


@pytest.mark.asyncio
async def test_reverify_namespace_matching_dns_refreshes_without_rotation(
    client, awid_db_infra, fake_redis, controller_identity,
):
    signing_key, controller_did = controller_identity
    domain = "reverify-refresh.example"
    await _register_namespace(client, signing_key, controller_did, domain)

    db = awid_db_infra.get_manager("aweb")
    await db.execute(
        """
        UPDATE {{tables.dns_namespaces}}
        SET last_verified_at = TIMESTAMPTZ '2026-04-01T00:00:00Z'
        WHERE domain = $1
        """,
        domain,
    )

    async def _same_domain_verifier(queried_domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{queried_domain}",
        )

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _same_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            resp = await recovery_client.post(f"/v1/namespaces/{domain}/reverify")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["controller_did"] == controller_did
            assert body["old_controller_did"] == controller_did
            assert body["new_controller_did"] == controller_did
            assert body["verification_status"] == "verified"
            assert body["last_verified_at"] != "2026-04-01T00:00:00+00:00"


@pytest.mark.asyncio
async def test_reverify_child_namespace_inherits_parent_dns_authority(
    client, awid_db_infra, fake_redis, controller_identity,
):
    parent_key, parent_controller_did = controller_identity
    parent_domain = "parent-reverify.example"
    child_domain = f"child.{parent_domain}"
    await _register_namespace(client, parent_key, parent_controller_did, parent_domain)

    child_key, child_pub = generate_keypair()
    child_controller_did = did_from_public_key(child_pub)
    child_headers = _sign(child_key, child_controller_did, domain=child_domain, operation="register")
    parent_headers = _sign(
        parent_key,
        parent_controller_did,
        domain=child_domain,
        operation="authorize_subdomain_registration",
        child_domain=child_domain,
        controller_did=child_controller_did,
    )
    child_headers["X-AWEB-Parent-Authorization"] = parent_headers["Authorization"]
    child_headers["X-AWEB-Parent-Timestamp"] = parent_headers["X-AWEB-Timestamp"]
    child_resp = await client.post(
        "/v1/namespaces",
        json={"domain": child_domain},
        headers=child_headers,
    )
    assert child_resp.status_code == 200, child_resp.text

    db = awid_db_infra.get_manager("aweb")
    await db.execute(
        """
        UPDATE {{tables.dns_namespaces}}
        SET last_verified_at = TIMESTAMPTZ '2026-04-01T00:00:00Z'
        WHERE domain = $1
        """,
        child_domain,
    )

    async def _parent_domain_verifier(queried_domain: str) -> DomainAuthority:
        assert queried_domain == child_domain
        return DomainAuthority(
            controller_did=parent_controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{parent_domain}",
            inherited=True,
        )

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _parent_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            resp = await recovery_client.post(f"/v1/namespaces/{child_domain}/reverify")
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["controller_did"] == child_controller_did
            assert body["old_controller_did"] == child_controller_did
            assert body["new_controller_did"] == child_controller_did
            assert body["verification_status"] == "verified"


@pytest.mark.asyncio
async def test_reverify_namespace_dns_failure_returns_422_without_revoking(
    client, awid_db_infra, fake_redis, controller_identity,
):
    signing_key, controller_did = controller_identity
    domain = "reverify-fail.example"
    await _register_namespace(client, signing_key, controller_did, domain)

    async def _failing_domain_verifier(queried_domain: str) -> DomainAuthority:
        raise DnsVerificationError(f"DNS lookup failed for _awid.{queried_domain}")

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _failing_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as recovery_client:
            resp = await recovery_client.post(f"/v1/namespaces/{domain}/reverify")
            assert resp.status_code == 422
            assert resp.json()["detail"] == f"DNS lookup failed for _awid.{domain}"

    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT controller_did, verification_status
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1
        """,
        domain,
    )
    assert row["controller_did"] == controller_did
    assert row["verification_status"] == "verified"


@pytest.mark.asyncio
async def test_reverify_namespace_local_returns_400(client, controller_identity):
    signing_key, controller_did = controller_identity
    await _register_namespace(client, signing_key, controller_did, "local")

    resp = await client.post("/v1/namespaces/local/reverify")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "local namespaces have no DNS to reverify"


@pytest.mark.asyncio
async def test_reverify_namespace_missing_returns_404(client):
    resp = await client.post("/v1/namespaces/nonexistent.example/reverify")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Namespace not found"


@pytest.mark.asyncio
async def test_stale_address_verification_updates_controller_instead_of_revoking(
    client, awid_db_infra, fake_redis, controller_identity, monkeypatch,
):
    old_signing_key, old_controller_did = controller_identity
    domain = "stale-update.example"
    await _register_namespace(client, old_signing_key, old_controller_did, domain)

    db = awid_db_infra.get_manager("aweb")
    await db.execute(
        """
        UPDATE {{tables.dns_namespaces}}
        SET last_verified_at = TIMESTAMPTZ '2026-04-01T00:00:00Z'
        WHERE domain = $1
        """,
        domain,
    )

    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)

    async def _rotated_domain_verifier(queried_domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=new_controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{queried_domain}",
        )

    logged: list[tuple[str, tuple[object, ...]]] = []

    def _capture_warning(message: str, *args) -> None:
        logged.append((message, args))

    monkeypatch.setattr(dns_namespace_reverify_routes.logger, "warning", _capture_warning)

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _rotated_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as address_client:
            _, old_member_pub = generate_keypair()
            old_member_did_key = did_from_public_key(old_member_pub)
            old_headers = _sign(
                old_signing_key,
                old_controller_did,
                domain=domain,
                operation="register_address",
                name="alice",
            )
            old_resp = await address_client.post(
                f"/v1/namespaces/{domain}/addresses",
                json={
                    "name": "alice",
                    "did_aw": stable_id_from_did_key(old_member_did_key),
                    "current_did_key": old_member_did_key,
                    "reachability": "public",
                },
                headers=old_headers,
            )
            assert old_resp.status_code == 403
            assert old_resp.json()["detail"] == "Only the namespace controller can manage addresses"

            new_address = await _register_address(address_client, new_signing_key, new_controller_did, domain, "alice")
            assert new_address["name"] == "alice"

    row = await db.fetch_one(
        """
        SELECT controller_did, verification_status
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1
        """,
        domain,
    )
    assert row["controller_did"] == new_controller_did
    assert row["verification_status"] == "verified"
    assert logged == [
        (
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            (domain, old_controller_did, new_controller_did),
        )
    ]


@pytest.mark.asyncio
async def test_stale_address_dns_failure_does_not_revoke_namespace(
    client, awid_db_infra, fake_redis, controller_identity,
):
    signing_key, controller_did = controller_identity
    domain = "stale-failure.example"
    await _register_namespace(client, signing_key, controller_did, domain)

    db = awid_db_infra.get_manager("aweb")
    await db.execute(
        """
        UPDATE {{tables.dns_namespaces}}
        SET last_verified_at = TIMESTAMPTZ '2026-04-01T00:00:00Z'
        WHERE domain = $1
        """,
        domain,
    )

    async def _failing_domain_verifier(queried_domain: str) -> DomainAuthority:
        raise DnsVerificationError(f"DNS lookup failed for _awid.{queried_domain}")

    app = create_app(db_infra=awid_db_infra, redis=fake_redis)
    app.dependency_overrides[get_domain_verifier] = lambda: _failing_domain_verifier
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as address_client:
            _, member_pub = generate_keypair()
            member_did_key = did_from_public_key(member_pub)
            headers = _sign(
                signing_key,
                controller_did,
                domain=domain,
                operation="register_address",
                name="alice",
            )
            resp = await address_client.post(
                f"/v1/namespaces/{domain}/addresses",
                json={
                    "name": "alice",
                    "did_aw": stable_id_from_did_key(member_did_key),
                    "current_did_key": member_did_key,
                    "reachability": "public",
                },
                headers=headers,
            )
            assert resp.status_code == 403
            assert resp.json()["detail"] == "Namespace DNS verification failed"

    row = await db.fetch_one(
        """
        SELECT controller_did, verification_status
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1
        """,
        domain,
    )
    assert row["controller_did"] == controller_did
    assert row["verification_status"] == "verified"


@pytest.mark.asyncio
async def test_local_namespace_behaves_like_normal_namespace(client):
    ns_key, ns_pub = generate_keypair()
    ns_did = did_from_public_key(ns_pub)
    await _register_namespace(client, ns_key, ns_did, "local")

    team_key, team_did, team = await _create_team(client, ns_key, ns_did, "local", "default")
    address = await _register_address(client, ns_key, ns_did, "local", "alice")
    cert = await _register_certificate(
        client,
        team_key,
        team_did,
        "local",
        "default",
        str(uuid4()),
        member_did_key=address["current_did_key"],
        member_did_aw=address["did_aw"],
        member_address="local/alice",
        alias="alice",
    )

    team_resp = await client.get("/v1/namespaces/local/teams/default")
    assert team_resp.status_code == 200, team_resp.text
    assert team_resp.json()["team_id"] == team["team_id"]

    address_resp = await client.get("/v1/namespaces/local/addresses/alice")
    assert address_resp.status_code == 200, address_resp.text
    assert address_resp.json()["did_aw"] == address["did_aw"]

    member_resp = await client.get("/v1/namespaces/local/teams/default/members/alice")
    assert member_resp.status_code == 200, member_resp.text
    assert member_resp.json()["certificate_id"] == cert["certificate_id"]


@pytest.mark.asyncio
async def test_delete_namespace_happy_path_cascades(client, controller_identity, awid_db_infra):
    ns_key, ns_did = controller_identity
    domain = "delete-ns.example"
    namespace = await _register_namespace(client, ns_key, ns_did, domain)
    _, _, team = await _create_team(client, ns_key, ns_did, domain, "backend")
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    team_key, team_pub = generate_keypair()
    team_did = did_from_public_key(team_pub)
    headers = _sign(ns_key, ns_did, domain=domain, operation="create_team", name="ops")
    resp = await client.post(
        f"/v1/namespaces/{domain}/teams",
        json={"name": "ops", "team_did_key": team_did},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    cert_id = str(uuid4())
    await _register_certificate(client, team_key, team_did, domain, "ops", cert_id)
    await _revoke_certificate(client, team_key, team_did, domain, "ops", cert_id)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.request(
        "DELETE",
        f"/v1/namespaces/{domain}",
        headers=headers,
        json={"reason": "rollback after downstream failure"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] is True
    assert body["namespace_id"] == namespace["namespace_id"]

    resp = await client.get(f"/v1/namespaces/{domain}")
    assert resp.status_code == 404

    resp = await client.get(f"/v1/namespaces/{domain}/teams")
    assert resp.status_code == 200
    assert resp.json()["teams"] == []

    resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert resp.status_code == 404

    db = awid_db_infra.get_manager("aweb")
    ns_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.dns_namespaces}} WHERE namespace_id = $1",
        namespace["namespace_id"],
    )
    team_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.teams}} WHERE domain = $1 AND name = $2",
        domain,
        "backend",
    )
    address_row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.public_addresses}} WHERE address_id = $1",
        address["address_id"],
    )
    cert_row = await db.fetch_one(
        "SELECT 1 FROM {{tables.team_certificates}} WHERE certificate_id = $1",
        cert_id,
    )
    assert ns_row["deleted_at"] is not None
    assert team_row["deleted_at"] is not None
    assert address_row["deleted_at"] is not None
    assert cert_row is None


@pytest.mark.asyncio
async def test_delete_namespace_with_active_certificates_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "active-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_certificate(client, team_key, team_did, domain, "backend", str(uuid4()))

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 409
    assert "active certificates" in resp.text


@pytest.mark.asyncio
async def test_delete_namespace_already_deleted_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "deleted-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 200

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_namespace")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_namespace_bad_signature_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    wrong_key, _ = generate_keypair()
    domain = "bad-sig-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _bad_signature_headers(
        wrong_key, ns_did, domain=domain, operation="delete_namespace",
    )
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_namespace_wrong_operation_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "wrong-op-ns.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete")
    resp = await client.delete(f"/v1/namespaces/{domain}", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_address_happy_path(client, controller_identity, awid_db_infra):
    ns_key, ns_did = controller_identity
    domain = "delete-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.request(
        "DELETE",
        f"/v1/namespaces/{domain}/addresses/alice",
        headers=headers,
        json={"reason": "rollback after downstream failure"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "deleted": True,
        "address_id": address["address_id"],
        "domain": domain,
        "name": "alice",
    }

    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert resp.status_code == 404

    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        "SELECT deleted_at FROM {{tables.public_addresses}} WHERE address_id = $1",
        address["address_id"],
    )
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_delete_address_with_active_certificates_returns_409(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "active-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_persistent_certificate_for_address(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        f"{domain}/alice",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 409
    assert "active certificates" in resp.text


@pytest.mark.asyncio
async def test_delete_address_already_deleted_returns_404(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "deleted-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 200

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete_address", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_address_bad_signature_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    wrong_key, _ = generate_keypair()
    domain = "bad-sig-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _bad_signature_headers(
        wrong_key, ns_did, domain=domain, operation="delete_address", name="alice",
    )
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_address_wrong_operation_returns_401(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "wrong-op-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address(client, ns_key, ns_did, domain, "alice")

    headers = _sign(ns_key, ns_did, domain=domain, operation="delete", name="alice")
    resp = await client.delete(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_public_address_get_allows_anonymous(client, controller_identity):
    ns_key, ns_did = controller_identity
    domain = "public-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address(client, ns_key, ns_did, domain, "alice")

    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert resp.status_code == 200, resp.text
    assert resp.json()["address_id"] == address["address_id"]


@pytest.mark.asyncio
async def test_nobody_address_get_requires_owner_signature(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "nobody-address.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    address = await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert owner_resp.json()["address_id"] == address["address_id"]

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    other_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    other_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_headers)
    assert other_resp.status_code == 404


@pytest.mark.asyncio
async def test_address_get_nonexistent_matches_nobody_404_shape(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    domain = "nobody-404-shape.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    hidden_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    hidden_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=hidden_headers)
    assert hidden_resp.status_code == 404
    assert hidden_resp.json() == {"detail": "Address not found"}

    missing_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="missing")
    missing_resp = await client.get(f"/v1/namespaces/{domain}/addresses/missing", headers=missing_headers)
    assert missing_resp.status_code == 404
    assert missing_resp.json() == hidden_resp.json()


@pytest.mark.asyncio
async def test_list_addresses_filters_nobody_to_owner(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "list-nobody.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        reachability="public",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "nobody-alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="list_addresses")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert [item["name"] for item in owner_resp.json()["addresses"]] == ["nobody-alice", "public-alice"]


@pytest.mark.asyncio
async def test_list_addresses_namespace_controller_bypasses_visibility_filters(client, controller_identity):
    ns_key, ns_did = controller_identity
    outsider_key, outsider_pub = generate_keypair()
    outsider_did_key = did_from_public_key(outsider_pub)
    domain = "list-controller-bypass.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "nobody-alice",
        reachability="nobody",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        reachability="public",
    )

    controller_headers = _sign(ns_key, ns_did, domain=domain, operation="list_addresses")
    controller_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=controller_headers)
    assert controller_resp.status_code == 200, controller_resp.text
    assert [item["name"] for item in controller_resp.json()["addresses"]] == ["nobody-alice", "public-alice"]

    outsider_headers = _sign(outsider_key, outsider_did_key, domain=domain, operation="list_addresses")
    outsider_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=outsider_headers)
    assert outsider_resp.status_code == 200, outsider_resp.text
    assert [item["name"] for item in outsider_resp.json()["addresses"]] == ["public-alice"]

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]


@pytest.mark.asyncio
async def test_org_only_address_get_allows_same_org_persistent_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    other_key, other_pub = generate_keypair()
    other_did_key = did_from_public_key(other_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "org-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="org_only",
    )
    member_cert = await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="member",
    )
    ephemeral_cert = await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        alias="ephemeral",
        lifetime="ephemeral",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text
    assert owner_resp.json()["reachability"] == "org_only"

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    member_headers["X-AWID-Team-Certificate"] = member_cert["certificate_header"]
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text

    member_without_cert_headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    member_without_cert_resp = await client.get(
        f"/v1/namespaces/{domain}/addresses/alice",
        headers=member_without_cert_headers,
    )
    assert member_without_cert_resp.status_code == 404

    other_headers = _sign(other_key, other_did_key, domain=domain, operation="get_address", name="alice")
    other_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_headers)
    assert other_resp.status_code == 404

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_headers["X-AWID-Team-Certificate"] = ephemeral_cert["certificate_header"]
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_org_only_address_get_accepts_unpublished_valid_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    domain = "org-only-unpublished.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="org_only",
    )

    headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    headers["X-AWID-Team-Certificate"] = _signed_certificate_header(
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="unpublished-member",
    )
    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)

    assert resp.status_code == 200, resp.text
    assert resp.json()["reachability"] == "org_only"


@pytest.mark.asyncio
async def test_private_address_get_hides_invalid_presented_certificate(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    domain = "org-only-invalid-cert.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="org_only",
    )

    headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    headers["X-AWID-Team-Certificate"] = base64.b64encode(b'{"version": 1}').decode()
    resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=headers)

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "Address not found"


@pytest.mark.asyncio
async def test_org_only_rejects_ephemeral_certificate_even_with_member_did_aw(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "org-only-ephemeral.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="org_only",
    )
    ephemeral_cert = await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        member_did_aw=stable_id_from_did_key(ephemeral_did_key),
        alias="ephemeral",
        lifetime="ephemeral",
    )

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_headers["X-AWID-Team-Certificate"] = ephemeral_cert["certificate_header"]
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_list_addresses_filters_org_only_to_same_org_persistent_members(client, controller_identity):
    ns_key, ns_did = controller_identity
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    outsider_key, outsider_pub = generate_keypair()
    outsider_did_key = did_from_public_key(outsider_pub)
    domain = "list-org-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    team_key, team_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "org-alice",
        reachability="org_only",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        reachability="public",
    )
    member_cert = await _register_certificate(
        client,
        team_key,
        team_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="member",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    outsider_headers = _sign(outsider_key, outsider_did_key, domain=domain, operation="list_addresses")
    outsider_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=outsider_headers)
    assert outsider_resp.status_code == 200, outsider_resp.text
    assert [item["name"] for item in outsider_resp.json()["addresses"]] == ["public-alice"]

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="list_addresses")
    member_headers["X-AWID-Team-Certificate"] = member_cert["certificate_header"]
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text
    assert [item["name"] for item in member_resp.json()["addresses"]] == ["org-alice", "public-alice"]


@pytest.mark.asyncio
async def test_team_members_only_address_get_allows_target_team_persistent_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    member_key, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)
    other_team_key, other_team_pub = generate_keypair()
    other_team_did_key = did_from_public_key(other_team_pub)
    ephemeral_key, ephemeral_pub = generate_keypair()
    ephemeral_did_key = did_from_public_key(ephemeral_pub)
    domain = "team-members-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    backend_key, backend_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    frontend_key, frontend_did, _ = await _create_team(client, ns_key, ns_did, domain, "frontend")
    address = await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )
    assert address["visible_to_team_id"] == f"backend:{domain}"

    backend_cert = await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=member_did_key,
        member_did_aw=stable_id_from_did_key(member_did_key),
        alias="backend-member",
    )
    frontend_cert = await _register_certificate(
        client,
        frontend_key,
        frontend_did,
        domain,
        "frontend",
        str(uuid4()),
        member_did_key=other_team_did_key,
        member_did_aw=stable_id_from_did_key(other_team_did_key),
        alias="frontend-member",
    )
    ephemeral_cert = await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=ephemeral_did_key,
        alias="backend-ephemeral",
        lifetime="ephemeral",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert anon_resp.status_code == 404

    owner_headers = _sign(owner_key, owner_did_key, domain=domain, operation="get_address", name="alice")
    owner_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=owner_headers)
    assert owner_resp.status_code == 200, owner_resp.text

    member_headers = _sign(member_key, member_did_key, domain=domain, operation="get_address", name="alice")
    member_headers["X-AWID-Team-Certificate"] = backend_cert["certificate_header"]
    member_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=member_headers)
    assert member_resp.status_code == 200, member_resp.text

    other_team_headers = _sign(other_team_key, other_team_did_key, domain=domain, operation="get_address", name="alice")
    other_team_headers["X-AWID-Team-Certificate"] = frontend_cert["certificate_header"]
    other_team_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=other_team_headers)
    assert other_team_resp.status_code == 404

    ephemeral_headers = _sign(ephemeral_key, ephemeral_did_key, domain=domain, operation="get_address", name="alice")
    ephemeral_headers["X-AWID-Team-Certificate"] = ephemeral_cert["certificate_header"]
    ephemeral_resp = await client.get(f"/v1/namespaces/{domain}/addresses/alice", headers=ephemeral_headers)
    assert ephemeral_resp.status_code == 404


@pytest.mark.asyncio
async def test_list_addresses_filters_team_members_only_to_target_team(client, controller_identity):
    ns_key, ns_did = controller_identity
    backend_member_key, backend_member_pub = generate_keypair()
    backend_member_did_key = did_from_public_key(backend_member_pub)
    frontend_member_key, frontend_member_pub = generate_keypair()
    frontend_member_did_key = did_from_public_key(frontend_member_pub)
    domain = "list-team-members-only.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    backend_key, backend_did, _ = await _create_team(client, ns_key, ns_did, domain, "backend")
    frontend_key, frontend_did, _ = await _create_team(client, ns_key, ns_did, domain, "frontend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "backend-alice",
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "public-alice",
        reachability="public",
    )
    backend_cert = await _register_certificate(
        client,
        backend_key,
        backend_did,
        domain,
        "backend",
        str(uuid4()),
        member_did_key=backend_member_did_key,
        member_did_aw=stable_id_from_did_key(backend_member_did_key),
        alias="backend-member",
    )
    frontend_cert = await _register_certificate(
        client,
        frontend_key,
        frontend_did,
        domain,
        "frontend",
        str(uuid4()),
        member_did_key=frontend_member_did_key,
        member_did_aw=stable_id_from_did_key(frontend_member_did_key),
        alias="frontend-member",
    )

    anon_resp = await client.get(f"/v1/namespaces/{domain}/addresses")
    assert anon_resp.status_code == 200, anon_resp.text
    assert [item["name"] for item in anon_resp.json()["addresses"]] == ["public-alice"]

    frontend_headers = _sign(frontend_member_key, frontend_member_did_key, domain=domain, operation="list_addresses")
    frontend_headers["X-AWID-Team-Certificate"] = frontend_cert["certificate_header"]
    frontend_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=frontend_headers)
    assert frontend_resp.status_code == 200, frontend_resp.text
    assert [item["name"] for item in frontend_resp.json()["addresses"]] == ["public-alice"]

    backend_headers = _sign(backend_member_key, backend_member_did_key, domain=domain, operation="list_addresses")
    backend_headers["X-AWID-Team-Certificate"] = backend_cert["certificate_header"]
    backend_resp = await client.get(f"/v1/namespaces/{domain}/addresses", headers=backend_headers)
    assert backend_resp.status_code == 200, backend_resp.text
    assert [item["name"] for item in backend_resp.json()["addresses"]] == ["backend-alice", "public-alice"]


@pytest.mark.asyncio
# Split the literals so residue greps can stay strict while this negative test
# still exercises server-side rejection of the removed enum values.
@pytest.mark.parametrize("reachability", ["contacts" + "_only", "org" + "_visible"])
async def test_register_address_rejects_legacy_reachability_values(client, controller_identity, reachability):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = f"legacy-{reachability.replace('_', '-')}.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": reachability,
        },
        headers=headers,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_address_requires_registered_did(client, controller_identity):
    ns_key, ns_did = controller_identity
    _, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "unregistered-address-did.example"
    await _register_namespace(client, ns_key, ns_did, domain)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": "public",
        },
        headers=headers,
    )

    assert resp.status_code == 409
    assert resp.json()["detail"] == "did_aw must be registered before address assignment"


@pytest.mark.asyncio
async def test_register_address_accepts_registered_did_without_extra_identity_rows(
    client,
    controller_identity,
    awid_db_infra,
):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    owner_did_aw = stable_id_from_did_key(owner_did_key)
    domain = "registered-address-did.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, owner_key, owner_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": owner_did_aw,
            "current_did_key": owner_did_key,
            "reachability": "public",
        },
        headers=headers,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["did_aw"] == owner_did_aw

    db = awid_db_infra.get_manager("aweb")
    mapping_count = await db.fetch_one(
        "SELECT COUNT(*) AS count FROM {{tables.did_aw_mappings}} WHERE did_aw = $1",
        owner_did_aw,
    )
    assert mapping_count["count"] == 1
    address = await db.fetch_one(
        """
        SELECT pa.did_aw, m.current_did_key
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
        WHERE pa.namespace_id = (
            SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1
        )
        AND pa.name = $2
        """,
        domain,
        "alice",
    )
    assert address["did_aw"] == owner_did_aw
    assert address["current_did_key"] == owner_did_key


@pytest.mark.asyncio
async def test_register_address_is_idempotent_for_same_did_and_key(
    client,
    controller_identity,
    awid_db_infra,
):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    owner_did_aw = stable_id_from_did_key(owner_did_key)
    domain = "address-idempotent.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, owner_key, owner_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    payload = {
        "name": "alice",
        "did_aw": owner_did_aw,
        "current_did_key": owner_did_key,
        "reachability": "public",
    }
    first = await client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers)
    assert first.status_code == 200, first.text

    second = await client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers)
    assert second.status_code == 200, second.text
    assert second.json() == first.json()
    assert await _active_address_count(awid_db_infra, domain, "alice") == 1


@pytest.mark.asyncio
async def test_register_address_rejects_existing_name_for_different_did_aw(client, controller_identity):
    ns_key, ns_did = controller_identity
    first_key, first_pub = generate_keypair()
    first_did_key = did_from_public_key(first_pub)
    second_key, second_pub = generate_keypair()
    second_did_key = did_from_public_key(second_pub)
    domain = "address-bound-conflict.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, first_key, first_did_key)
    await _register_identity(client, second_key, second_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    first = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(first_did_key),
            "current_did_key": first_did_key,
            "reachability": "public",
        },
        headers=headers,
    )
    assert first.status_code == 200, first.text

    second = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(second_did_key),
            "current_did_key": second_did_key,
            "reachability": "public",
        },
        headers=headers,
    )
    assert second.status_code == 409
    assert second.json()["detail"] == "address already bound to a different did_aw"


@pytest.mark.asyncio
async def test_reregister_address_rejects_stale_did_key_after_rotation(client, controller_identity):
    ns_key, ns_did = controller_identity
    old_key, old_pub = generate_keypair()
    old_did_key = did_from_public_key(old_pub)
    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    owner_did_aw = stable_id_from_did_key(old_did_key)
    domain = "address-idempotent-rotated.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, old_key, old_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    payload = {
        "name": "alice",
        "did_aw": owner_did_aw,
        "current_did_key": old_did_key,
        "reachability": "public",
    }
    first = await client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers)
    assert first.status_code == 200, first.text

    await _rotate_identity(client, old_key, owner_did_aw, old_did_key, new_did_key)

    second = await client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers)
    assert second.status_code == 409
    assert second.json()["detail"] == "did_aw current key does not match"


@pytest.mark.asyncio
async def test_concurrent_register_address_exact_match_creates_one_row(
    client,
    controller_identity,
    awid_db_infra,
):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    owner_did_aw = stable_id_from_did_key(owner_did_key)
    domain = "address-idempotent-race.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, owner_key, owner_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    payload = {
        "name": "alice",
        "did_aw": owner_did_aw,
        "current_did_key": owner_did_key,
        "reachability": "public",
    }

    responses = await asyncio.gather(
        client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers),
        client.post(f"/v1/namespaces/{domain}/addresses", json=payload, headers=headers),
    )

    assert [resp.status_code for resp in responses] == [200, 200]
    assert responses[0].json() == responses[1].json()
    assert await _active_address_count(awid_db_infra, domain, "alice") == 1


@pytest.mark.asyncio
async def test_registry_client_maps_address_already_bound_error():
    async def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/v1/namespaces/example.com/addresses"
        return Response(409, json={"detail": "address already bound to a different did_aw"})

    controller_key, _ = generate_keypair()
    registry = RegistryClient(
        registry_url="http://registry.test",
        transport=MockTransport(handler),
    )
    try:
        with pytest.raises(AddressAlreadyBoundError):
            await registry.register_address(
                "example.com",
                "alice",
                "did:aw:bound",
                controller_key,
                "public",
                current_did_key="did:key:z6MkBound",
            )
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_address_reads_reflect_rotated_did_key_without_address_update(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    owner_did_aw = stable_id_from_did_key(owner_did_key)
    domain = "rotated-address-read.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="public",
    )
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice-alt",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="public",
    )

    await _rotate_identity(client, owner_key, owner_did_aw, owner_did_key, new_did_key)

    alice = await client.get(f"/v1/namespaces/{domain}/addresses/alice")
    assert alice.status_code == 200, alice.text
    assert alice.json()["current_did_key"] == new_did_key

    by_did = await client.get(f"/v1/did/{owner_did_aw}/addresses")
    assert by_did.status_code == 200, by_did.text
    assert [item["current_did_key"] for item in by_did.json()["addresses"]] == [
        new_did_key,
        new_did_key,
    ]


@pytest.mark.asyncio
async def test_register_address_rejects_stale_did_key_after_rotation(client, controller_identity):
    ns_key, ns_did = controller_identity
    old_key, old_pub = generate_keypair()
    old_did_key = did_from_public_key(old_pub)
    _, new_pub = generate_keypair()
    new_did_key = did_from_public_key(new_pub)
    owner_did_aw = stable_id_from_did_key(old_did_key)
    domain = "rotated-address-did.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, old_key, old_did_key)
    await _rotate_identity(client, old_key, owner_did_aw, old_did_key, new_did_key)

    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": owner_did_aw,
            "current_did_key": old_did_key,
            "reachability": "public",
        },
        headers=headers,
    )

    assert resp.status_code == 409
    assert resp.json()["detail"] == "did_aw current key does not match"


@pytest.mark.asyncio
async def test_register_team_members_only_requires_visible_to_team_id(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "missing-team-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, owner_key, owner_did_key)
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": "team_members_only",
        },
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is required when reachability=team_members_only"


@pytest.mark.asyncio
async def test_register_non_team_members_only_rejects_visible_to_team_id(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "unexpected-team-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _register_identity(client, owner_key, owner_did_key)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    headers = _sign(ns_key, ns_did, domain=domain, operation="register_address", name="alice")
    resp = await client.post(
        f"/v1/namespaces/{domain}/addresses",
        json={
            "name": "alice",
            "did_aw": stable_id_from_did_key(owner_did_key),
            "current_did_key": owner_did_key,
            "reachability": "org_only",
            "visible_to_team_id": f"backend:{domain}",
        },
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is only allowed when reachability=team_members_only"


@pytest.mark.asyncio
async def test_update_address_clears_visible_to_team_id_when_leaving_team_members_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "update-address-visibility.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="team_members_only",
        visible_to_team_id=f"backend:{domain}",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="update_address", name="alice")
    resp = await client.put(
        f"/v1/namespaces/{domain}/addresses/alice",
        json={"reachability": "org_only"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["reachability"] == "org_only"
    assert resp.json()["visible_to_team_id"] is None


@pytest.mark.asyncio
async def test_update_address_rejects_visible_to_team_id_with_org_only(client, controller_identity):
    ns_key, ns_did = controller_identity
    owner_key, owner_pub = generate_keypair()
    owner_did_key = did_from_public_key(owner_pub)
    domain = "update-address-invalid-scope.example"
    await _register_namespace(client, ns_key, ns_did, domain)
    await _create_team(client, ns_key, ns_did, domain, "backend")
    await _register_address_for_identity(
        client,
        ns_key,
        ns_did,
        domain,
        "alice",
        member_signing_key=owner_key,
        member_did_key=owner_did_key,
        reachability="nobody",
    )

    headers = _sign(ns_key, ns_did, domain=domain, operation="update_address", name="alice")
    resp = await client.put(
        f"/v1/namespaces/{domain}/addresses/alice",
        json={"reachability": "org_only", "visible_to_team_id": f"backend:{domain}"},
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "visible_to_team_id is only allowed when reachability=team_members_only"
