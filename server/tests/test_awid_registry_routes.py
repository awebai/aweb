from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.awid import did_from_public_key, generate_keypair, sign_message, stable_id_from_did_key
from aweb.awid.log import log_entry_payload, state_hash
from aweb.awid.signing import canonical_json_bytes
from aweb.db import get_db_infra
from aweb.deps import get_domain_verifier
from aweb.dns_verify import DomainAuthority
from aweb.ratelimit import MemoryFixedWindowRateLimiter
from aweb.routes.did import router as did_router
from aweb.routes.dns_addresses import router as dns_addresses_router
from aweb.routes.dns_namespaces import router as dns_namespaces_router


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db) -> None:
        self.aweb_db = aweb_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self.aweb_db
        raise KeyError(name)


def _build_registry_test_app(*, aweb_db, domain_verifier) -> FastAPI:
    app = FastAPI(title="aweb registry routes test")
    app.include_router(did_router)
    app.include_router(dns_addresses_router)
    app.include_router(dns_namespaces_router)
    app.state.db = _DbInfra(aweb_db=aweb_db)
    app.state.rate_limiter = MemoryFixedWindowRateLimiter()
    app.dependency_overrides[get_db_infra] = lambda: _DbInfra(aweb_db=aweb_db)
    app.dependency_overrides[get_domain_verifier] = lambda: domain_verifier
    return app


def _authority(domain: str, controller_did: str) -> DomainAuthority:
    return DomainAuthority(
        controller_did=controller_did,
        registry_url="https://api.awid.ai",
        dns_name=f"_awid.{domain}",
    )


def _signed_address_headers(
    *,
    domain: str,
    name: str,
    operation: str,
    signing_key: bytes,
    did_key: str,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "domain": domain,
            "name": name,
            "operation": operation,
            "timestamp": timestamp,
        }
    )
    signature = sign_message(signing_key, payload)
    return {
        "Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
    }


def _signed_namespace_headers(
    *,
    domain: str,
    operation: str,
    signing_key: bytes,
    did_key: str,
    extra_payload: dict[str, str] | None = None,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {
        "domain": domain,
        "operation": operation,
        "timestamp": timestamp,
    }
    if extra_payload:
        payload.update(extra_payload)
    signature = sign_message(signing_key, canonical_json_bytes(payload))
    return {
        "Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
    }


def _signed_namespace_rotation_headers(
    *,
    domain: str,
    new_controller_did: str,
    signing_key: bytes,
    did_key: str,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "domain": domain,
            "new_controller_did": new_controller_did,
            "operation": "rotate_controller",
            "timestamp": timestamp,
        }
    )
    signature = sign_message(signing_key, payload)
    return {
        "Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Timestamp": timestamp,
    }


def _signed_parent_rotation_headers(
    *,
    child_domain: str,
    new_controller_did: str,
    signing_key: bytes,
    did_key: str,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "domain": child_domain,
            "child_domain": child_domain,
            "new_controller_did": new_controller_did,
            "operation": "authorize_subdomain_rotation",
            "timestamp": timestamp,
        }
    )
    signature = sign_message(signing_key, payload)
    return {
        "X-AWEB-Parent-Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Parent-Timestamp": timestamp,
    }


def _signed_parent_registration_headers(
    *,
    child_domain: str,
    controller_did: str,
    signing_key: bytes,
    did_key: str,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes(
        {
            "domain": child_domain,
            "child_domain": child_domain,
            "controller_did": controller_did,
            "operation": "authorize_subdomain_registration",
            "timestamp": timestamp,
        }
    )
    signature = sign_message(signing_key, payload)
    return {
        "X-AWEB-Parent-Authorization": f"DIDKey {did_key} {signature}",
        "X-AWEB-Parent-Timestamp": timestamp,
    }


@pytest.mark.asyncio
async def test_register_did_allows_unbound_identity(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    mapping_state_hash = state_hash(
        did_aw=did_aw,
        current_did_key=did_key,
        server="",
        address="",
        handle=None,
    )
    proof = sign_message(
        signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="create",
            previous_did_key=None,
            new_did_key=did_key,
            prev_entry_hash=None,
            state_hash=mapping_state_hash,
            authorized_by=did_key,
            timestamp=timestamp,
        ),
    )

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=lambda _domain: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/did",
            json={
                "did_aw": did_aw,
                "did_key": did_key,
                "server": "",
                "address": "",
                "handle": None,
                "seq": 1,
                "prev_entry_hash": None,
                "state_hash": mapping_state_hash,
                "authorized_by": did_key,
                "timestamp": timestamp,
                "proof": proof,
            },
        )
        full_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        full_path = f"/v1/did/{did_aw}/full"
        full_signature = sign_message(
            signing_key,
            f"{full_timestamp}\nGET\n{full_path}".encode("utf-8"),
        )
        full_response = await client.get(
            full_path,
            headers={
                "Authorization": f"DIDKey {did_key} {full_signature}",
                "X-AWEB-Timestamp": full_timestamp,
            },
        )

    assert response.status_code == 200, response.text
    assert full_response.status_code == 200, full_response.text
    assert full_response.json()["server"] == ""
    row = await aweb_db.fetch_one(
        "SELECT did_aw, current_did_key, server_url, address, handle FROM {{tables.did_aw_mappings}} WHERE did_aw = $1",
        did_aw,
    )
    assert row is not None
    assert row["did_aw"] == did_aw
    assert row["current_did_key"] == did_key
    assert row["server_url"] == ""
    assert row["address"] == ""
    assert row["handle"] is None


@pytest.mark.asyncio
async def test_register_did_accepts_empty_handle_with_null_equivalent_state_hash(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    mapping_state_hash = state_hash(
        did_aw=did_aw,
        current_did_key=did_key,
        server="",
        address="",
        handle=None,
    )
    proof = sign_message(
        signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="create",
            previous_did_key=None,
            new_did_key=did_key,
            prev_entry_hash=None,
            state_hash=mapping_state_hash,
            authorized_by=did_key,
            timestamp=timestamp,
        ),
    )

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=lambda _domain: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/did",
            json={
                "did_aw": did_aw,
                "did_key": did_key,
                "server": "",
                "address": "",
                "handle": "",
                "seq": 1,
                "prev_entry_hash": None,
                "state_hash": mapping_state_hash,
                "authorized_by": did_key,
                "timestamp": timestamp,
                "proof": proof,
            },
        )

    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_get_full_requires_current_or_owning_did_key(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    did_aw = stable_id_from_did_key(did_key)
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    mapping_state_hash = state_hash(
        did_aw=did_aw,
        current_did_key=did_key,
        server="https://app.aweb.ai",
        address="acme.com/alice",
        handle="alice",
    )
    proof = sign_message(
        signing_key,
        log_entry_payload(
            did_aw=did_aw,
            seq=1,
            operation="create",
            previous_did_key=None,
            new_did_key=did_key,
            prev_entry_hash=None,
            state_hash=mapping_state_hash,
            authorized_by=did_key,
            timestamp=timestamp,
        ),
    )
    attacker_signing_key, attacker_public_key = generate_keypair()
    attacker_did_key = did_from_public_key(attacker_public_key)

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=lambda _domain: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        create_response = await client.post(
            "/v1/did",
            json={
                "did_aw": did_aw,
                "did_key": did_key,
                "server": "https://app.aweb.ai",
                "address": "acme.com/alice",
                "handle": "alice",
                "seq": 1,
                "prev_entry_hash": None,
                "state_hash": mapping_state_hash,
                "authorized_by": did_key,
                "timestamp": timestamp,
                "proof": proof,
            },
        )
        full_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        full_path = f"/v1/did/{did_aw}/full"
        full_signature = sign_message(
            attacker_signing_key,
            f"{full_timestamp}\nGET\n{full_path}".encode("utf-8"),
        )
        full_response = await client.get(
            full_path,
            headers={
                "Authorization": f"DIDKey {attacker_did_key} {full_signature}",
                "X-AWEB-Timestamp": full_timestamp,
            },
        )

    assert create_response.status_code == 200, create_response.text
    assert full_response.status_code == 403, full_response.text
    assert full_response.json() == {"detail": "forbidden"}


@pytest.mark.asyncio
async def test_list_did_addresses_returns_active_addresses_for_identity(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    subject_signing_key, subject_public_key = generate_keypair()
    subject_did_key = did_from_public_key(subject_public_key)
    did_aw = stable_id_from_did_key(subject_did_key)
    other_signing_key, other_public_key = generate_keypair()
    other_did_aw = stable_id_from_did_key(did_from_public_key(other_public_key))

    namespace_one = uuid.uuid4()
    namespace_two = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified'),
               ($5, $6, $7, 'verified', $4, $4, 'dns_verified')
        """,
        namespace_one,
        "acme.com",
        "did:key:zcontroller1",
        created_at,
        namespace_two,
        "zeta.com",
        "did:key:zcontroller2",
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.public_addresses}}
            (address_id, namespace_id, name, did_aw, current_did_key, reachability, created_at, deleted_at)
        VALUES
            ($1, $2, 'support', $3, $4, 'public', $5, NULL),
            ($6, $7, 'ops', $3, $4, 'private', $5, NULL),
            ($8, $2, 'old', $3, $4, 'private', $5, NOW()),
            ($9, $2, 'other', $10, $11, 'public', $5, NULL)
        """,
        uuid.uuid4(),
        namespace_one,
        did_aw,
        subject_did_key,
        created_at,
        uuid.uuid4(),
        namespace_two,
        uuid.uuid4(),
        uuid.uuid4(),
        other_did_aw,
        did_from_public_key(other_public_key),
    )

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=lambda _domain: None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/v1/did/{did_aw}/addresses")

    assert response.status_code == 200, response.text
    data = response.json()
    assert [item["domain"] for item in data["addresses"]] == ["acme.com", "zeta.com"]
    assert [item["name"] for item in data["addresses"]] == ["support", "ops"]






@pytest.mark.asyncio
async def test_update_address_changes_reachability_not_did_key(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    controller_signing_key, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)
    subject_signing_key, subject_public_key = generate_keypair()
    current_did_key = did_from_public_key(subject_public_key)
    did_aw = stable_id_from_did_key(current_did_key)
    namespace_id = uuid.uuid4()
    address_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified')
        """,
        namespace_id,
        "acme.com",
        controller_did,
        created_at,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.public_addresses}}
            (address_id, namespace_id, name, did_aw, current_did_key, reachability, created_at)
        VALUES ($1, $2, 'support', $3, $4, 'private', $5)
        """,
        address_id,
        namespace_id,
        did_aw,
        current_did_key,
        created_at,
    )

    async def _verify_domain(domain: str) -> DomainAuthority:
        return _authority(domain, controller_did)

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.put(
            "/v1/namespaces/acme.com/addresses/support",
            headers=_signed_address_headers(
                domain="acme.com",
                name="support",
                operation="update_address",
                signing_key=controller_signing_key,
                did_key=controller_did,
            ),
            json={"reachability": "public"},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["reachability"] == "public"
    assert data["current_did_key"] == current_did_key

    row = await aweb_db.fetch_one(
        """
        SELECT current_did_key, reachability
        FROM {{tables.public_addresses}}
        WHERE address_id = $1
        """,
        address_id,
    )
    assert row is not None
    assert row["current_did_key"] == current_did_key
    assert row["reachability"] == "public"


@pytest.mark.asyncio
async def test_register_subdomain_with_parent_authorization_skips_dns(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)
    child_signing_key, child_public_key = generate_keypair()
    child_controller_did = did_from_public_key(child_public_key)
    parent_namespace_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified')
        """,
        parent_namespace_id,
        "aweb.ai",
        parent_controller_did,
        created_at,
    )

    async def _verify_domain(_domain: str) -> DomainAuthority:
        raise AssertionError("DNS verification should be skipped for parent-authorized subdomains")

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/namespaces",
            headers={
                **_signed_namespace_headers(
                    domain="project.aweb.ai",
                    operation="register",
                    signing_key=child_signing_key,
                    did_key=child_controller_did,
                ),
                **_signed_parent_registration_headers(
                    child_domain="project.aweb.ai",
                    controller_did=child_controller_did,
                    signing_key=parent_signing_key,
                    did_key=parent_controller_did,
                ),
            },
            json={"domain": "project.aweb.ai", "controller_did": child_controller_did},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["controller_did"] == child_controller_did


@pytest.mark.asyncio
async def test_register_subdomain_rejects_parent_signature_for_different_controller(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)
    requested_child_signing_key, requested_child_public_key = generate_keypair()
    requested_child_controller_did = did_from_public_key(requested_child_public_key)
    other_child_signing_key, other_child_public_key = generate_keypair()
    other_child_controller_did = did_from_public_key(other_child_public_key)
    parent_namespace_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    del requested_child_signing_key

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified')
        """,
        parent_namespace_id,
        "aweb.ai",
        parent_controller_did,
        created_at,
    )

    async def _verify_domain(_domain: str) -> DomainAuthority:
        raise AssertionError("DNS verification should be skipped for parent-authorized subdomains")

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/namespaces",
            headers={
                **_signed_namespace_headers(
                    domain="project.aweb.ai",
                    operation="register",
                    signing_key=other_child_signing_key,
                    did_key=other_child_controller_did,
                ),
                **_signed_parent_registration_headers(
                    child_domain="project.aweb.ai",
                    controller_did=other_child_controller_did,
                    signing_key=parent_signing_key,
                    did_key=parent_controller_did,
                ),
            },
            json={"domain": "project.aweb.ai", "controller_did": requested_child_controller_did},
        )

    assert response.status_code == 403, response.text


@pytest.mark.asyncio
async def test_rotate_subdomain_with_invalid_parent_auth_does_not_fall_back_to_dns(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)
    other_parent_signing_key, other_parent_public_key = generate_keypair()
    other_parent_controller_did = did_from_public_key(other_parent_public_key)
    old_signing_key, old_public_key = generate_keypair()
    old_controller_did = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)
    parent_namespace_id = uuid.uuid4()
    child_namespace_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    del old_signing_key

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $5, $5, 'dns_verified'),
               ($4, $6, $7, 'verified', $5, $5, 'dns_verified')
        """,
        parent_namespace_id,
        "aweb.ai",
        parent_controller_did,
        child_namespace_id,
        created_at,
        "project.aweb.ai",
        old_controller_did,
    )

    async def _verify_domain(domain: str) -> DomainAuthority:
        return _authority(domain, new_controller_did)

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.put(
            "/v1/namespaces/project.aweb.ai",
            headers={
                **_signed_namespace_rotation_headers(
                    domain="project.aweb.ai",
                    new_controller_did=new_controller_did,
                    signing_key=new_signing_key,
                    did_key=new_controller_did,
                ),
                **_signed_parent_rotation_headers(
                    child_domain="project.aweb.ai",
                    new_controller_did=new_controller_did,
                    signing_key=other_parent_signing_key,
                    did_key=other_parent_controller_did,
                ),
            },
            json={"new_controller_did": new_controller_did},
        )

    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_rotate_subdomain_controller_with_parent_authorization_skips_dns(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    parent_signing_key, parent_public_key = generate_keypair()
    parent_controller_did = did_from_public_key(parent_public_key)
    old_signing_key, old_public_key = generate_keypair()
    old_controller_did = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)
    parent_namespace_id = uuid.uuid4()
    child_namespace_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    del old_signing_key

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $5, $5, 'dns_verified'),
               ($4, $6, $7, 'verified', $5, $5, 'dns_verified')
        """,
        parent_namespace_id,
        "aweb.ai",
        parent_controller_did,
        child_namespace_id,
        created_at,
        "project.aweb.ai",
        old_controller_did,
    )

    async def _verify_domain(_domain: str) -> DomainAuthority:
        raise AssertionError("DNS verification should be skipped for parent-authorized subdomains")

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.put(
            "/v1/namespaces/project.aweb.ai",
            headers={
                **_signed_namespace_rotation_headers(
                    domain="project.aweb.ai",
                    new_controller_did=new_controller_did,
                    signing_key=new_signing_key,
                    did_key=new_controller_did,
                ),
                **_signed_parent_rotation_headers(
                    child_domain="project.aweb.ai",
                    new_controller_did=new_controller_did,
                    signing_key=parent_signing_key,
                    did_key=parent_controller_did,
                ),
            },
            json={"new_controller_did": new_controller_did},
        )

    assert response.status_code == 200, response.text
    assert response.json()["controller_did"] == new_controller_did


@pytest.mark.asyncio
async def test_rotate_namespace_controller_reverifies_dns_and_updates_controller(aweb_cloud_db):
    aweb_db = aweb_cloud_db.aweb_db
    _old_signing_key, old_public_key = generate_keypair()
    old_controller_did = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_controller_did = did_from_public_key(new_public_key)
    namespace_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)

    await aweb_db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified')
        """,
        namespace_id,
        "example.com",
        old_controller_did,
        created_at,
    )

    async def _verify_domain(domain: str) -> DomainAuthority:
        return _authority(domain, new_controller_did)

    app = _build_registry_test_app(aweb_db=aweb_db, domain_verifier=_verify_domain)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.put(
            "/v1/namespaces/example.com",
            headers=_signed_namespace_rotation_headers(
                domain="example.com",
                new_controller_did=new_controller_did,
                signing_key=new_signing_key,
                did_key=new_controller_did,
            ),
            json={"new_controller_did": new_controller_did},
        )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["controller_did"] == new_controller_did

    row = await aweb_db.fetch_one(
        """
        SELECT controller_did, verification_status
        FROM {{tables.dns_namespaces}}
        WHERE namespace_id = $1
        """,
        namespace_id,
    )
    assert row is not None
    assert row["controller_did"] == new_controller_did
    assert row["verification_status"] == "verified"
