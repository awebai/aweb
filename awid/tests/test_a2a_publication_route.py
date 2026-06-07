from __future__ import annotations

import json
from pathlib import Path

import pytest

import awid_service.routes.a2a_publications as a2a_routes
from awid.a2a_publication import (
    A2A_AUTHORITY_SELF_DELEGATION,
    A2A_AUTHORITY_SELF_IDENTITY_KEY,
    A2A_CARD_DIGEST_ALG_SHA256,
    A2A_CONFLICT_CODES,
    A2A_CUSTODY_DELEGATED_BRIDGE,
    A2A_DELEGATION_OPERATION,
    A2A_PUBLICATION_OPERATION,
    A2A_STATUS_ACTIVE,
    A2ADelegationFields,
    A2APublicationFields,
    a2a_delegation_canonical,
    a2a_publication_canonical,
    normalize_a2a_delegation_fields,
    normalize_a2a_publication_fields,
    signed_assertion_digest,
)
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message

from conftest import build_signed_headers

_ROOT = Path(__file__).resolve().parents[2]
_ISSUED_AT = "2026-06-07T20:00:00Z"
_PUBLISHED_AT = "2026-06-07T20:01:00Z"
_EXPIRES_AT = "2026-07-07T20:00:00Z"
_REGISTRY_URL = "https://API.AWID.AI/"
_CARD_DIGEST = "sha256:1af084d5252fdf3bb11a0bc93ca8b257d88325152c02a9f336a179e736f3d5c7"


@pytest.fixture(autouse=True)
def _allow_static_timestamp(monkeypatch):
    monkeypatch.setattr(a2a_routes, "enforce_timestamp_skew", lambda _timestamp: None)


def test_a2a_publication_vector_canonical_bytes_and_conflict_codes():
    vector = json.loads(
        (_ROOT / "docs" / "vectors" / "a2a-awid-publication-v1.json").read_text(
            encoding="utf-8",
        )
    )

    assert canonical_json_bytes(vector["publication"]["payload"]).decode("utf-8") == vector["publication"]["canonical"]
    assert canonical_json_bytes(vector["delegation"]["payload"]).decode("utf-8") == vector["delegation"]["canonical"]
    assert vector["conflict_codes"] == list(A2A_CONFLICT_CODES)

    delegation_digest = signed_assertion_digest(
        vector["delegation"]["canonical"].encode("utf-8"),
        vector["delegation"]["signature"],
    )
    assert vector["publication"]["payload"]["delegation_digest"] == delegation_digest


async def _register_namespace(client, signing_key, controller_did, domain="example.com"):
    headers = build_signed_headers(signing_key, controller_did, domain=domain, operation="register")
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _seed_address(client, awid_db_infra, controller_identity):
    controller_signing_key, controller_did = controller_identity
    await _register_namespace(client, controller_signing_key, controller_did)
    identity_signing_key, identity_public_key = generate_keypair()
    identity_did_key = did_from_public_key(identity_public_key)
    identity_did_aw = stable_id_from_did_key(identity_did_key)
    gateway_signing_key, gateway_public_key = generate_keypair()
    gateway_did_key = did_from_public_key(gateway_public_key)
    gateway_did_aw = stable_id_from_did_key(gateway_did_key)

    db = awid_db_infra.get_manager("aweb")
    ns = await db.fetch_one(
        "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1",
        "example.com",
    )
    await db.execute(
        """
        INSERT INTO {{tables.did_aw_mappings}} (did_aw, current_did_key)
        VALUES ($1, $2), ($3, $4)
        """,
        identity_did_aw,
        identity_did_key,
        gateway_did_aw,
        gateway_did_key,
    )
    await db.execute(
        """
        INSERT INTO {{tables.public_addresses}} (namespace_id, name, did_aw)
        VALUES ($1, $2, $3)
        """,
        ns["namespace_id"],
        "research",
        identity_did_aw,
    )
    return {
        "identity_signing_key": identity_signing_key,
        "identity_did_key": identity_did_key,
        "identity_did_aw": identity_did_aw,
        "gateway_did_aw": gateway_did_aw,
    }


def _delegation_body(
    seed: dict,
    *,
    signature_override: str | None = None,
    card_digest: str = _CARD_DIGEST,
    status: str = A2A_STATUS_ACTIVE,
    revoked_at: str | None = None,
    revocation_reason: str | None = None,
) -> dict:
    fields = normalize_a2a_delegation_fields(
        A2ADelegationFields(
            operation=A2A_DELEGATION_OPERATION,
            delegation_id="del_test_01",
            delegator_did_aw=seed["identity_did_aw"],
            delegator_current_did_key=seed["identity_did_key"],
            delegated_gateway_identity=seed["gateway_did_aw"],
            address="example.com/research",
            route_id="r_research",
            card_url="https://example.com/a2a/agents/r_research/agent-card.json",
            rpc_url="https://example.com/a2a/agents/r_research/rpc",
            allowed_operations=("send_task", "receive_reply", "cancel_task", "serve_card"),
            card_digest_alg=A2A_CARD_DIGEST_ALG_SHA256,
            card_digest=card_digest,
            custody_mode=A2A_CUSTODY_DELEGATED_BRIDGE,
            authority_source=A2A_AUTHORITY_SELF_DELEGATION,
            signer_did=seed["identity_did_key"],
            signer_kid=seed["identity_did_key"] + "#ed25519",
            issued_at=_ISSUED_AT,
            expires_at=_EXPIRES_AT,
            status=status,
            revoked_at=revoked_at,
            revocation_reason=revocation_reason,
            registry_url=_REGISTRY_URL,
        )
    )
    canonical = a2a_delegation_canonical(fields)
    signature = signature_override or sign_message(seed["identity_signing_key"], canonical)
    return {
        **json.loads(canonical.decode("utf-8")),
        "signature": signature,
    }


def _publication_body(
    seed: dict,
    delegation_body: dict | None,
    *,
    delegation_digest: str | None = None,
    direct: bool = False,
    identity_custody: str = "self",
    authority_source: str = A2A_AUTHORITY_SELF_IDENTITY_KEY,
) -> dict:
    if delegation_digest is None:
        delegation_digest = (
            None
            if direct
            else signed_assertion_digest(
                canonical_json_bytes({k: v for k, v in delegation_body.items() if k != "signature"}),
                delegation_body["signature"],
            )
        )
    fields = normalize_a2a_publication_fields(
        A2APublicationFields(
            operation=A2A_PUBLICATION_OPERATION,
            assertion_id="pub_test_01",
            address="example.com/research",
            did_aw=seed["identity_did_aw"],
            current_did_key=seed["identity_did_key"],
            signer_did=seed["identity_did_key"],
            signer_kid=seed["identity_did_key"] + "#ed25519",
            card_url="https://example.com/a2a/agents/r_research/agent-card.json",
            rpc_url="https://example.com/a2a/agents/r_research/rpc",
            route_id="r_research",
            tenant=None,
            gateway_identity=seed["identity_did_aw"] if direct else seed["gateway_did_aw"],
            delegation_id=None if direct else "del_test_01",
            delegation_digest=delegation_digest,
            card_digest_alg=A2A_CARD_DIGEST_ALG_SHA256,
            card_digest=_CARD_DIGEST,
            card_revision="2026-06-07.1",
            default_for_host=False,
            status=A2A_STATUS_ACTIVE,
            published_at=_PUBLISHED_AT,
            expires_at=_EXPIRES_AT,
            registry_url=_REGISTRY_URL,
            identity_custody=identity_custody,
            authority_source=authority_source,
        )
    )
    canonical = a2a_publication_canonical(fields)
    return {
        **json.loads(canonical.decode("utf-8")),
        "signature": sign_message(seed["identity_signing_key"], canonical),
    }


async def _counts(awid_db_infra) -> tuple[int, int]:
    db = awid_db_infra.get_manager("aweb")
    delegations = await db.fetch_one("SELECT COUNT(*) AS count FROM {{tables.a2a_bridge_delegations}}")
    publications = await db.fetch_one("SELECT COUNT(*) AS count FROM {{tables.a2a_route_publications}}")
    return delegations["count"], publications["count"]


@pytest.mark.asyncio
async def test_a2a_delegation_publication_and_anonymous_lookup(client, awid_db_infra, controller_identity):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    delegation = _delegation_body(seed)
    delegation_resp = await client.post("/v1/a2a/delegations", json=delegation)
    assert delegation_resp.status_code == 200, delegation_resp.text
    assert delegation_resp.json()["status"] == "applied"

    publication = _publication_body(seed, delegation)
    publication_resp = await client.post("/v1/a2a/publications", json=publication)
    assert publication_resp.status_code == 200, publication_resp.text
    assert publication_resp.json()["status"] == "applied"

    lookup = await client.get("/v1/namespaces/example.com/addresses/research/a2a")
    assert lookup.status_code == 200, lookup.text
    payload = lookup.json()
    assert payload["address"] == "example.com/research"
    assert payload["did_aw"] == seed["identity_did_aw"]
    assert payload["a2a"]["verification"] == "awid_publication_available"
    assert payload["a2a"]["card_digest"] == _CARD_DIGEST
    assert "tenant" not in payload["a2a"]


@pytest.mark.asyncio
async def test_a2a_direct_hosted_publication_succeeds(client, awid_db_infra, controller_identity):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    publication = _publication_body(
        seed,
        None,
        direct=True,
        identity_custody="hosted_custodial",
        authority_source="hosted_session",
    )

    publication_resp = await client.post("/v1/a2a/publications", json=publication)

    assert publication_resp.status_code == 200, publication_resp.text
    lookup = await client.get("/v1/namespaces/example.com/addresses/research/a2a")
    assert lookup.status_code == 200, lookup.text
    assert lookup.json()["a2a"]["gateway_identity"] == seed["identity_did_aw"]


@pytest.mark.asyncio
async def test_a2a_delegation_bad_signature_fails_before_writes(client, awid_db_infra, controller_identity):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    other_signing_key, _ = generate_keypair()
    delegation = _delegation_body(
        seed,
        signature_override=sign_message(other_signing_key, b"not the canonical payload"),
    )

    resp = await client.post("/v1/a2a/delegations", json=delegation)

    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"]["code"] == "a2a_delegation_signature_invalid"
    assert await _counts(awid_db_infra) == (0, 0)


@pytest.mark.asyncio
async def test_a2a_publication_delegation_digest_mismatch_fails_before_write(
    client,
    awid_db_infra,
    controller_identity,
):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    delegation = _delegation_body(seed)
    delegation_resp = await client.post("/v1/a2a/delegations", json=delegation)
    assert delegation_resp.status_code == 200, delegation_resp.text

    publication = _publication_body(seed, delegation, delegation_digest="sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    resp = await client.post("/v1/a2a/publications", json=publication)

    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "a2a_delegation_digest_mismatch"
    assert await _counts(awid_db_infra) == (1, 0)


@pytest.mark.asyncio
async def test_a2a_revoked_delegation_suppresses_delegated_publication_lookup(
    client,
    awid_db_infra,
    controller_identity,
):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    delegation = _delegation_body(seed)
    assert (await client.post("/v1/a2a/delegations", json=delegation)).status_code == 200
    publication = _publication_body(seed, delegation)
    assert (await client.post("/v1/a2a/publications", json=publication)).status_code == 200

    revoked = _delegation_body(
        seed,
        status="revoked",
        revoked_at="2026-06-08T20:00:00Z",
        revocation_reason="operator_revoked",
    )
    revoke_resp = await client.post("/v1/a2a/delegations", json=revoked)
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["status"] == "revoked"

    lookup = await client.get("/v1/namespaces/example.com/addresses/research/a2a")
    assert lookup.status_code == 200, lookup.text
    assert "a2a" not in lookup.json()


@pytest.mark.asyncio
async def test_a2a_publication_feature_flag_disabled(client, awid_db_infra, controller_identity, monkeypatch):
    seed = await _seed_address(client, awid_db_infra, controller_identity)
    delegation = _delegation_body(seed)
    monkeypatch.setenv("AWID_ENABLE_A2A_PUBLICATION", "0")

    resp = await client.post("/v1/a2a/delegations", json=delegation)

    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["code"] == "a2a_primitive_disabled"
    assert await _counts(awid_db_infra) == (0, 0)
