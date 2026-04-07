from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key


@pytest.mark.asyncio
async def test_registry_routes_read_from_awid_schema(client, awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    now = datetime.now(timezone.utc)
    namespace_id = uuid4()
    address_id = uuid4()
    _, subject_public_key = generate_keypair()
    did_key = did_from_public_key(subject_public_key)
    did_aw = stable_id_from_did_key(did_key)
    _, controller_public_key = generate_keypair()
    controller_did = did_from_public_key(controller_public_key)

    await db.execute(
        """
        INSERT INTO {{tables.did_aw_mappings}}
            (did_aw, current_did_key, server_url, address, handle, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        """,
        did_aw,
        did_key,
        "https://registry.example",
        "registry.example/support",
        "support",
        now,
    )
    await db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, $3, 'verified', $4, $4, 'dns_verified')
        """,
        namespace_id,
        "registry.example",
        controller_did,
        now,
    )
    await db.execute(
        """
        INSERT INTO {{tables.public_addresses}}
            (address_id, namespace_id, name, did_aw, current_did_key, reachability, created_at)
        VALUES ($1, $2, $3, $4, $5, 'public', $6)
        """,
        address_id,
        namespace_id,
        "support",
        did_aw,
        did_key,
        now,
    )

    resp = await client.get(f"/v1/did/{did_aw}/addresses")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["addresses"] == [
        {
            "address_id": str(address_id),
            "domain": "registry.example",
            "name": "support",
            "did_aw": did_aw,
            "current_did_key": did_key,
            "reachability": "public",
            "created_at": now.isoformat(),
        }
    ]
