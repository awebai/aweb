from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import asyncpg
import pytest
from pgdbm.errors import QueryError

from awid.delegation import (
    DELEGATION_VERSION,
    DelegationPayload,
    canonical_delegation_payload,
    delegation_entry_hash,
)
from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import DomainAuthority
from awid.registry_migration import (
    CanonicalOverlapPayload,
    DestinationCompletePayload,
    OverlapObservationPayload,
    make_receipt,
)
from awid.signing import canonical_json_bytes, sign_message
from awid_service.db import AwidDatabaseInfra
from awid_service.delegation_state import (
    DelegationStateError,
    append_transition,
    stored_delegation_chain,
)
import awid_service.registry_migration as registry_migration_module
from awid_service.registry_migration import RegistryMigrationError, RegistryMigrationService
from awid_service.routes.dns_namespaces import (
    get_namespace,
    get_namespace_delegation_log,
)


def make_source_service(db):
    async def verifier(domain):
        controller = await db.fetch_value(
            "SELECT controller_did FROM {{tables.dns_namespaces}} WHERE domain=$1 ORDER BY (deleted_at IS NULL) DESC,created_at DESC LIMIT 1",
            domain,
        )
        return DomainAuthority(
            controller_did=controller,
            registry_url="https://source.example",
            dns_name=f"_awid.{domain}",
            inherited=False,
            ttl_seconds=5,
            authoritative_ttl_seconds=300,
        )

    return RegistryMigrationService(db, verify_domain=verifier)


def make_destination_service(
    db, *, verifier=None, public_origin="https://destination.example"
):
    return RegistryMigrationService(
        db, verify_domain=verifier, public_origin=public_origin
    )


def migration_assertion(
    *, parent, child, controller, sequence, previous, key, signer, operation="delegate"
):
    payload = DelegationPayload(
        version=DELEGATION_VERSION, operation=operation, parent_domain=parent,
        child_domain=child, child_controller_did=controller, sequence=sequence,
        previous_delegation_hash=previous,
    )
    canonical = canonical_delegation_payload(payload)
    return {
        "payload": payload.model_dump(mode="json"),
        "entry_hash": delegation_entry_hash(canonical),
        "signatures": [{"controller_did": signer, "signature": sign_message(key, canonical)}],
    }


def clone_artifact(artifact, *, cutover_id: str, root_domain: str | None = None):
    payload = json.loads(json.dumps(artifact.payload))
    payload["cutover_id"] = cutover_id
    if root_domain is not None:
        payload["root_domain"] = root_domain
    for item in payload["items"]:
        item["row"]["state_cutover_id"] = cutover_id
    payload["manifest_digest"] = RegistryMigrationService._digest(payload["items"])
    return {
        "payload": payload,
        "snapshot_digest": RegistryMigrationService._digest(payload),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [[], "artifact", {"payload": [], "snapshot_digest": "sha256:" + "0" * 64}],
)
async def test_malformed_artifact_containers_fail_before_database(value):
    class NoDatabase:
        @asynccontextmanager
        async def transaction(self):
            raise AssertionError("malformed artifact reached database")
            yield

    service = RegistryMigrationService(
        NoDatabase(), public_origin="https://destination.example"
    )
    with pytest.raises(RegistryMigrationError):
        await service.import_artifact(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["prepare", "import"])
async def test_canonical_transactions_pin_utc_before_any_lock_or_serialization(operation):
    class StopAfterUTC(Exception):
        pass

    class RecordingTx:
        def __init__(self):
            self.calls = []

        async def execute(self, query, *args):
            self.calls.append(("execute", query, args))

        async def fetch_value(self, query, *args):
            self.calls.append(("fetch_value", query, args))
            raise StopAfterUTC

    class RecordingDB:
        def __init__(self):
            self.tx = RecordingTx()

        @asynccontextmanager
        async def transaction(self):
            yield self.tx

    async def verifier(_domain):
        return DomainAuthority(
            controller_did="did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
            registry_url="https://source.example",
            dns_name="_awid.example.com",
            inherited=False,
            ttl_seconds=5,
            authoritative_ttl_seconds=300,
        )

    db = RecordingDB()
    service = RegistryMigrationService(
        db, verify_domain=verifier, public_origin="https://destination.example"
    )
    with pytest.raises(StopAfterUTC):
        if operation == "prepare":
            await service.prepare(
                root_domain="example.com",
                destination_registry_id=str(uuid4()),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
        else:
            evidence_payload = {
                "dns_name": "_awid.example.com",
                "old_registry_origin": "https://source.example",
                "controller_did": "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
                "ttl_seconds": 300,
                "authority_answer_digest": RegistryMigrationService._digest({
                    "controller_did": "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
                    "dns_name": "_awid.example.com",
                    "registry_origin": "https://source.example",
                }),
                "observed_at": "2026-08-26T18:00:00Z",
            }
            payload = {
                "version": "awid.registry-migration.v1",
                "source_registry_id": str(uuid4()),
                "destination_registry_id": str(uuid4()),
                "cutover_id": str(uuid4()),
                "root_domain": "example.com",
                "source_generation": 1,
                "manifest_digest": RegistryMigrationService._digest([]),
                "old_selection_evidence": {
                    **evidence_payload,
                    "evidence_hash": RegistryMigrationService._digest(evidence_payload),
                },
                "expected_source_origin": "https://source.example",
                "expected_destination_origin": "https://destination.example",
                "items": [],
            }
            await service.import_artifact({
                "payload": payload,
                "snapshot_digest": RegistryMigrationService._digest(payload),
            })
    assert db.tx.calls[0] == ("execute", "SET LOCAL TIME ZONE 'UTC'", ())
    assert db.tx.calls[1][0] == "fetch_value"


@pytest.mark.asyncio
async def test_two_database_prepare_import_readback_fence_and_cancel(shared_test_pool):
    source = AwidDatabaseInfra(schema="awid_migration_source")
    destination = AwidDatabaseInfra(schema="awid_migration_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_db = source.get_manager("aweb")
        destination_db = destination.get_manager("aweb")
        source_service = make_source_service(source_db)
        destination_service = make_destination_service(destination_db)

        did_aw = "did:aw:migration-shared"
        await source_db.execute(
            "INSERT INTO {{tables.did_aw_mappings}} (did_aw,current_did_key) VALUES ($1,$2)",
            did_aw,
            "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
        )
        root_namespace_id = uuid4()
        outside_namespace_id = uuid4()
        await source_db.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id,domain,controller_did,verification_status)
            VALUES ($1,'move.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified'),
                   ($2,'outside.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')
            """,
            root_namespace_id,
            outside_namespace_id,
        )
        inside_address_id = uuid4()
        await source_db.execute(
            """
            INSERT INTO {{tables.public_addresses}}
                (address_id,namespace_id,name,did_aw)
            VALUES ($1,$2,'inside',$3),($4,$5,'outside',$3)
            """,
            inside_address_id,
            root_namespace_id,
            did_aw,
            uuid4(),
            outside_namespace_id,
        )
        team_id = uuid4()
        await source_db.execute(
            "INSERT INTO {{tables.teams}} (team_uuid,domain,name,display_name,team_did_key) VALUES ($1,'move.example','moving','Moving','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd')",
            team_id,
        )

        artifact = await source_service.prepare(
            root_domain="move.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        payload = artifact.payload
        original_verifier = source_service.verify_domain

        async def unavailable_dns(_domain):
            raise AssertionError("exact frozen retry must not resolve DNS")

        source_service.verify_domain = unavailable_dns
        status = await source_service.status(payload["cutover_id"])
        assert status["expected_destination_origin"] == "https://destination.example"
        assert status["roles"][0]["updated_at"].endswith("Z")
        assert await source_service.prepare(
            root_domain="move.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
            cutover_id=payload["cutover_id"],
        ) == artifact
        source_service.verify_domain = original_verifier
        with pytest.raises(RegistryMigrationError, match="expected origin"):
            await source_service.prepare(
                root_domain="move.example",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://changed.example",
                expected_destination_origin="https://destination.example",
                cutover_id=payload["cutover_id"],
            )
        with pytest.raises(RegistryMigrationError, match="conflicting source cutover"):
            await source_service.prepare(
                root_domain="move.example",
                destination_registry_id=str(uuid4()),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
                cutover_id=payload["cutover_id"],
            )
        assert payload["source_registry_id"] == await source_service.registry_id()
        assert payload["destination_registry_id"] == await destination_service.registry_id()
        assert {item["kind"] for item in payload["items"]} >= {"namespace", "address", "did"}
        assert sum(item["kind"] == "address" for item in payload["items"]) == 1

        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                "UPDATE {{tables.did_aw_mappings}} SET updated_at=NOW() WHERE did_aw=$1",
                did_aw,
            )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='move.example'"
            )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                "UPDATE {{tables.teams}} SET domain='outside.example' WHERE team_uuid=$1",
                team_id,
            )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                "UPDATE {{tables.public_addresses}} SET namespace_id=$2 WHERE address_id=$1",
                inside_address_id,
                outside_namespace_id,
            )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                """
                INSERT INTO {{tables.teams}}
                    (domain,name,display_name,team_did_key)
                VALUES ('move.example','new-team','New Team','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd')
                """
            )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                """
                INSERT INTO {{tables.namespace_delegation_heads}}
                    (child_domain,parent_domain,head_sequence,head_hash,
                     head_operation,head_controller_did)
                VALUES ('new.move.example','move.example',1,$1,'delegate','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd')
                """,
                "sha256:" + "a" * 64,
            )
        await source_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='outside.example'"
        )

        wrong_origin_service = make_destination_service(
            destination_db, public_origin="https://wrong.example"
        )
        with pytest.raises(RegistryMigrationError, match="destination origin mismatch"):
            await wrong_origin_service.import_artifact(artifact.as_dict())
        tampered = artifact.as_dict() | {"snapshot_digest": "sha256:" + "0" * 64}
        with pytest.raises(RegistryMigrationError, match="snapshot digest"):
            await destination_service.import_artifact(tampered)
        await destination_db.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (domain,controller_did,verification_status)
            VALUES ('destination-local.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')
            """
        )
        readback, concurrent_readback = await asyncio.gather(
            destination_service.import_artifact(artifact.as_dict()),
            destination_service.import_artifact(artifact.as_dict()),
        )
        assert concurrent_readback == readback
        assert readback["payload"]["snapshot_digest"] == artifact.snapshot_digest
        assert readback["payload"]["manifest_digest"] == payload["manifest_digest"]
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.dns_namespaces}} WHERE domain='move.example'"
        ) == 1
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.dns_namespaces}} WHERE domain='outside.example'"
        ) == 0
        imported = await destination_db.fetch_one(
            "SELECT state_source_registry_id,state_cutover_id,state_generation FROM {{tables.did_aw_mappings}} WHERE did_aw=$1",
            did_aw,
        )
        assert str(imported["state_source_registry_id"]) == payload["source_registry_id"]
        assert str(imported["state_cutover_id"]) == payload["cutover_id"]
        assert imported["state_generation"] == payload["source_generation"]

        assert await destination_service.import_artifact(artifact.as_dict()) == readback
        outside_destination_namespace = await destination_db.fetch_value(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain='destination-local.example'"
        )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await destination_db.execute(
                """
                INSERT INTO {{tables.public_addresses}}
                    (address_id,namespace_id,name,did_aw)
                VALUES ($1,$2,'cross-root',$3)
                """,
                uuid4(), outside_destination_namespace, did_aw,
            )
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.public_addresses}} WHERE namespace_id=$1",
            outside_destination_namespace,
        ) == 0
        with pytest.raises(RegistryMigrationError, match="requires DNS authorization"):
            await destination_service.observe_destination(
                payload["cutover_id"],
                destination_registry_origin="https://new.example",
                destination_dns_name="_awid.move.example",
                destination_dns_answer_digest="sha256:" + "8" * 64,
                observed_at="2026-08-26T18:00:00Z",
            )

        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="invalid_registry_cancel_cleanup_provenance"):
            async with destination_db.transaction() as tx:
                await tx.fetch_value("SELECT set_config('awid.cancel_cleanup_mode','true',TRUE)")
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_source_registry_id',$1,TRUE)",
                    payload["source_registry_id"],
                )
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_cutover_id',$1,TRUE)",
                    str(uuid4()),
                )
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_source_generation',$1,TRUE)",
                    str(payload["source_generation"]),
                )
                await tx.execute(
                    "DELETE FROM {{tables.public_addresses}} WHERE namespace_id=(SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain='move.example')"
                )

        async def unauthorized_cleanup(source_id, cutover, generation):
            async with destination_db.transaction() as tx:
                await tx.fetch_value("SELECT set_config('awid.cancel_cleanup_mode','true',TRUE)")
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_source_registry_id',$1,TRUE)", source_id,
                )
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_cutover_id',$1,TRUE)", cutover,
                )
                await tx.fetch_value(
                    "SELECT set_config('awid.cancel_cleanup_source_generation',$1,TRUE)", str(generation),
                )
                await tx.execute("DELETE FROM {{tables.public_addresses}} WHERE namespace_id=(SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain='move.example')")

        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="invalid_registry_cancel_cleanup_provenance"):
            await unauthorized_cleanup(str(uuid4()), payload["cutover_id"], payload["source_generation"])
        with pytest.raises(asyncpg.ObjectNotInPrerequisiteStateError, match="invalid_registry_cancel_cleanup_provenance"):
            await unauthorized_cleanup(payload["source_registry_id"], payload["cutover_id"], payload["source_generation"] + 1)

        async with destination_db.transaction() as tx:
            for name, value in (
                ("awid.registry_import_mode", "true"),
                ("awid.registry_import_cutover_id", payload["cutover_id"]),
                ("awid.registry_import_source_registry_id", payload["source_registry_id"]),
                ("awid.registry_import_source_generation", str(payload["source_generation"])),
            ):
                await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
            await tx.execute(
                """
                INSERT INTO {{tables.did_aw_log}}
                    (did_aw,seq,operation,new_did_key,entry_hash,state_hash,
                     authorized_by,signature,timestamp)
                VALUES ($1,1,'register_did',$2,$3,$4,$2,'signature','2026-08-26T18:00:00Z')
                """,
                did_aw,
                "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
                "c" * 64,
                "d" * 64,
            )
        with pytest.raises(RegistryMigrationError, match="provenance cohort mismatch"):
            await destination_service.cancel_destination(payload["cutover_id"])
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.did_aw_mappings}} WHERE did_aw=$1", did_aw
        ) == 1
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.did_aw_log}} WHERE did_aw=$1", did_aw
        ) == 1
        async with destination_db.transaction() as tx:
            for name, value in (
                ("awid.cancel_cleanup_mode", "true"),
                ("awid.cancel_cleanup_cutover_id", payload["cutover_id"]),
                ("awid.cancel_cleanup_source_registry_id", payload["source_registry_id"]),
                ("awid.cancel_cleanup_source_generation", str(payload["source_generation"])),
            ):
                await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
            await tx.execute(
                "DELETE FROM {{tables.did_aw_log}} WHERE did_aw=$1 AND seq=1", did_aw
            )

        cancel_task = None
        async with destination_db.transaction() as mutation_tx:
            await mutation_tx.fetch_one(
                "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain='move.example' FOR UPDATE"
            )
            cancel_task = asyncio.create_task(
                destination_service.cancel_destination(payload["cutover_id"])
            )
            await asyncio.sleep(0.05)
            assert not cancel_task.done()
            with pytest.raises(
                asyncpg.ObjectNotInPrerequisiteStateError,
                match="registry_migration_fenced",
            ):
                await mutation_tx.execute(
                    "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='move.example'"
                )
        canceled = await cancel_task
        assert canceled["state"] == "canceled"
        assert await destination_service.cancel_destination(payload["cutover_id"]) == canceled
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.did_aw_mappings}} WHERE did_aw=$1", did_aw
        ) == 0
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.dns_namespaces}} WHERE domain='destination-local.example'"
        ) == 1
        audit = await destination_db.fetch_one(
            "SELECT state,cancel_digest FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination'",
            payload["cutover_id"],
        )
        assert audit["state"] == "canceled"
        assert audit["cancel_digest"].startswith("sha256:")
        with pytest.raises(RegistryMigrationError, match="requires DNS authorization"):
            await destination_service.observe_destination(
                payload["cutover_id"],
                destination_registry_origin="https://new.example",
                destination_dns_name="_awid.move.example",
                destination_dns_answer_digest="sha256:" + "8" * 64,
                observed_at="2026-08-26T18:00:00Z",
            )
        assert await source_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.did_aw_mappings}} WHERE did_aw=$1", did_aw
        ) == 1
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_dormant_and_deleted_delegation_roots_export_exact_history(shared_test_pool):
    source = AwidDatabaseInfra(schema="awid_dormant_migration_source")
    destination = AwidDatabaseInfra(schema="awid_dormant_migration_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = source.get_manager("aweb")
        grand_key, grand_public = generate_keypair()
        grand_did = did_from_public_key(grand_public)
        dormant_key, dormant_public = generate_keypair()
        dormant_did = did_from_public_key(dormant_public)
        direct_key, direct_public = generate_keypair()
        direct_did = did_from_public_key(direct_public)
        deleted_key, deleted_public = generate_keypair()
        deleted_did = did_from_public_key(deleted_public)
        await db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('history-grand.example',$1,'verified')",
            grand_did,
        )
        dormant = migration_assertion(
            parent="history-grand.example", child="dormant.history-grand.example",
            controller=dormant_did, sequence=1, previous=None,
            key=grand_key, signer=grand_did,
        )
        deleted_genesis = migration_assertion(
            parent="history-grand.example", child="deleted.history-grand.example",
            controller=deleted_did, sequence=1, previous=None,
            key=grand_key, signer=grand_did,
        )
        deleted_revoke = migration_assertion(
            parent="history-grand.example", child="deleted.history-grand.example",
            controller=deleted_did, sequence=2, previous=deleted_genesis["entry_hash"],
            key=deleted_key, signer=deleted_did, operation="revoke",
        )
        async with db.transaction() as tx:
            await append_transition(
                tx, dormant, authority_did=grand_did,
                expected_child_domain="dormant.history-grand.example",
                expected_child_controller_did=dormant_did, expected_operation="delegate",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('dormant.history-grand.example',$1,'verified',NULL)",
                direct_did,
            )
            await append_transition(
                tx, deleted_genesis, authority_did=grand_did,
                expected_child_domain="deleted.history-grand.example",
                expected_child_controller_did=deleted_did, expected_operation="delegate",
            )
            await append_transition(
                tx, deleted_revoke, authority_did=deleted_did,
                expected_child_domain="deleted.history-grand.example",
                expected_child_controller_did=deleted_did, expected_operation="revoke",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash,deleted_at) VALUES ('deleted.history-grand.example',$1,'verified',$2,NOW())",
                deleted_did, deleted_revoke["entry_hash"],
            )

        async def verify_domain(domain):
            if domain == "dormant.history-grand.example":
                return DomainAuthority(
                    controller_did=direct_did, registry_url="https://source.example",
                    dns_name="_awid.dormant.history-grand.example", inherited=False,
                    ttl_seconds=5, authoritative_ttl_seconds=300,
                )
            return DomainAuthority(
                controller_did=grand_did, registry_url="https://source.example",
                dns_name="_awid.history-grand.example", inherited=True,
                ttl_seconds=5, authoritative_ttl_seconds=300,
            )

        service = RegistryMigrationService(db, verify_domain=verify_domain)
        destination_id = await make_destination_service(destination.get_manager("aweb")).registry_id()
        dormant_artifact = await service.prepare(
            root_domain="dormant.history-grand.example",
            destination_registry_id=destination_id,
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        assert any(
            item["kind"] == "delegation_head"
            and item["row"]["child_domain"] == "dormant.history-grand.example"
            for item in dormant_artifact.payload["items"]
        )
        assert not any(
            item["kind"] == "namespace" and item["row"]["domain"] == "history-grand.example"
            for item in dormant_artifact.payload["items"]
        )
        deleted_artifact = await service.prepare(
            root_domain="deleted.history-grand.example",
            destination_registry_id=destination_id,
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        deleted_entries = [
            item for item in deleted_artifact.payload["items"]
            if item["kind"] == "delegation_entry"
            and item["row"]["child_domain"] == "deleted.history-grand.example"
        ]
        assert [item["row"]["operation"] for item in deleted_entries] == ["delegate", "revoke"]
        assert any(
            item["kind"] == "namespace" and item["row"]["deleted_at"] is not None
            for item in deleted_artifact.payload["items"]
        )
        destination_service = make_destination_service(destination.get_manager("aweb"))
        await destination_service.import_artifact(deleted_artifact.as_dict())
        page = await get_namespace_delegation_log(
            "deleted.history-grand.example", after_sequence=0, limit=1,
            cursor=None, db_infra=destination,
        )
        assert page.next_cursor is not None
        cancel_task = read_task = None
        async with destination.get_manager("aweb").transaction() as page_tx:
            await page_tx.fetch_one(
                "SELECT token_hash FROM {{tables.namespace_delegation_read_pages}} FOR UPDATE"
            )
            read_task = asyncio.create_task(
                get_namespace_delegation_log(
                    "deleted.history-grand.example", after_sequence=0, limit=1,
                    cursor=page.next_cursor, db_infra=destination,
                )
            )
            await asyncio.sleep(0.05)
            async with destination.get_manager("aweb").transaction() as probe_tx:
                with pytest.raises(asyncpg.LockNotAvailableError):
                    await probe_tx.fetch_one(
                        "SELECT child_domain FROM {{tables.namespace_delegation_heads}} WHERE child_domain=$1 FOR UPDATE NOWAIT",
                        "deleted.history-grand.example",
                    )
            cancel_task = asyncio.create_task(
                destination_service.cancel_destination(
                    deleted_artifact.payload["cutover_id"]
                )
            )
            await asyncio.sleep(0.05)
            assert not read_task.done()
            assert not cancel_task.done()
            assert await page_tx.fetch_value(
                "SELECT COUNT(*) FROM {{tables.namespace_delegation_read_snapshots}} WHERE child_domain=$1",
                "deleted.history-grand.example",
            ) == 1
            assert await page_tx.fetch_value(
                "SELECT COUNT(*) FROM {{tables.namespace_delegation_read_pages}}"
            ) == 1
        read_result = await read_task
        assert read_result.head_hash == deleted_revoke["entry_hash"]
        canceled = await cancel_task
        assert canceled["state"] == "canceled"
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_delegation_read_snapshots}}"
        ) == 0
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_delegation_heads}}"
        ) == 0
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_delegated_root_artifact_includes_reachable_suffix_and_pins_source_dns(
    shared_test_pool,
):
    source = AwidDatabaseInfra(schema="awid_delegated_migration_source")
    destination = AwidDatabaseInfra(schema="awid_delegated_migration_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = source.get_manager("aweb")
        grand_key, grand_public = generate_keypair()
        grand_did = did_from_public_key(grand_public)
        parent_key, parent_public = generate_keypair()
        parent_did = did_from_public_key(parent_public)
        root_key, root_public = generate_keypair()
        root_did = did_from_public_key(root_public)
        parent = migration_assertion(
            parent="grand.example", child="parent.grand.example", controller=parent_did,
            sequence=1, previous=None, key=grand_key, signer=grand_did,
        )
        root = migration_assertion(
            parent="parent.grand.example", child="root.parent.grand.example", controller=root_did,
            sequence=1, previous=None, key=parent_key, signer=parent_did,
        )
        await db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('grand.example',$1,'verified')",
            grand_did,
        )
        async with db.transaction() as tx:
            await append_transition(
                tx, parent, authority_did=grand_did,
                expected_child_domain="parent.grand.example",
                expected_child_controller_did=parent_did, expected_operation="delegate",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('parent.grand.example',$1,'verified',$2)",
                parent_did, parent["entry_hash"],
            )
            await append_transition(
                tx, root, authority_did=parent_did,
                expected_child_domain="root.parent.grand.example",
                expected_child_controller_did=root_did, expected_operation="delegate",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('root.parent.grand.example',$1,'verified',$2)",
                root_did, root["entry_hash"],
            )

        selected_authority = {
            "origin": "https://source.example",
            "controller": grand_did,
            "dns_name": "_awid.grand.example",
        }

        async def verify_domain(domain):
            assert domain == "root.parent.grand.example"
            return DomainAuthority(
                controller_did=selected_authority["controller"],
                registry_url=selected_authority["origin"],
                dns_name=selected_authority["dns_name"],
                inherited=True, ttl_seconds=5,
                authoritative_ttl_seconds=300,
            )

        source_service = RegistryMigrationService(db, verify_domain=verify_domain)
        destination_service = make_destination_service(destination.get_manager("aweb"))
        destination_registry_id = await destination_service.registry_id()
        with pytest.raises(RegistryMigrationError, match="live DNS verifier"):
            await RegistryMigrationService(db).prepare(
                root_domain="root.parent.grand.example",
                destination_registry_id=destination_registry_id,
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
        with pytest.raises(RegistryMigrationError, match="expected source registry origin"):
            await source_service.prepare(
                root_domain="root.parent.grand.example",
                destination_registry_id=destination_registry_id,
                expected_destination_origin="https://destination.example",
            )
        selected_authority["origin"] = "https://changed.example"
        with pytest.raises(RegistryMigrationError, match="no longer selects"):
            await source_service.prepare(
                root_domain="ROOT.PARENT.GRAND.EXAMPLE.",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
        selected_authority["origin"] = "https://source.example"
        selected_authority["controller"] = parent_did
        with pytest.raises(RegistryMigrationError, match="does not terminate"):
            await source_service.prepare(
                root_domain="root.parent.grand.example",
                destination_registry_id=destination_registry_id,
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
        selected_authority["dns_name"] = "_awid.parent.grand.example"
        with pytest.raises(RegistryMigrationError, match="does not terminate"):
            await source_service.prepare(
                root_domain="root.parent.grand.example",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
        selected_authority["controller"] = grand_did
        selected_authority["dns_name"] = "_awid.grand.example"
        artifact = await source_service.prepare(
            root_domain="ROOT.PARENT.GRAND.EXAMPLE.",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        assert artifact.payload["root_domain"] == "root.parent.grand.example"
        assert artifact.payload["expected_source_origin"] == "https://source.example"
        assert {
            item["row"]["child_domain"]
            for item in artifact.payload["items"]
            if item["kind"] == "delegation_head"
        } == {"parent.grand.example", "root.parent.grand.example"}
        assert {
            item["row"]["domain"]
            for item in artifact.payload["items"]
            if item["kind"] == "namespace"
        } == {"root.parent.grand.example"}
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await db.execute(
                """
                INSERT INTO {{tables.namespace_delegation_signatures}}
                    (child_domain,sequence,controller_did,signature)
                VALUES ('parent.grand.example',1,'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','blocked')
                """
            )
        await destination_service.import_artifact(artifact.as_dict())
        namespace = await get_namespace(
            "root.parent.grand.example", db_infra=destination
        )
        assert [item.entry_hash for item in namespace.delegation_chain] == [
            parent["entry_hash"], root["entry_hash"],
        ]
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_delegation_heads}}"
        ) == 2
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.dns_namespaces}}"
        ) == 1
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_sequential_siblings_reuse_only_non_cancelable_shared_dependencies(
    shared_test_pool,
):
    source = AwidDatabaseInfra(schema="awid_shared_source")
    destination = AwidDatabaseInfra(schema="awid_shared_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = source.get_manager("aweb")
        grand_key, grand_public = generate_keypair()
        grand_did = did_from_public_key(grand_public)
        parent_key, parent_public = generate_keypair()
        parent_did = did_from_public_key(parent_public)
        await db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('shared-grand.example',$1,'verified')",
            grand_did,
        )
        parent = migration_assertion(
            parent="shared-grand.example", child="parent.shared-grand.example",
            controller=parent_did, sequence=1, previous=None,
            key=grand_key, signer=grand_did,
        )
        siblings = []
        async with db.transaction() as tx:
            await append_transition(
                tx, parent, authority_did=grand_did,
                expected_child_domain="parent.shared-grand.example",
                expected_child_controller_did=parent_did, expected_operation="delegate",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('parent.shared-grand.example',$1,'verified',$2)",
                parent_did, parent["entry_hash"],
            )
            for name in ("alpha", "beta"):
                _, public = generate_keypair()
                did = did_from_public_key(public)
                domain = f"{name}.parent.shared-grand.example"
                assertion = migration_assertion(
                    parent="parent.shared-grand.example", child=domain,
                    controller=did, sequence=1, previous=None,
                    key=parent_key, signer=parent_did,
                )
                await append_transition(
                    tx, assertion, authority_did=parent_did,
                    expected_child_domain=domain,
                    expected_child_controller_did=did, expected_operation="delegate",
                )
                namespace_id = uuid4()
                await tx.execute(
                    "INSERT INTO {{tables.dns_namespaces}} (namespace_id,domain,controller_did,verification_status,active_delegation_hash) VALUES ($1,$2,$3,'verified',$4)",
                    namespace_id, domain, did, assertion["entry_hash"],
                )
                siblings.append((domain, namespace_id))
        shared_did = "did:aw:shared-migration"
        await db.execute(
            "INSERT INTO {{tables.did_aw_mappings}} (did_aw,current_did_key) VALUES ($1,'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd')",
            shared_did,
        )
        await db.execute(
            """
            INSERT INTO {{tables.did_aw_log}}
                (did_aw,seq,operation,new_did_key,entry_hash,state_hash,
                 authorized_by,signature,timestamp)
            VALUES ($1,1,'register_did','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd',$2,$3,
                    'did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','signature','2026-08-26T18:00:00Z')
            """,
            shared_did, "a" * 64, "b" * 64,
        )
        encryption_key_id = "sha256:" + "c" * 64
        await db.execute(
            """
            INSERT INTO {{tables.identity_encryption_keys}}
                (did_aw,encryption_key_id,encryption_public_key,algorithm,
                 identity_did,identity_stable_id,assertion_signature,
                 assertion_canonical,created_at_text,not_before_text,
                 expires_at_text,assertion_created_at,not_before_at,expires_at)
            VALUES ($1,$2,'public-key','x25519','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd',$1,
                    'signature','canonical','2026-08-26T18:00:00Z',
                    '2026-08-26T18:00:00Z','2027-08-26T18:00:00Z',
                    '2026-08-26T18:00:00Z','2026-08-26T18:00:00Z',
                    '2027-08-26T18:00:00Z')
            """,
            shared_did, encryption_key_id,
        )
        for index, (_, namespace_id) in enumerate(siblings):
            await db.execute(
                "INSERT INTO {{tables.public_addresses}} (address_id,namespace_id,name,did_aw) VALUES ($1,$2,$3,$4)",
                uuid4(), namespace_id, f"member-{index}", shared_did,
            )

        async def verify_domain(domain):
            return DomainAuthority(
                controller_did=grand_did, registry_url="https://source.example",
                dns_name="_awid.shared-grand.example", inherited=True,
                ttl_seconds=5, authoritative_ttl_seconds=300,
            )

        source_service = RegistryMigrationService(db, verify_domain=verify_domain)
        destination_service = make_destination_service(destination.get_manager("aweb"))
        destination_db = destination.get_manager("aweb")
        for table, predicate, args in (
            ("did_aw_mappings", "did_aw=$1", (shared_did,)),
            ("did_aw_log", "did_aw=$1 AND seq=1", (shared_did,)),
            (
                "identity_encryption_keys",
                "did_aw=$1 AND encryption_key_id=$2",
                (shared_did, encryption_key_id),
            ),
        ):
            source_row = await db.fetch_value(
                f"SELECT to_jsonb(t)::text FROM {{{{tables.{table}}}}} t WHERE {predicate}",
                *args,
            )
            await destination_db.execute(
                f"INSERT INTO {{{{tables.{table}}}}} SELECT (jsonb_populate_record(NULL::{{{{tables.{table}}}}},$1::jsonb)).*",
                source_row,
            )
        artifacts = [
            await source_service.prepare(
                root_domain=domain,
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
            )
            for domain, _ in siblings
        ]
        readback_a = await destination_service.import_artifact(artifacts[0].as_dict())
        assert readback_a["payload"]["counts"]["did"]["reused"] == 1
        assert readback_a["payload"]["counts"]["did_log"]["reused"] == 1
        assert readback_a["payload"]["counts"]["encryption_key"]["reused"] == 1
        with pytest.raises(RegistryMigrationError, match="owner is still cancelable"):
            await destination_service.import_artifact(artifacts[1].as_dict())
        authorization_a = await source_service.confirm_readback(
            artifacts[0].payload["cutover_id"], readback_a
        )
        await destination_service.apply_dns_authorization(
            artifacts[0].payload["cutover_id"], authorization_a
        )
        preexisting_tables = {
            "namespace": "dns_namespaces",
            "delegation_head": "namespace_delegation_heads",
            "delegation_entry": "namespace_delegation_entries",
            "delegation_signature": "namespace_delegation_signatures",
        }
        for item in artifacts[1].payload["items"]:
            is_starting_namespace = (
                item["kind"] == "namespace"
                and item["row"]["domain"] == siblings[1][0]
            )
            is_starting_delegation = (
                item["kind"].startswith("delegation_")
                and item["row"]["child_domain"] == siblings[1][0]
            )
            if is_starting_namespace or is_starting_delegation:
                table = preexisting_tables[item["kind"]]
                await destination_db.execute(
                    f"INSERT INTO {{{{tables.{table}}}}} SELECT (jsonb_populate_record(NULL::{{{{tables.{table}}}}},$1::jsonb)).*",
                    json.dumps(item["row"], separators=(",", ":")),
                )
        frozen_source_cutover = uuid4()
        await destination_db.execute(
            """
            INSERT INTO {{tables.registry_migration_cutovers}}
                (cutover_id,role,source_registry_id,destination_registry_id,
                 expected_destination_origin,root_domain,source_generation,
                 snapshot_digest,manifest_digest,state)
            SELECT $1,'source',source_registry_id,destination_registry_id,
                   expected_destination_origin,'unrelated.example',source_generation,
                   snapshot_digest,manifest_digest,'frozen'
            FROM {{tables.registry_migration_cutovers}}
            WHERE cutover_id=$2::uuid AND role='destination'
            """,
            frozen_source_cutover,
            artifacts[0].payload["cutover_id"],
        )
        await destination_db.execute(
            """
            INSERT INTO {{tables.registry_migration_items}}
                (cutover_id,role,kind,item_key,content_digest,source_registry_id,
                 source_generation,imported)
            SELECT $1,'source','did',$2,content_digest,source_registry_id,
                   source_generation,FALSE
            FROM {{tables.registry_migration_items}}
            WHERE cutover_id=$3::uuid AND role='destination'
              AND kind='did' AND item_key=$2
            """,
            frozen_source_cutover,
            shared_did,
            artifacts[0].payload["cutover_id"],
        )
        with pytest.raises(asyncpg.PostgresError, match="registry_migration_fenced"):
            await destination_service.import_artifact(artifacts[1].as_dict())
        await destination_db.execute(
            "DELETE FROM {{tables.registry_migration_items}} WHERE cutover_id=$1 AND role='source'",
            frozen_source_cutover,
        )
        await destination_db.execute(
            "DELETE FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1 AND role='source'",
            frozen_source_cutover,
        )
        await destination_service.import_artifact(artifacts[1].as_dict())
        imported_namespace = await get_namespace(
            siblings[1][0], db_infra=destination
        )
        assert [item.payload.child_domain for item in imported_namespace.delegation_chain] == [
            "parent.shared-grand.example", siblings[1][0],
        ]
        dispositions = await destination.get_manager("aweb").fetch_all(
            """
            SELECT kind,item_key,disposition FROM {{tables.registry_migration_items}}
            WHERE cutover_id=$1::uuid AND role='destination'
              AND disposition='reused'
            ORDER BY kind,item_key
            """,
            artifacts[1].payload["cutover_id"],
        )
        assert any(row["kind"] == "delegation_head" and row["item_key"] == "parent.shared-grand.example" for row in dispositions)
        assert any(row["kind"] == "namespace" and row["item_key"] == str(siblings[1][1]) for row in dispositions)
        assert any(row["kind"] == "delegation_head" and row["item_key"] == siblings[1][0] for row in dispositions)
        migrated_namespace = await destination_db.fetch_one(
            "SELECT state_cutover_id FROM {{tables.dns_namespaces}} WHERE domain=$1 AND deleted_at IS NULL",
            siblings[1][0],
        )
        reused_starting_head = await destination_db.fetch_one(
            "SELECT state_cutover_id FROM {{tables.namespace_delegation_heads}} WHERE child_domain=$1",
            siblings[1][0],
        )
        assert migrated_namespace["state_cutover_id"] is None
        assert reused_starting_head["state_cutover_id"] is None
        current_ancestor_item = await destination_db.fetch_value(
            """
            SELECT to_jsonb(i)::text
            FROM {{tables.registry_migration_items}} i
            WHERE cutover_id=$1::uuid AND role='destination'
              AND kind='delegation_head' AND item_key='parent.shared-grand.example'
            """,
            artifacts[1].payload["cutover_id"],
        )
        await destination_db.execute(
            """
            DELETE FROM {{tables.registry_migration_items}}
            WHERE cutover_id=$1::uuid AND role='destination'
              AND kind='delegation_head' AND item_key='parent.shared-grand.example'
            """,
            artifacts[1].payload["cutover_id"],
        )
        with pytest.raises(DelegationStateError, match="imported delegation cohort"):
            await stored_delegation_chain(destination_db, siblings[1][0])
        await destination_db.execute(
            """
            INSERT INTO {{tables.registry_migration_items}}
            SELECT (jsonb_populate_record(NULL::{{tables.registry_migration_items}},$1::jsonb)).*
            """,
            current_ancestor_item,
        )
        assert any(row["kind"] == "did" and row["item_key"] == shared_did for row in dispositions)
        assert any(row["kind"] == "did_log" for row in dispositions)
        assert any(row["kind"] == "encryption_key" for row in dispositions)
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await destination_db.execute(
                "UPDATE {{tables.did_aw_mappings}} SET updated_at=NOW() WHERE did_aw=$1",
                shared_did,
            )
        canceled = await destination_service.cancel_destination(
            artifacts[1].payload["cutover_id"]
        )
        assert canceled["state"] == "canceled"
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.did_aw_mappings}} WHERE did_aw=$1", shared_did
        ) == 1
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.namespace_delegation_heads}} WHERE child_domain='parent.shared-grand.example'"
        ) == 1
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_source_and_destination_reject_overlapping_cutover_ids(shared_test_pool):
    source = AwidDatabaseInfra(schema="awid_overlap_admission_source")
    destination = AwidDatabaseInfra(schema="awid_overlap_admission_destination")
    destination_race = AwidDatabaseInfra(schema="awid_overlap_admission_destination_race")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination_race.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_db = source.get_manager("aweb")
        source_service = make_source_service(source_db)
        destination_service = make_destination_service(destination.get_manager("aweb"))
        destination_race_service = make_destination_service(destination_race.get_manager("aweb"))
        await source_db.execute(
            """
            INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status)
            VALUES ('admission.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified'),
                   ('child.admission.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified'),
                   ('race-admission.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')
            """
        )
        blocking_rollover = str(uuid4())
        await source_db.execute(
            """
            INSERT INTO {{tables.namespace_controller_rollovers}}
                (rollover_id,parent_domain,old_controller_did,new_controller_did,state,recovery_mode)
            VALUES ($1::uuid,'child.admission.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2','ready','none')
            """,
            blocking_rollover,
        )
        with pytest.raises(RegistryMigrationError, match="controller rollover intersects"):
            await source_service.prepare(
                root_domain="admission.example",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
                cutover_id=str(uuid4()),
            )
        await source_db.execute(
            "UPDATE {{tables.namespace_controller_rollovers}} SET state='canceled' WHERE rollover_id=$1::uuid",
            blocking_rollover,
        )
        first_id = str(uuid4())
        first = await source_service.prepare(
            root_domain="admission.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
            cutover_id=first_id,
        )
        for root in ("admission.example", "child.admission.example"):
            with pytest.raises(RegistryMigrationError, match="overlapping source cutover"):
                await source_service.prepare(
                    root_domain=root,
                    destination_registry_id=await destination_service.registry_id(),
                    expected_source_origin="https://source.example",
                    expected_destination_origin="https://destination.example",
                    cutover_id=str(uuid4()),
                )
        assert await source_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.registry_migration_cutovers}} WHERE role='source' AND state NOT IN ('completed','canceled') AND (root_domain='admission.example' OR root_domain LIKE '%.admission.example')"
        ) == 1
        await source_db.execute(
            "UPDATE {{tables.registry_migration_cutovers}} SET state='completed' WHERE cutover_id=$1::uuid AND role='source'",
            first_id,
        )
        fresh = await source_service.prepare(
            root_domain="admission.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
            cutover_id=str(uuid4()),
        )
        assert fresh.payload["cutover_id"] != first_id
        await source_db.execute(
            "UPDATE {{tables.registry_migration_cutovers}} SET state='completed' WHERE cutover_id=$1::uuid AND role='source'",
            fresh.payload["cutover_id"],
        )
        cross_role_id = str(uuid4())
        registry_id = await source_service.registry_id()
        await source_db.execute(
            """
            INSERT INTO {{tables.registry_migration_cutovers}}
                (cutover_id,role,source_registry_id,destination_registry_id,
                 expected_destination_origin,root_domain,source_generation,
                 snapshot_digest,manifest_digest,state)
            VALUES ($1::uuid,'destination',$2,$3,'https://destination.example',
                    'child.admission.example',0,$4,$4,'verified')
            """,
            cross_role_id, registry_id, uuid4(), "sha256:" + "f" * 64,
        )
        with pytest.raises(RegistryMigrationError, match="overlapping source cutover"):
            await source_service.prepare(
                root_domain="admission.example",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
                cutover_id=str(uuid4()),
            )
        await source_db.execute(
            "UPDATE {{tables.registry_migration_cutovers}} SET state='canceled' WHERE cutover_id=$1::uuid AND role='destination'",
            cross_role_id,
        )

        race_ids = [str(uuid4()), str(uuid4())]
        race_results = await asyncio.gather(
            *[
                source_service.prepare(
                    root_domain="race-admission.example",
                    destination_registry_id=await destination_race_service.registry_id(),
                    expected_source_origin="https://source.example",
                    expected_destination_origin="https://destination.example",
                    cutover_id=value,
                )
                for value in race_ids
            ],
            return_exceptions=True,
        )
        assert sum(not isinstance(value, Exception) for value in race_results) == 1
        assert sum(isinstance(value, RegistryMigrationError) for value in race_results) == 1

        imported = await destination_service.import_artifact(first.as_dict())
        nested = clone_artifact(first, cutover_id=str(uuid4()), root_domain="child.admission.example")
        with pytest.raises(RegistryMigrationError, match="overlapping destination cutover"):
            await destination_service.import_artifact(nested)
        assert await destination.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.registry_migration_cutovers}} WHERE role='destination' AND state NOT IN ('completed','canceled')"
        ) == 1
        assert await destination_service.import_artifact(first.as_dict()) == imported

        race_artifacts = [
            clone_artifact(first, cutover_id=str(uuid4())) for _ in range(2)
        ]
        for artifact in race_artifacts:
            artifact["payload"]["destination_registry_id"] = await destination_race_service.registry_id()
            artifact["snapshot_digest"] = RegistryMigrationService._digest(artifact["payload"])
        destination_results = await asyncio.gather(
            *(destination_race_service.import_artifact(value) for value in race_artifacts),
            return_exceptions=True,
        )
        assert sum(not isinstance(value, Exception) for value in destination_results) == 1
        assert sum(isinstance(value, RegistryMigrationError) for value in destination_results) == 1
        assert await destination_race.get_manager("aweb").fetch_value(
            "SELECT COUNT(*) FROM {{tables.registry_migration_cutovers}} WHERE role='destination' AND state NOT IN ('completed','canceled')"
        ) == 1
    finally:
        await source.close()
        await destination.close()
        await destination_race.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["mutation", "omission"])
async def test_actual_table_readback_detects_post_import_corruption(
    shared_test_pool, corruption,
):
    source = AwidDatabaseInfra(schema=f"awid_readback_source_{corruption}")
    destination = AwidDatabaseInfra(schema=f"awid_readback_destination_{corruption}")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_db = source.get_manager("aweb")
        destination_db = destination.get_manager("aweb")
        source_service = make_source_service(source_db)
        destination_service = make_destination_service(destination_db)
        await source_db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('readback.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')"
        )
        artifact = await source_service.prepare(
            root_domain="readback.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        await destination_service.import_artifact(artifact.as_dict())
        async with destination_db.transaction() as tx:
            if corruption == "mutation":
                for name, value in (
                    ("awid.registry_import_mode", "true"),
                    ("awid.registry_import_cutover_id", artifact.payload["cutover_id"]),
                    ("awid.registry_import_source_registry_id", artifact.payload["source_registry_id"]),
                    ("awid.registry_import_source_generation", str(artifact.payload["source_generation"])),
                ):
                    await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
                await tx.execute(
                    "UPDATE {{tables.dns_namespaces}} SET controller_did='did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2' WHERE domain='readback.example'"
                )
            else:
                for name, value in (
                    ("awid.cancel_cleanup_mode", "true"),
                    ("awid.cancel_cleanup_cutover_id", artifact.payload["cutover_id"]),
                    ("awid.cancel_cleanup_source_registry_id", artifact.payload["source_registry_id"]),
                    ("awid.cancel_cleanup_source_generation", str(artifact.payload["source_generation"])),
                ):
                    await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
                await tx.execute(
                    "DELETE FROM {{tables.dns_namespaces}} WHERE domain='readback.example'"
                )
        with pytest.raises(RegistryMigrationError, match=(
            "semantic readback mismatch" if corruption == "mutation" else "omitted an item"
        )):
            await destination_service.readback(artifact.payload["cutover_id"])
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption", [
        "duplicate", "unknown_field", "invalid_row", "semantic_conflict",
        "bad_uuid", "bad_root", "bad_generation", "bad_origin",
        "bad_evidence", "bad_answer_digest", "bad_origin_type",
        "source_origin_mismatch", "bad_item_key",
    ]
)
async def test_corrupt_artifact_rolls_back_destination_without_fragments(
    shared_test_pool, corruption,
):
    source = AwidDatabaseInfra(schema=f"awid_corrupt_source_{corruption}")
    destination = AwidDatabaseInfra(schema=f"awid_corrupt_destination_{corruption}")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_db = source.get_manager("aweb")
        destination_db = destination.get_manager("aweb")
        source_service = make_source_service(source_db)
        destination_service = make_destination_service(destination_db)
        await source_db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('corrupt.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')"
        )
        artifact = await source_service.prepare(
            root_domain="corrupt.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )
        value = artifact.as_dict()
        payload = json.loads(json.dumps(value["payload"]))
        namespace = next(item for item in payload["items"] if item["kind"] == "namespace")
        if corruption == "duplicate":
            payload["items"].append(payload["items"][0])
        elif corruption == "unknown_field":
            payload["items"][0]["unexpected"] = True
        elif corruption == "invalid_row":
            namespace["row"]["domain"] = None
        elif corruption == "bad_uuid":
            payload["source_registry_id"] = "not-a-uuid"
        elif corruption == "bad_root":
            payload["root_domain"] = "Bad.Example."
        elif corruption == "bad_generation":
            payload["source_generation"] = True
        elif corruption == "bad_origin":
            payload["expected_destination_origin"] = "HTTPS://DESTINATION.EXAMPLE/"
        elif corruption == "bad_evidence":
            payload["old_selection_evidence"]["observed_at"] = "2026-99-99T25:00:00Z"
        elif corruption == "bad_answer_digest":
            payload["old_selection_evidence"]["authority_answer_digest"] = (
                "sha256:" + "0" * 64
            )
        elif corruption == "bad_origin_type":
            payload["old_selection_evidence"]["old_registry_origin"] = 42
        elif corruption == "source_origin_mismatch":
            payload["expected_source_origin"] = "https://different-source.example"
        elif corruption == "bad_item_key":
            namespace["key"] = str(uuid4())
        else:
            await destination_db.execute(
                """
                INSERT INTO {{tables.dns_namespaces}}
                    (namespace_id,domain,controller_did,verification_status)
                VALUES ($1::uuid,$2,'did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2','verified')
                """,
                namespace["key"], namespace["row"]["domain"],
            )
        payload["manifest_digest"] = RegistryMigrationService._digest(payload["items"])
        corrupt = {"payload": payload, "snapshot_digest": RegistryMigrationService._digest(payload)}
        expected_error = (
            asyncpg.NotNullViolationError
            if corruption == "invalid_row"
            else RegistryMigrationError
        )
        with pytest.raises(expected_error):
            await destination_service.import_artifact(corrupt)
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.registry_migration_cutovers}}"
        ) == 0
        assert await destination_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.dns_namespaces}}"
        ) == (1 if corruption == "semantic_conflict" else 0)
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_prepare_serializes_with_ordinary_subtree_mutation(shared_test_pool):
    source = AwidDatabaseInfra(schema="awid_prepare_race_source")
    destination = AwidDatabaseInfra(schema="awid_prepare_race_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        db = source.get_manager("aweb")
        service = make_source_service(db)
        destination_service = make_destination_service(destination.get_manager("aweb"))
        await db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('race-move.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')"
        )
        cutover_id = str(uuid4())
        with pytest.raises(RegistryMigrationError, match="live DNS verifier"):
            await RegistryMigrationService(db).prepare(
                root_domain="race-move.example",
                destination_registry_id=await destination_service.registry_id(),
            )
        with pytest.raises(RegistryMigrationError, match="expected source registry origin"):
            await service.prepare(
                root_domain="race-move.example",
                destination_registry_id=await destination_service.registry_id(),
            )

        async def mutate():
            try:
                await db.execute(
                    "INSERT INTO {{tables.teams}} (domain,name,display_name,team_did_key) VALUES ('race-move.example','racer','Racer','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd')"
                )
                return "committed"
            except QueryError as exc:
                assert "registry_migration_fenced" in str(exc)
                return "fenced"

        artifact, mutation = await asyncio.gather(
            service.prepare(
                root_domain="race-move.example",
                destination_registry_id=await destination_service.registry_id(),
                expected_source_origin="https://source.example",
                expected_destination_origin="https://destination.example",
                cutover_id=cutover_id,
            ),
            mutate(),
        )
        if mutation == "committed":
            assert any(
                item["kind"] == "team" and item["row"]["name"] == "racer"
                for item in artifact.payload["items"]
            )
        else:
            assert not any(item["kind"] == "team" for item in artifact.payload["items"])
        canceled = await service.cancel_source(cutover_id)
        assert canceled["state"] == "canceled"
        assert await service.cancel_source(cutover_id) == canceled
        await db.execute(
            "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='race-move.example'"
        )
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_import_serializes_with_destination_subtree_write(shared_test_pool):
    source = AwidDatabaseInfra(schema="awid_import_race_source")
    destination = AwidDatabaseInfra(schema="awid_import_race_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_service = make_source_service(source.get_manager("aweb"))
        destination_db = destination.get_manager("aweb")
        destination_service = make_destination_service(destination_db)
        await source.get_manager("aweb").execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('import-race.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')"
        )
        artifact = await source_service.prepare(
            root_domain="import-race.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://destination.example",
        )

        async def ordinary_write():
            try:
                await destination_db.execute(
                    "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('import-race.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')"
                )
                return "committed"
            except QueryError as exc:
                assert "registry_migration_fenced" in str(exc)
                return "fenced"

        import_result, write_result = await asyncio.gather(
            destination_service.import_artifact(artifact.as_dict()),
            ordinary_write(),
            return_exceptions=True,
        )
        if write_result == "fenced":
            assert not isinstance(import_result, Exception)
            assert await destination_service.import_artifact(artifact.as_dict()) == import_result
            assert await destination_db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.dns_namespaces}} WHERE domain='import-race.example'"
            ) == 1
        else:
            assert write_result == "committed"
            assert isinstance(import_result, RegistryMigrationError)
            assert "semantic conflict" in str(import_result)
            assert await destination_db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.registry_migration_cutovers}}"
            ) == 0
            with pytest.raises(RegistryMigrationError, match="semantic conflict"):
                await destination_service.import_artifact(artifact.as_dict())
    finally:
        await source.close()
        await destination.close()


@pytest.mark.asyncio
async def test_two_database_overlap_receipts_converge_and_fence_early_release(
    shared_test_pool, monkeypatch,
):
    source = AwidDatabaseInfra(schema="awid_overlap_source")
    destination = AwidDatabaseInfra(schema="awid_overlap_destination")
    await source.initialize(shared_pool=shared_test_pool, run_migrations=True)
    await destination.initialize(shared_pool=shared_test_pool, run_migrations=True)
    try:
        source_db = source.get_manager("aweb")
        destination_db = destination.get_manager("aweb")

        async def destination_selected(_domain):
            return DomainAuthority(
                controller_did="did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
                registry_url="https://new.example",
                dns_name="_awid.overlap.example",
                inherited=False,
                ttl_seconds=5,
                authoritative_ttl_seconds=300,
            )

        source_service = make_source_service(source_db)
        destination_service = make_destination_service(
            destination_db,
            verifier=destination_selected,
            public_origin="https://new.example",
        )
        namespace_id = uuid4()
        await source_db.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id,domain,controller_did,verification_status)
            VALUES ($1,'overlap.example','did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd','verified')
            """,
            namespace_id,
        )
        artifact = await source_service.prepare(
            root_domain="overlap.example",
            destination_registry_id=await destination_service.registry_id(),
            expected_source_origin="https://source.example",
            expected_destination_origin="https://new.example",
        )
        cutover_id = artifact.payload["cutover_id"]
        readback = await destination_service.import_artifact(artifact.as_dict())
        malformed_readback = json.loads(json.dumps(readback))
        first_kind = next(iter(malformed_readback["payload"]["counts"]))
        malformed_readback["payload"]["counts"][first_kind]["bogus"] = 0
        malformed_readback["readback_hash"] = RegistryMigrationService._digest(
            malformed_readback["payload"]
        )
        with pytest.raises(RegistryMigrationError, match="counts are malformed"):
            await source_service.confirm_readback(cutover_id, malformed_readback)
        wrong_count = json.loads(json.dumps(readback))
        wrong_count["payload"]["counts"][first_kind]["inserted"] += 1
        wrong_count["readback_hash"] = RegistryMigrationService._digest(wrong_count["payload"])
        with pytest.raises(RegistryMigrationError, match="counts mismatch"):
            await source_service.confirm_readback(cutover_id, wrong_count)
        original_source_verifier = source_service.verify_domain

        async def changed_old_source(domain):
            authority = await original_source_verifier(domain)
            return DomainAuthority(
                controller_did=authority.controller_did,
                registry_url="https://changed.example",
                dns_name=authority.dns_name,
                inherited=authority.inherited,
                ttl_seconds=authority.ttl_seconds,
                authoritative_ttl_seconds=authority.authoritative_ttl_seconds,
            )

        source_service.verify_domain = changed_old_source
        with pytest.raises(RegistryMigrationError, match="frozen old selection"):
            await source_service.confirm_readback(cutover_id, readback)
        source_service.verify_domain = original_source_verifier
        authorization = await source_service.confirm_readback(cutover_id, readback)
        assert authorization["payload"]["cutover_id"] == cutover_id
        assert await source_service.confirm_readback(cutover_id, readback) == authorization
        wrong_payload = authorization["payload"] | {"cutover_id": str(uuid4())}
        wrong_authorization = {
            "payload": wrong_payload,
            "receipt_hash": "sha256:" + hashlib.sha256(
                canonical_json_bytes(wrong_payload)
            ).hexdigest(),
        }
        with pytest.raises(RegistryMigrationError, match="does not match destination"):
            await destination_service.apply_dns_authorization(cutover_id, wrong_authorization)
        assert await destination_service.apply_dns_authorization(cutover_id, authorization) == authorization
        assert await destination_service.apply_dns_authorization(cutover_id, authorization) == authorization
        resumed_after_authorization = await destination_service.import_artifact(
            artifact.as_dict()
        )
        assert resumed_after_authorization["payload"]["destination_state"] == "dns_authorized"
        with pytest.raises(RegistryMigrationError, match="can no longer be canceled"):
            await destination_service.cancel_destination(cutover_id)

        source_service.verify_domain = destination_selected
        destination_digest = RegistryMigrationService._digest({
            "controller_did": "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
            "dns_name": "_awid.overlap.example",
            "registry_origin": "https://new.example",
        })
        observation = await destination_service.observe_destination(
            cutover_id,
            destination_registry_origin="https://new.example",
            destination_dns_name="_awid.overlap.example",
            destination_dns_answer_digest=destination_digest,
            observed_at="2026-08-26T18:00:00Z",
        )
        assert await destination_service.observe_destination(
            cutover_id,
            destination_registry_origin="https://new.example",
            destination_dns_name="_awid.overlap.example",
            destination_dns_answer_digest=destination_digest,
            observed_at="2026-08-26T18:00:00Z",
        ) == observation
        stored_observation_bytes = bytes(await destination_db.fetch_value(
            "SELECT destination_observation_payload FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination'",
            cutover_id,
        ))
        noncanonical_observation_bytes = json.dumps(
            json.loads(stored_observation_bytes.decode()), indent=2
        ).encode()
        assert noncanonical_observation_bytes != stored_observation_bytes
        await destination_db.execute(
            "UPDATE {{tables.registry_migration_cutovers}} SET destination_observation_payload=$2 WHERE cutover_id=$1::uuid AND role='destination'",
            cutover_id,
            noncanonical_observation_bytes,
        )
        with pytest.raises(RegistryMigrationError, match="payload is not canonical"):
            await destination_service.observe_destination(cutover_id)
        await destination_db.execute(
            "UPDATE {{tables.registry_migration_cutovers}} SET destination_observation_payload=$2 WHERE cutover_id=$1::uuid AND role='destination'",
            cutover_id,
            stored_observation_bytes,
        )
        async def different_source_controller(_domain):
            return DomainAuthority(
                controller_did="did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
                registry_url="https://new.example",
                dns_name="_awid.overlap.example",
                inherited=False,
                ttl_seconds=5,
                authoritative_ttl_seconds=300,
            )

        source_service.verify_domain = different_source_controller
        with pytest.raises(RegistryMigrationError, match="source DNS does not match"):
            await source_service.establish_overlap(
                cutover_id,
                observation,
                now=datetime(2026, 8, 26, 18, 0, 20, tzinfo=timezone.utc),
            )
        source_service.verify_domain = destination_selected
        changed_controller_payload = OverlapObservationPayload.model_validate(
            observation["payload"]
            | {"destination_dns_answer_digest": "sha256:" + "6" * 64}
        )
        changed_controller_observation = make_receipt(
            changed_controller_payload
        ).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="authority digest differs"):
            await source_service.establish_overlap(
                cutover_id,
                changed_controller_observation,
                now=datetime(2026, 8, 26, 18, 0, 20, tzinfo=timezone.utc),
            )
        with pytest.raises(RegistryMigrationError, match="clock-skew"):
            await source_service.establish_overlap(
                cutover_id,
                observation,
                source_dns_answer_digest=destination_digest,
                source_observed_at="2026-08-26T18:00:10Z",
                now=datetime(2026, 8, 26, 18, 10, 0, tzinfo=timezone.utc),
            )
        substituted_payload = OverlapObservationPayload.model_validate(
            observation["payload"] | {"cutover_id": str(uuid4())}
        )
        substituted = make_receipt(substituted_payload).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="does not match cutover"):
            await source_service.establish_overlap(
                cutover_id,
                substituted,
                source_dns_answer_digest=destination_digest,
                source_observed_at="2026-08-26T18:00:10Z",
                now=datetime(2026, 8, 26, 18, 0, 20, tzinfo=timezone.utc),
            )
        source_service.verify_domain = None
        with pytest.raises(RegistryMigrationError, match="source observation"):
            await source_service.establish_overlap(
                cutover_id,
                observation,
                source_dns_answer_digest=destination_digest,
                source_observed_at="2026-08-26T18:10:10Z",
                now=datetime(2026, 8, 26, 18, 0, 20, tzinfo=timezone.utc),
            )
        class PostResolverDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 8, 26, 18, 0, 10, tzinfo=timezone.utc)

        async def timed_destination(domain):
            assert PostResolverDateTime.calls == 0
            return await destination_selected(domain)

        source_service.verify_domain = timed_destination
        monkeypatch.setattr(registry_migration_module, "datetime", PostResolverDateTime)
        overlap = await source_service.establish_overlap(cutover_id, observation)
        assert PostResolverDateTime.calls >= 1
        monkeypatch.setattr(registry_migration_module, "datetime", datetime)
        assert overlap["payload"]["overlap_started_at"] == "2026-08-26T18:00:10Z"
        assert overlap["payload"]["complete_after"] == "2026-08-26T18:10:10Z"
        source_service.verify_domain = destination_selected
        divergent_source_payload = CanonicalOverlapPayload.model_validate(
            overlap["payload"] | {"source_dns_answer_digest": "sha256:" + "7" * 64}
        )
        divergent_source_overlap = make_receipt(
            divergent_source_payload
        ).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="binding mismatch"):
            await destination_service.apply_overlap(
                cutover_id, divergent_source_overlap
            )
        shortened_payload = CanonicalOverlapPayload.model_validate(
            overlap["payload"] | {"complete_after": "2026-08-26T18:05:10Z"}
        )
        shortened = make_receipt(shortened_payload).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="timing bound"):
            await destination_service.apply_overlap(cutover_id, shortened)
        cross_overlap_payload = CanonicalOverlapPayload.model_validate(
            overlap["payload"] | {"cutover_id": str(uuid4())}
        )
        cross_overlap = make_receipt(cross_overlap_payload).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="does not match destination"):
            await destination_service.apply_overlap(cutover_id, cross_overlap)
        assert await destination_service.apply_overlap(cutover_id, overlap) == overlap

        async def unavailable_after_store(_domain):
            raise AssertionError("stored receipt retry must not resolve DNS")

        destination_service.verify_domain = unavailable_after_store
        assert await destination_service.observe_destination(cutover_id) == observation
        source_service.verify_domain = unavailable_after_store
        assert await source_service.establish_overlap(
            cutover_id, observation
        ) == overlap
        conflicting_observation_payload = OverlapObservationPayload.model_validate(
            observation["payload"]
            | {"destination_observed_at": "2026-08-26T18:00:01Z"}
        )
        conflicting_observation = make_receipt(
            conflicting_observation_payload
        ).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="conflicting destination observation"):
            await source_service.establish_overlap(
                cutover_id, conflicting_observation
            )
        destination_service.verify_domain = destination_selected
        source_service.verify_domain = destination_selected
        with pytest.raises(RegistryMigrationError, match="can no longer be canceled"):
            await destination_service.cancel_destination(cutover_id)

        source_receipt = await source_db.fetch_one(
            "SELECT overlap_payload,overlap_receipt_hash,complete_after FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source'",
            cutover_id,
        )
        destination_receipt = await destination_db.fetch_one(
            "SELECT overlap_payload,overlap_receipt_hash,complete_after FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination'",
            cutover_id,
        )
        assert bytes(source_receipt["overlap_payload"]) == bytes(destination_receipt["overlap_payload"])
        assert source_receipt["overlap_receipt_hash"] == destination_receipt["overlap_receipt_hash"]
        assert source_receipt["complete_after"] == destination_receipt["complete_after"]

        early = datetime(2026, 8, 26, 18, 10, 9, tzinfo=timezone.utc)
        with pytest.raises(RegistryMigrationError, match="has not elapsed"):
            await destination_service.complete_destination(cutover_id, completed_at=early)
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await destination_db.execute(
                "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='overlap.example'"
            )

        complete_time = datetime(2026, 8, 26, 18, 10, 10, tzinfo=timezone.utc)

        async def wrong_destination(_domain):
            return DomainAuthority(
                controller_did="did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
                registry_url="https://new.example",
                dns_name="_awid.overlap.example",
                inherited=False,
                ttl_seconds=5,
                authoritative_ttl_seconds=300,
            )

        destination_service.verify_domain = wrong_destination
        with pytest.raises(RegistryMigrationError, match="fresh destination DNS"):
            await destination_service.complete_destination(
                cutover_id, completed_at=complete_time
            )
        class DestinationCompletionDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 8, 26, 18, 10, 10, tzinfo=timezone.utc)

        async def timed_destination_completion(domain):
            assert DestinationCompletionDateTime.calls == 0
            return await destination_selected(domain)

        destination_service.verify_domain = timed_destination_completion
        monkeypatch.setattr(
            registry_migration_module, "datetime", DestinationCompletionDateTime
        )
        destination_complete = await destination_service.complete_destination(cutover_id)
        assert DestinationCompletionDateTime.calls >= 1
        monkeypatch.setattr(registry_migration_module, "datetime", datetime)
        assert await destination_service.complete_destination(
            cutover_id, completed_at=complete_time.replace(second=11)
        ) == destination_complete
        assert await destination_service.observe_destination(cutover_id) == observation
        destination_service.verify_domain = unavailable_after_store
        source_service.verify_domain = unavailable_after_store
        assert await source_service.confirm_readback(cutover_id, readback) == authorization
        with pytest.raises(RegistryMigrationError, match="counts mismatch"):
            await source_service.confirm_readback(cutover_id, wrong_count)
        assert await destination_service.apply_dns_authorization(
            cutover_id, authorization
        ) == authorization
        with pytest.raises(RegistryMigrationError, match="conflicting destination"):
            await destination_service.apply_dns_authorization(
                cutover_id, wrong_authorization
            )
        assert await destination_service.apply_overlap(cutover_id, overlap) == overlap
        with pytest.raises(RegistryMigrationError, match="does not match destination"):
            await destination_service.apply_overlap(cutover_id, cross_overlap)
        await destination_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='overlap.example'"
        )
        with pytest.raises(QueryError, match="registry_migration_fenced"):
            await source_db.execute(
                "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='overlap.example'"
            )
        premature_payload = DestinationCompletePayload.model_validate(
            destination_complete["payload"]
            | {"destination_completed_at": "2026-08-26T18:10:09Z"}
        )
        premature = make_receipt(premature_payload).model_dump(mode="json")
        with pytest.raises(RegistryMigrationError, match="destination completion"):
            await source_service.complete_source(
                cutover_id, premature, completed_at=complete_time,
            )
        source_service.verify_domain = wrong_destination
        with pytest.raises(RegistryMigrationError, match="fresh source DNS"):
            await source_service.complete_source(
                cutover_id, destination_complete, completed_at=complete_time,
            )
        class SourceCompletionDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 8, 26, 18, 10, 10, tzinfo=timezone.utc)

        async def timed_source_completion(domain):
            assert SourceCompletionDateTime.calls == 0
            return await destination_selected(domain)

        source_service.verify_domain = timed_source_completion
        monkeypatch.setattr(
            registry_migration_module, "datetime", SourceCompletionDateTime
        )
        source_completed = await source_service.complete_source(
            cutover_id, destination_complete
        )
        assert SourceCompletionDateTime.calls >= 1
        monkeypatch.setattr(registry_migration_module, "datetime", datetime)
        assert source_completed == {
            "state": "completed",
            "destination_complete_hash": destination_complete["receipt_hash"],
        }
        assert await source_db.fetch_value(
            "SELECT source_final_observation->>'consumed_destination_complete_hash' FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source'",
            cutover_id,
        ) == destination_complete["receipt_hash"]
        assert await source_service.complete_source(
            cutover_id, destination_complete, completed_at=complete_time.replace(second=12)
        ) == source_completed
        source_service.verify_domain = unavailable_after_store
        assert await source_service.confirm_readback(cutover_id, readback) == authorization
        with pytest.raises(RegistryMigrationError, match="counts mismatch"):
            await source_service.confirm_readback(cutover_id, wrong_count)
        await source_db.execute(
            "UPDATE {{tables.dns_namespaces}} SET last_verified_at=NOW() WHERE domain='overlap.example'"
        )
    finally:
        await source.close()
        await destination.close()
