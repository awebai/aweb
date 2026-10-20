"""Export, erasure and restore exercise content plus a separate live ledger."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import subprocess
from dataclasses import replace

import pytest

from aweb_naapp.page_store import Access, PageStore, StoreError
from aweb_naapp.page_store.lifecycle import Coverage, ExternalArchive, LifecycleHooks
from tests.page_store.test_store import (
    OWNER,
    POLICY,
    READER,
    SCOPE,
    STRANGER,
    create,
    record_change,
)


async def test_export_is_authorized_complete_checksummed_and_safe_to_import(store):
    await create(store)
    await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change()])
    archive = await store.export_page(SCOPE, OWNER)
    assert archive["manifest"]["format"] == "aweb.page-export/1"
    assert archive["manifest"]["revision_cut"] == 2
    assert archive["manifest"]["unresolved_references"] == [
        {"kind": "application_inventory", "reason": "adapter_unconfigured"}
    ]
    assert archive["content"]["records"]["items"][0]["rev"] == 2
    assert len(archive["content"]["audit"]) == 2
    restored_scope = replace(SCOPE, page_id="imported")
    await store.import_page(
        restored_scope,
        OWNER,
        archive=archive,
        access=Access(owner=OWNER.did_key),
        acl_mapping={OWNER.did_key: OWNER.did_key},
        key="import",
    )
    restored = await store.read(restored_scope, OWNER)
    assert (
        await store.read_widget(
            restored_scope,
            OWNER,
            widget_id="items",
            expected_page_rev=1,
            bind={"collection": "items"},
        )
    )["records"][0]["value"]["checked"] is True
    assert restored["widget_state"] == {}
    corrupt = copy.deepcopy(archive)
    corrupt["content"]["records"]["items"][0]["value"]["checked"] = False
    with pytest.raises(StoreError, match="archive_checksum_invalid"):
        await store.import_page(
            replace(SCOPE, page_id="corrupt"),
            OWNER,
            archive=corrupt,
            access=Access(owner=OWNER.did_key),
            acl_mapping={OWNER.did_key: OWNER.did_key},
            key="corrupt",
        )
    with pytest.raises(StoreError, match="action_denied"):
        await store.export_page(SCOPE, READER)
    with pytest.raises(StoreError, match="acl_mapping_required"):
        await store.import_page(
            replace(SCOPE, page_id="unmapped"),
            OWNER,
            archive=archive,
            access=Access(owner=OWNER.did_key),
            acl_mapping={},
            key="unmapped",
        )


class EmptyAppHooks(LifecycleHooks):
    """A real adapter for an app with no assets, links, approvals or external effects."""

    async def export(self, scope, principal):
        return ExternalArchive(artifacts={}, unresolved_references=[])

    async def revoke(self, scope, job_id):
        return Coverage(
            complete=True, details={"links": 0, "approvals": 0, "undispatched_requests": 0}
        )

    async def purge(self, scope, job_id):
        return Coverage(
            complete=True,
            details={
                "assets": 0,
                "caches": 0,
                "search": 0,
                "external_operations": [],
                "retained_task_references": [],
            },
        )

    async def backup_status(self, scope, job_id):
        return Coverage(
            complete=True, details={"encrypted": True, "expired": True, "provider_deletions": []}
        )


async def test_delete_is_durable_revokes_access_and_does_not_claim_unowned_coverage(store):
    await create(store)
    receipt = await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    assert receipt["state"] == "requested"
    for call in (
        store.read(SCOPE, OWNER),
        store.mutate(SCOPE, OWNER, expected_rev=1, key="late", records=[record_change()]),
    ):
        with pytest.raises(StoreError, match="resource_not_found"):
            await call
    assert await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete") == receipt
    pending = await store.advance_delete(SCOPE)
    assert pending["state"] == "requested"
    assert pending["remaining"] == ["application_revocation"]
    store.lifecycle = EmptyAppHooks()
    done = await store.advance_delete(SCOPE)
    assert done["state"] == "complete"
    assert done["tombstone_rev"] == 2
    assert done["policy"]["version"] == POLICY.version
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_records}}") == 0
    document = json.loads(await store.db.fetch_value("SELECT document FROM {{tables.pages}}"))
    assert document == {"page_id": SCOPE.page_id, "rev": 2}
    assert "Verify fixture inventory" not in json.dumps(done)
    assert await store.deletion_status(SCOPE, OWNER) == done
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.deletion_status(SCOPE, STRANGER)
    event = await store.db.fetch_value(
        "SELECT payload FROM {{tables.outbox_events}} ORDER BY position DESC LIMIT 1"
    )
    assert json.loads(bytes(event))["deleted"] is True


async def test_backup_restore_cannot_resurrect_deleted_page_or_prior_receipt(store, tmp_path):
    await create(store)
    backup = tmp_path / "before-delete.dump"
    config = store.db.config
    database = await store.db.fetch_value("SELECT current_database()")
    assert database.startswith("test_")
    env = {
        **os.environ,
        "PGHOST": config.host,
        "PGPORT": str(config.port),
        "PGUSER": config.user,
        "PGPASSWORD": config.password,
        "PGDATABASE": database,
    }
    await asyncio.to_thread(
        subprocess.run,
        ["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--file", str(backup)],
        env=env,
        check=True,
        capture_output=True,
    )
    store.lifecycle = EmptyAppHooks()
    await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    await store.advance_delete(SCOPE)
    # Actual SQL restore into the content DB, keeping the separate ledger live.
    await store.db.disconnect()
    await asyncio.to_thread(
        subprocess.run,
        [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            "--dbname",
            database,
            str(backup),
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    await store.db.connect()
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_records}}") == 1
    fresh_process = PageStore(store.db, ledger=store.ledger, retention=POLICY)
    with pytest.raises(StoreError, match="restore_not_ready"):
        await fresh_process.read(SCOPE, OWNER)
    await fresh_process.start()
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_records}}") == 0
    with pytest.raises(StoreError, match="resource_not_found"):
        await fresh_process.read(SCOPE, OWNER)
    with pytest.raises(StoreError, match="resource_not_found"):
        await create(fresh_process)
    assert (await fresh_process.deletion_status(SCOPE, OWNER))["state"] == "complete"


class PendingAppHooks(EmptyAppHooks):
    async def purge(self, scope, job_id):
        return Coverage(
            complete=False,
            details={
                "external_operations": ["operation-opaque"],
                "retained_task_references": ["task-opaque"],
            },
        )


async def test_dispatched_effects_and_backup_retention_block_completion(store):
    await create(store)
    store.lifecycle = PendingAppHooks()
    await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    pending = await store.advance_delete(SCOPE)
    assert pending["state"] == "purging"
    assert "application_purge" in pending["remaining"]
    assert pending["coverage"]["application_purge"]["external_operations"] == ["operation-opaque"]
    assert pending["retention_deadline"]
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_records}}") == 0
    store.lifecycle = EmptyAppHooks()
    assert (await store.advance_delete(SCOPE))["state"] == "complete"


async def test_delete_key_cannot_collide_with_a_prior_mutation_key(store):
    await create(store)
    with pytest.raises(StoreError, match="idempotency_conflict"):
        await store.request_delete(SCOPE, OWNER, expected_rev=1, key="create")
    assert (await store.read(SCOPE, OWNER))["rev"] == 1


async def test_delete_remains_available_using_the_stored_operator_policy(store):
    await create(store)
    store.retention = None
    receipt = await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    assert receipt["policy"]["version"] == POLICY.version


async def test_installation_export_needs_current_admin_and_per_page_grants(store):
    await create(store)
    with pytest.raises(StoreError, match="action_denied"):
        await store.export_installation(SCOPE, READER)

    async def lifecycle_grant(scope, principal, operation):
        return principal.did_key == READER.did_key and operation in {
            "export_installation",
            "export",
        }

    store.lifecycle_authorizer = lifecycle_grant
    archive = await store.export_installation(SCOPE, READER)
    assert len(archive["pages"]) == 1


async def test_open_schema_fields_round_trip_without_silent_data_loss(store):
    from tests.page_store.test_store import page

    doc = page()
    doc["collections"][0]["schema"].update(additionalProperties=True, maxProperties=8)
    doc["collections"][0]["records"][0]["value"]["extra"] = "Retained customer value"
    await create(store, doc)
    projection = await store.read_widget(
        SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind={"collection": "items"}
    )
    assert projection["records"][0]["value"]["extra"] == "Retained customer value"
    archive = await store.export_page(SCOPE, OWNER)
    assert archive["content"]["records"]["items"][0]["value"]["extra"] == "Retained customer value"


async def test_startup_reapplies_erasure_after_key_expiry(store):
    await create(store)
    await store.request_delete(SCOPE, OWNER, expected_rev=1, key="delete")
    await store.db.execute(
        "UPDATE {{tables.idempotency_keys}} SET expires_at=NOW()-INTERVAL '1 second'"
    )
    await store.start()
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.read(SCOPE, OWNER)
