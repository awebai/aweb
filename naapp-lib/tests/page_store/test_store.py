"""Page transactions and projections against real PostgreSQL."""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest

from aweb_naapp.page_store import (
    Access,
    PageStore,
    RetentionPolicy,
    Scope,
    StoreError,
    apply_page_store_migrations,
)
from aweb_naapp.pages import validate_page
from aweb_naapp.runtime.team_auth import Principal

FIXTURE = Path(__file__).resolve().parents[3] / "docs/design/agent-pages/examples/fixture-page.json"
SCOPE = Scope("install-1", "team:example.com", "fixture", "fixture-home")
OWNER = Principal(SCOPE.team_id, "did:key:owner", None, None, "owner", "cert-owner", "did:key:team")
READER = Principal(
    SCOPE.team_id, "did:key:reader", None, None, "reader", "cert-reader", "did:key:team"
)
STRANGER = Principal(
    SCOPE.team_id, "did:key:other", None, None, "other", "cert-other", "did:key:team"
)
POLICY = RetentionPolicy(
    version="synthetic-test",
    content_purge_days=1,
    audit_content_days=2,
    backup_expiry_days=3,
    backup_interval_hours=4,
    restore_rpo_hours=4,
    retry_horizon_days=5,
    encrypted_backups=True,
    legal_exceptions=(),
)


@pytest.fixture
async def store(test_db_factory):
    db = await test_db_factory.create_db(suffix="page_content")
    ledger = await test_db_factory.create_db(suffix="page_deletions")
    await apply_page_store_migrations(db, ledger)
    result = PageStore(db, ledger=ledger, retention=POLICY)
    await result.start()
    return result


def page():
    return json.loads(FIXTURE.read_text())


async def create(store, document=None, **changes):
    access = Access(owner=OWNER.did_key, readers={READER.did_key}, **changes)
    return await store.create(
        SCOPE, OWNER, page() if document is None else document, access=access, key="create"
    )


def record_change(value=True, **changes):
    result = {
        "op": "update",
        "collection": "items",
        "id": "item-1",
        "expected_rev": 1,
        "value": {"label": "Verify fixture inventory", "checked": value},
    }
    result.update(changes)
    return result


async def test_write_requires_explicit_operator_policy(store):
    store.retention = None
    with pytest.raises(StoreError) as refused:
        await create(store)
    assert (refused.value.status, refused.value.code) == (503, "retention_policy_required")
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.pages}}") == 0


async def test_mutation_receipt_replay_conflicts_and_atomic_audit_outbox(store):
    created = await create(store)
    assert created["page_rev"] == 1
    receipt = await store.mutate(
        SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change()]
    )
    assert receipt["page_rev"] == 2
    assert receipt["record_revs"] == {"items/item-1": 2}
    assert (
        await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change()])
        == receipt
    )
    with pytest.raises(StoreError, match="idempotency_conflict"):
        await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change(False)])
    with pytest.raises(StoreError, match="revision_conflict"):
        await store.mutate(SCOPE, OWNER, expected_rev=1, key="stale", records=[record_change()])
    snapshot = await store.read(SCOPE, OWNER)
    assert (
        await store.read_widget(
            SCOPE, OWNER, widget_id="items", expected_page_rev=2, bind={"collection": "items"}
        )
    )["records"][0]["value"]["checked"] is True
    assert validate_page(snapshot).valid
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 2
    events = await store.db.fetch_all(
        "SELECT payload FROM {{tables.outbox_events}} ORDER BY position"
    )
    assert len(events) == 2
    payload = json.loads(bytes(events[-1]["payload"]))
    assert payload == {
        "app_id": "fixture",
        "installation_id": "install-1",
        "page_id": "fixture-home",
        "rev": 2,
        "deleted": False,
    }
    audit = await store.db.fetch_one(
        "SELECT evidence FROM {{tables.page_audit}} ORDER BY new_rev DESC LIMIT 1"
    )
    assert json.loads(audit["evidence"])["certificate_id"] == "cert-owner"


async def test_batch_is_all_or_nothing_and_record_tombstones_prevent_reuse(store):
    await create(store)
    with pytest.raises(StoreError, match="revision_conflict"):
        await store.mutate(
            SCOPE,
            OWNER,
            expected_rev=1,
            key="bad-batch",
            records=[
                record_change(),
                {"op": "delete", "collection": "items", "id": "missing", "expected_rev": 1},
            ],
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 1
    await store.mutate(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="delete-row",
        records=[record_change(op="delete", value=None)],
    )
    with pytest.raises(StoreError, match="revision_conflict"):
        await store.mutate(
            SCOPE,
            OWNER,
            expected_rev=2,
            key="recreate-row",
            records=[record_change(op="create", expected_rev=0)],
        )
    assert (await store.read(SCOPE, OWNER))["collections"][0]["records"] == []


async def test_concurrent_writers_never_silently_overwrite(store):
    await create(store)
    outcomes = await asyncio.gather(
        *[
            store.mutate(
                SCOPE, OWNER, expected_rev=1, key=f"race-{i}", records=[record_change(bool(i))]
            )
            for i in range(2)
        ],
        return_exceptions=True,
    )
    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert (
        sum(isinstance(item, StoreError) and item.code == "revision_conflict" for item in outcomes)
        == 1
    )


async def test_acl_is_before_filter_sort_count_and_no_historical_receipt_bypass(store):
    doc = page()
    doc["collections"][0]["schema"]["properties"]["private"] = {"type": "integer"}
    doc["collections"][0]["records"] += [
        {"id": "hidden", "rev": 1, "value": {"label": "Secret", "checked": False, "private": 3}}
    ]
    await create(
        store,
        doc,
        hidden_rows={READER.did_key: {"items": {"hidden"}}},
        fields={READER.did_key: {"items": {"label", "checked"}}},
    )
    projection = await store.read_widget(
        SCOPE,
        READER,
        widget_id="items",
        expected_page_rev=1,
        bind={"collection": "items", "all": [{"field": "checked", "op": "eq", "value": False}]},
    )
    assert [row["id"] for row in projection["records"]] == ["item-1"]
    assert projection["count"] == 1
    for bind in (
        {"collection": "items", "sort": [{"field": "private", "direction": "asc"}]},
        {"collection": "items", "all": [{"field": "private", "op": "eq", "value": 3}]},
    ):
        with pytest.raises(StoreError, match="query_denied"):
            await store.read_widget(
                SCOPE, READER, widget_id="items", expected_page_rev=1, bind=bind
            )
    snapshot = await store.read(SCOPE, READER)
    assert validate_page(snapshot).valid
    assert "private" not in json.dumps(snapshot)
    with pytest.raises(StoreError, match="resource_not_found"):
        await store.read(SCOPE, STRANGER)
    await store.change_access(
        SCOPE, OWNER, expected_rev=1, key="revoke", access=Access(owner=STRANGER.did_key)
    )
    with pytest.raises(StoreError, match="resource_not_found"):
        await create(store, doc)


async def test_synced_records_only_change_through_sync_and_schema_migration_checks_all_rows(store):
    doc = page()
    doc["collections"][0]["mode"] = "synced"
    source = {
        "system": "synthetic",
        "external_id": "remote-1",
        "version": "v1",
        "synced_at": "2026-10-20T00:00:00Z",
    }
    doc["collections"][0]["records"][0]["source"] = source
    await create(store, doc)
    with pytest.raises(StoreError, match="synced_write_denied"):
        await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change()])
    await store.sync(
        SCOPE,
        OWNER,
        expected_rev=1,
        key="sync",
        records=[record_change(source={**source, "version": "v2"})],
    )
    schema = copy.deepcopy(doc["collections"][0]["schema"])
    schema["properties"]["checked"] = {"type": "string", "maxLength": 32}
    with pytest.raises(StoreError, match="schema_invalid"):
        await store.migrate_schema(
            SCOPE, OWNER, expected_rev=2, key="schema", collection="items", schema=schema, values={}
        )
    await store.migrate_schema(
        SCOPE,
        OWNER,
        expected_rev=2,
        key="schema-fixed",
        collection="items",
        schema=schema,
        values={"item-1": {"label": "Verify fixture inventory", "checked": "yes"}},
    )
    snapshot = await store.read(SCOPE, OWNER)
    assert snapshot["collections"][0]["schema_version"] == 2
    assert (
        await store.read_widget(
            SCOPE, OWNER, widget_id="items", expected_page_rev=3, bind={"collection": "items"}
        )
    )["records"][0]["source"]["version"] == "v2"


async def test_cursor_binds_actor_policy_query_and_snapshot(store):
    doc = page()
    doc["collections"][0]["records"] += [
        {"id": "item-2", "rev": 1, "value": {"label": "Two", "checked": False}}
    ]
    await create(store, doc)
    bind = {"collection": "items", "limit": 1}
    first = await store.read_widget(SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind=bind)
    second = await store.read_widget(
        SCOPE,
        OWNER,
        widget_id="items",
        expected_page_rev=1,
        bind={**bind, "cursor": first["next_cursor"]},
    )
    assert [r["id"] for r in first["records"] + second["records"]] == ["item-1", "item-2"]
    with pytest.raises(StoreError, match="cursor_invalid"):
        await store.read_widget(
            SCOPE,
            READER,
            widget_id="items",
            expected_page_rev=1,
            bind={**bind, "cursor": first["next_cursor"]},
        )
    await store.mutate(SCOPE, OWNER, expected_rev=1, key="edit", records=[record_change()])
    with pytest.raises(StoreError, match="revision_conflict"):
        await store.read_widget(SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind=bind)


async def test_more_than_one_snapshot_of_records_can_be_stored_and_schema_migrated(store):
    await create(store)
    changes = [
        {
            "op": "create",
            "collection": "items",
            "id": f"row-{i}",
            "expected_rev": 0,
            "value": {"label": str(i), "checked": False},
        }
        for i in range(205)
    ]
    await store.mutate(SCOPE, OWNER, expected_rev=1, key="bulk", records=changes)
    snapshot = await store.read(SCOPE, OWNER)
    assert snapshot["collections"][0]["records"] == []
    assert validate_page(snapshot).valid
    bind = {"collection": "items", "limit": 200}
    first = await store.read_widget(SCOPE, OWNER, widget_id="items", expected_page_rev=2, bind=bind)
    last = await store.read_widget(
        SCOPE,
        OWNER,
        widget_id="items",
        expected_page_rev=2,
        bind={**bind, "cursor": first["next_cursor"]},
    )
    assert len(first["records"]) + len(last["records"]) == 206
    schema = copy.deepcopy(snapshot["collections"][0]["schema"])
    schema["properties"]["label"]["maxLength"] = 1
    with pytest.raises(StoreError, match="schema_invalid"):
        await store.migrate_schema(
            SCOPE,
            OWNER,
            expected_rev=2,
            key="invalid-old-row",
            collection="items",
            schema=schema,
            values={},
        )


async def test_expired_request_key_never_executes_again(store):
    await create(store)
    await store.db.execute(
        "UPDATE {{tables.idempotency_keys}} SET expires_at=NOW() - $1::interval", timedelta(days=1)
    )
    with pytest.raises(StoreError, match="idempotency_expired"):
        await create(store)


async def test_outbox_failure_rolls_back_data_audit_and_idempotency(store):
    await create(store)
    await store.db.execute("""CREATE FUNCTION refuse_page_event() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'synthetic outbox failure'; END $$""")
    await store.db.execute(
        "CREATE TRIGGER refuse_event BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION refuse_page_event()"
    )
    with pytest.raises(Exception, match="synthetic outbox failure"):
        await store.mutate(
            SCOPE, OWNER, expected_rev=1, key="retry-after-fault", records=[record_change()]
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 1
    assert await store.db.fetch_value("SELECT count(*) FROM {{tables.page_audit}}") == 1
    await store.db.execute("DROP TRIGGER refuse_event ON outbox_events")
    assert (
        await store.mutate(
            SCOPE, OWNER, expected_rev=1, key="retry-after-fault", records=[record_change()]
        )
    )["page_rev"] == 2


@pytest.mark.parametrize(
    "change",
    [
        {"expected_rev": None},
        {"expected_rev": True},
        {"value": {"label": 8, "checked": False}},
        {"value": {"label": "x", "checked": False, "acl": "owner"}},
        {"op": "patch", "path": "/owner"},
    ],
)
async def test_invalid_mutations_have_no_partial_effect(store, change):
    await create(store)
    with pytest.raises(StoreError):
        await store.mutate(
            SCOPE, OWNER, expected_rev=1, key="invalid", records=[record_change(**change)]
        )
    assert (await store.read(SCOPE, OWNER))["rev"] == 1


async def test_sort_filter_types_and_bootstrap_are_bounded_to_the_widget_projection(store):
    doc = page()
    doc["collections"][0]["schema"]["properties"]["quantity"] = {"type": "integer"}
    doc["collections"][0]["records"] = [
        {"id": f"row-{n}", "rev": 1, "value": {"label": str(n), "checked": False, "quantity": n}}
        for n in (20, 3, 11)
    ]
    await create(store, doc)
    assert (await store.read(SCOPE, OWNER))["collections"][0]["records"] == []
    bind = {
        "collection": "items",
        "sort": [{"field": "quantity", "direction": "asc"}],
        "all": [{"field": "quantity", "op": "in", "value": [20, 3]}],
    }
    result = await store.read_widget(
        SCOPE, OWNER, widget_id="items", expected_page_rev=1, bind=bind
    )
    assert [r["value"]["quantity"] for r in result["records"]] == [3, 20]
    with pytest.raises(StoreError, match="schema_invalid"):
        await store.read_widget(
            SCOPE,
            OWNER,
            widget_id="items",
            expected_page_rev=1,
            bind={"collection": "items", "all": [{"field": "quantity", "op": "eq", "value": "3"}]},
        )


async def test_bundle_bootstrap_carries_exact_records_and_private_decisions_are_inert(store):
    vectors = json.loads((FIXTURE.parents[3] / "vectors/page-format-v1.json").read_text())
    doc = vectors["bases"]["bundle"]
    doc.update(page_id=SCOPE.page_id, rev=1)
    await create(store, doc, hidden_rows={READER.did_key: {"proposals": {"week-44"}}})
    snapshot = await store.read(SCOPE, OWNER)
    assert validate_page(snapshot).valid
    assert len(snapshot["collections"][0]["records"]) == 2
    await store.mutate(
        SCOPE, OWNER, expected_rev=1, key="state", state={"items": {"message": "Checked"}}
    )
    restricted = await store.read(SCOPE, READER)
    assert validate_page(restricted).valid
    card = next(w for w in restricted["layout"] if w["id"] == "batch-decision")
    assert card["type"] == "access_unavailable"
    assert all(c["records"] == [] for c in restricted["collections"])
