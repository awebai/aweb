"""Metadata-only discovery entries join the caller's PageStore transaction."""

from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.team_auth import record_observed_principal
from pgdbm import AsyncMigrationManager
from test_record_storage import ACTOR

from folio.collection_documents import (
    collection_scope,
    find_collection_document,
    list_collection_documents,
    put_collection_document_on,
)

INSTALLATION = AdmittedInstallation(team_id=ACTOR.team_id, app_id="folio", installation_id="install-1", generation=1)
MIGRATIONS = Path(__file__).resolve().parents[1] / "src/folio/migrations"


@pytest.fixture
async def database(test_db_factory):
    db = await test_db_factory.create_db(suffix="collection_index")
    await AsyncMigrationManager(db, migrations_path=str(MIGRATIONS), module_name="folio").apply_pending_migrations()
    await record_observed_principal(db, ACTOR)
    return db


def test_page_id_is_stable_per_installed_team_and_collection_and_accepts_long_ids():
    scope = collection_scope(INSTALLATION, "discovery")
    assert scope == collection_scope(INSTALLATION, "discovery")
    assert str(UUID(scope.page_id)) == scope.page_id
    for changes in [dict(installation_id="install-2"), dict(team_id="other:example.test"), dict(app_id="other-app")]:
        other = AdmittedInstallation(**{**INSTALLATION.__dict__, **changes})
        assert collection_scope(other, "discovery").page_id != scope.page_id
    assert collection_scope(INSTALLATION, "x" * 128).page_id != scope.page_id


async def test_index_insert_is_atomic_idempotent_and_contains_no_record_copy(database):
    scope = collection_scope(INSTALLATION, "discovery")
    async with database.transaction() as tx:
        first = await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries and conversations")
    async with database.transaction() as tx:
        retried = await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries and conversations")
    assert first == retried
    assert first["kind"] == "table"
    assert first["collection_id"] == "discovery"
    assert first["slug"]
    assert await database.fetch_value("SELECT count(*) FROM {{tables.documents}}") == 1
    assert await database.fetch_value("SELECT count(*) FROM {{tables.collection_documents}}") == 1
    assert await database.fetch_value("SELECT count(*) FROM {{tables.document_versions}}") == 0
    assert "body" not in first and "records" not in first
    found = await find_collection_document(database, INSTALLATION, slug=first["slug"])
    assert found == first


async def test_caller_transaction_rollback_also_removes_the_discovery_entry(database):
    scope = collection_scope(INSTALLATION, "discovery")
    with pytest.raises(RuntimeError, match="abort definition"):
        async with database.transaction() as tx:
            await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries")
            raise RuntimeError("abort definition")
    assert await database.fetch_value("SELECT count(*) FROM {{tables.documents}}") == 0
    assert await database.fetch_value("SELECT count(*) FROM {{tables.collection_documents}}") == 0


async def test_index_lookup_is_bound_to_active_installation_team_and_app(database):
    scope = collection_scope(INSTALLATION, "discovery")
    async with database.transaction() as tx:
        row = await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries")
    assert await list_collection_documents(database, INSTALLATION) == [row]
    for changes in [dict(installation_id="install-2"), dict(team_id="other:example.test"), dict(app_id="other-app")]:
        other = AdmittedInstallation(**{**INSTALLATION.__dict__, **changes})
        assert await list_collection_documents(database, other) == []
        assert await find_collection_document(database, other, slug=row["slug"]) is None


async def test_legacy_document_list_cannot_bypass_page_store_acl_for_a_table(database):
    from folio.repository import list_documents

    scope = collection_scope(INSTALLATION, "discovery")
    async with database.transaction() as tx:
        await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries")
    # The API joins authorized table entries separately; the legacy repository
    # cannot return them solely because a caller belongs to the same team.
    assert await list_documents(database, principal=ACTOR) == []


async def test_markdown_append_and_versions_cannot_change_a_collection_table(database):
    from aweb_naapp.outbox import RetryPolicy
    from aweb_naapp.runtime.event_emit import AppEvents
    from fastapi import HTTPException

    from folio.repository import append_version, list_versions

    scope = collection_scope(INSTALLATION, "discovery")
    async with database.transaction() as tx:
        entry = await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries")
    events = AppEvents(app_id="folio", origin=None, key=None, policy=RetryPolicy(stalled_after=timedelta(hours=1)))
    with pytest.raises(HTTPException) as refused:
        await append_version(database, principal=ACTOR, events=events, slug=entry["slug"], body="not a record")
    assert refused.value.status_code == 404
    with pytest.raises(HTTPException) as refused:
        await list_versions(database, principal=ACTOR, slug=entry["slug"])
    assert refused.value.status_code == 404
    assert await database.fetch_value("SELECT count(*) FROM {{tables.document_versions}}") == 0


async def test_plain_documents_stay_visible_and_appendable_next_to_tables(database):
    from aweb_naapp.outbox import RetryPolicy
    from aweb_naapp.runtime.event_emit import AppEvents

    from folio.repository import append_version, create_document, list_documents, list_versions

    events = AppEvents(app_id="folio", origin=None, key=None, policy=RetryPolicy(stalled_after=timedelta(hours=1)))
    scope = collection_scope(INSTALLATION, "discovery")
    async with database.transaction() as tx:
        await put_collection_document_on(tx, scope, ACTOR, collection_id="discovery", title="Discoveries")
    await create_document(database, principal=ACTOR, events=events, slug="plain-note", title="A note", body="version one")
    appended = await append_version(database, principal=ACTOR, events=events, slug="plain-note", body="version two")
    assert appended["body"] == "version two" and appended["current_version"] == 2
    assert [entry["slug"] for entry in await list_documents(database, principal=ACTOR)] == ["plain-note"]
    assert [version["version_number"] for version in await list_versions(database, principal=ACTOR, slug="plain-note")] == [2, 1]
