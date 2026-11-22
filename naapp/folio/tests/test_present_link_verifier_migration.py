"""Read-only link tokens already stored in clear are replaced by their verifier in place."""

from __future__ import annotations

import shutil
from datetime import timedelta
from pathlib import Path

from aweb_naapp.outbox import RetryPolicy
from aweb_naapp.runtime.db import ApplyMigrations, NaappDatabase
from aweb_naapp.runtime.event_emit import AppEvents
from aweb_naapp.runtime.installation import apply_installation_migrations
from aweb_naapp.runtime.link_requests import secret_verifier
from aweb_naapp.runtime.team_auth import record_observed_principal
from test_present_privacy import OWNER

from folio.config import Settings
from folio.models import LinkKind
from folio.repository import create_document, mint_presentation_link

_MIGRATIONS = Path(__file__).resolve().parents[1] / "src/folio/migrations"
_BEFORE_VERIFIERS = (
    "001_initial.sql",
    "002_edit_sessions.sql",
    "003_installation_capabilities.sql",
)


def _no_app_events(settings: Settings) -> AppEvents:
    """The app-event configuration of a deployment that emits no app events."""
    return AppEvents(
        app_id=settings.app_id,
        origin=None,
        key=None,
        policy=RetryPolicy(
            stalled_after=timedelta(seconds=settings.app_events_stalled_after_seconds)
        ),
    )


def _storage(settings: Settings, migrations: Path) -> NaappDatabase:
    return NaappDatabase(
        settings,
        module_name="folio",
        migrations_path=migrations,
        stores=(apply_installation_migrations,),
        schema_preparation=ApplyMigrations(),
    )


async def test_existing_read_only_tokens_are_hashed_and_editable_link_ids_kept(
    test_db_factory, tmp_path
):
    database = await test_db_factory.create_db(suffix="folio_verifier_migration")
    settings = Settings(
        _env_file=None, database_url=database.config.get_dsn(), db_schema="naapp_test"
    )
    earlier = tmp_path / "migrations"
    earlier.mkdir()
    for name in _BEFORE_VERIFIERS:
        shutil.copy(_MIGRATIONS / name, earlier / name)

    read_only = "r" * 43
    # The shipped 001-003 migrations, applied by pgdbm's AsyncMigrationManager.
    before = _storage(settings, earlier)
    await before.connect()
    try:
        db = before.db
        await record_observed_principal(db, OWNER)
        await create_document(
            db, principal=OWNER, events=_no_app_events(settings), slug="d", title="D", body="b"
        )
        editable = await mint_presentation_link(
            db,
            installation_id="installation",
            principal=OWNER,
            settings=settings,
            slug="d",
            version=None,
            ttl_seconds=None,
            kind=LinkKind.EDITABLE,
        )
        # unreachable-state: pre-004 read-only presentation link stored with its token in clear (migration 004)
        await db.execute(
            """INSERT INTO {{tables.presentation_links}}
            (token, document_id, version_number, expires_at, created_by_did_key, created_by_alias,
             certificate_id, editable)
            SELECT $1, document_id, 1, NOW() + interval '1 day', $2, $3, $4, FALSE
            FROM {{tables.documents}} WHERE team_id = $5 AND slug = 'd'""",
            read_only,
            OWNER.did_key,
            OWNER.alias,
            OWNER.certificate_id,
            OWNER.team_id,
        )
    finally:
        await before.disconnect()

    # Migration 004, through the same manager.
    after = _storage(settings, _MIGRATIONS)
    await after.connect()
    try:
        keys = {
            row["token"]: row["editable"]
            for row in await after.db.fetch_all(
                "SELECT token, editable FROM {{tables.presentation_links}}"
            )
        }
    finally:
        await after.disconnect()
    assert keys == {secret_verifier(read_only): False, editable["token"]: True}
