"""Read-only link tokens already stored in clear are replaced by their verifier in place."""

from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

from aweb_naapp.runtime.db import NaappDatabase
from aweb_naapp.runtime.installation import apply_installation_migrations
from aweb_naapp.runtime.link_requests import secret_verifier

from folio.config import Settings

_MIGRATIONS = Path(__file__).resolve().parents[1] / "src/folio/migrations"
_BEFORE_VERIFIERS = (
    "001_initial.sql",
    "002_edit_sessions.sql",
    "003_installation_capabilities.sql",
)


def _storage(settings: Settings, migrations: Path) -> NaappDatabase:
    return NaappDatabase(
        settings,
        module_name="folio",
        migrations_path=migrations,
        stores=(apply_installation_migrations,),
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

    read_only, editable_id = "r" * 43, "e" * 22
    before = _storage(settings, earlier)
    await before.connect()
    try:
        db = before.db
        document_id = uuid4()
        # unreachable-state: a team row stored before migration 004, under the 001-003 schema
        await db.execute(
            "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ('t:x', 'did:key:t')"
        )
        # unreachable-state: a document stored before migration 004, under the 001-003 schema
        await db.execute(
            """INSERT INTO {{tables.documents}} (document_id, team_id, slug, title, created_by_did_key, created_by_alias)
            VALUES ($1, 't:x', 'd', 'D', 'did:key:m', 'm')""",
            document_id,
        )
        # unreachable-state: a document version stored before migration 004, under the 001-003 schema
        await db.execute(
            """INSERT INTO {{tables.document_versions}}
            (version_id, document_id, version_number, body, created_by_did_key, created_by_alias, certificate_id)
            VALUES ($1, $2, 1, 'b', 'did:key:m', 'm', 'c')""",
            uuid4(),
            document_id,
        )
        for token, editable in ((read_only, False), (editable_id, True)):
            # unreachable-state: a presentation link whose token is stored in clear, before migration 004
            await db.execute(
                """INSERT INTO {{tables.presentation_links}}
                (token, document_id, version_number, expires_at, created_by_did_key, created_by_alias,
                 certificate_id, editable)
                VALUES ($1, $2, 1, NOW() + interval '1 day', 'did:key:m', 'm', 'c', $3)""",
                token,
                document_id,
                editable,
            )
    finally:
        await before.disconnect()

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
    assert keys == {secret_verifier(read_only): False, editable_id: True}
