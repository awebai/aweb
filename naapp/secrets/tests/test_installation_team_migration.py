"""Legacy rows keep only an evidenced, unambiguous installation/team binding."""

from __future__ import annotations

import json
import shutil

import pytest
from pgdbm import AsyncMigrationManager

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.change_policy import MIGRATIONS_PATH as SETTINGS_PATH
from aweb_secrets.change_policy import apply_change_policy_migrations
from aweb_secrets.revisions import MIGRATIONS_PATH as REVISIONS_PATH
from aweb_secrets.revisions import apply_revision_migrations
from tests.test_records_store import INSTALLATION, POLICY, SECRET, TEAM


async def _legacy(db, tmp_path, source, module, last):
    old = tmp_path / module
    old.mkdir()
    for path in source.glob("*.sql"):
        if int(path.name.split("_", 1)[0]) <= last:
            shutil.copyfile(path, old / path.name)
    await AsyncMigrationManager(
        db, migrations_path=str(old), module_name=module
    ).apply_pending_migrations()


@pytest.mark.parametrize("kind", ["revisions", "settings"])
@pytest.mark.parametrize("evidence", ["unique", "missing", "ambiguous"])
async def test_legacy_installation_state_requires_one_evidenced_team(
    test_db_factory, tmp_path, kind, evidence
):
    db = await test_db_factory.create_db(suffix="team_upgrade")
    if kind == "revisions":
        source, module, table, value = (
            REVISIONS_PATH,
            "aweb_secrets_revisions",
            "config_revisions",
            "revision",
        )
        upgrade = apply_revision_migrations
    else:
        source, module, table, value = (
            SETTINGS_PATH,
            "aweb_secrets_change_policy",
            "change_set_settings",
            "revision",
        )
        upgrade = apply_change_policy_migrations
    await _legacy(db, tmp_path, source, module, 1)
    await db.execute(
        f"INSERT INTO {{{{tables.{table}}}}} (installation_id,{value}) VALUES ($1,7)", INSTALLATION
    )
    # Use the real legacy records schema as retained team attribution evidence.
    await _legacy(db, tmp_path, MIGRATIONS_PATH, MODULE_NAME, 7)
    if evidence != "missing":
        await db.execute(
            "INSERT INTO {{tables.secrets}} (secret_id,installation_id,team_id,ref,record) VALUES ($1,$2,$3,$4,$5)",
            SECRET.secret_id,
            INSTALLATION,
            TEAM,
            SECRET.ref,
            json.dumps(SECRET.after),
        )
    if evidence == "ambiguous":
        await db.execute(
            "INSERT INTO {{tables.secrets}} (secret_id,installation_id,team_id,ref,record) VALUES ($1,$2,$3,$4,$5)",
            "sec_other_team",
            INSTALLATION,
            "other:acme.com",
            "other-ref",
            json.dumps(SECRET.after),
        )
    if evidence == "unique":
        await upgrade(db)
        row = await db.fetch_one(
            f"SELECT team_id,{value} FROM {{{{tables.{table}}}}} WHERE installation_id=$1",
            INSTALLATION,
        )
        assert row["team_id"] == TEAM and row[value] == 7
    else:
        with pytest.raises(Exception, match="missing or ambiguous team attribution"):
            await upgrade(db)
        # Failed migration rolls back the schema and retains the legacy row.
        assert (
            await db.fetch_value(
                f"SELECT {value} FROM {{{{tables.{table}}}}} WHERE installation_id=$1", INSTALLATION
            )
            == 7
        )


async def test_legacy_record_keys_retain_their_evidenced_team(test_db_factory, tmp_path):
    db = await test_db_factory.create_db(suffix="records_team_upgrade")
    await _legacy(db, tmp_path, MIGRATIONS_PATH, MODULE_NAME, 7)
    await db.execute(
        "INSERT INTO {{tables.secrets}} (secret_id,installation_id,team_id,ref,record) VALUES ($1,$2,$3,$4,$5)",
        SECRET.secret_id,
        INSTALLATION,
        TEAM,
        SECRET.ref,
        json.dumps(SECRET.after),
    )
    await db.execute(
        "INSERT INTO {{tables.policies}} (installation_id,digest,body) VALUES ($1,$2,$3)",
        INSTALLATION,
        POLICY.digest,
        json.dumps(dict(POLICY.body)),
    )
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    assert (
        await db.fetch_value(
            "SELECT team_id FROM {{tables.policies}} WHERE installation_id=$1", INSTALLATION
        )
        == TEAM
    )
    assert await db.fetch_value(
        "SELECT body FROM {{tables.policies}} WHERE installation_id=$1", INSTALLATION
    ) == json.dumps(dict(POLICY.body))
