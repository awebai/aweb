"""Load captured pre-cutover data, only into the real pre-cutover schema."""

import base64
import json
from datetime import datetime
from pathlib import Path

from pgdbm import AsyncMigrationManager

from aweb_secrets.owners import MIGRATIONS_MODULE, MIGRATIONS_PATH

TABLES = (
    "owner_act_nonces",
    "role_assignments",
    "owner_principals",
    "installation_fences",
    "passkey_approvers",
    "passkey_owner_acts",
    "passkey_enrolments",
    "passkey_credentials",
    "passkey_challenges",
    "credential_authorizations",
    "credential_completion_links",
    "credential_audit_events",
)


def decoded(value):
    if isinstance(value, dict) and set(value) == {"datetime"}:
        return datetime.fromisoformat(value["datetime"])
    if isinstance(value, dict) and set(value) == {"base64"}:
        return base64.b64decode(value["base64"], validate=True)
    return value


async def load_owner_history(world, *, mixed_key=False):
    name = "legacy-mixed-key.json" if mixed_key else "legacy-human.json"
    source = Path(__file__).parent / "fixtures" / "owner_holding_cutover" / name
    fixture = json.loads(source.read_text())
    assert fixture["format"] == "aweb.secrets.owner-cutover-fixture/1"
    assert tuple(fixture["tables"]) == TABLES
    manager = AsyncMigrationManager(
        world.db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    )
    assert list(await manager.get_applied_migrations()) == ["001_owner_principals.sql"]
    async with world.db.transaction() as tx:
        # This fixture's fresh installation was admitted before the history load;
        # the captured installation row is the historical input being tested.
        await tx.execute("DELETE FROM {{tables.installation_fences}}")
        for table in TABLES:
            for row in fixture["tables"][table]:
                columns = list(row)
                # All identifiers come from this checked-in, fixed-table data.
                assert all(c.replace("_", "").isalnum() for c in columns)
                identity = " OVERRIDING SYSTEM VALUE" if table == "credential_audit_events" else ""
                await tx.execute(
                    "INSERT INTO {{tables."
                    + table
                    + "}} ("
                    + ",".join(columns)
                    + ")"
                    + identity
                    + " VALUES ("
                    + ",".join(f"${i}" for i in range(1, len(row) + 1))
                    + ")",
                    *(decoded(row[c]) for c in columns),
                )
        # A captured public assertion answers its original real challenge. Only
        # that ephemeral challenge's expiry is moved; signed inputs are intact.
        await tx.execute(
            "UPDATE {{tables.passkey_challenges}} SET expires_at=clock_timestamp()+interval '5 minutes'"
            " WHERE purpose='login' AND used_at IS NULL"
        )
        for table, column in (
            ("passkey_challenges", "issued_seq"),
            ("credential_audit_events", "event_id"),
        ):
            await tx.execute(
                "SELECT setval(pg_get_serial_sequence('{{tables." + table + "}}', $1),"
                " (SELECT max(" + column + ") FROM {{tables." + table + "}}))",
                column,
            )
    await world.console.fence.refresh(fixture["team_id"])
    return fixture
