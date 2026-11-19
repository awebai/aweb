"""Deliberate pre-cutover data capture, never part of normal test collection.

Run only at the recorded pre-cutover source head, in an authorised private PG
fixture. The output contains public credential material and signed LOGIN
answers, never authenticator private keys or plaintext enrolment tokens.
"""

import base64
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

import pytest
from aweb_naapp.roles import PrincipalKey
from aweb_naapp_testing import did_key

from aweb_secrets.owners import MIGRATIONS_PATH
from tests.test_owner_bootstrap import ALICE, BOB, TEAM, _apply, _enrol
from tests.test_owner_bootstrap import world as world  # noqa: F401

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


def encoded(value):
    if isinstance(value, datetime):
        return {"datetime": value.isoformat()}
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    return value


@pytest.mark.parametrize("mixed_key", [False, True], ids=["human", "mixed-key"])
async def test_capture_pre_cutover_owner_data(world, mixed_key):
    if os.environ.get("OWNER_CUTOVER_WRITE_FIXTURES") != "1":
        pytest.fail("fixture capture must be requested explicitly")
    assert [p.name for p in MIGRATIONS_PATH.glob("*.sql")] == ["001_owner_principals.sql"], (
        "capture requires the genuine pre-cutover source; never run it after cutover"
    )
    second = PrincipalKey(TEAM, did_key(world.owner.team_key)) if mixed_key else BOB
    devices = {}
    for principal, contact in ((ALICE, "alice@example.com"), (second, "second@example.com")):
        designation = await _apply(world, "app-role.designate", principal, contact)
        devices[designation.approver.scope] = await _enrol(world, contact)
    # Keep public signed answers to real outstanding LOGIN challenges. Tests
    # can verify the old credential after upgrade without retaining private keys.
    answers = {
        scope: device.get(await world.passkeys.login_options(scope))
        for scope, device in devices.items()
    }
    tables = {}
    for table in TABLES:
        rows = await world.db.fetch_all("SELECT * FROM {{tables." + table + "}}")
        tables[table] = [{key: encoded(value) for key, value in dict(row).items()} for row in rows]
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=MIGRATIONS_PATH, text=True
    ).strip()
    fixture = {
        "format": "aweb.secrets.owner-cutover-fixture/1",
        "source_sha": source,
        "generator_command": (
            "OWNER_CUTOVER_WRITE_FIXTURES=1 uv run --frozen --no-sync --with pytest-xdist "
            "pytest -n 2 --dist loadscope --assert=plain -q "
            "tests/fixtures/owner_holding_cutover/generate.py"
        ),
        "owner_migrations_through": "001_owner_principals.sql",
        "team_id": TEAM,
        "login_assertions": answers,
        "tables": tables,
    }
    name = "legacy-mixed-key.json" if mixed_key else "legacy-human.json"
    Path(__file__).with_name(name).write_text(json.dumps(fixture, indent=2) + "\n")
