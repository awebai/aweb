#!/usr/bin/env python3
"""Store team-signed attestation records in a real AWID fixture's database.

aw cannot publish these records: their routes take the covering (v2) controller
envelope, which the Go client does not sign. Go tests that need stored records
(aw's team-key rotation) put them here instead. The records are real signed
records; AWID's rotation verifies them exactly as it would published ones. The
publish routes themselves are tested in awid/tests.

Input on stdin, JSON: {"domain", "name", "certificates": [{"certificate_id",
"member_did_key", "alias"}], "records": [{"kind", "record", "signature"}]},
where kind is team_custodians, member_custody or member_person. Certificates
are optional: they let a test hold more members than the production
certificate_register limit allows it to register.
Environment: AWID_DATABASE_URL and AWID_DB_SCHEMA, from awid_fixture.py's
second stdout line. Run with the awid project's environment.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import asyncpg

from awid.signing import canonical_json_bytes

KEY_COLUMNS = {
    "team_custodians": ("custodian_id",),
    "member_custody": ("certificate_id", "custodian_id"),
    "member_person": ("certificate_id", "single_person"),
}


def issued_at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


async def seed(payload: dict) -> None:
    schema = os.environ["AWID_DB_SCHEMA"]
    if not schema.isidentifier():
        raise SystemExit("AWID_DB_SCHEMA must be a plain identifier")
    conn = await asyncpg.connect(os.environ["AWID_DATABASE_URL"])
    try:
        team_uuid = await conn.fetchval(
            f"SELECT team_uuid FROM {schema}.teams WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
            payload["domain"], payload["name"],
        )
        if team_uuid is None:
            raise SystemExit("team not found")
        for certificate in payload.get("certificates") or []:
            await conn.execute(
                f"INSERT INTO {schema}.team_certificates (team_uuid, certificate_id, member_did_key, alias, identity_scope)"
                " VALUES ($1, $2, $3, $4, 'local')",
                team_uuid, certificate["certificate_id"], certificate["member_did_key"], certificate["alias"],
            )
        for entry in payload.get("records") or []:
            kind, record = entry["kind"], entry["record"]
            columns = KEY_COLUMNS[kind]
            names = ", ".join(("team_uuid", *columns, "record_json", "signature", "team_did_key", "issued_at"))
            values = ", ".join(f"${index}" for index in range(1, len(columns) + 6))
            await conn.execute(
                f"INSERT INTO {schema}.{kind} ({names}) VALUES ({values})",
                team_uuid, *(record[column] for column in columns),
                canonical_json_bytes(record).decode("utf-8"), entry["signature"],
                record["team_did_key"], issued_at(record["issued_at"]),
            )
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(seed(json.load(sys.stdin)))
