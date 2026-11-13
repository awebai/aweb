"""What the protected signer signed, read from its own database.

Runs inside the signer's container, as its process uid, with the host's own
AWEB_PROTECTED_* settings. Read only: each operation's stored outcome,
whether it holds a signed result, and its refusal code. The round trip uses it
as evidence that nothing it must not sign was signed.

  evidence.py --operation-id ID [--operation-id ID ...]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from aweb.protected_signing.host import HostSettings
from awid.db_config import build_database_config
from pgdbm import AsyncDatabaseManager


async def evidence(operation_ids: list[str]) -> dict:
    settings = HostSettings()
    db = AsyncDatabaseManager(
        build_database_config(
            connection_string=settings.database_url.get_secret_value(),
            schema=settings.database_schema,
            min_connections=1,
            max_connections=1,
        )
    )
    await db.connect()
    try:
        rows = await db.fetch_all(
            "SELECT operation_id, result IS NOT NULL AS signed, refusal_code "
            "FROM {{tables.protected_signer_operations}} WHERE operation_id = ANY($1::text[])",
            operation_ids,
        )
    finally:
        await db.disconnect()
    return {row["operation_id"]: {"signed": row["signed"], "refusal_code": row["refusal_code"]} for row in rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--operation-id", action="append", required=True)
    args = parser.parse_args()
    json.dump(asyncio.run(evidence(args.operation_id)), sys.stdout)


if __name__ == "__main__":
    main()
