"""The registry operator's explicit protection of one team.

Runs inside the registry's own container with its AWID_DATABASE_URL and
AWID_DB_SCHEMA, and calls the registry host's administrator transition
(awid_service.protected_teams.provision_team_protection, which has no HTTP
route) in one transaction, as HOST.md describes. The team must exist and must
never have been protected: the transition is made from generation 0. Prints
the binding it recorded, which names only public values.

  protect_team.py --domain D --name N --service-id S --service-did-key K --approval-ref R
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from awid.db_config import build_database_config
from awid_service.protected_teams import provision_team_protection
from pgdbm import AsyncDatabaseManager


async def protect(args: argparse.Namespace) -> dict:
    db = AsyncDatabaseManager(build_database_config(connection_string=os.environ["AWID_DATABASE_URL"],
                                                    schema=os.environ.get("AWID_DB_SCHEMA") or "awid",
                                                    min_connections=1, max_connections=1))
    await db.connect()
    try:
        async with db.transaction() as tx:
            return await provision_team_protection(
                tx, domain=args.domain, name=args.name, service_id=args.service_id,
                service_did_key=args.service_did_key, expected_generation=0, approval_ref=args.approval_ref)
    finally:
        await db.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("--domain", "--name", "--service-id", "--service-did-key", "--approval-ref"):
        parser.add_argument(name, required=True)
    json.dump(asyncio.run(protect(parser.parse_args())), sys.stdout, default=str)


if __name__ == "__main__":
    main()
