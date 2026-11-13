"""What the protected signer signed, read from its own database.

Runs inside the signer's container, as its process uid, with the host's own
AWEB_PROTECTED_* settings. Read only: each operation's stored outcome,
whether it holds a signed result, and its refusal code. The round trip uses it
as evidence that nothing it must not sign was signed. Each operation also
names its expiry and the nonce its request froze at prepare; a signed one names
the act it signed, by H, the SHA-256 of the exact signing bytes, and by that
act's nonce. It prints neither the signing bytes nor the signature.

  evidence.py --operation-id ID [--operation-id ID ...]
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import sys

from aweb.protected_signing.host import HostSettings
from awid.db_config import build_database_config
from pgdbm import AsyncDatabaseManager

# The owner-act signing prefix (naapp-lib hooks/owner_act.py PREFIX).
OWNER_ACT_PREFIX = b"aweb.owner-act/1\n"


def signed_act(result: str | dict) -> dict:
    """The act a stored result signs: H over the decoded signing bytes, and
    the act's nonce."""
    fields = json.loads(result) if isinstance(result, str) else result
    signing = base64.b64decode(fields["signing"], validate=True)
    if not signing.startswith(OWNER_ACT_PREFIX):
        raise SystemExit("the stored result does not sign an owner act")
    return {"act_sha256": hashlib.sha256(signing).hexdigest(),
            "nonce": json.loads(signing[len(OWNER_ACT_PREFIX):])["nonce"]}


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
            "SELECT operation_id, result IS NOT NULL AS signed, refusal_code, result, request, expires_at "
            "FROM {{tables.protected_signer_operations}} WHERE operation_id = ANY($1::text[])",
            operation_ids,
        )
    finally:
        await db.disconnect()
    return {
        row["operation_id"]: {
            "signed": row["signed"],
            "refusal_code": row["refusal_code"],
            "expires_at": row["expires_at"].isoformat(),
            "frozen_nonce": json.loads(bytes(row["request"]))["artifact"]["nonce"],
            **(signed_act(row["result"]) if row["signed"] else {}),
        }
        for row in rows
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--operation-id", action="append", required=True)
    args = parser.parse_args()
    json.dump(asyncio.run(evidence(args.operation_id)), sys.stdout)


if __name__ == "__main__":
    main()
