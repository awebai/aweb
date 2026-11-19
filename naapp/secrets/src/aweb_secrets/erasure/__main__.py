"""Offline erasure initialization and identifier-only operator receipts."""

import argparse
import asyncio
import json
import logging
from dataclasses import asdict
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote

from aweb_naapp.key_file import read_key_file
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from .errors import ErasureUnavailable
from .initialize import backup_age_seconds, initialize_erasure_store, quoted_identifier
from .store import operator_receipts


class Command(StrEnum):
    INITIALISE = "init-erasure"
    RECEIPTS = "receipts"


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("command", type=Command, choices=list(Command))
    credential = command.add_mutually_exclusive_group(required=True)
    credential.add_argument("--operator-dsn-file", type=Path)
    credential.add_argument("--bundled-password-file", type=Path)
    command.add_argument("--content-schema", default="public")
    command.add_argument("--application-role")
    command.add_argument("--max-backup-age-seconds", type=int)
    return command


async def run(arguments: argparse.Namespace) -> None:
    quoted_identifier(arguments.content_schema)
    if arguments.command is Command.INITIALISE:
        if arguments.application_role is None or arguments.max_backup_age_seconds is None:
            raise ValueError(
                "init-erasure requires --application-role and --max-backup-age-seconds"
            )
        quoted_identifier(arguments.application_role)
        backup_age_seconds(timedelta(seconds=arguments.max_backup_age_seconds))
    # The connection string is read from protected input, never argv or output.
    if arguments.operator_dsn_file is not None:
        dsn = read_key_file(arguments.operator_dsn_file).decode("utf-8").strip()
    else:
        # Only the one-shot bundled operator container mounts this password.
        # Externally managed PostgreSQL always takes the operator's DSN file.
        password = read_key_file(arguments.bundled_password_file).decode("utf-8").rstrip("\n")
        dsn = f"postgresql://postgres:{quote(password, safe='')}@postgres:5432/secrets"
    db = AsyncDatabaseManager(
        DatabaseConfig(
            connection_string=dsn,
            schema=arguments.content_schema,
            min_connections=1,
            max_connections=2,
        )
    )
    await db.connect()
    try:
        if arguments.command is Command.INITIALISE:
            identity = await initialize_erasure_store(
                db,
                application_role=arguments.application_role,
                max_backup_age=timedelta(seconds=arguments.max_backup_age_seconds),
            )
            print(json.dumps({"erasure_store_identity": str(identity), "result": "initialised"}))
        else:
            for receipt in await operator_receipts(db):
                print(
                    json.dumps({**asdict(receipt), "explanation": receipt.explanation}, default=str)
                )
    finally:
        await db.disconnect()


def main() -> None:
    arguments = parser().parse_args()
    # Third-party connection diagnostics can contain credential-bearing DSNs.
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(run(arguments))
    except ErasureUnavailable as refusal:
        raise SystemExit(f"{refusal.code}: {refusal}") from None
    except ValueError:
        raise SystemExit(
            "Invalid erasure operator arguments; check the role, schema and backup lifetime."
        ) from None
    except Exception:
        # Refuse, without printing a DSN, SQL parameters or a credential file.
        raise SystemExit(
            "Erasure operation failed. Keep Secrets stopped and check operator database access."
        ) from None


if __name__ == "__main__":
    main()
