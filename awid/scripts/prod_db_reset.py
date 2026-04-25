#!/usr/bin/env python3
"""Production awid registry DB lifecycle: dump, drop schema, migrate, restore, verify.

The awid registry uses a single consolidated migration file
(`001_registry.sql`). When schema changes land in that file in-place,
pgdbm's checksum guard refuses to start the service. Recovery path is to
dump data, drop the schema, run the new migration from scratch, and
restore the data.

This script encodes that path. Subcommands:

    dump            pg_dump --data-only --column-inserts --schema=<S>
    drop-schema     DROP SCHEMA <S> CASCADE
    migrate         AwidDatabaseInfra(schema=<S>).initialize(run_migrations=True)
    restore         psql < dump
    verify          report row counts per table
    reset           dump -> drop-schema -> migrate -> restore -> verify

The default `--env-file` is `aweb/.env.awid-production`, which contains
`AWID_DATABASE_URL` and `AWID_DB_SCHEMA=awid`.

Use `--column-inserts` for the dump so we can restore into a schema with
additional NULLABLE columns (e.g. `team_certificates.certificate` added
in 0.5.x).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


AWID_TABLES = [
    "did_aw_mappings",
    "did_aw_log",
    "dns_namespaces",
    "public_addresses",
    "replacement_announcements",
    "teams",
    "team_certificates",
]


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise SystemExit(f"env file not found: {path}")

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        values[key] = value
    return values


def _config_from_env(env_file: Path) -> tuple[str, str]:
    values = _load_env_file(env_file)
    database_url = (
        values.get("AWID_DATABASE_URL")
        or values.get("DATABASE_URL")
        or os.environ.get("AWID_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
    )
    if not database_url:
        raise SystemExit(
            f"AWID_DATABASE_URL not found in {env_file} or environment"
        )
    schema = (
        values.get("AWID_DB_SCHEMA")
        or os.environ.get("AWID_DB_SCHEMA")
        or "awid"
    ).strip() or "awid"
    return database_url, schema


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    env: Optional[dict[str, str]] = None,
    stdin: Optional[str] = None,
) -> subprocess.CompletedProcess[str]:
    display = " ".join(shlex.quote(part) for part in cmd)
    print(f"+ {display}", flush=True)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        input=stdin,
        text=True,
        check=True,
    )


def _psql_query(*, database_url: str, sql: str) -> str:
    result = subprocess.run(
        ["psql", "-At", "-v", "ON_ERROR_STOP=1", database_url, "-c", sql],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


# Sanitize dumps for restore:
#   - pg_dump 17+ emits `SET transaction_timeout = 0;` which PG 16 servers
#     (Neon prod, the awid-up local stack) reject as unknown parameter.
#   - The drop-and-migrate step rebuilds `schema_migrations` from the new
#     migration file. Restoring the dumped rows would either collide on the
#     primary key or pin an old checksum that pgdbm would reject on next boot.
#     Strip schema_migrations DML so the freshly-applied migration record
#     remains canonical.
_INCOMPATIBLE_SET_PREFIXES = (
    "SET transaction_timeout",
)


def _is_schema_migrations_dml(line: str, schema: str) -> bool:
    head = line.lstrip()
    qualified = f"{schema}.schema_migrations"
    if head.startswith(f"INSERT INTO {qualified}"):
        return True
    if head.startswith("SELECT pg_catalog.setval(") and "schema_migrations_id_seq" in head:
        return True
    return False


def _sanitize_dump_in_place(path: Path, *, schema: str) -> None:
    text = path.read_text(encoding="utf-8")
    kept: list[str] = []
    stripped_set = 0
    stripped_migrations = 0
    for line in text.splitlines(keepends=True):
        head = line.lstrip()
        if any(head.startswith(prefix) for prefix in _INCOMPATIBLE_SET_PREFIXES):
            stripped_set += 1
            continue
        if _is_schema_migrations_dml(line, schema):
            stripped_migrations += 1
            continue
        kept.append(line)
    if stripped_set or stripped_migrations:
        path.write_text("".join(kept), encoding="utf-8")
        if stripped_set:
            print(
                f"Sanitized dump: stripped {stripped_set} forward-only SET line(s)",
                flush=True,
            )
        if stripped_migrations:
            print(
                f"Sanitized dump: stripped {stripped_migrations} schema_migrations DML line(s)",
                flush=True,
            )


def _row_counts(*, database_url: str, schema: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in AWID_TABLES:
        sql = (
            f"SELECT COUNT(*) FROM {_quote_ident(schema)}.{_quote_ident(table)};"
        )
        try:
            out = _psql_query(database_url=database_url, sql=sql).strip()
            counts[table] = int(out) if out else 0
        except subprocess.CalledProcessError:
            counts[table] = -1  # table missing
    return counts


def _print_counts(label: str, counts: dict[str, int]) -> None:
    print(f"\n{label}", flush=True)
    print("-" * len(label), flush=True)
    width = max(len(t) for t in counts)
    for table, count in counts.items():
        marker = "(missing)" if count < 0 else ""
        print(f"  {table:<{width}}  {count:>10} {marker}", flush=True)
    print("", flush=True)


def cmd_dump(args: argparse.Namespace) -> None:
    database_url, schema = _config_from_env(args.env_file)
    output = args.output
    if output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = Path(f"/tmp/awid-{schema}-{ts}.sql")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    pre_counts = _row_counts(database_url=database_url, schema=schema)
    _print_counts("Row counts before dump", pre_counts)

    _run(
        [
            "pg_dump",
            "--data-only",
            "--column-inserts",
            "--no-owner",
            "--no-privileges",
            f"--schema={schema}",
            "--file",
            str(output),
            database_url,
        ],
        cwd=Path.cwd(),
    )
    _sanitize_dump_in_place(output, schema=schema)
    print(f"\nDump written: {output}", flush=True)
    print(f"Size: {output.stat().st_size:,} bytes", flush=True)


def cmd_drop_schema(args: argparse.Namespace) -> None:
    database_url, schema = _config_from_env(args.env_file)
    if not args.yes:
        raise SystemExit(
            f"refusing to DROP SCHEMA {schema} CASCADE without --yes"
        )
    print(
        f"DROP SCHEMA {_quote_ident(schema)} CASCADE on {_redact_url(database_url)}",
        flush=True,
    )
    _run(
        [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            database_url,
            "-c",
            f"DROP SCHEMA IF EXISTS {_quote_ident(schema)} CASCADE;",
        ],
        cwd=Path.cwd(),
    )
    print(f"Schema {schema} dropped", flush=True)


def cmd_migrate(args: argparse.Namespace) -> None:
    database_url, schema = _config_from_env(args.env_file)
    print(
        f"Running awid migrations against {_redact_url(database_url)} (schema={schema})",
        flush=True,
    )
    asyncio.run(_run_migrations(database_url=database_url, schema=schema))
    print("Migrations applied", flush=True)


async def _run_migrations(*, database_url: str, schema: str) -> None:
    os.environ["AWID_DATABASE_URL"] = database_url
    os.environ["AWID_DB_SCHEMA"] = schema
    from awid_service.db import AwidDatabaseInfra

    infra = AwidDatabaseInfra(schema=schema)
    await infra.initialize(run_migrations=True)
    await infra.close()


def cmd_restore(args: argparse.Namespace) -> None:
    database_url, schema = _config_from_env(args.env_file)
    dump = args.dump.resolve()
    if not dump.exists():
        raise SystemExit(f"dump file not found: {dump}")

    print(
        f"Restoring {dump} into {_redact_url(database_url)} (schema={schema})",
        flush=True,
    )
    _sanitize_dump_in_place(dump, schema=schema)
    _run(
        [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            str(dump),
            database_url,
        ],
        cwd=Path.cwd(),
    )
    counts = _row_counts(database_url=database_url, schema=schema)
    _print_counts("Row counts after restore", counts)


def cmd_verify(args: argparse.Namespace) -> None:
    database_url, schema = _config_from_env(args.env_file)
    counts = _row_counts(database_url=database_url, schema=schema)
    _print_counts(f"Row counts (schema={schema})", counts)


def cmd_reset(args: argparse.Namespace) -> None:
    """Orchestrate dump -> drop-schema -> migrate -> restore -> verify."""
    if not args.yes:
        raise SystemExit("refusing to reset without --yes")

    database_url, schema = _config_from_env(args.env_file)
    pre_counts = _row_counts(database_url=database_url, schema=schema)
    _print_counts("Row counts BEFORE reset", pre_counts)

    output = args.output
    if output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = Path(f"/tmp/awid-{schema}-reset-{ts}.sql")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    print("\n=== Step 1/4: dump ===", flush=True)
    _run(
        [
            "pg_dump",
            "--data-only",
            "--column-inserts",
            "--no-owner",
            "--no-privileges",
            f"--schema={schema}",
            "--file",
            str(output),
            database_url,
        ],
        cwd=Path.cwd(),
    )
    _sanitize_dump_in_place(output, schema=schema)
    print(f"Dump written: {output} ({output.stat().st_size:,} bytes)", flush=True)

    print("\n=== Step 2/4: drop schema ===", flush=True)
    _run(
        [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            database_url,
            "-c",
            f"DROP SCHEMA IF EXISTS {_quote_ident(schema)} CASCADE;",
        ],
        cwd=Path.cwd(),
    )

    print("\n=== Step 3/4: migrate ===", flush=True)
    asyncio.run(_run_migrations(database_url=database_url, schema=schema))

    print("\n=== Step 4/4: restore ===", flush=True)
    _run(
        [
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            str(output),
            database_url,
        ],
        cwd=Path.cwd(),
    )

    post_counts = _row_counts(database_url=database_url, schema=schema)
    _print_counts("Row counts AFTER reset", post_counts)

    mismatches = []
    for table, before in pre_counts.items():
        after = post_counts.get(table, -1)
        if before < 0:
            continue  # table didn't exist before; new in this migration
        if after != before:
            mismatches.append(f"{table}: before={before} after={after}")

    if mismatches:
        print("ROW COUNT MISMATCHES:", file=sys.stderr)
        for m in mismatches:
            print(f"  - {m}", file=sys.stderr)
        raise SystemExit(1)

    print(f"\nReset complete. Dump preserved at {output}", flush=True)


def _redact_url(url: str) -> str:
    if "@" not in url:
        return url
    head, tail = url.split("@", 1)
    if "://" not in head:
        return f"***@{tail}"
    scheme = head.split("://", 1)[0]
    return f"{scheme}://***@{tail}"


def parse_args() -> argparse.Namespace:
    default_env = (
        Path(__file__).resolve().parents[2] / ".env.awid-production"
    )

    parser = argparse.ArgumentParser(
        description="awid registry production DB lifecycle helpers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_env(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--env-file",
            type=Path,
            default=default_env,
            help=f"env file with AWID_DATABASE_URL (default: {default_env})",
        )

    p_dump = sub.add_parser("dump", help="Dump data only (--column-inserts).")
    add_env(p_dump)
    p_dump.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output file (default: /tmp/awid-<schema>-<timestamp>.sql)",
    )

    p_drop = sub.add_parser("drop-schema", help="DROP SCHEMA <schema> CASCADE.")
    add_env(p_drop)
    p_drop.add_argument(
        "--yes",
        action="store_true",
        help="confirm destructive drop",
    )

    p_mig = sub.add_parser("migrate", help="Apply pending awid migrations.")
    add_env(p_mig)

    p_res = sub.add_parser("restore", help="psql -f <dump> against the target.")
    add_env(p_res)
    p_res.add_argument("--dump", type=Path, required=True)

    p_ver = sub.add_parser("verify", help="Print row counts per awid table.")
    add_env(p_ver)

    p_rst = sub.add_parser(
        "reset",
        help="Orchestrate dump -> drop-schema -> migrate -> restore -> verify.",
    )
    add_env(p_rst)
    p_rst.add_argument(
        "--output",
        type=Path,
        default=None,
        help="dump file path (default: /tmp/awid-<schema>-reset-<timestamp>.sql)",
    )
    p_rst.add_argument(
        "--yes",
        action="store_true",
        help="confirm destructive reset",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    handlers = {
        "dump": cmd_dump,
        "drop-schema": cmd_drop_schema,
        "migrate": cmd_migrate,
        "restore": cmd_restore,
        "verify": cmd_verify,
        "reset": cmd_reset,
    }
    handler = handlers.get(args.command)
    if handler is None:
        raise SystemExit(f"unknown command: {args.command}")
    handler(args)


if __name__ == "__main__":
    main()
