#!/usr/bin/env python3
"""One-time, manifest-bound AWID hosted namespace controller alignment.

This operator script talks directly to PostgreSQL.  It scans AWID's complete
active direct-child ``*.aweb.ai`` universe, then requires every row to be
present in the reviewed, canonical manifest supplied by AC before it may update
anything.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import asyncpg

from awid.did import validate_did


BASE_DOMAIN = "aweb.ai"
MANIFEST_KEYS = {
    "schema_version",
    "base_domain",
    "expected_count",
    "target_controller_did",
    "targets",
}
TARGET_KEYS = {
    "domain",
    "expected_old_controller_did",
    "new_controller_did",
}
BACKUP_KEYS = {
    "schema_version",
    "kind",
    "database_schema",
    "manifest_sha256",
    "base_domain",
    "expected_count",
    "expected_present_count",
    "target_controller_did",
    "absent_domains",
    "rows",
}
BACKUP_KIND = "awid_dns_namespaces_controller_before_image"
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class AlignmentError(RuntimeError):
    """A fail-closed validation or alignment error."""


@dataclass(frozen=True)
class Target:
    domain: str
    old_controller_did: str
    new_controller_did: str


@dataclass(frozen=True)
class Manifest:
    sha256: str
    base_domain: str
    expected_count: int
    target_controller_did: str
    targets: tuple[Target, ...]


@dataclass(frozen=True)
class DatabaseState:
    rows: tuple[dict[str, Any], ...]
    absent_domains: tuple[str, ...]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlignmentError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _parse_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise AlignmentError(f"{label} must have exactly one terminal newline")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlignmentError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise AlignmentError(f"{label} must be a JSON object")
    if _canonical_bytes(value) != raw:
        raise AlignmentError(
            f"{label} is not canonical JSON (sorted keys, compact separators, terminal newline)"
        )
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise AlignmentError(f"{label} keys mismatch: missing={missing} extra={extra}")


def _require_did(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not validate_did(value):
        raise AlignmentError(f"{label} must be a canonical did:key value")
    return value


def _validate_direct_child(domain: Any, base_domain: str) -> str:
    if not isinstance(domain, str):
        raise AlignmentError("target domain must be a string")
    suffix = f".{base_domain}"
    if not domain.endswith(suffix):
        raise AlignmentError(f"target is not under {base_domain}: {domain}")
    child = domain[: -len(suffix)]
    if LABEL_RE.fullmatch(child) is None:
        raise AlignmentError(f"target is not a canonical direct child: {domain}")
    return domain


def load_manifest(
    path: Path,
    *,
    required_sha256: str,
    required_count: int,
    required_parent_controller_did: str,
) -> Manifest:
    if SHA256_RE.fullmatch(required_sha256) is None:
        raise AlignmentError("--manifest-sha256 must be 64 lowercase hex characters")
    raw = path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != required_sha256:
        raise AlignmentError(
            f"manifest SHA-256 mismatch: expected {required_sha256}, got {actual_sha256}"
        )
    value = _parse_canonical_json(raw, label="manifest")
    _require_exact_keys(value, MANIFEST_KEYS, label="manifest")

    if value["schema_version"] != 1:
        raise AlignmentError("manifest schema_version must be 1")
    if value["base_domain"] != BASE_DOMAIN:
        raise AlignmentError(f"manifest base_domain must be {BASE_DOMAIN}")
    count = value["expected_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise AlignmentError("manifest expected_count must be a positive integer")
    if count != required_count:
        raise AlignmentError(
            f"manifest count mismatch: expected {required_count}, manifest has {count}"
        )
    parent_did = _require_did(
        value["target_controller_did"], label="manifest target_controller_did"
    )
    required_did = _require_did(
        required_parent_controller_did,
        label="--expected-parent-controller-did",
    )
    if parent_did != required_did:
        raise AlignmentError("manifest target controller does not match required parent DID")

    raw_targets = value["targets"]
    if not isinstance(raw_targets, list):
        raise AlignmentError("manifest targets must be a list")
    if len(raw_targets) != count:
        raise AlignmentError(
            f"manifest target length mismatch: expected {count}, got {len(raw_targets)}"
        )

    targets: list[Target] = []
    for index, item in enumerate(raw_targets):
        if not isinstance(item, dict):
            raise AlignmentError(f"target {index} must be an object")
        _require_exact_keys(item, TARGET_KEYS, label=f"target {index}")
        domain = _validate_direct_child(item["domain"], BASE_DOMAIN)
        old_did = _require_did(
            item["expected_old_controller_did"],
            label=f"target {domain} expected_old_controller_did",
        )
        new_did = _require_did(
            item["new_controller_did"],
            label=f"target {domain} new_controller_did",
        )
        if new_did != parent_did:
            raise AlignmentError(f"target {domain} new controller differs from parent DID")
        if old_did == new_did:
            raise AlignmentError(f"target {domain} old and new controllers must differ")
        targets.append(Target(domain, old_did, new_did))

    domains = [target.domain for target in targets]
    if domains != sorted(domains):
        raise AlignmentError("manifest targets must be sorted by domain")
    if len(set(domains)) != len(domains):
        raise AlignmentError("manifest target domains must be unique")

    return Manifest(
        sha256=actual_sha256,
        base_domain=BASE_DOMAIN,
        expected_count=count,
        target_controller_did=parent_did,
        targets=tuple(targets),
    )


def _table(schema: str) -> str:
    if IDENT_RE.fullmatch(schema) is None:
        raise AlignmentError(f"invalid database schema name: {schema}")
    return f'"{schema}"."dns_namespaces"'


def _decode_rows(records: Iterable[asyncpg.Record]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        value = json.loads(record["row_json"])
        if not isinstance(value, dict):
            raise AlignmentError("database returned a non-object row")
        rows.append(value)
    return rows


async def _fetch_rows(
    connection: asyncpg.Connection,
    *,
    table: str,
    domains: list[str],
    lock: bool,
) -> list[dict[str, Any]]:
    lock_clause = " FOR UPDATE OF n" if lock else ""
    records = await connection.fetch(
        f"""
        SELECT row_to_json(n)::text AS row_json
        FROM {table} AS n
        WHERE n.domain = ANY($1::text[])
          AND n.deleted_at IS NULL
        ORDER BY n.domain
        {lock_clause}
        """,
        domains,
    )
    return _decode_rows(records)


async def _fetch_active_child_universe(
    connection: asyncpg.Connection,
    *,
    table: str,
    base_domain: str,
    lock: bool,
) -> list[dict[str, Any]]:
    lock_clause = " FOR UPDATE OF n" if lock else ""
    records = await connection.fetch(
        f"""
        SELECT row_to_json(n)::text AS row_json
        FROM {table} AS n
        WHERE n.domain ~ $1
          AND n.deleted_at IS NULL
        ORDER BY n.domain
        {lock_clause}
        """,
        rf"^[^.]+\.{re.escape(base_domain)}$",
    )
    return _decode_rows(records)


async def _validate_database_state(
    connection: asyncpg.Connection,
    *,
    table: str,
    manifest: Manifest,
    expected_present_count: int,
    lock: bool,
    required_controller: str,
) -> DatabaseState:
    parent_rows = await _fetch_rows(
        connection,
        table=table,
        domains=[manifest.base_domain],
        lock=lock,
    )
    if len(parent_rows) != 1:
        raise AlignmentError(
            f"expected exactly one active {manifest.base_domain} parent row, got {len(parent_rows)}"
        )
    parent = parent_rows[0]
    if parent.get("verification_status") != "verified":
        raise AlignmentError(f"{manifest.base_domain} parent is not verified")
    if parent.get("controller_did") != manifest.target_controller_did:
        raise AlignmentError(
            f"{manifest.base_domain} parent controller differs from target DID"
        )

    if (
        expected_present_count <= 0
        or expected_present_count > manifest.expected_count
    ):
        raise AlignmentError("expected present count must be within the manifest count")

    rows = await _fetch_active_child_universe(
        connection,
        table=table,
        base_domain=manifest.base_domain,
        lock=lock,
    )
    if len(rows) != expected_present_count:
        raise AlignmentError(
            "active child universe count mismatch: "
            f"expected {expected_present_count}, got {len(rows)}"
        )

    targets_by_domain = {target.domain: target for target in manifest.targets}
    rows_by_domain: dict[str, dict[str, Any]] = {}
    for row in rows:
        domain = row.get("domain")
        if not isinstance(domain, str) or domain in rows_by_domain:
            raise AlignmentError(
                f"database returned duplicate/invalid child domain: {domain}"
            )
        _validate_direct_child(domain, manifest.base_domain)
        if domain not in targets_by_domain:
            raise AlignmentError(f"active AWID child is absent from manifest: {domain}")
        if row.get("verification_status") != "verified":
            raise AlignmentError(f"active AWID child is not verified: {domain}")
        rows_by_domain[domain] = row

    for domain, row in rows_by_domain.items():
        target = targets_by_domain[domain]
        current = row.get("controller_did")
        expected = (
            target.old_controller_did
            if required_controller == "old"
            else target.new_controller_did
        )
        if required_controller == "either":
            if current not in {target.old_controller_did, target.new_controller_did}:
                raise AlignmentError(f"unexpected controller for {domain}: {current}")
        elif current != expected:
            raise AlignmentError(
                f"unexpected {required_controller} controller for {domain}: {current}"
            )

    absent_domains = tuple(sorted(set(targets_by_domain) - set(rows_by_domain)))
    expected_absent_count = manifest.expected_count - expected_present_count
    if len(absent_domains) != expected_absent_count:
        raise AlignmentError(
            "manifest/AWID partition mismatch: "
            f"expected {expected_absent_count} absent, got {len(absent_domains)}"
        )
    return DatabaseState(rows=tuple(rows), absent_domains=absent_domains)


def _result(
    command: str, manifest: Manifest, state: DatabaseState
) -> dict[str, Any]:
    by_domain = {target.domain: target for target in manifest.targets}
    aligned = sum(
        row["controller_did"] == by_domain[row["domain"]].new_controller_did
        for row in state.rows
    )
    return {
        "command": command,
        "manifest_sha256": manifest.sha256,
        "expected_count": manifest.expected_count,
        "present_count": len(state.rows),
        "absent_count": len(state.absent_domains),
        "present_domains_sha256": hashlib.sha256(
            _canonical_bytes([row["domain"] for row in state.rows])
        ).hexdigest(),
        "absent_domains_sha256": hashlib.sha256(
            _canonical_bytes(list(state.absent_domains))
        ).hexdigest(),
        "target_controller_did": manifest.target_controller_did,
        "already_aligned": aligned,
        "needs_alignment": len(state.rows) - aligned,
    }


def _backup_document(
    *,
    manifest: Manifest,
    schema: str,
    expected_present_count: int,
    state: DatabaseState,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": BACKUP_KIND,
        "database_schema": schema,
        "manifest_sha256": manifest.sha256,
        "base_domain": manifest.base_domain,
        "expected_count": manifest.expected_count,
        "expected_present_count": expected_present_count,
        "target_controller_did": manifest.target_controller_did,
        "absent_domains": list(state.absent_domains),
        "rows": list(state.rows),
    }


def _write_backup(path: Path, document: dict[str, Any]) -> str:
    if not path.parent.is_dir():
        raise AlignmentError(f"backup parent directory does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    raw = _canonical_bytes(document)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise AlignmentError(f"backup mode is {mode:o}, expected 600")
    return hashlib.sha256(raw).hexdigest()


def _load_backup(
    path: Path,
    *,
    required_sha256: str,
    manifest: Manifest,
    schema: str,
    expected_present_count: int,
) -> DatabaseState:
    if SHA256_RE.fullmatch(required_sha256) is None:
        raise AlignmentError("--backup-sha256 must be 64 lowercase hex characters")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise AlignmentError(f"backup mode is {mode:o}, expected 600")
    raw = path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != required_sha256:
        raise AlignmentError(
            f"backup SHA-256 mismatch: expected {required_sha256}, got {actual_sha256}"
        )
    value = _parse_canonical_json(raw, label="backup")
    _require_exact_keys(value, BACKUP_KEYS, label="backup")
    expected_metadata = {
        "schema_version": 1,
        "kind": BACKUP_KIND,
        "database_schema": schema,
        "manifest_sha256": manifest.sha256,
        "base_domain": manifest.base_domain,
        "expected_count": manifest.expected_count,
        "expected_present_count": expected_present_count,
        "target_controller_did": manifest.target_controller_did,
    }
    for key, expected in expected_metadata.items():
        if value[key] != expected:
            raise AlignmentError(f"backup {key} mismatch")
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) != expected_present_count:
        raise AlignmentError("backup row count mismatch")
    if not all(isinstance(row, dict) for row in rows):
        raise AlignmentError("backup rows must be objects")
    domains = [row.get("domain") for row in rows]
    if domains != sorted(domains) or len(set(domains)) != len(domains):
        raise AlignmentError("backup row domains must be sorted and unique")
    targets_by_domain = {target.domain: target for target in manifest.targets}
    if not set(domains).issubset(targets_by_domain):
        raise AlignmentError("backup contains a row absent from the manifest")
    absent_domains = value["absent_domains"]
    if (
        not isinstance(absent_domains, list)
        or not all(isinstance(domain, str) for domain in absent_domains)
        or absent_domains != sorted(absent_domains)
        or len(set(absent_domains)) != len(absent_domains)
    ):
        raise AlignmentError("backup absent domains must be a sorted unique list")
    if len(absent_domains) != manifest.expected_count - expected_present_count:
        raise AlignmentError("backup absent-domain count mismatch")
    manifest_domains = set(targets_by_domain)
    if set(domains).isdisjoint(absent_domains) is False:
        raise AlignmentError("backup present and absent domains overlap")
    if set(domains) | set(absent_domains) != manifest_domains:
        raise AlignmentError("backup partition does not exactly cover the manifest")
    for row in rows:
        target = targets_by_domain[row["domain"]]
        if (
            row.get("verification_status") != "verified"
            or row.get("deleted_at") is not None
        ):
            raise AlignmentError(
                f"backup row is not active and verified: {target.domain}"
            )
        if row.get("controller_did") != target.old_controller_did:
            raise AlignmentError(f"backup controller mismatch: {target.domain}")
    return DatabaseState(rows=tuple(rows), absent_domains=tuple(absent_domains))


def _assert_partition_unchanged(
    current: DatabaseState, backup: DatabaseState
) -> None:
    if current.absent_domains != backup.absent_domains:
        raise AlignmentError("AWID/manifest absent-domain partition changed since backup")
    if [row["domain"] for row in current.rows] != [
        row["domain"] for row in backup.rows
    ]:
        raise AlignmentError("AWID present-domain partition changed since backup")


def _assert_only_controller_may_differ(
    current_rows: list[dict[str, Any]],
    backup_rows: list[dict[str, Any]],
    *,
    manifest: Manifest,
    require_current_target: bool,
) -> None:
    current_by_domain = {row["domain"]: row for row in current_rows}
    targets_by_domain = {target.domain: target for target in manifest.targets}
    for backup in backup_rows:
        target = targets_by_domain[backup["domain"]]
        current = current_by_domain.get(target.domain)
        if current is None:
            raise AlignmentError(f"current row missing: {target.domain}")
        current_controller = current.get("controller_did")
        if require_current_target:
            if current_controller != target.new_controller_did:
                raise AlignmentError(
                    f"restore requires current target controller: {target.domain}"
                )
        elif current_controller not in {
            backup.get("controller_did"),
            target.new_controller_did,
        }:
            raise AlignmentError(
                f"current controller differs from backup/target: {target.domain}"
            )
        current_other = {
            key: value for key, value in current.items() if key != "controller_did"
        }
        backup_other = {
            key: value for key, value in backup.items() if key != "controller_did"
        }
        if current_other != backup_other:
            raise AlignmentError(
                f"non-controller columns changed since backup: {target.domain}"
            )


async def _set_controllers(
    connection: asyncpg.Connection,
    *,
    table: str,
    changes: list[dict[str, str]],
) -> set[str]:
    if not changes:
        return set()
    records = await connection.fetch(
        f"""
        UPDATE {table} AS n
        SET controller_did = change.new_controller_did
        FROM jsonb_to_recordset($1::jsonb) AS change(
            domain text,
            expected_controller_did text,
            new_controller_did text
        )
        WHERE n.domain = change.domain
          AND n.deleted_at IS NULL
          AND n.verification_status = 'verified'
          AND n.controller_did = change.expected_controller_did
        RETURNING n.domain
        """,
        json.dumps(changes, separators=(",", ":")),
    )
    return {record["domain"] for record in records}


async def run_operation(
    *,
    command: str,
    database_url: str,
    schema: str,
    manifest: Manifest,
    expected_present_count: int | None = None,
    backup_path: Path | None = None,
    backup_sha256: str | None = None,
) -> dict[str, Any]:
    if expected_present_count is None:
        expected_present_count = manifest.expected_count
    table = _table(schema)
    if (
        command in {"backup", "apply", "verify", "restore"}
        and backup_path is None
    ):
        raise AlignmentError(f"{command} requires --backup")
    if command in {"apply", "verify", "restore"} and backup_sha256 is None:
        raise AlignmentError(f"{command} requires --backup-sha256")
    connection = await asyncpg.connect(database_url)
    try:
        read_only = command in {"plan", "verify"}
        async with connection.transaction(
            isolation="serializable",
            readonly=read_only,
        ):
            required_controller = {
                "plan": "old",
                "backup": "old",
                "apply": "either",
                "verify": "new",
                "restore": "new",
            }[command]
            state = await _validate_database_state(
                connection,
                table=table,
                manifest=manifest,
                expected_present_count=expected_present_count,
                lock=not read_only,
                required_controller=required_controller,
            )
            if command == "plan":
                return _result(command, manifest, state)
            if command == "backup":
                assert backup_path is not None
                backup_digest = _write_backup(
                    backup_path,
                    _backup_document(
                        manifest=manifest,
                        schema=schema,
                        expected_present_count=expected_present_count,
                        state=state,
                    ),
                )
                result = _result(command, manifest, state)
                result["backup"] = str(backup_path)
                result["backup_sha256"] = backup_digest
                return result

            assert backup_path is not None
            assert backup_sha256 is not None
            backup_state = _load_backup(
                backup_path,
                required_sha256=backup_sha256,
                manifest=manifest,
                schema=schema,
                expected_present_count=expected_present_count,
            )
            _assert_partition_unchanged(state, backup_state)
            if command == "verify":
                _assert_only_controller_may_differ(
                    list(state.rows),
                    list(backup_state.rows),
                    manifest=manifest,
                    require_current_target=True,
                )
                return _result(command, manifest, state)
            if command == "apply":
                _assert_only_controller_may_differ(
                    list(state.rows),
                    list(backup_state.rows),
                    manifest=manifest,
                    require_current_target=False,
                )
                current_by_domain = {row["domain"]: row for row in state.rows}
                targets_by_domain = {
                    target.domain: target for target in manifest.targets
                }
                changes = [
                    {
                        "domain": domain,
                        "expected_controller_did": targets_by_domain[
                            domain
                        ].old_controller_did,
                        "new_controller_did": targets_by_domain[
                            domain
                        ].new_controller_did,
                    }
                    for domain in sorted(current_by_domain)
                    if current_by_domain[domain]["controller_did"]
                    == targets_by_domain[domain].old_controller_did
                ]
                changed = await _set_controllers(
                    connection, table=table, changes=changes
                )
                expected_changed = {change["domain"] for change in changes}
                if changed != expected_changed:
                    raise AlignmentError(
                        "guarded update count/domain mismatch; transaction rolled back"
                    )
                after = await _validate_database_state(
                    connection,
                    table=table,
                    manifest=manifest,
                    expected_present_count=expected_present_count,
                    lock=True,
                    required_controller="new",
                )
                _assert_partition_unchanged(after, backup_state)
                _assert_only_controller_may_differ(
                    list(after.rows),
                    list(backup_state.rows),
                    manifest=manifest,
                    require_current_target=True,
                )
                result = _result(command, manifest, after)
                result["updated"] = len(changed)
                return result

            if command == "restore":
                _assert_only_controller_may_differ(
                    list(state.rows),
                    list(backup_state.rows),
                    manifest=manifest,
                    require_current_target=True,
                )
                targets_by_domain = {
                    target.domain: target for target in manifest.targets
                }
                changes = [
                    {
                        "domain": backup["domain"],
                        "expected_controller_did": targets_by_domain[
                            backup["domain"]
                        ].new_controller_did,
                        "new_controller_did": backup["controller_did"],
                    }
                    for backup in backup_state.rows
                ]
                changed = await _set_controllers(
                    connection, table=table, changes=changes
                )
                expected_changed = {change["domain"] for change in changes}
                if changed != expected_changed:
                    raise AlignmentError(
                        "guarded restore count/domain mismatch; transaction rolled back"
                    )
                restored_state = await _validate_database_state(
                    connection,
                    table=table,
                    manifest=manifest,
                    expected_present_count=expected_present_count,
                    lock=True,
                    required_controller="old",
                )
                _assert_partition_unchanged(restored_state, backup_state)
                if restored_state.rows != backup_state.rows:
                    raise AlignmentError(
                        "restore postcondition failed; transaction rolled back"
                    )
                result = _result(command, manifest, restored_state)
                result["restored"] = len(changed)
                return result

            raise AlignmentError(f"unsupported command: {command}")
    finally:
        await connection.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        default="plan",
        choices=("plan", "backup", "apply", "verify", "restore"),
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--expected-count", required=True, type=int)
    parser.add_argument("--expected-present-count", required=True, type=int)
    parser.add_argument("--expected-parent-controller-did", required=True)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--backup-sha256")
    parser.add_argument(
        "--schema",
        default=os.environ.get("AWID_DB_SCHEMA", "awid"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    database_url = os.environ.get("AWID_DATABASE_URL")
    if not database_url:
        print("error: AWID_DATABASE_URL is required", file=sys.stderr)
        return 2
    try:
        manifest = load_manifest(
            args.manifest,
            required_sha256=args.manifest_sha256,
            required_count=args.expected_count,
            required_parent_controller_did=args.expected_parent_controller_did,
        )
        result = asyncio.run(
            run_operation(
                command=args.command,
                database_url=database_url,
                schema=args.schema,
                manifest=manifest,
                expected_present_count=args.expected_present_count,
                backup_path=args.backup,
                backup_sha256=args.backup_sha256,
            )
        )
    except (AlignmentError, OSError, asyncpg.PostgresError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
