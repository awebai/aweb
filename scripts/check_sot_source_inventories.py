#!/usr/bin/env python3
"""Check source-derived inventories embedded in the canonical implementation SOTs."""

from __future__ import annotations

import ast
import operator
import re
import sys
from pathlib import Path


_TABLE_EVENT_PATTERN = re.compile(
    r"(CREATE|DROP)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"
    r"\{\{tables\.([A-Za-z0-9_]+)\}\}",
    re.IGNORECASE,
)
_RAW_TABLE_EVENT_PATTERN = re.compile(
    r"\b(?:CREATE\s+(?:(?:GLOBAL|LOCAL)\s+)?(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?|DROP\s+)TABLE\b",
    re.IGNORECASE,
)
_SQL_COMMENT_PATTERN = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_ITEM_PATTERN = re.compile(r"^- `([^`]+)`$")
_INTEGER_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
}


def extract_sql_tables(migrations_dir: Path) -> list[str]:
    """Apply ordered CREATE/DROP events and return component application tables."""
    tables: list[str] = []
    for migration in sorted(migrations_dir.glob("*.sql")):
        sql = _SQL_COMMENT_PATTERN.sub("", migration.read_text())
        raw_events = _RAW_TABLE_EVENT_PATTERN.findall(sql)
        events = _TABLE_EVENT_PATTERN.findall(sql)
        if len(events) != len(raw_events):
            raise ValueError(
                f"unsupported table declaration in {migration}: every CREATE/DROP TABLE "
                "must use the {{tables.name}} templated form"
            )
        for operation, table in events:
            if operation.upper() == "CREATE":
                if table not in tables:
                    tables.append(table)
            elif table in tables:
                tables.remove(table)
    return tables


def extract_fastapi_routers(api_source: Path) -> list[str]:
    """Return top-level REST router names in application mount order."""
    calls: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(api_source.read_text())):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        is_app_include = (
            isinstance(function, ast.Attribute)
            and function.attr == "include_router"
            and isinstance(function.value, ast.Name)
            and function.value.id == "app"
        )
        if not is_app_include:
            continue
        if not node.args:
            raise ValueError(f"unsupported app.include_router call at line {node.lineno}: missing router")
        router = node.args[0]
        if not isinstance(router, ast.Name) or not router.id.endswith("_router"):
            raise ValueError(
                "unsupported app.include_router argument at "
                f"line {node.lineno}: {ast.unparse(router)}"
            )
        calls.append((node.lineno, router.id.removesuffix("_router")))
    return [name for _, name in sorted(calls)]


def _integer_expression(node: ast.expr) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _INTEGER_OPERATORS:
        return _INTEGER_OPERATORS[type(node.op)](
            _integer_expression(node.left),
            _integer_expression(node.right),
        )
    raise ValueError("cache constants must use integer arithmetic")


def extract_team_cache_facts(registry_source: Path) -> list[str]:
    """Return the team metadata/revocation fresh and stale windows."""
    wanted = {
        "_TEAM_METADATA_CACHE_TTL_SECONDS",
        "_TEAM_REVOCATIONS_CACHE_TTL_SECONDS",
        "_STALE_MULTIPLIER",
    }
    constants: dict[str, int] = {}
    for statement in ast.parse(registry_source.read_text()).body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if isinstance(target, ast.Name) and target.id in wanted:
            constants[target.id] = _integer_expression(statement.value)
    missing = sorted(wanted - constants.keys())
    if missing:
        raise ValueError(f"missing AWID cache constants: {', '.join(missing)}")
    metadata = constants["_TEAM_METADATA_CACHE_TTL_SECONDS"]
    revocations = constants["_TEAM_REVOCATIONS_CACHE_TTL_SECONDS"]
    stale_multiplier = constants["_STALE_MULTIPLIER"]
    return [
        f"team_metadata_fresh_seconds={metadata}",
        f"team_metadata_stale_seconds={metadata * (stale_multiplier - 1)}",
        f"team_revocations_fresh_seconds={revocations}",
        f"team_revocations_stale_seconds={revocations * (stale_multiplier - 1)}",
    ]


def render_inventory(name: str, values: list[str]) -> str:
    lines = [f"<!-- BEGIN SOURCE INVENTORY: {name} -->"]
    lines.extend(f"- `{value}`" for value in values)
    lines.append(f"<!-- END SOURCE INVENTORY: {name} -->")
    return "\n".join(lines) + "\n"


def _documented_inventory(document: Path, name: str) -> tuple[list[str] | None, str | None]:
    text = document.read_text()
    start = f"<!-- BEGIN SOURCE INVENTORY: {name} -->"
    end = f"<!-- END SOURCE INVENTORY: {name} -->"
    if text.count(start) != 1 or text.count(end) != 1:
        return None, f"{document}: inventory {name!r} must have exactly one start and end marker"
    body = text.split(start, 1)[1].split(end, 1)[0]
    values: list[str] = []
    for line in body.splitlines():
        if not line.strip():
            continue
        match = _ITEM_PATTERN.fullmatch(line.strip())
        if match is None:
            return None, f"{document}: inventory {name!r} has invalid line {line!r}"
        values.append(match.group(1))
    return values, None


def _inventory_error(name: str, expected: list[str], actual: list[str]) -> str:
    missing = [value for value in expected if value not in actual]
    stale = [value for value in actual if value not in expected]
    order_mismatch = not missing and not stale and expected != actual
    details: list[str] = []
    if missing:
        details.append(f"missing={','.join(missing)}")
    if stale:
        details.append(f"stale={','.join(stale)}")
    if order_mismatch:
        details.append("source order differs")
    return f"{name} differs from source ({'; '.join(details)})"


def check_repository(root: Path) -> list[str]:
    specs = [
        (
            "aweb-tables",
            root / "docs/aweb-sot.md",
            extract_sql_tables(root / "server/src/aweb/migrations/aweb"),
        ),
        (
            "aweb-routers",
            root / "docs/aweb-sot.md",
            extract_fastapi_routers(root / "server/src/aweb/api.py"),
        ),
        (
            "awid-tables",
            root / "docs/awid-sot.md",
            extract_sql_tables(root / "awid/src/awid_service/migrations"),
        ),
        (
            "aweb-awid-cache",
            root / "docs/aweb-sot.md",
            extract_team_cache_facts(root / "awid/src/awid/registry.py"),
        ),
    ]
    errors: list[str] = []
    for name, document, expected in specs:
        actual, parse_error = _documented_inventory(document, name)
        if parse_error is not None:
            errors.append(parse_error)
        elif actual != expected:
            errors.append(_inventory_error(name, expected, actual or []))
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        errors = check_repository(root)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    aweb_tables = extract_sql_tables(root / "server/src/aweb/migrations/aweb")
    routers = extract_fastapi_routers(root / "server/src/aweb/api.py")
    awid_tables = extract_sql_tables(root / "awid/src/awid_service/migrations")
    print(
        "canonical SOT inventories match source "
        f"(aweb application tables={len(aweb_tables)}, routers={len(routers)}, "
        f"awid application tables={len(awid_tables)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
