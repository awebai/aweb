#!/usr/bin/env python3
"""Rewrite imports of aweb_naapp's contract modules to aweb_naapp_contracts.

The naapp contracts (manifest, egress, the hook wire formats, task requests and
their helpers) are published as the aweb-naapp-contracts distribution under the
import name aweb_naapp_contracts, and their test support (the AWID member and
registry helpers and the network fixtures) as aweb-naapp-contracts-testing,
imported as aweb_naapp_contracts_testing. Code that imported them from
aweb_naapp or aweb_naapp_testing runs this over its Python files:

    python3 scripts/naapp_contracts_rename.py PATH [PATH ...]

Dotted names are renamed wherever they appear, in imports, strings and
comments. ``from aweb_naapp[.hooks|.runtime] import ...`` statements that name
both contract and runtime modules are split in two. A reference the script
cannot place (the bare ``aweb_naapp.hooks`` or ``aweb_naapp_testing`` package,
or a split import with a comment inside) is printed with its line and left as it is, and the exit status
is 1, so a person decides it. The pgdbm migration module name
``aweb_naapp_hooks`` is a different name and is never touched.

A renamed line can outgrow the line length or the import order; run the
project's import sorter (``ruff check --select I --fix``) on the changed files
afterwards.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

CONTRACTS = "aweb_naapp_contracts"
CONTRACTS_TESTING = "aweb_naapp_contracts_testing"
# The contract test support that moves out of aweb_naapp_testing: its root
# names and these modules.
_TESTING_MODULES = ("network", "production_registry", "team_facts", "human_members")
_TESTING_ROOT_NAMES = {
    "REGISTRY_URL",
    "SERVICE_TOKEN",
    "Member",
    "RecordingTransport",
    "Registry",
    "attested",
    "awid_registry",
    "did_key",
    "envelope_headers",
    "utc_timestamp",
}

# Contract modules under each aweb_naapp package that a ``from X import name``
# can name, and where each lands in the contracts package.
_IMPORTED_MODULES = {
    "aweb_naapp": (
        CONTRACTS,
        {"client_identity", "did_key", "key_file", "manifest", "manifest_keys", "egress"},
    ),
    "aweb_naapp.hooks": (
        f"{CONTRACTS}.hooks",
        {"strictjson", "owner_act", "owner_act_nonces", "catalog", "envelope", "delivery"},
    ),
    "aweb_naapp.runtime": (CONTRACTS, {"task_requests"}),
    "aweb_naapp_testing": (CONTRACTS_TESTING, _TESTING_ROOT_NAMES | set(_TESTING_MODULES)),
}

_DOTTED = re.compile(
    r"\baweb_naapp\."
    r"(runtime\.task_requests"
    r"|hooks\.(?:strictjson|owner_act_nonces|owner_act|catalog|envelope|delivery)"
    r"|client_identity|did_key|key_file|manifest_keys|manifest|egress)"
    r"(?![A-Za-z0-9_])"
)
_DOTTED_TESTING = re.compile(
    r"\baweb_naapp_testing\.(" + "|".join(_TESTING_MODULES) + r")(?![A-Za-z0-9_])"
)
_PACKAGED_HOOKS = re.compile(r"""files\((["'])aweb_naapp\.hooks\1\)""")
# A ``from aweb_naapp.hooks import`` or ``from aweb_naapp_testing import`` left
# after the split names runtime modules only.
_BARE_PACKAGES = re.compile(
    r"\b(?:aweb_naapp\.hooks|aweb_naapp_testing)(?![.A-Za-z0-9_])(?! import )"
)
_TEXT_IMPORT = re.compile(
    r"from (aweb_naapp(?:\.hooks|\.runtime)?|aweb_naapp_testing) import ([A-Za-z_][A-Za-z0-9_]*(?: as [A-Za-z_][A-Za-z0-9_]*)?"
    r"(?:, *[A-Za-z_][A-Za-z0-9_]*(?: as [A-Za-z_][A-Za-z0-9_]*)?)*)"
)
_LINE_LENGTH = 100


def _dotted(match: re.Match[str]) -> str:
    module = match.group(1)
    if module == "runtime.task_requests":
        return f"{CONTRACTS}.task_requests"
    return f"{CONTRACTS}.{module}"


def _alias(alias: ast.alias) -> str:
    return alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"


def _statement(indent: str, module: str, names: list[str]) -> list[str]:
    line = f"{indent}from {module} import {', '.join(names)}"
    if len(line) <= _LINE_LENGTH:
        return [line]
    return [
        f"{indent}from {module} import (",
        *(f"{indent}    {name}," for name in names),
        f"{indent})",
    ]


def _split_imports(lines: list[str], tree: ast.Module) -> tuple[list[str], list[tuple[int, str]]]:
    """Split each ``from <package> import`` that names a contract module."""
    ambiguous: list[tuple[int, str]] = []
    replacements: list[tuple[int, int, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.level or node.module not in _IMPORTED_MODULES:
            continue
        target, contract_names = _IMPORTED_MODULES[node.module]
        moving = [alias for alias in node.names if alias.name in contract_names]
        if not moving:
            continue
        staying = [alias for alias in node.names if alias.name not in contract_names]
        start, end = node.lineno - 1, node.end_lineno
        assert end is not None
        span = lines[start:end]
        if any("#" in line for line in span):
            ambiguous.append((node.lineno, f"from {node.module} import (comment inside)"))
            continue
        indent = span[0][: len(span[0]) - len(span[0].lstrip())]
        new: list[str] = []
        if staying:
            new += _statement(indent, node.module, [_alias(a) for a in staying])
        new += _statement(indent, target, [_alias(a) for a in moving])
        replacements.append((start, end, new))
    for start, end, new in sorted(replacements, reverse=True):
        lines[start:end] = new
    return lines, ambiguous


def rename_source(source: str) -> tuple[str, list[tuple[int, str]]]:
    """The renamed source, and the references left for a person to decide."""
    lines = source.split("\n")
    lines, ambiguous = _split_imports(lines, ast.parse(source))
    renamed = "\n".join(lines)
    renamed = _PACKAGED_HOOKS.sub(lambda m: f"files({m.group(1)}{CONTRACTS}.hooks{m.group(1)})", renamed)
    renamed = _DOTTED.sub(_dotted, renamed)
    renamed = _DOTTED_TESTING.sub(lambda m: f"{CONTRACTS_TESTING}.{m.group(1)}", renamed)
    for number, line in enumerate(renamed.split("\n"), start=1):
        for match in _BARE_PACKAGES.finditer(line):
            ambiguous.append((number, match.group(0)))
        # Real import statements were split above; one still naming a contract
        # module is inside a string, where only a person can rewrite it.
        for match in _TEXT_IMPORT.finditer(line):
            names = {name.split(" as ")[0].strip() for name in match.group(2).split(",")}
            if names & _IMPORTED_MODULES[match.group(1)][1]:
                ambiguous.append((number, match.group(0).strip()))
    return renamed, sorted(ambiguous)


@dataclass(frozen=True)
class Result:
    path: Path
    changed: bool
    ambiguous: list[tuple[int, str]]


def rename_file(path: Path) -> Result:
    source = path.read_text()
    renamed, ambiguous = rename_source(source)
    if renamed != source:
        path.write_text(renamed)
    return Result(path=path, changed=renamed != source, ambiguous=ambiguous)


def _python_files(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found += sorted(p for p in path.rglob("*.py") if ".venv" not in p.parts)
        else:
            found.append(path)
    return found


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    unresolved = False
    for path in _python_files([Path(arg) for arg in argv]):
        result = rename_file(path)
        if result.changed:
            print(f"renamed {path}")
        for number, what in result.ambiguous:
            unresolved = True
            print(f"decide {path}:{number}: {what}")
    return 1 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
