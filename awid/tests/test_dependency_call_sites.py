"""Check AWID dependency calls and ownership of fixture verifier resolution."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

GETTERS = {
    f"awid_service.deps.{name}"
    for name in (
        "get_db",
        "get_redis",
        "get_domain_verifier",
    )
}
ROOT = Path(__file__).resolve().parents[2]
DOMAIN_VERIFIER = "awid_service.deps.get_domain_verifier"
FIXTURE_CONSUMERS = ("naapp-contracts/testing/", "server/tests/")


@dataclass(frozen=True)
class GetterCall:
    getter: str
    spelling: str
    line: int
    awaited: bool


def _import_resolver(tree: ast.AST, package: str) -> Callable[[ast.expr], str]:
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                imports[name.asname or name.name.split(".")[0]] = (
                    name.name if name.asname else name.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                if not package:
                    continue
                module = importlib.util.resolve_name("." * node.level + module, package)
            for name in node.names:
                imports[name.asname or name.name] = f"{module}.{name.name}"

    def resolve(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{resolve(node.value)}.{node.attr}"
        return ""

    return resolve


def getter_calls(source: str, *, package: str = "") -> list[GetterCall]:
    """Inventory direct calls, including aliases; Depends(getter) is not a call."""
    tree = ast.parse(source)
    resolve = _import_resolver(tree, package)
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    return [
        GetterCall(
            resolve(node.func),
            ast.unparse(node.func),
            node.lineno,
            isinstance(parents.get(node), ast.Await),
        )
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and resolve(node.func) in GETTERS
    ]


def verifier_override_reads(source: str, *, package: str = "") -> list[int]:
    """Find direct reads of the verifier override instead of its fixture owner."""
    tree = ast.parse(source)
    resolve = _import_resolver(tree, package)
    reads = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "dependency_overrides"
            and resolve(node.slice) == DOMAIN_VERIFIER
        ):
            reads.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "dependency_overrides"
            and node.args
            and resolve(node.args[0]) == DOMAIN_VERIFIER
        ):
            reads.append(node.lineno)
    return sorted(reads)


def test_override_inventory_resolves_aliases_and_preserves_override_installation() -> (
    None
):
    source = """\
from awid_service.deps import get_domain_verifier as owner
from awid_service import deps as providers
app.dependency_overrides[owner] = factory
from_mapping = app.dependency_overrides[owner]
from_get = app.dependency_overrides.get(providers.get_domain_verifier)
unrelated = app.dependency_overrides.get(get_domain_verifier)
"""
    assert verifier_override_reads(source) == [4, 5]


@pytest.mark.parametrize(
    "declaration,call,package",
    [
        ("from awid_service.deps import get_db", "get_db(request)", ""),
        (
            "from awid_service.deps import get_db as get_db_infra",
            "get_db_infra(request)",
            "",
        ),
        ("import awid_service.deps as owners", "owners.get_db(request)", ""),
        ("from awid_service import deps as owners", "owners.get_db(request)", ""),
        ("import awid_service.deps", "awid_service.deps.get_db(request)", ""),
        ("import awid_service as service", "service.deps.get_db(request)", ""),
        ("from ..deps import get_db as owner", "owner(request)", "awid_service.routes"),
    ],
)
def test_alias_inventory_distinguishes_sync_call_from_await_and_dependency(
    declaration: str,
    call: str,
    package: str,
) -> None:
    sync = f'{declaration}\ndef _db(request):\n    return {call}.get_manager("aweb")\n'
    awaited = f'{declaration}\nasync def _db(request):\n    return (await {call}).get_manager("aweb")\n'
    dependency = f"{declaration}\nvalue = Depends({call.removesuffix('(request)')})\n"
    assert getter_calls(sync, package=package) == [
        GetterCall("awid_service.deps.get_db", call.removesuffix("(request)"), 3, False)
    ]
    assert getter_calls(awaited, package=package) == [
        GetterCall("awid_service.deps.get_db", call.removesuffix("(request)"), 3, True)
    ]
    assert getter_calls(dependency, package=package) == []


def test_direct_awid_getter_calls_are_awaited() -> None:
    paths = subprocess.check_output(
        ["git", "ls-files", "*.py"], cwd=ROOT, text=True
    ).splitlines()
    unawaited = []
    override_reads = []
    for name in paths:
        path = Path(name)
        parts = path.parts
        package = ".".join(parts[parts.index("src") + 1 : -1]) if "src" in parts else ""
        source = (ROOT / path).read_text()
        for call in getter_calls(source, package=package):
            if not call.awaited:
                unawaited.append(
                    f"{name}:{call.line}: {call.spelling} -> {call.getter}"
                )
        if name.startswith(FIXTURE_CONSUMERS):
            override_reads.extend(
                f"{name}:{line}"
                for line in verifier_override_reads(source, package=package)
            )
    assert not unawaited, "Direct AWID getter calls must be awaited:\n" + "\n".join(
        unawaited
    )
    assert not override_reads, (
        "Use fixture_domain_authority to read verifier overrides:\n"
        + "\n".join(override_reads)
    )
