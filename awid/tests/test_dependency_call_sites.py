"""Resolve AWID getter imports before checking direct callers' await boundaries."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
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


@dataclass(frozen=True)
class GetterCall:
    getter: str
    spelling: str
    line: int
    awaited: bool


def getter_calls(source: str, *, package: str = "") -> list[GetterCall]:
    """Inventory direct calls, including aliases; Depends(getter) is not a call."""
    tree = ast.parse(source)
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
    for name in paths:
        path = Path(name)
        parts = path.parts
        package = ".".join(parts[parts.index("src") + 1 : -1]) if "src" in parts else ""
        for call in getter_calls((ROOT / path).read_text(), package=package):
            if not call.awaited:
                unawaited.append(
                    f"{name}:{call.line}: {call.spelling} -> {call.getter}"
                )
    assert not unawaited, "Direct AWID getter calls must be awaited:\n" + "\n".join(
        unawaited
    )
