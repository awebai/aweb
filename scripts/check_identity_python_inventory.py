#!/usr/bin/env python3
"""Refuse raw Ed25519 uses outside shared implementations and named legacy files.

Syntactic source check only; reflection and dynamic dispatch are outside scope.
Identity creation coverage is documentation, not a call-count catalog.
"""

from __future__ import annotations

import ast
from collections import defaultdict
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys


# Everything tracked (and new nonignored source awaiting git add) is scanned.
# This checker is the only reviewed script exclusion: it contains the literal
# primitive catalog itself. Tests are excluded separately by path/name.
EXCLUDED_SCRIPTS = frozenset({"scripts/check_identity_python_inventory.py"})
PRIMITIVE_MODULES = (
    "nacl.signing.", "nacl.bindings.", "cryptography.hazmat.primitives.asymmetric.ed25519.",
)
SHARED_SITES = {
    ("awid/src/awid/id_certificates.py", "verify_ed25519"),
    ("awid/src/awid/did.py", "strict_ed25519_point"),
    ("awid/src/awid/did.py", "generate_keypair"),
}


def excluded(file: str) -> bool:
    path = PurePosixPath(file)
    if "src" in path.parts:
        # A production module called test_foo.py is still production source.
        # Only an explicit tests directory below src exempts its contents.
        return "tests" in path.parts[path.parts.index("src") + 1:-1]
    return (file in EXCLUDED_SCRIPTS or path.name.startswith("test_")
            or path.name == "conftest.py" or any(p in {"test", "tests"} for p in path.parts[:-1]))


def source_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.py"],
        cwd=root, check=True, capture_output=True,
    )
    return [root / file for file in sorted(set(result.stdout.decode().split("\0")))
            if file and not excluded(file) and (root / file).is_file()]


def module_name(file: str) -> str:
    parts = list(PurePosixPath(file).with_suffix("").parts)
    if "src" in parts:
        parts = parts[len(parts) - 1 - parts[::-1].index("src") + 1:]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def scan_python_source(source: str, *, module: str = "fixture", package: bool = False) -> dict[str, set[str]]:
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = module.split(".") if package else module.split(".")[:-1]
                if node.level > len(parent):
                    raise ValueError("relative import escapes its package")
                base = ".".join(parent[:len(parent) - node.level + 1] + ([base] if base else []))
            for name in node.names:
                if name.name == "*" and any((base + ".").startswith(prefix) for prefix in PRIMITIVE_MODULES):
                    raise ValueError("wildcard import hides an identity primitive: " + base)
                aliases[name.asname or name.name] = base + "." + name.name

    def called_name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return called_name(node.value) + "." + node.attr
        if isinstance(node, ast.Call):
            return called_name(node.func) + "()"
        return "<expression>"

    calls = defaultdict(set)
    parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    def primitive(name):
        return name.startswith(PRIMITIVE_MODULES)

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []

        def scoped(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        visit_ClassDef = scoped
        visit_FunctionDef = scoped
        visit_AsyncFunctionDef = scoped

        def record(self, name):
            calls[".".join(self.scope) or "<module>"].add(name)

        def visit_Call(self, node):
            name = called_name(node.func)
            if primitive(name):
                self.record(name)
            self.generic_visit(node)

        def reference(self, node):
            parent = parents.get(id(node))
            is_callee = isinstance(parent, ast.Call) and parent.func is node
            is_receiver = isinstance(parent, ast.Attribute) and parent.value is node
            if isinstance(node.ctx, ast.Load) and not is_callee and not is_receiver:
                name = called_name(node)
                if primitive(name):
                    self.record("reference:" + name)
            self.generic_visit(node)

        visit_Name = reference
        visit_Attribute = reference

    Visitor().visit(tree)
    return dict(calls)


def check_inventory(root: Path, inventory: dict) -> list[str]:
    errors = []
    legacy = {}
    for entry in inventory["primitive_guard"]["legacy_files"]:
        if not entry.get("file") or not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            errors.append("legacy primitive file requires a reason")
        else:
            legacy[entry["file"]] = entry["reason"]
    for path in source_files(root):
        file = path.relative_to(root).as_posix()
        try:
            uses = scan_python_source(path.read_text(encoding="utf-8"), module=module_name(file), package=path.name == "__init__.py")
        except (SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"cannot scan {file}: {exc}")
            continue
        for symbol in uses:
            if (file, symbol) not in SHARED_SITES and file not in legacy:
                errors.append(f"raw Python crypto must use the shared verifier: {file}:{symbol}")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    inventory = json.loads((root / "docs/identity-tree-coverage.json").read_text())
    errors = check_inventory(root, inventory)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Python primitive-use boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
