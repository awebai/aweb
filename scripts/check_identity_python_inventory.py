#!/usr/bin/env python3
"""Pin Python identity primitive calls to exact canonical inventory sites.

This is the Python checkpoint of S8b, not release qualification or the Go/TS
scanner. It catches ordinary source additions and bypasses, not arbitrary
dynamic Python execution. Updating its catalog is an explicit review change.
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys


# Everything tracked (and new nonignored source awaiting git add) is scanned.
# This checker is the only reviewed script exclusion: it contains the literal
# primitive catalog itself. Tests are excluded separately by path/name.
EXCLUDED_SCRIPTS = frozenset({"scripts/check_identity_python_inventory.py"})
# Constructors, raw crypto and the public identity/certificate authority seams.
# Do not derive this list from imports in the inventory: deleting an inventory
# field must not switch off source discovery.
PRIMITIVE_NAMES = frozenset({
    "sign", "verify", "SigningKey", "VerifyKey", "Ed25519PrivateKey",
    "Ed25519PublicKey", "generate_keypair", "generate_identity",
    "public_key_to_did_key", "did_key_from_public_key", "create_identity",
    "verify_id_chain", "verify_id_certificate", "id_certificate_signing_bytes",
    "encode_id_chain_header", "decode_id_chain_header", "verify_identity_binding",
    "register_did", "register_certificate", "revoke_certificate",
    "verify_identity_log", "crypto_core_ed25519_is_valid_point",
    "crypto_sign", "crypto_sign_open", "crypto_sign_verify_detached",
})
PRIMITIVE_MODULES = (
    "nacl.signing.", "nacl.bindings.", "cryptography.hazmat.primitives.asymmetric.ed25519.",
    "awid.did.", "awid.signing.", "awid.team_certificate.",
    "awid.identity_log_verify.", "awid.id_certificates.",
)
STRICT_MODULE = "awid/src/awid/id_certificates.py"
RAW_VERIFY_SITE = (STRICT_MODULE, "verify_ed25519")
RAW_VERIFY_NAMES = frozenset({
    "verify", "VerifyKey", "verify_signature", "verify_signature_with_public_key",
    "verify_did_key_signature",
    "crypto_sign", "crypto_sign_open", "crypto_sign_verify_detached",
})


def excluded(file: str) -> bool:
    path = PurePosixPath(file)
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


def scan_python_source(source: str, *, module: str = "fixture", package: bool = False) -> dict[str, Counter]:
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
                aliases[name.asname or name.name] = base + "." + name.name

    def called_name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return called_name(node.value) + "." + node.attr
        if isinstance(node, ast.Call):
            return called_name(node.func) + "()"
        return "<expression>"

    calls = defaultdict(Counter)
    parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str)
    }

    def primitive(name):
        terminal = name.rsplit(".", 1)[-1]
        return terminal in PRIMITIVE_NAMES or terminal.startswith(("sign_", "verify_")) or name.startswith(PRIMITIVE_MODULES)

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
            calls[".".join(self.scope) or "<module>"][name] += 1

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

        def visit_Constant(self, node):
            if id(node) not in docstrings and isinstance(node.value, str):
                for prefix in ("did:key", "did:aw"):
                    if node.value.startswith(prefix + ":"):
                        self.record("literal:" + prefix)

    Visitor().visit(tree)
    return dict(calls)


def check_inventory(root: Path, inventory: dict) -> list[str]:
    errors = []
    guard = inventory.get("python_guard", {})
    if inventory.get("v") != 1 or guard.get("v") != 1 or not isinstance(guard.get("sites"), list):
        return ["identity inventory requires v=1 and python_guard {v:1, sites:[]}"]
    rows = {}
    for row in inventory.get("sites", []):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            return ["identity inventory row requires an id"]
        if row["id"] in rows:
            errors.append("duplicate inventory row " + row["id"])
        rows[row["id"]] = row
    declared = {}
    for entry in guard["sites"]:
        if not isinstance(entry, dict) or set(entry) != {"row", "file", "symbol", "calls"}:
            errors.append("Python catalog entry requires exactly row/file/symbol/calls")
            continue
        file, symbol, counts = entry["file"], entry["symbol"], entry["calls"]
        if not isinstance(file, str) or not isinstance(symbol, str) or not symbol:
            errors.append("Python catalog file and symbol must be strings")
            continue
        path = PurePosixPath(file)
        if path.is_absolute() or ".." in path.parts or not file.endswith(".py") or excluded(file):
            errors.append("Python catalog path outside scanned source: " + file)
            continue
        key = (file, symbol)
        if key in declared:
            errors.append("duplicate Python catalog site " + repr(key))
        if not isinstance(counts, dict) or not counts or any(not isinstance(k, str) or not k or type(n) is not int or n < 1 for k, n in counts.items()):
            errors.append("Python primitive call counts must be positive integers: " + repr(key))
            continue
        declared[key] = counts
        row = rows.get(entry["row"], {})
        if row.get("repo") != "aweb" or file not in row.get("files", []) or {"file": file, "symbol": symbol} not in row.get("sites", []):
            errors.append("Python primitive needs a mapped exact site: " + repr(key))
        if row.get("ed25519_profile") not in {"strict", "legacy"}:
            errors.append("Python primitive row needs strict|legacy profile: " + repr(key))
        if file == STRICT_MODULE and row.get("ed25519_profile") != "strict":
            errors.append("ID certificate module cannot downgrade its strict profile: " + symbol)
        if row.get("ed25519_profile") == "strict" and any(c.rsplit(".", 1)[-1] in RAW_VERIFY_NAMES for c in counts) and key != RAW_VERIFY_SITE:
            errors.append("raw ID crypto must use the shared strict verifier: " + symbol)
    observed = {}
    for path in source_files(root):
        file = path.relative_to(root).as_posix()
        try:
            calls = scan_python_source(path.read_text(encoding="utf-8"), module=module_name(file), package=path.name == "__init__.py")
        except (SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"cannot scan {file}: {exc}")
            continue
        observed.update({(file, symbol): dict(counts) for symbol, counts in calls.items()})
    for key, counts in observed.items():
        if key not in declared:
            errors.append("unlisted Python identity primitive site: " + repr(key))
        elif counts != declared[key]:
            errors.append(f"Python primitive call counts changed at {key!r}: expected {declared[key]!r}, observed {counts!r}")
    for key in declared.keys() - observed.keys():
        errors.append("stale Python identity primitive site: " + repr(key))
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    inventory = json.loads((root / "docs/identity-tree-coverage.json").read_text())
    errors = check_inventory(root, inventory)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Python identity primitive inventory passed ({len(inventory['python_guard']['sites'])} exact sites); S8b release qualification remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
