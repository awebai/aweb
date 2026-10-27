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
import sys


ROOTS = ("awid/src", "server/src", "naapp-lib/src")
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
})
PRIMITIVE_MODULES = (
    "nacl.signing.", "cryptography.hazmat.primitives.asymmetric.ed25519.",
    "awid.did.", "awid.signing.", "awid.team_certificate.",
    "awid.identity_log_verify.", "awid.id_certificates.",
)
STRICT_MODULE = "awid/src/awid/id_certificates.py"
RAW_VERIFY_SITE = (STRICT_MODULE, "verify_id_certificate")
RAW_VERIFY_NAMES = frozenset({
    "verify", "VerifyKey", "verify_signature", "verify_signature_with_public_key",
    "verify_did_key_signature",
})


def scan_python_source(source: str) -> dict[str, Counter]:
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for name in node.names:
                aliases[name.asname or name.name] = (node.module or "") + "." + name.name

    def called_name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return called_name(node.value) + "." + node.attr
        if isinstance(node, ast.Call):
            return called_name(node.func) + "()"
        return "<expression>"

    calls = defaultdict(Counter)

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
            if name.rsplit(".", 1)[-1] in PRIMITIVE_NAMES or name.startswith(PRIMITIVE_MODULES):
                self.record(name)
            self.generic_visit(node)

        def visit_BinOp(self, node):
            if isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                for prefix in ("did:key", "did:aw"):
                    if node.left.value.startswith(prefix + ":"):
                        self.record("construct:" + prefix)
            self.generic_visit(node)

        def visit_JoinedStr(self, node):
            if node.values and isinstance(node.values[0], ast.Constant) and isinstance(node.values[0].value, str):
                for prefix in ("did:key", "did:aw"):
                    if node.values[0].value.startswith(prefix + ":"):
                        self.record("construct:" + prefix)
            self.generic_visit(node)

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
        if path.is_absolute() or ".." in path.parts or not file.endswith(".py") or not any(file.startswith(r + "/") for r in ROOTS):
            errors.append("Python catalog path outside source roots: " + file)
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
    for directory in ROOTS:
        for path in sorted((root / directory).rglob("*.py")):
            file = path.relative_to(root).as_posix()
            try:
                calls = scan_python_source(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeError) as exc:
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
