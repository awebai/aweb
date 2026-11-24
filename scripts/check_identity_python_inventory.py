#!/usr/bin/env python3
"""Refuse raw Ed25519 uses outside shared implementations and named call sites.

This syntactic check follows local key bindings and direct ``self`` fields with
class annotations or recognizable assignments. It does not infer fields on
other objects, inherited fields, method results, cross-module return types,
or reflective and computed access.
Identity creation coverage is documentation, not a call-count catalog.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

# Everything tracked (and new nonignored source awaiting git add) is scanned.
# This checker is the only reviewed script exclusion: it contains the literal
# primitive catalog itself. Tests are excluded separately by path/name.
EXCLUDED_SCRIPTS = frozenset({"scripts/check_identity_python_inventory.py"})
PRIMITIVE_MODULES = (
    "nacl.signing.",
    "nacl.bindings.",
    "cryptography.hazmat.primitives.asymmetric.ed25519.",
)
NACL_SIGNING_KEY = "nacl.signing.SigningKey"
NACL_VERIFY_KEY = "nacl.signing.VerifyKey"
KEY_TYPES = frozenset(
    {
        NACL_SIGNING_KEY,
        NACL_VERIFY_KEY,
        "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey",
        "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey",
    }
)
SHARED_SITES = {
    ("awid/src/awid/signature_wire.py", "verify_bytes"),
    ("awid/src/awid/signature_wire.py", "sign_bytes"),
    ("awid/src/awid/signature_wire.py", "_prime_point"),
    ("awid/src/awid/did.py", "generate_keypair"),
    ("awid/src/awid/did.py", "did_key_from_signing_key"),
}


def excluded(file: str) -> bool:
    path = PurePosixPath(file)
    if "src" in path.parts:
        # A production module called test_foo.py is still production source.
        # Only an explicit tests directory below src exempts its contents.
        return "tests" in path.parts[path.parts.index("src") + 1 : -1]
    return (
        file in EXCLUDED_SCRIPTS
        or path.name.startswith("test_")
        or path.name == "conftest.py"
        or any(p in {"test", "tests"} for p in path.parts[:-1])
    )


def source_files(root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.py",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [
        root / file
        for file in sorted(set(result.stdout.decode().split("\0")))
        if file and not excluded(file) and (root / file).is_file()
    ]


def module_name(file: str) -> str:
    parts = list(PurePosixPath(file).with_suffix("").parts)
    if "src" in parts:
        parts = parts[len(parts) - 1 - parts[::-1].index("src") + 1 :]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def scan_python_source(
    source: str, *, module: str = "fixture", package: bool = False
) -> dict[str, Counter[str]]:
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split(".")[0]] = (
                    name.name if name.asname else name.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = module.split(".") if package else module.split(".")[:-1]
                if node.level > len(parent):
                    raise ValueError("relative import escapes its package")
                base = ".".join(
                    parent[: len(parent) - node.level + 1] + ([base] if base else [])
                )
            for name in node.names:
                if name.name == "*" and any(
                    (base + ".").startswith(prefix) for prefix in PRIMITIVE_MODULES
                ):
                    raise ValueError(
                        "wildcard import hides an identity primitive: " + base
                    )
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
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    annotations = {
        id(child)
        for node in ast.walk(tree)
        for annotation in (
            getattr(node, "annotation", None),
            getattr(node, "returns", None),
        )
        if annotation is not None
        for child in ast.walk(annotation)
    }
    returns_key = {
        node.name: called_name(node.returns)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and called_name(node.returns) in KEY_TYPES
    }

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
            self.key_bindings = [{}]
            self.instance_keys = []

        def scoped(self, node):
            self.scope.append(node.name)
            self.key_bindings.append({})
            for argument in ast.iter_child_nodes(node.args):
                if isinstance(argument, ast.arg):
                    self.bind(argument.arg, called_name(argument.annotation))
            self.generic_visit(node)
            self.key_bindings.pop()
            self.scope.pop()

        visit_FunctionDef = scoped
        visit_AsyncFunctionDef = scoped

        def visit_ClassDef(self, node):
            self.scope.append(node.name)
            self.key_bindings.append({})
            self.instance_keys.append(
                {
                    field.target.id: called_name(field.annotation)
                    for field in node.body
                    if isinstance(field, ast.AnnAssign)
                    and isinstance(field.target, ast.Name)
                    and called_name(field.annotation) in KEY_TYPES
                }
            )
            # The constructor establishes fields even when it follows a reader
            # in the source. Scan it exactly once.
            constructor = next(
                (
                    member
                    for member in node.body
                    if isinstance(member, ast.FunctionDef) and member.name == "__init__"
                ),
                None,
            )
            if constructor is not None:
                self.visit(constructor)
            for child in ast.iter_child_nodes(node):
                if child is not constructor:
                    self.visit(child)
            self.instance_keys.pop()
            self.key_bindings.pop()
            self.scope.pop()

        def instance_field(self, node):
            return (
                self.instance_keys
                and isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
            )

        def bind_target(self, target, key_type):
            if isinstance(target, ast.Name):
                self.bind(target.id, key_type)
            elif self.instance_field(target) and key_type in KEY_TYPES:
                self.instance_keys[-1][target.attr] = key_type

        def verification_key_projection(self, node):
            return (
                isinstance(node, ast.Attribute)
                and node.attr == "verify_key"
                and self.key_type(node.value) == NACL_SIGNING_KEY
            )

        def bind(self, name, key_type):
            self.key_bindings[-1][name] = key_type if key_type in KEY_TYPES else None

        def key_type(self, node):
            if isinstance(node, ast.Name):
                for frame in reversed(self.key_bindings):
                    if node.id in frame:
                        return frame[node.id]
            if self.verification_key_projection(node):
                return NACL_VERIFY_KEY
            if self.instance_field(node):
                return self.instance_keys[-1].get(node.attr)
            if isinstance(node, ast.Call):
                callee = called_name(node.func)
                if callee in returns_key:
                    return returns_key[callee]
                if callee in KEY_TYPES:
                    return callee
                owner, _, operation = callee.rpartition(".")
                if owner in KEY_TYPES and operation in {
                    "generate",
                    "from_private_bytes",
                    "from_public_bytes",
                }:
                    return owner
            return None

        def visit_Assign(self, node):
            self.generic_visit(node)
            key_type = self.key_type(node.value)
            for target in node.targets:
                self.bind_target(target, key_type)

        def visit_AnnAssign(self, node):
            self.generic_visit(node)
            self.bind_target(node.target, called_name(node.annotation))

        def resolved_name(self, node):
            if isinstance(node, ast.Attribute) and node.attr in {"sign", "verify"}:
                owner = self.key_type(node.value)
                if owner is not None:
                    return f"{owner}.{node.attr}"
            return called_name(node)

        def record(self, name):
            calls[".".join(self.scope) or "<module>"][name] += 1

        def visit_Call(self, node):
            name = self.resolved_name(node.func)
            if primitive(name):
                self.record(name)
            self.generic_visit(node)

        def reference(self, node):
            parent = parents.get(id(node))
            is_callee = isinstance(parent, ast.Call) and parent.func is node
            is_receiver = isinstance(parent, ast.Attribute) and parent.value is node
            is_type_check = (
                isinstance(parent, ast.Call)
                and called_name(parent.func) in {"isinstance", "issubclass"}
                and len(parent.args) == 2
                and parent.args[1] is node
                and called_name(node) in KEY_TYPES
            )
            if (
                isinstance(node.ctx, ast.Load)
                and id(node) not in annotations
                and self.verification_key_projection(node)
            ):
                self.record(f"reference:{NACL_SIGNING_KEY}.verify_key")
            elif (
                isinstance(node.ctx, ast.Load)
                and id(node) not in annotations
                and not is_callee
                and not is_receiver
                and not is_type_check
            ):
                name = self.resolved_name(node)
                if primitive(name):
                    self.record("reference:" + name)
            self.generic_visit(node)

        visit_Name = reference
        visit_Attribute = reference

    Visitor().visit(tree)
    return dict(calls)


def primitive(name: str) -> bool:
    return name.startswith(PRIMITIVE_MODULES)


def listed_file_error(root: Path, file: str) -> str | None:
    path = PurePosixPath(file)
    if path.is_absolute() or path.as_posix() != file or ".." in path.parts:
        return f"listed source file must be a repository-relative path: {file}"
    resolved = root / file
    if not resolved.is_file():
        return f"listed source file {file} is missing or is not a regular file"
    return None


def check_inventory(root: Path, inventory: dict) -> list[str]:
    errors = []
    guard = inventory["primitive_guard"]
    if "legacy_files" in guard:
        errors.append("legacy_files is replaced by primitive_guard.exempt_calls")
    matches: dict[tuple[str, str, str], int] = {}
    listed_files = {
        file
        for path in inventory.get("creation_paths", ())
        if path.get("repo") == "aweb"
        for file in path.get("files", ())
        if file.endswith(".py")
    }
    exemptions = guard.get("exempt_calls")
    if not isinstance(exemptions, list):
        return [*errors, "primitive_guard.exempt_calls must be an array"]
    for entry in exemptions:
        if not isinstance(entry, dict):
            errors.append(
                "primitive exemption requires file, symbol, callee and reason"
            )
            continue
        file, symbol, callee, reason = (
            entry.get(key) for key in ("file", "symbol", "callee", "reason")
        )
        if not isinstance(file, str) or not file.strip():
            errors.append(
                "primitive exemption requires file, symbol, callee and reason"
            )
            continue
        if not file.endswith(".py"):
            continue
        listed_files.add(file)
        if not all(
            isinstance(value, str) and value.strip()
            for value in (symbol, callee, reason)
        ):
            errors.append(
                "primitive exemption requires file, symbol, callee and reason"
            )
            continue
        key = (file, symbol, callee)
        site = ":".join(key)
        if not primitive(callee):
            errors.append(f"primitive exemption must name a call: {site}")
        elif key in matches:
            errors.append(f"duplicate primitive exemption: {site}")
        else:
            matches[key] = 0
    for file in sorted(listed_files):
        error = listed_file_error(root, file)
        if error is not None:
            errors.append(error)

    for path in source_files(root):
        file = path.relative_to(root).as_posix()
        try:
            uses = scan_python_source(
                path.read_text(encoding="utf-8"),
                module=module_name(file),
                package=path.name == "__init__.py",
            )
        except (SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"cannot scan {file}: {exc}")
            continue
        for symbol, calls in uses.items():
            if (file, symbol) in SHARED_SITES:
                continue
            for callee, count in calls.items():
                key = (file, symbol, callee)
                if key in matches:
                    matches[key] += count
                else:
                    errors.append(
                        "raw Python crypto must use the shared verifier: "
                        + ":".join(key)
                    )
    for key, count in matches.items():
        site = ":".join(key)
        if count == 0:
            errors.append(f"unused primitive exemption: {site}")
        elif count != 1:
            errors.append(f"primitive exemption matches {count} calls: {site}")
    return sorted(errors)


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
