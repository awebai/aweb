from __future__ import annotations

import ast
from pathlib import Path


def test_beadhub_only_imports_supported_aweb_surface() -> None:
    """Guardrail: keep beadhub's dependency on aweb intentional and stable.

    BeadHub embeds the aweb protocol server, so imports from `aweb.routes.*` are expected.
    Everything else should be a small, explicit public surface.
    """

    allowed_roots = ("aweb",)
    allowed_prefixes = (
        "aweb.alias_allocator",
        "aweb.api",
        "aweb.auth",
        "aweb.bootstrap",
        "aweb.client",
        "aweb.messages_service",
        "aweb.presence",
        "aweb.routes",
        "aweb.service_errors",
        "aweb.tasks_service",
    )

    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src" / "beadhub"

    violations: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name in allowed_roots:
                        continue
                    if name.startswith("aweb."):
                        if not any(name == p or name.startswith(p + ".") for p in allowed_prefixes):
                            violations.append(f"{path}: import {name}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod in allowed_roots:
                    continue
                if mod.startswith("aweb."):
                    if not any(mod == p or mod.startswith(p + ".") for p in allowed_prefixes):
                        violations.append(f"{path}: from {mod} import ...")

    assert not violations, "Unsupported aweb imports:\n" + "\n".join(violations)
