#!/usr/bin/env python3
"""Check extension/interoperability documentation against repository source."""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path

PRIVATE_TRANSITION_DOCS = {
    "a2a-ac-managed-gateway-contract.md",
    "custodial-managed-encryption.md",
    "restructuring/ac-cross-boundary-fk-inventory.md",
    "support/aasn-migration-evidence-runbook.md",
}

REMOVED_DOCS = {
    "federation-architecture.md",
    "restructuring/app-event-subscriptions-contract.md",
    "restructuring/app-manifest-schema.md",
    "restructuring/app-registry-grants-read-api.md",
}

PUBLIC_EXTENSION_DOCS = (
    "README.md",
    "a2a.md",
    "a2a-awid-publication-contract.md",
    "a2a-release-runbook.md",
    "app-events.md",
    "app-manifest.md",
    "app-registry.md",
    "aw-hooks-sot.md",
    "support-contract-v1.md",
    "team-auth-envelope-v2.md",
    "vectors/README.md",
)

HOOK_SOURCES = (
    "server/src/aweb/routes/messages.py",
    "server/src/aweb/routes/chat.py",
    "server/src/aweb/routes/federation.py",
    "server/src/aweb/routes/reservations.py",
    "server/src/aweb/coordination/routes/tasks.py",
)

FORBIDDEN_PUBLIC_REFERENCES = (
    "../ac",
    "ac/docs/",
    "awebai/naapp-specs",
    "a2a-ac-managed-gateway-contract",
    "a2a-gateway-ac-managed",
    "restructuring/app-event-subscriptions-contract.md",
    "restructuring/app-manifest-schema.md",
    "restructuring/app-registry-grants-read-api.md",
)


def _string_literals(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _string_literals(node.body) | _string_literals(node.orelse)
    return set()


def _source_hook_events(root: Path, failures: list[str]) -> set[str]:
    events: set[str] = set()
    for relative in HOOK_SOURCES:
        path = root / relative
        if not path.is_file():
            failures.append(f"missing hook source: {relative}")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            function = node.func
            name = function.id if isinstance(function, ast.Name) else ""
            if name == "fire_mutation_hook":
                events.update(_string_literals(node.args[1]))
    return events


def check(root: Path) -> list[str]:
    failures: list[str] = []
    docs = root / "docs"

    for relative in REMOVED_DOCS:
        if (docs / relative).exists():
            failures.append(f"superseded document still exists: docs/{relative}")
    for relative in PRIVATE_TRANSITION_DOCS:
        if not (docs / relative).is_file():
            failures.append(f"managed/private transition artifact moved outside coordinated relocation: docs/{relative}")

    public_text: dict[str, str] = {}
    for relative in PUBLIC_EXTENSION_DOCS:
        path = docs / relative
        if not path.is_file():
            failures.append(f"missing public extension document: docs/{relative}")
            continue
        public_text[relative] = path.read_text(encoding="utf-8")

    for relative, text in public_text.items():
        for forbidden in FORBIDDEN_PUBLIC_REFERENCES:
            if forbidden in text:
                failures.append(f"docs/{relative} retains private/superseded reference {forbidden!r}")

    hook_text = public_text.get("aw-hooks-sot.md", "")
    for event in sorted(_source_hook_events(root, failures)):
        if f"`{event}`" not in hook_text:
            failures.append(f"aw-hooks-sot.md omits source-emitted event {event!r}")
    if "app.state.on_mutation" not in hook_text:
        failures.append("aw-hooks-sot.md omits the shipped app.state.on_mutation seam")

    vectors = sorted(path.name for path in (docs / "vectors").glob("*.json"))
    vector_index = public_text.get("vectors/README.md", "")
    for name in vectors:
        if f"`{name}`" not in vector_index:
            failures.append(f"vectors/README.md omits {name}")
    if "digest-only fixture" not in vector_index or "placeholder" not in vector_index:
        failures.append("vectors/README.md does not identify the non-verifying digest-only fixture")

    support_text = public_text.get("support-contract-v1.md", "")
    if "current for OSS registry-read envelopes" not in support_text or "doctor.v1" not in support_text:
        failures.append("support-contract-v1.md does not state its current registry/doctor compatibility boundary")
    for relative in ("app-events.md", "app-manifest.md", "app-registry.md"):
        # Checking only the header keeps a distant use of the word from masking a bad status.
        header = "\n".join(public_text.get(relative, "").splitlines()[:12])
        if "experimental" not in header:
            failures.append(f"docs/{relative} does not state its experimental lifecycle in the header")

    identity_contract = docs / "identity-messaging-contract.md"
    if not identity_contract.is_file():
        failures.append("missing current federation authority: docs/identity-messaging-contract.md")
    else:
        text = identity_contract.read_text(encoding="utf-8")
        if "Accept-Encoding: identity" not in text or "Federation Compatibility" not in text:
            failures.append("current identity messaging authority lacks retained federation compatibility rules")

    all_markdown = {str(path.relative_to(docs)) for path in docs.rglob("*.md")}
    expected_public = all_markdown - {"README.md"} - PRIVATE_TRANSITION_DOCS
    readme = (docs / "README.md").read_text(encoding="utf-8")
    links = [
        target
        for target in re.findall(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)", readme)
        if target.endswith(".md") and not target.startswith("../")
    ]
    counts = Counter(links)
    missing = sorted(expected_public - set(counts))
    duplicate = sorted(target for target, count in counts.items() if count != 1)
    extra = sorted(set(counts) - expected_public)
    if missing:
        failures.append(f"docs/README.md omits public Markdown paths: {', '.join(missing)}")
    if duplicate:
        failures.append(f"docs/README.md duplicates public Markdown paths: {', '.join(duplicate)}")
    if extra:
        failures.append(f"docs/README.md links non-public/absent Markdown paths: {', '.join(extra)}")
    if f"{len(all_markdown)} tracked Markdown" not in readme:
        failures.append("docs/README.md tracked-Markdown count is stale")
    if f"{len(expected_public)} public Markdown" not in readme:
        failures.append("docs/README.md public-Markdown count is stale")

    return failures


def self_test(root: Path) -> int:
    if failures := check(root):
        print("self-test setup is not green:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        shutil.copytree(root / "docs", tmp / "docs")
        for relative in HOOK_SOURCES:
            destination = tmp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination)
        hook = tmp / "docs/aw-hooks-sot.md"
        hook.write_text(hook.read_text(encoding="utf-8").replace("`task.created`", "`task-created`"), encoding="utf-8")
        failures = check(tmp)
        if not any("task.created" in failure for failure in failures):
            print("self-test failed: removing a source-emitted hook event was not detected")
            return 1

    print("self-test passed: source/doc hook drift is rejected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()

    if args.self_test:
        return self_test(root)

    failures = check(root)
    if failures:
        print("Extension documentation check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("extension documentation matches source inventories and authority map")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
