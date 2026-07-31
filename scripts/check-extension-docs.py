#!/usr/bin/env python3
"""Check extension/interoperability documentation against repository source."""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

PRIVATE_TRANSITION_DOCS = {
    "restructuring/ac-cross-boundary-fk-inventory.md",
    "support/aasn-migration-evidence-runbook.md",
}

REMOVED_DOCS = {
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

HOOK_INVENTORY = "vectors/mutation-hook-call-sites-v1.json"

MANAGED_GATEWAY_PRIVATE_TOKENS = (
    "a" + "c_config",
    "a" + "c_base_url",
    "AWEB_A2A_GW_" + "AC_BASE_URL",
    "a2a-" + "ac-managed-gateway-contract",
    "a2a-gateway-" + "ac-managed",
    "a2a-gw-" + "ac",
    "a" + "c_config_expired",
    "/api/v1/a2a/gateway/" + "config",
    "AC-" + "managed",
    "AC runtime " + "config",
    "AC " + "bridge",
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


class _HookCallVisitor(ast.NodeVisitor):
    def __init__(self, relative: str, failures: list[str]) -> None:
        self.relative = relative
        self.failures = failures
        self.function_stack: list[str] = []
        self.call_sites: list[dict[str, str]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        function = node.func
        if isinstance(function, ast.Name):
            name = function.id
        elif isinstance(function, ast.Attribute):
            name = function.attr
        else:
            name = ""
        if name == "fire_mutation_hook":
            event_expression = node.args[1] if len(node.args) >= 2 else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "event_type"),
                None,
            )
            literals = _string_literals(event_expression) if event_expression is not None else set()
            if not literals:
                self.failures.append(
                    f"unsupported non-literal fire_mutation_hook event expression: {self.relative}:{node.lineno}"
                )
            else:
                enclosing_function = ".".join(self.function_stack) or "<module>"
                for event in sorted(literals):
                    self.call_sites.append(
                        {"source": self.relative, "function": enclosing_function, "event": event}
                    )
        self.generic_visit(node)


def _source_hook_call_sites(root: Path, failures: list[str]) -> list[dict[str, str]]:
    call_sites: list[dict[str, str]] = []
    source_root = root / "server/src/aweb"
    if not source_root.is_dir():
        failures.append("missing hook source root: server/src/aweb")
        return call_sites
    for path in sorted(source_root.rglob("*.py")):
        relative = str(path.relative_to(root))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        visitor = _HookCallVisitor(relative, failures)
        visitor.visit(tree)
        call_sites.extend(visitor.call_sites)
    call_sites.sort(key=lambda item: (item["source"], item["function"], item["event"]))
    if not call_sites:
        failures.append("no fire_mutation_hook event calls found under server/src/aweb")
    return call_sites


def _tracked_files(root: Path, failures: list[str]) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        failures.append("cannot derive tracked repository corpus with git ls-files")
        return set()
    return {path for path in result.stdout.decode("utf-8").split("\0") if path}


def _tracked_docs_markdown(root: Path, failures: list[str]) -> set[str]:
    return {
        path.removeprefix("docs/")
        for path in _tracked_files(root, failures)
        if path.startswith("docs/") and path.endswith(".md")
    }


def _is_managed_gateway_surface(relative: str) -> bool:
    return (
        (
            relative.startswith("cli/go/")
            and any("a2a" in part.lower() for part in Path(relative).parts[2:])
        )
        or relative.startswith("cli/go/npm/")
        or relative.startswith("docs/a2a")
        or relative.startswith("docs/examples/a2a-")
        or relative.startswith("docs/vectors/a2a-")
        or relative.startswith("cli/go/internal/conformance/vectors/a2a-")
        or relative in {
            "docs/README.md",
            "docs/vectors/README.md",
            "cli/go/.goreleaser.yaml",
            "Makefile",
            "scripts/check-extension-docs.py",
        }
        or (
            relative.startswith(".github/workflows/")
            and "a2a" in Path(relative).name.lower()
        )
        or (
            relative.startswith("cli/go/")
            and relative.count("/") == 2
            and "a2a" in Path(relative).name.lower()
        )
        or (relative.startswith("scripts/") and "a2a" in Path(relative).name.lower())
    )


def check(
    root: Path,
    tracked_markdown: set[str] | None = None,
    tracked_files: set[str] | None = None,
) -> list[str]:
    failures: list[str] = []

    if tracked_files is None:
        tracked_files = _tracked_files(root, failures)
    neutrality_paths = [root / relative for relative in sorted(tracked_files) if _is_managed_gateway_surface(relative)]
    for path in neutrality_paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in MANAGED_GATEWAY_PRIVATE_TOKENS:
            if token in text:
                failures.append(f"{path.relative_to(root)} retains private managed-gateway token {token!r}")
    removed_private_paths = (
        root / "docs" / ("a2a-" + "ac-managed-gateway-contract.md"),
        root / "docs/examples" / ("a2a-gateway-" + "ac-managed.yaml"),
    )
    for path in removed_private_paths:
        if path.exists():
            failures.append(f"removed private managed-gateway path returned: {path.relative_to(root)}")
    docs = root / "docs"

    for relative in REMOVED_DOCS:
        if (docs / relative).exists():
            failures.append(f"superseded document still exists: docs/{relative}")
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
    source_call_sites = _source_hook_call_sites(root, failures)
    for event in sorted({item["event"] for item in source_call_sites}):
        if f"`{event}`" not in hook_text:
            failures.append(f"aw-hooks-sot.md omits source-emitted event {event!r}")
    if "app.state.on_mutation" not in hook_text:
        failures.append("aw-hooks-sot.md omits the shipped app.state.on_mutation seam")

    inventory_path = docs / HOOK_INVENTORY
    if not inventory_path.is_file():
        failures.append(f"missing mutation hook call-site inventory: docs/{HOOK_INVENTORY}")
    else:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory_call_sites = inventory.get("call_sites") if isinstance(inventory, dict) else None
        if (
            not isinstance(inventory, dict)
            or inventory.get("schema") != "aweb.mutation-hook-call-sites.v1"
            or not isinstance(inventory_call_sites, list)
            or not all(
                isinstance(item, dict)
                and set(item) == {"source", "function", "event"}
                and all(isinstance(value, str) and value for value in item.values())
                for item in inventory_call_sites
            )
        ):
            failures.append(f"invalid mutation hook call-site inventory: docs/{HOOK_INVENTORY}")
        else:
            source_counts = Counter(
                (item["source"], item["function"], item["event"]) for item in source_call_sites
            )
            inventory_counts = Counter(
                (item["source"], item["function"], item["event"]) for item in inventory_call_sites
            )
            for call_site, count in sorted((source_counts - inventory_counts).items()):
                failures.append(f"mutation hook inventory omits source call site {call_site!r} x{count}")
            for call_site, count in sorted((inventory_counts - source_counts).items()):
                failures.append(f"mutation hook inventory retains absent call site {call_site!r} x{count}")

    runbook = public_text.get("a2a-release-runbook.md", "")
    makefile = (root / "Makefile").read_text(encoding="utf-8") if (root / "Makefile").is_file() else ""
    generator = "go run ./tools/a2a-gateway-check-workspace -output"
    if generator not in runbook or generator not in makefile:
        failures.append("A2A release image check does not generate a synthetic gateway workspace")
    if '$(CURDIR):/workspace:ro' in makefile:
        failures.append("A2A release image check mounts the real repository workspace")
    if '-v "$$workspace:/workspace:ro"' not in makefile:
        failures.append("A2A release image check does not mount its throwaway workspace")

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

    all_markdown = tracked_markdown if tracked_markdown is not None else _tracked_docs_markdown(root, failures)
    for relative in sorted(all_markdown):
        if not (docs / relative).is_file():
            failures.append(f"tracked Markdown is missing from the working tree: docs/{relative}")
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

    tracked_failures: list[str] = []
    tracked_files = _tracked_files(root, tracked_failures)
    tracked_markdown = {
        path.removeprefix("docs/")
        for path in tracked_files
        if path.startswith("docs/") and path.endswith(".md")
    }
    if tracked_failures:
        print(f"self-test setup failed: {tracked_failures[0]}")
        return 1

    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        shutil.copytree(root / "docs", tmp / "docs")
        for relative in sorted(tracked_files):
            if not _is_managed_gateway_surface(relative) or relative.startswith("docs/"):
                continue
            destination = tmp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination)
        for relative in HOOK_SOURCES:
            destination = tmp / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination)

        untracked_note = tmp / "docs/untracked-self-test-note.md"
        untracked_note.write_text("not part of the tracked corpus\n", encoding="utf-8")
        if failures := check(tmp, tracked_markdown, tracked_files):
            print(f"self-test failed: untracked Markdown changed the tracked corpus: {failures[0]}")
            return 1
        newly_tracked = tracked_markdown | {"untracked-self-test-note.md"}
        failures = check(tmp, newly_tracked, tracked_files)
        if not any(
            "omits public Markdown paths: untracked-self-test-note.md" in failure
            for failure in failures
        ):
            print("self-test failed: existing newly tracked public Markdown was not rejected")
            return 1
        untracked_note.unlink()
        failures = check(tmp, tracked_markdown | {"missing-tracked-self-test-note.md"}, tracked_files)
        if not any("tracked Markdown is missing" in failure for failure in failures):
            print("self-test failed: missing tracked Markdown was not detected")
            return 1

        neutrality_mutations = (
            ("cli/go/cmd/aweb-a2a-gw/audit.go", "a" + "c_config", False),
            ("cli/go/a2a/client.go", "a" + "c_config", False),
            ("cli/go/cmd/aw/a2a.go", "a" + "c_config", False),
            ("cli/go/tools/a2a-gateway-check-workspace/main.go", "a" + "c_config", False),
            ("docs/a2a-release-runbook.md", "a" + "c_config", False),
            ("cli/go/cmd/aweb-a2a-gw/new_surface.go", "a" + "c_config", True),
            ("cli/go/a2a/new_surface.go", "a" + "c_config", True),
            (".github/workflows/a2a-gateway-secondary.yml", "a" + "c_config", True),
            ("docs/a2a.md", "a2a-gw-" + "ac.yaml", False),
        )
        for relative, token, newly_tracked_surface in neutrality_mutations:
            path = tmp / relative
            original = path.read_text(encoding="utf-8") if path.exists() else None
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text((original or "") + f"\n{token}\n", encoding="utf-8")
            mutation_files = tracked_files | ({relative} if newly_tracked_surface else set())
            mutation_failures = check(tmp, tracked_markdown, mutation_files)
            expected = f"{relative} retains private managed-gateway token"
            if not any(expected in failure for failure in mutation_failures):
                print(f"self-test failed: managed-gateway neutrality mutation was not detected in {relative}")
                return 1
            if original is None:
                path.unlink()
            else:
                path.write_text(original, encoding="utf-8")

        hook = tmp / "docs/aw-hooks-sot.md"
        hook.write_text(hook.read_text(encoding="utf-8").replace("`task.created`", "`task-created`"), encoding="utf-8")

        message_source = tmp / "server/src/aweb/routes/messages.py"
        message_text = message_source.read_text(encoding="utf-8")
        message_text = message_text.replace("await fire_mutation_hook(", "await omitted_mutation_hook(", 1)
        message_text += '\n\nasync def negative_new_hook_call_site():\n    await fire_mutation_hook(None, "message.sent", {})\n'
        message_source.write_text(message_text, encoding="utf-8")

        chat_source = tmp / "server/src/aweb/routes/chat.py"
        chat_source.write_text(
            chat_source.read_text(encoding="utf-8").replace('"chat.message_sent",', "dynamic_event_name,", 1),
            encoding="utf-8",
        )

        makefile = tmp / "Makefile"
        makefile.write_text(
            makefile.read_text(encoding="utf-8").replace(
                '-v "$$workspace:/workspace:ro"', '-v "$(CURDIR):/workspace:ro"', 1
            ),
            encoding="utf-8",
        )
        failures = check(tmp, tracked_markdown, tracked_files)
        required_failures = {
            "missing documented event": "task.created",
            "new repeated-event call site": "inventory omits source call site",
            "removed repeated-event call site": "inventory retains absent call site",
            "dynamic event expression": "unsupported non-literal",
            "real workspace release mount": "mounts the real repository workspace",
        }
        for label, expected in required_failures.items():
            if not any(expected in failure for failure in failures):
                print(f"self-test failed: {label} was not detected")
                return 1

    print(
        "self-test passed: tracked corpus, managed-gateway neutrality, event/call-site multiplicity, "
        "dynamic-expression, and real-workspace release-mount drift controls reject their mutations"
    )
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
