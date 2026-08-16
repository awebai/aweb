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

PRIVATE_TRANSITION_PATHS = (
    "docs/restructuring/" + "ac-cross-boundary-" + "fk-inventory.md",
    "docs/support/" + "aasn-migration-" + "evidence-runbook.md",
)

PRIVATE_TRANSITION_PATH_NAMES = (
    "ac-cross-boundary-" + "fk-inventory",
    "aasn-migration-" + "evidence-runbook",
)

PRIVATE_TRANSITION_CONTENT_RULES = (
    (
        "private database inventory",
        ("cross-boundary " + "foreign keys", "aweb_" + "cloud", "aweb_" + "overlay"),
    ),
    (
        "private production runbook",
        ("migration " + "evidence runbook", "production " + "stop conditions"),
    ),
    (
        "AC-only path/name",
        ("ac/backend/src/" + "aweb_cloud/migrations",),
    ),
    (
        "credentialed operator procedure",
        ("database_url=" + "service=", "pg_dump --" + "data-only"),
    ),
    (
        "private version/image baseline",
        ("production baseline: " + "ac", "server-v1."),
    ),
    (
        "private personnel approval flow",
        ("credentialed " + "human operator", "reviews this plan before execution"),
    ),
)

# One non-document surface per content rule, so every category is proven outside
# docs/. Keyed by rule label: adding a rule without a fixture fails the self-test.
PRIVATE_TRANSITION_NON_DOC_SURFACES = {
    "private database inventory": "skills/transition-evidence/SKILL.md",
    "private production runbook": "scripts/self-test-transition-evidence.sh",
    "AC-only path/name": "channel/self-test-package.json",
    "credentialed operator procedure": "deploy/self-test-operator.yaml",
    "private version/image baseline": "server/tests/fixtures/self-test-baseline.txt",
    "private personnel approval flow": "cli/go/npm/self-test-approval.js",
}

REMOVED_DOCS = {
    "aweb-product-sot.md",
    "bootstrapping-operating-patterns-worklog.md",
    "cli-setup-surface-sot.md",
    "company-agent-platform-thesis.md",
    "drafts/agent-guide-running-agents-update.md",
    "launch-readiness-sot.md",
    "market-entry-wedge-research.md",
    "orchestrator-evidence-review.md",
    "restructuring/app-event-subscriptions-contract.md",
    "restructuring/app-manifest-schema.md",
    "restructuring/app-registry-grants-read-api.md",
    "team-blueprints-sot.md",
    "team-extend-implementation-plan.md",
    "website-dashboard-strategy.md",
}

REMOVED_REPO_PATHS = {
    "agents/souls/consultant/decisions/aweb-control-plane-and-apps.md",
    "agents/souls/consultant/docs/customer-centered-aweb-positioning.md",
    "agents/souls/consultant/memory/aweb-anapp-product-constraints.md",
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

FEDERATION_DOC_REQUIREMENTS = {
    "aweb-sot.md": (
        "strict cross-registry sender authority",
        "receiver-wide replay identity",
        "message_ingress_receipts",
        "federation_mutation_outbox",
        "contact_did_aw",
        "/v1/contacts/{contact_id}/bind",
        "legacy_unreplayable",
    ),
    "awid-sot.md": (
        "cross-registry consumption",
        "receiver cache policy",
        "suppress an unseen transition",
    ),
    "identity-messaging-contract.md": (
        "strict cross-registry sender authority",
        "post /v1/federation/messages",
        "aweb_federation_authority_reuse_seconds",
        "receiver-wide replay and contact compatibility",
        "postgresql is the shared authorization",
        "federation-error-reference.md",
    ),
    "global-local-identity-routing.md": (
        "configured home registry",
        "legacy_unreplayable",
        "explicit recipient acceptance",
    ),
    "trust-model.md": (
        "strict external-address",
        "explicit acceptance",
        "never transfers",
    ),
    "identity-key-verification.md": (
        "strict federation use",
        "does not prove source freshness",
        "strict federation ingress does not accept",
    ),
    "e2e-messaging-contract.md": (
        "cross-registry authority ordering",
        "recipient_encryption_assertion_missing",
        "receiver-wide receipt",
    ),
    "mail-and-chat.md": (
        "identity-bound contact",
        "one receiver-wide",
        "federation error reference",
    ),
    "messaging-contract-matrix.md": (
        "source suppression",
        "legacy_unreplayable",
        "strict sender ed25519",
    ),
    "self-hosting-guide.md": (
        "cross-registry authority and migration",
        "015_federation_delivery_policy.sql",
        "aweb_federation_authority_reuse_seconds",
        "cannot authorize during a postgresql outage",
        "at-least-once",
        "generated federation error reference",
    ),
}

MANAGED_GATEWAY_PRIVATE_TOKENS = (
    "a" + "c_config",
    "a" + "c_base_url",
    "AWEB_A2A_GW_AC_" + "BASE_URL",
    "a2a-ac-" + "managed-gateway-contract",
    "a2a-gateway-ac-" + "managed",
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


def _readme_h2_links(readme: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current_section = ""
    for line in readme.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", line)
        if heading:
            current_section = heading.group(1)
            sections.setdefault(current_section, [])
        sections.setdefault(current_section, []).extend(
            target
            for target in re.findall(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)", line)
            if target.endswith(".md") and not target.startswith("../")
        )
    return sections


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


def _decodable_text(path: Path) -> str | None:
    """Return casefolded file text, or None when the content is binary or not UTF-8.

    Content rules run over every tracked file, so binary blobs are excluded
    explicitly rather than coerced into text with replacement characters.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8").casefold()
    except UnicodeDecodeError:
        return None


def _tracked_text_corpus(root: Path, tracked_files: set[str]) -> dict[str, str]:
    corpus: dict[str, str] = {}
    for relative in tracked_files:
        path = root / relative
        if not path.is_file():
            continue
        text = _decodable_text(path)
        if text is not None:
            corpus[relative] = text
    return corpus


def _is_managed_gateway_surface(relative: str) -> bool:
    return (
        any("a2a" in part.lower() for part in Path(relative).parts)
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


def _check_federation_docs(root: Path, failures: list[str]) -> None:
    docs = root / "docs"
    vector_path = docs / "vectors/federation-authority-state-v1.json"
    reference_path = docs / "federation-error-reference.md"
    try:
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"cannot read canonical federation authority vector: {exc}")
        return

    policies = vector.get("selected_policies", {})
    if (
        policies.get("receiver_reuse_default_seconds") != 60
        or policies.get("receiver_reuse_max_seconds") != 60
        or policies.get("receiver_reuse_configurable_only_downward") is not True
        or policies.get("receiver_reuse_is_freshness_sla") is not False
        or policies.get("contact_authority") != "identity_bound_address_and_did_aw"
        or policies.get("contact_replacement")
        != "controller_proof_and_authenticated_recipient_acceptance"
        or policies.get("contact_transfer") != "never_automatic"
    ):
        failures.append("canonical federation selected-policy vector changed without docs reconciliation")

    if not reference_path.is_file():
        failures.append("missing generated federation error reference")
    else:
        reference = reference_path.read_text(encoding="utf-8")
        for error in vector.get("stable_errors", []):
            reason = error.get("reason") if isinstance(error, dict) else None
            if not isinstance(reason, str) or reference.count(f"| `{reason}` |") != 1:
                failures.append(f"generated federation error reference does not contain {reason!r} exactly once")

    for relative, required_text in FEDERATION_DOC_REQUIREMENTS.items():
        path = docs / relative
        if not path.is_file():
            failures.append(f"missing federation SOT/support surface: docs/{relative}")
            continue
        text = path.read_text(encoding="utf-8").casefold()
        for requirement in required_text:
            if requirement.casefold() not in text:
                failures.append(f"docs/{relative} omits federation contract text {requirement!r}")


def check(
    root: Path,
    tracked_markdown: set[str] | None = None,
    tracked_files: set[str] | None = None,
) -> list[str]:
    failures: list[str] = []

    if tracked_files is None:
        tracked_files = _tracked_files(root, failures)
    for relative in sorted(tracked_files):
        normalized_relative = relative.casefold()
        for token in MANAGED_GATEWAY_PRIVATE_TOKENS:
            if token.casefold() in normalized_relative:
                failures.append(f"tracked path {relative} retains private managed-gateway name {token!r}")
        for name in PRIVATE_TRANSITION_PATH_NAMES:
            if name.casefold() in normalized_relative:
                failures.append(f"tracked path {relative} retains private transition document name")

    for relative, normalized_text in sorted(_tracked_text_corpus(root, tracked_files).items()):
        for name in PRIVATE_TRANSITION_PATH_NAMES:
            if name.casefold() in normalized_text:
                failures.append(f"tracked file {relative} references private transition document name")
        for label, terms in PRIVATE_TRANSITION_CONTENT_RULES:
            if all(term.casefold() in normalized_text for term in terms):
                failures.append(f"{relative} retains {label}")

    for relative in PRIVATE_TRANSITION_PATHS:
        if (root / relative).exists():
            failures.append(f"removed private transition path returned: {relative}")

    for relative in sorted(REMOVED_REPO_PATHS):
        if (root / relative).exists():
            failures.append(f"removed company-strategy path returned: {relative}")

    for relative in sorted(tracked_files):
        path = root / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        normalized_text = raw.decode("utf-8", errors="replace").casefold()
        for token in MANAGED_GATEWAY_PRIVATE_TOKENS:
            if token.casefold() in normalized_text:
                failures.append(f"{relative} retains private managed-gateway token {token!r}")
    removed_private_paths = (
        root / "docs" / ("a2a-ac-" + "managed-gateway-contract.md"),
        root / "docs/examples" / ("a2a-gateway-ac-" + "managed.yaml"),
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
    e2e_script_path = root / "scripts" / "e2e-a2a-gateway-docker.sh"
    e2e_script = e2e_script_path.read_text(encoding="utf-8") if e2e_script_path.is_file() else ""
    generator = "go run ./tools/a2a-gateway-check-workspace -output"
    if generator not in runbook:
        failures.append("A2A release image check does not generate a synthetic gateway workspace")
    if '$(CURDIR):/workspace:ro' in makefile or '"$ROOT:/workspace' in e2e_script:
        failures.append("A2A release image check mounts the real repository workspace")
    if '-v "$GATEWAY_DIR:/workspace:ro"' not in e2e_script:
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

    _check_federation_docs(root, failures)

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
    expected_public = all_markdown - {"README.md"}
    readme = (docs / "README.md").read_text(encoding="utf-8")
    links = [
        target
        for target in re.findall(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)", readme)
        if target.endswith(".md") and not target.startswith("../")
    ]
    counts = Counter(links)
    section_links = _readme_h2_links(readme)
    if section_links.get("Non-normative strategy and research"):
        failures.append("public docs index still publishes a strategy/research section")
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

        private_transition_mutations = (
            (
                "private database inventory",
                "Cross-boundary " + "foreign keys\naweb_" + "cloud rows\naweb_" + "overlay changes\n",
            ),
            (
                "private production runbook",
                "Migration " + "evidence runbook\nProduction " + "stop conditions\n",
            ),
            (
                "AC-only path/name",
                "ac/backend/src/" + "aweb_cloud/migrations/001.sql\n",
            ),
            (
                "credentialed operator procedure",
                "DATABASE_URL=" + "service=production\npg_dump --" + "data-only\n",
            ),
            (
                "private version/image baseline",
                "Production baseline: " + "AC v9.9.9\nserver-v1.2.3\n",
            ),
            (
                "private personnel approval flow",
                "Credentialed " + "human operator\nReviewer reviews this plan before execution\n",
            ),
        )
        rule_labels = {label for label, _ in PRIVATE_TRANSITION_CONTENT_RULES}
        if {label for label, _ in private_transition_mutations} != rule_labels:
            print("self-test failed: every content rule needs a document fixture")
            return 1
        if set(PRIVATE_TRANSITION_NON_DOC_SURFACES) != rule_labels:
            print("self-test failed: every content rule needs a non-document surface fixture")
            return 1

        for index, (label, content) in enumerate(private_transition_mutations):
            relative = f"docs/private-transition-negative-{index}.md"
            path = tmp / relative
            path.write_text(content, encoding="utf-8")
            mutation_failures = check(
                tmp,
                tracked_markdown | {relative.removeprefix("docs/")},
                tracked_files | {relative},
            )
            expected = f"{relative} retains {label}"
            if expected not in mutation_failures:
                print(f"self-test failed: {label} fixture was not detected")
                return 1
            path.unlink()

        for label, content in private_transition_mutations:
            relative = PRIVATE_TRANSITION_NON_DOC_SURFACES[label]
            path = tmp / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            mutation_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            expected = f"{relative} retains {label}"
            if expected not in mutation_failures:
                print(f"self-test failed: {label} was not detected on non-document surface {relative}")
                return 1
            path.unlink()

        for index, (label, content) in enumerate(private_transition_mutations):
            relative = f"server/tests/fixtures/private-transition-binary-{index}.bin"
            path = tmp / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\0\x1f\x8b" + content.encode("utf-8") + b"\0")
            mutation_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            if any(failure.startswith(f"{relative} retains") for failure in mutation_failures):
                print(f"self-test failed: binary content was scanned as text for {label}")
                return 1
            path.write_bytes("Príväte".encode("latin-1") + content.encode("utf-8"))
            mutation_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            if any(failure.startswith(f"{relative} retains") for failure in mutation_failures):
                print(f"self-test failed: undecodable content was scanned as text for {label}")
                return 1
            path.unlink()

        for transition_path in PRIVATE_TRANSITION_PATHS:
            transition_file = tmp / transition_path
            transition_file.parent.mkdir(parents=True, exist_ok=True)
            transition_file.write_text("generic: true\n", encoding="utf-8")
            transition_failures = check(tmp, tracked_markdown, tracked_files)
            expected = f"removed private transition path returned: {transition_path}"
            if expected not in transition_failures:
                print(f"self-test failed: private transition path returned: {transition_path}")
                return 1
            transition_file.unlink()

        for index, transition_name in enumerate(PRIVATE_TRANSITION_PATH_NAMES):
            relative = f"reviewer/{transition_name}-{index}.md"
            transition_file = tmp / relative
            transition_file.parent.mkdir(parents=True, exist_ok=True)
            transition_file.write_text("generic: true\n", encoding="utf-8")
            transition_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            expected = f"tracked path {relative} retains private transition document name"
            if expected not in transition_failures:
                print(f"self-test failed: private transition name returned: {transition_name}")
                return 1
            transition_file.unlink()

            consumer_relative = f"reviewer/private-transition-consumer-{index}.txt"
            consumer_file = tmp / consumer_relative
            consumer_file.write_text(f"docs/archive/{transition_name}.md\n", encoding="utf-8")
            transition_failures = check(
                tmp,
                tracked_markdown,
                tracked_files | {consumer_relative},
            )
            expected = f"tracked file {consumer_relative} references private transition document name"
            if expected not in transition_failures:
                print(f"self-test failed: private transition consumer returned: {transition_name}")
                return 1
            consumer_file.unlink()

        neutrality_mutations = (
            ("README.md", "a" + "c_config", False),
            ("cli/go/cmd/aweb-a2a-gw/audit.go", "a" + "c_config", False),
            ("cli/go/a2a/client.go", "a" + "c_config", False),
            ("awid/src/awid/a2a_publication.py", "a" + "c_config", False),
            ("cli/go/awid/a2a_publication.go", "a" + "c_config", False),
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

        path_mutations = (
            "docs/examples/A2A-GW-" + "AC.yaml",
            "reviewer/AC_" + "CONFIG.go",
            "reviewer/a2a/AC_" + "CONFIG.go",
            "docs/examples/a2a-ac-" + "managed-gateway-contract-copy.yaml",
        )
        for relative in path_mutations:
            path = tmp / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("generic: true\n", encoding="utf-8")
            mutation_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            expected = f"tracked path {relative} retains private managed-gateway name"
            if not any(expected in failure for failure in mutation_failures):
                print(f"self-test failed: private managed-gateway path was not detected: {relative}")
                return 1
            path.unlink()

        for relative in sorted(REMOVED_REPO_PATHS):
            path = tmp / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("retired company strategy\n", encoding="utf-8")
            mutation_failures = check(tmp, tracked_markdown, tracked_files | {relative})
            expected = f"removed company-strategy path returned: {relative}"
            if not any(expected in failure for failure in mutation_failures):
                print(f"self-test failed: removed strategy path was not detected: {relative}")
                return 1
            path.unlink()

        for relative, required_text in FEDERATION_DOC_REQUIREMENTS.items():
            path = tmp / "docs" / relative
            original = path.read_text(encoding="utf-8")
            requirement = required_text[0]
            mutated = re.sub(re.escape(requirement), "removed-federation-contract-text", original, flags=re.I)
            if mutated == original:
                print(f"self-test setup failed: docs/{relative} lacks {requirement!r}")
                return 1
            path.write_text(mutated, encoding="utf-8")
            mutation_failures = check(tmp, tracked_markdown, tracked_files)
            expected = f"docs/{relative} omits federation contract text"
            if not any(expected in failure for failure in mutation_failures):
                print(f"self-test failed: federation contract mutation was not detected in docs/{relative}")
                return 1
            path.write_text(original, encoding="utf-8")

        reference = tmp / "docs/federation-error-reference.md"
        reference_original = reference.read_text(encoding="utf-8")
        first_reason = json.loads(
            (tmp / "docs/vectors/federation-authority-state-v1.json").read_text(encoding="utf-8")
        )["stable_errors"][0]["reason"]
        reference.write_text(
            reference_original.replace(f"| `{first_reason}` |", "| `removed_error` |", 1),
            encoding="utf-8",
        )
        mutation_failures = check(tmp, tracked_markdown, tracked_files)
        if not any("generated federation error reference" in failure for failure in mutation_failures):
            print("self-test failed: removed federation error row was not detected")
            return 1
        reference.write_text(reference_original, encoding="utf-8")

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

        gateway_e2e = tmp / "scripts/e2e-a2a-gateway-docker.sh"
        gateway_e2e.write_text(
            gateway_e2e.read_text(encoding="utf-8").replace(
                '-v "$GATEWAY_DIR:/workspace:ro"', '-v "$ROOT:/workspace:ro"', 1
            ),
            encoding="utf-8",
        )

        readme = tmp / "docs/README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "\n## Non-normative strategy and research\n\n"
            + "- [Company strategy](identity.md)\n",
            encoding="utf-8",
        )
        failures = check(tmp, tracked_markdown, tracked_files)
        required_failures = {
            "missing documented event": "task.created",
            "new repeated-event call site": "inventory omits source call site",
            "removed repeated-event call site": "inventory retains absent call site",
            "dynamic event expression": "unsupported non-literal",
            "real workspace release mount": "mounts the real repository workspace",
            "public strategy section": "public docs index still publishes a strategy/research section",
        }
        for label, expected in required_failures.items():
            if not any(expected in failure for failure in failures):
                print(f"self-test failed: {label} was not detected")
                return 1

    print(
        "self-test passed: tracked corpus, public-strategy exclusion, removed-strategy paths, "
        "private-transition removal, managed-gateway neutrality, "
        "federation SOT/error-reference coverage, event/call-site multiplicity, "
        "dynamic-expression, and real-workspace release-mount controls reject their mutations"
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
