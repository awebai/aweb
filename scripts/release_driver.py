"""Release driver: computes what must ship and in what order from the declared
component graph, checks declared inputs before anything runs, and matches
reruns against sealed receipts.

The graph lives in release/components.toml. Every edge is typed; an unknown
type refuses to load rather than being ignored, because an ignored edge is a
dependency the release silently stops respecting.

State reads are behind a provider interface: FixtureState for tests,
GitRepositoryState for the real repository (authoritative-remote reads only).
This module holds the pure logic; publish-lane execution binds to the staged
lane modes as those land (aweb-abbe.2 through .4) and skew execution to the
matrix runner (aweb-abbe.7).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = REPO_ROOT / "release" / "components.toml"

EDGE_TYPES = frozenset(
    {
        "bundled-build-input",
        "publication-prerequisite",
        "pointer",
        "delivery-restart",
        "sibling-pin",
        "runtime-contract",
    }
)


class GraphError(Exception):
    pass


class ApprovalRequired(Exception):
    pass


@dataclass(frozen=True)
class Component:
    name: str
    source_paths: tuple[str, ...] = ()
    version_source: dict | None = None
    tag_format: str | None = None
    publishable: bool = True
    approval_required: bool = False
    credential_paths: tuple[dict, ...] = ()
    sibling_pins: tuple[dict, ...] = ()
    pointer_for: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeContractEdge:
    a: str
    b: str
    journey: str
    supported: dict


@dataclass
class Graph:
    components: dict[str, Component]
    bundled_into: dict[str, tuple[str, ...]]  # input -> consumers
    prerequisites: dict[str, tuple[str, ...]]  # component -> its prerequisites
    runtime_contracts: tuple[RuntimeContractEdge, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "Graph":
        raw_components = data.get("component", {})
        if not raw_components:
            raise GraphError("graph declares no components")
        components: dict[str, Component] = {}
        for name, spec in raw_components.items():
            components[name] = Component(
                name=name,
                source_paths=tuple(spec.get("source_paths", ())),
                version_source=spec.get("version_source"),
                tag_format=spec.get("tag_format"),
                publishable=spec.get("publishable", True),
                approval_required=spec.get("approval_required", False),
                credential_paths=tuple(spec.get("credential_paths", ())),
                sibling_pins=tuple(spec.get("sibling_pins", ())),
                pointer_for=tuple(spec.get("pointer_for", ())),
            )

        def known(name: str, context: str) -> str:
            if name not in components:
                raise GraphError(f"{context} names unknown component {name!r}")
            return name

        bundled_into: dict[str, tuple[str, ...]] = {}
        prerequisites: dict[str, list[str]] = {name: [] for name in components}
        contracts: list[RuntimeContractEdge] = []
        for edge in data.get("edge", ()):
            edge_type = edge.get("type")
            if edge_type not in EDGE_TYPES:
                raise GraphError(
                    f"unknown edge type {edge_type!r}; every edge must be one of "
                    f"{sorted(EDGE_TYPES)}"
                )
            if edge_type == "bundled-build-input":
                source = known(edge["from"], "bundled-build-input")
                consumers = tuple(known(c, "bundled-build-input") for c in edge["to"])
                bundled_into[source] = bundled_into.get(source, ()) + consumers
            elif edge_type == "publication-prerequisite":
                source = known(edge["from"], "publication-prerequisite")
                for dependent in edge["to"]:
                    prerequisites[known(dependent, "publication-prerequisite")].append(
                        source
                    )
            elif edge_type == "runtime-contract":
                contracts.append(
                    RuntimeContractEdge(
                        a=known(edge["a"], "runtime-contract"),
                        b=known(edge["b"], "runtime-contract"),
                        journey=edge.get("journey", ""),
                        supported=edge.get("supported", {}),
                    )
                )
            # pointer edges are declared via pointer_for on the component today;
            # sibling-pin and delivery-restart edges via component fields. The
            # types stay reserved here so a future top-level declaration cannot
            # be silently ignored.

        graph = cls(
            components=components,
            bundled_into=bundled_into,
            prerequisites={k: tuple(v) for k, v in prerequisites.items()},
            runtime_contracts=tuple(contracts),
        )
        graph._refuse_cycles()
        return graph

    def _refuse_cycles(self) -> None:
        seen: dict[str, int] = {}  # 0 visiting, 1 done

        def visit(name: str, chain: tuple[str, ...]) -> None:
            state = seen.get(name)
            if state == 1:
                return
            if state == 0:
                raise GraphError(
                    "publication-prerequisite cycle: " + " -> ".join(chain + (name,))
                )
            seen[name] = 0
            for prerequisite in self.prerequisites.get(name, ()):
                visit(prerequisite, chain + (name,))
            seen[name] = 1

        for name in self.components:
            visit(name, ())

    @classmethod
    def load(cls, path: Path = GRAPH_PATH) -> "Graph":
        with open(path, "rb") as handle:
            return cls.from_dict(tomllib.load(handle))


@dataclass
class FixtureState:
    """Test provider: which components changed, plus environment and paths."""

    changed_components: dict[str, bool] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    existing_paths: set[str] = field(default_factory=set)

    def component_changed(self, component: Component) -> bool:
        return self.changed_components.get(component.name, False)

    def env_value(self, name: str) -> str | None:
        return self.env.get(name)

    def path_exists(self, path: str) -> bool:
        return path in self.existing_paths


@dataclass(frozen=True)
class PlanNode:
    component: str
    reason: str  # "changed" | "bundled-input:<name>" | "pointer:<name>"


@dataclass
class Plan:
    moving: list[PlanNode]
    runtime_contract_edges: list[RuntimeContractEdge]


def compute_plan(graph: Graph, state) -> Plan:
    reasons: dict[str, str] = {}
    for name, component in graph.components.items():
        if component.publishable and state.component_changed(component):
            reasons[name] = "changed"
    # A changed non-publishable input moves every consumer that bundles it.
    for source, consumers in graph.bundled_into.items():
        if state.component_changed(graph.components[source]):
            for consumer in consumers:
                reasons.setdefault(consumer, f"bundled-input:{source}")

    ordered: list[str] = []
    placed: set[str] = set()

    def place(name: str) -> None:
        if name in placed or name not in reasons:
            return
        for prerequisite in graph.prerequisites.get(name, ()):
            if prerequisite in reasons:
                place(prerequisite)
        placed.add(name)
        ordered.append(name)

    for name in sorted(reasons):
        place(name)

    moving = [PlanNode(component=n, reason=reasons[n]) for n in ordered]

    # Pointers follow the sources they advertise.
    for name, component in graph.components.items():
        for source in component.pointer_for:
            if source in placed and name not in placed:
                placed.add(name)
                moving.append(PlanNode(component=name, reason=f"pointer:{source}"))

    moving_names = {node.component for node in moving}
    contracts = [
        edge
        for edge in graph.runtime_contracts
        if edge.a in moving_names or edge.b in moving_names
    ]
    return Plan(moving=moving, runtime_contract_edges=contracts)


def check_declared_inputs(graph: Graph, plan: Plan, state) -> list[str]:
    """Every declared input of every moving component must be satisfiable
    BEFORE anything runs. Presence only: credential contents are never read."""
    problems: list[str] = []
    for node in plan.moving:
        component = graph.components[node.component]
        for credential in component.credential_paths:
            env_name = credential["env"]
            value = state.env_value(env_name)
            if not value:
                problems.append(
                    f"{component.name}: required credential path variable "
                    f"{env_name} is unset ({credential.get('purpose', 'declared input')})"
                )
            elif not state.path_exists(value):
                problems.append(
                    f"{component.name}: {env_name} names a path that does not exist"
                )
        for pin in component.sibling_pins:
            checkout = pin["checkout"]
            if not state.path_exists(checkout):
                problems.append(
                    f"{component.name}: sibling checkout {checkout} (pin file "
                    f"{pin['pin_file']}, component {pin['component']}) is absent"
                )
    return problems


@dataclass(frozen=True)
class ReceiptEntry:
    version: str
    digest: str


@dataclass
class Receipt:
    plan_digest: str
    entries: dict[str, ReceiptEntry]


def receipt_accepts(
    receipt: Receipt, component: str, *, version: str, digest: str
) -> tuple[bool, str]:
    entry = receipt.entries.get(component)
    if entry is None:
        return False, f"receipt has no entry for {component}; rerun cannot assume it"
    if entry.version != version:
        return False, f"version mismatch: receipt {entry.version}, observed {version}"
    if entry.digest != digest:
        return False, f"digest mismatch: receipt {entry.digest}, observed {digest}"
    return True, "exact match"


def require_approval(node: PlanNode, *, approval: str | None) -> None:
    if approval is None:
        raise ApprovalRequired(
            f"{node.component} is approval-required; pass the human approval "
            "record explicitly (who and when)"
        )


class GitRepositoryState:
    """Authoritative-state provider for `plan` against the real repository:
    remote refs via ls-remote, change detection via path diffs since each
    component's last published tag. Never reads local branch state."""

    def __init__(self, repo_root: Path = REPO_ROOT):
        self.repo_root = repo_root
        self._remote_tags: list[str] | None = None

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def remote_tags(self) -> list[str]:
        if self._remote_tags is None:
            out = self._git("ls-remote", "--tags", "origin")
            self._remote_tags = [
                line.split("refs/tags/", 1)[1]
                for line in out.splitlines()
                if "refs/tags/" in line and not line.endswith("^{}")
            ]
        return self._remote_tags

    def last_published_tag(self, component: Component) -> str | None:
        if not component.tag_format:
            return None
        prefix = component.tag_format.split("{version}", 1)[0]
        versions = []
        for tag in self.remote_tags():
            if tag.startswith(prefix):
                suffix = tag[len(prefix) :]
                parts = suffix.split(".")
                if all(p.isdigit() for p in parts) and parts:
                    versions.append((tuple(int(p) for p in parts), tag))
        if not versions:
            return None
        return max(versions)[1]

    def component_changed(self, component: Component) -> bool:
        if not component.source_paths:
            return False
        tag = self.last_published_tag(component)
        if tag is None:
            return True
        out = self._git(
            "diff", "--name-only", f"{tag}..origin/main", "--", *component.source_paths
        )
        return bool(out.strip())

    def env_value(self, name: str) -> str | None:
        import os

        return os.environ.get(name)

    def path_exists(self, path: str) -> bool:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.repo_root / path
        return candidate.exists()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("plan", help="compute the moving set and order from remote state")
    args = parser.parse_args(argv)

    if args.verb == "plan":
        graph = Graph.load()
        state = GitRepositoryState()
        subprocess.run(
            ["git", "-C", str(REPO_ROOT), "fetch", "origin", "--quiet"], check=True
        )
        plan = compute_plan(graph, state)
        problems = check_declared_inputs(graph, plan, state)
        print(
            json.dumps(
                {
                    "moving": [
                        {"component": n.component, "reason": n.reason}
                        for n in plan.moving
                    ],
                    "runtime_contract_edges": [
                        {"a": e.a, "b": e.b, "journey": e.journey}
                        for e in plan.runtime_contract_edges
                    ],
                    "declared_input_problems": problems,
                },
                indent=2,
            )
        )
        return 1 if problems else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
