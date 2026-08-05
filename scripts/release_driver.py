"""Release driver: computes what must ship and in what order from the declared
component graph, resolves source/published/candidate versions, checks every
declared input before anything runs, orchestrates publish lanes through
injectable interfaces that fail closed when a lane is unavailable, and seals
receipts whose expected digest lives with an external authority.

The graph is release/components.toml. Every edge type is parsed, validated,
and acted on; an unknown type or component reference refuses to load. Lane
internals belong to aweb-abbe.2 through .4 and skew execution to .7; this
module owns the orchestration contracts and refuses, by name, anything those
tasks have not yet provided.
"""

from __future__ import annotations

import argparse
import hashlib
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
        "runtime-contract",
    }
)


class GraphError(Exception):
    pass


class ApprovalRequired(Exception):
    pass


class ReceiptError(Exception):
    pass


class LaneUnavailable(Exception):
    pass


class BlockedByDeclaredInputs(Exception):
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
    publish_lane: dict | None = None
    verify: dict | None = None
    delivery_restart: dict | None = None


@dataclass(frozen=True)
class RuntimeContractEdge:
    a: str
    b: str
    journey: str
    artifacts: dict
    direction: str
    supported: dict

    @property
    def declared_incomplete(self) -> bool:
        """Support is complete only when it names a fleet measurement or an
        explicitly approved deprecation. Anything else — including an absent
        set — is declared-incomplete and blocks execution when touched.
        Floors are never invented here (G5)."""
        declared = self.supported.get("set", "")
        return not (
            declared.startswith("measured:")
            or declared.startswith("approved-deprecation:")
        )


@dataclass
class Graph:
    components: dict[str, Component]
    bundled_into: dict[str, tuple[str, ...]]
    prerequisites: dict[str, tuple[str, ...]]
    pointer_targets: dict[str, tuple[str, ...]]  # source -> pointer consumers
    runtime_contracts: tuple[RuntimeContractEdge, ...]
    canonical: dict  # the validated raw declaration, digest-bound into plans

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
                publish_lane=spec.get("publish_lane"),
                verify=spec.get("verify"),
                delivery_restart=spec.get("delivery_restart"),
            )

        def known(name: str, context: str) -> str:
            if name not in components:
                raise GraphError(f"{context} names unknown component {name!r}")
            return name

        for component in components.values():
            for pin in component.sibling_pins:
                known(pin["component"], f"{component.name} sibling_pins")

        bundled_into: dict[str, tuple[str, ...]] = {}
        prerequisites: dict[str, list[str]] = {name: [] for name in components}
        pointer_targets: dict[str, tuple[str, ...]] = {}
        contracts: list[RuntimeContractEdge] = []
        for edge in data.get("edge", ()):
            edge_type = edge.get("type")
            if edge_type not in EDGE_TYPES:
                raise GraphError(
                    f"unknown edge type {edge_type!r}; supported: {sorted(EDGE_TYPES)}"
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
            elif edge_type == "pointer":
                source = known(edge["from"], "pointer")
                targets = tuple(known(c, "pointer") for c in edge["to"])
                pointer_targets[source] = pointer_targets.get(source, ()) + targets
            elif edge_type == "runtime-contract":
                for required in ("journey", "artifacts", "direction"):
                    if required not in edge:
                        raise GraphError(
                            f"runtime-contract {edge.get('a')}<->{edge.get('b')} "
                            f"lacks required field {required!r}"
                        )
                contracts.append(
                    RuntimeContractEdge(
                        a=known(edge["a"], "runtime-contract"),
                        b=known(edge["b"], "runtime-contract"),
                        journey=edge["journey"],
                        artifacts=edge["artifacts"],
                        direction=edge["direction"],
                        supported=edge.get("supported", {}),
                    )
                )

        graph = cls(
            components=components,
            bundled_into=bundled_into,
            prerequisites={k: tuple(v) for k, v in prerequisites.items()},
            pointer_targets=pointer_targets,
            runtime_contracts=tuple(contracts),
            canonical=data,
        )
        graph._refuse_cycles()
        return graph

    def _refuse_cycles(self) -> None:
        seen: dict[str, int] = {}

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
    """Test provider. versions = current source versions; published_versions =
    latest registry-visible; tag_versions = versions whose release tag exists;
    pin_values = parsed pin-file SHAs; checkout_heads/checkout_remotes =
    sibling checkout identity."""

    changed_components: dict[str, bool] = field(default_factory=dict)
    bundled_changed_for: dict[tuple[str, str], bool] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    published_versions: dict[str, str] = field(default_factory=dict)
    tag_versions: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    existing_paths: set[str] = field(default_factory=set)
    pin_values: dict[str, str] = field(default_factory=dict)
    checkout_heads: dict[str, str] = field(default_factory=dict)
    checkout_remotes: dict[str, str] = field(default_factory=dict)

    def component_changed(self, component: Component) -> bool:
        return self.changed_components.get(component.name, False)

    def bundled_input_changed_for(
        self, bundled: Component, consumer: Component
    ) -> bool:
        key = (bundled.name, consumer.name)
        if key in self.bundled_changed_for:
            return self.bundled_changed_for[key]
        return self.changed_components.get(bundled.name, False)

    def source_version(self, component: Component) -> str | None:
        return self.versions.get(component.name)

    def published_version(self, component: Component) -> str | None:
        return self.published_versions.get(component.name)

    def tag_version(self, component: Component) -> str | None:
        return self.tag_versions.get(component.name)

    def env_value(self, name: str) -> str | None:
        return self.env.get(name)

    def path_exists(self, path: str) -> bool:
        return path in self.existing_paths

    def pin_sha(self, pin_file: str) -> str | None:
        return self.pin_values.get(pin_file)

    def checkout_head(self, path: str) -> str | None:
        return self.checkout_heads.get(path)

    def checkout_remote(self, path: str) -> str | None:
        return self.checkout_remotes.get(path)


@dataclass(frozen=True)
class PlanNode:
    component: str
    reason: str
    version: str | None = None  # proposed candidate
    published_version: str | None = None


@dataclass
class Plan:
    moving: list[PlanNode]
    runtime_contract_edges: list[RuntimeContractEdge]


def compute_plan(graph: Graph, state) -> Plan:
    reasons: dict[str, str] = {}
    for name, component in graph.components.items():
        if component.publishable and state.component_changed(component):
            reasons[name] = "changed"
    # A bundled input's change is asked per consumer, against that consumer's
    # last published baseline: the input ships inside the consumer.
    for source, consumers in graph.bundled_into.items():
        for consumer in consumers:
            if state.bundled_input_changed_for(
                graph.components[source], graph.components[consumer]
            ):
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

    # Pointer consumers are FORCED: their sources moving is what makes their
    # state stale, so they join the plan after every moving source, always.
    pointer_reasons: dict[str, str] = {}
    for source, targets in graph.pointer_targets.items():
        if source in placed:
            for target in targets:
                if target not in placed:
                    pointer_reasons.setdefault(target, f"pointer:{source}")
    ordered.extend(sorted(pointer_reasons))
    reasons.update(pointer_reasons)

    moving = []
    for name in ordered:
        component = graph.components[name]
        moving.append(
            PlanNode(
                component=name,
                reason=reasons[name],
                version=state.source_version(component),
                published_version=state.published_version(component),
            )
        )

    moving_names = set(reasons)
    contracts = [
        e
        for e in graph.runtime_contracts
        if e.a in moving_names or e.b in moving_names
    ]
    return Plan(moving=moving, runtime_contract_edges=contracts)


def check_declared_inputs(graph: Graph, plan: Plan, state) -> list[str]:
    """Everything a release needs, checked BEFORE anything runs, each failure
    named. Credential paths are presence-only: contents are never read."""
    problems: list[str] = []
    for node in plan.moving:
        component = graph.components[node.component]

        source_version = state.source_version(component)
        published = state.published_version(component)
        if component.version_source and source_version is not None:
            if published is not None and source_version == published:
                problems.append(
                    f"{component.name}: version not advanced - source version "
                    f"{source_version} is already published"
                )
            tag_version = state.tag_version(component)
            if (
                tag_version is not None
                and published is not None
                and tag_version != published
            ):
                problems.append(
                    f"{component.name}: tag {tag_version} disagrees with "
                    f"registry-visible {published}; a tag is not a published artifact"
                )

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
                continue
            pinned = state.pin_sha(pin["pin_file"])
            head = state.checkout_head(checkout)
            if pinned is None:
                problems.append(
                    f"{component.name}: pin file {pin['pin_file']} is unreadable"
                )
            elif head != pinned:
                problems.append(
                    f"{component.name}: checkout {checkout} HEAD {head} does not "
                    f"equal pinned {pinned}"
                )
            declared_repo = pin.get("repository")
            if declared_repo:
                remote = state.checkout_remote(checkout)
                if remote != declared_repo:
                    problems.append(
                        f"{component.name}: checkout {checkout} remote {remote} is "
                        f"not the declared repository {declared_repo}"
                    )

    for edge in plan.runtime_contract_edges:
        if edge.declared_incomplete:
            problems.append(
                f"runtime-contract {edge.a}<->{edge.b}: support is "
                "declared-incomplete (no fleet measurement or approved "
                "deprecation); execution is blocked until aweb-abbe.7 measures"
            )
    return problems


def plan_digest(plan: Plan, graph: Graph) -> str:
    """Binds the moving set AND the full canonical graph declaration, so any
    change to an edge's floor, policy, journey, or artifact locator changes
    the digest."""
    canonical = json.dumps(
        {
            "graph": graph.canonical,
            "moving": [
                [n.component, n.reason, n.version, n.published_version]
                for n in plan.moving
            ],
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    who: str
    when: str


def require_approval(node: PlanNode, *, approval) -> None:
    if not isinstance(approval, Approval) or not approval.who or not approval.when:
        raise ApprovalRequired(
            f"{node.component} is approval-required; pass a structured human "
            "approval record (who and when), not free text"
        )


@dataclass(frozen=True)
class ReceiptEntry:
    version: str
    digest: str
    pointer_state: str | None = None
    delivery_proof: str | None = None


@dataclass
class Receipt:
    plan_digest: str
    source_sha: str
    entries: dict[str, ReceiptEntry]
    approvals: tuple[dict, ...] = ()


def seal_receipt(
    plan: Plan,
    graph: Graph,
    *,
    source_sha: str,
    entries: dict[str, ReceiptEntry],
    approvals: tuple[Approval, ...],
) -> tuple[bytes, str]:
    """Returns (sealed bytes, digest). The digest MUST be recorded with an
    external authority (workflow artifact metadata, the task record); a digest
    stored beside the receipt is a recomputable checksum, not tamper evidence.
    The entry set must equal the planned set exactly."""
    planned = {n.component for n in plan.moving}
    if set(entries) != planned:
        missing = planned - set(entries)
        extra = set(entries) - planned
        raise ReceiptError(
            f"receipt entries must equal the planned set; missing={sorted(missing)}"
            f" extra={sorted(extra)}"
        )
    body = json.dumps(
        {
            "plan_digest": plan_digest(plan, graph),
            "source_sha": source_sha,
            "entries": {
                name: {
                    "version": e.version,
                    "digest": e.digest,
                    "pointer_state": e.pointer_state,
                    "delivery_proof": e.delivery_proof,
                }
                for name, e in sorted(entries.items())
            },
            "approvals": [
                {"who": a.who, "when": a.when} for a in approvals
            ],
        },
        sort_keys=True,
    )
    seal = hashlib.sha256(body.encode()).hexdigest()
    sealed = json.dumps({"body": body, "seal": seal}).encode()
    return sealed, hashlib.sha256(sealed).hexdigest()


def load_sealed_receipt(data: bytes, *, expected_digest: str) -> Receipt:
    """expected_digest comes from the external authority that recorded it at
    seal time. Without it, any locally-presented receipt+checksum pair is
    trivially forgeable."""
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ReceiptError(
            "receipt bytes do not match the externally recorded digest"
        )
    try:
        outer = json.loads(data)
        body, seal = outer["body"], outer["seal"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReceiptError(f"unreadable receipt: {exc}") from exc
    if hashlib.sha256(body.encode()).hexdigest() != seal:
        raise ReceiptError("receipt seal does not match its body")
    parsed = json.loads(body)
    return Receipt(
        plan_digest=parsed["plan_digest"],
        source_sha=parsed["source_sha"],
        entries={
            name: ReceiptEntry(
                version=e["version"],
                digest=e["digest"],
                pointer_state=e.get("pointer_state"),
                delivery_proof=e.get("delivery_proof"),
            )
            for name, e in parsed["entries"].items()
        },
        approvals=tuple(parsed.get("approvals", ())),
    )


def receipt_matches_run(
    receipt: Receipt, plan: Plan, graph: Graph, *, source_sha: str
) -> tuple[bool, str]:
    if receipt.source_sha != source_sha:
        return False, (
            f"source mismatch: receipt {receipt.source_sha}, run {source_sha}"
        )
    current = plan_digest(plan, graph)
    if receipt.plan_digest != current:
        return False, f"plan digest mismatch: receipt {receipt.plan_digest}, run {current}"
    planned = {n.component for n in plan.moving}
    if set(receipt.entries) != planned:
        return False, "receipt entry set does not equal the planned set"
    return True, "receipt matches this run"


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


def run_plan(
    plan: Plan,
    graph: Graph,
    lanes,
    *,
    source_sha: str,
    approvals: dict[str, Approval],
    state=None,
) -> dict[str, ReceiptEntry]:
    """Orchestrates stage-then-publish over the injectable lane provider in
    plan order. Fails closed BEFORE anything executes: every unavailable lane
    is named, and unsatisfied declared inputs block the run."""
    if state is not None:
        problems = check_declared_inputs(graph, plan, state)
        if problems:
            raise BlockedByDeclaredInputs("; ".join(problems))
    missing = [n.component for n in plan.moving if not lanes.has_lane(n.component)]
    if missing:
        raise LaneUnavailable(
            "no publish lane available for: "
            + ", ".join(missing)
            + " (lanes arrive with aweb-abbe.2-.4)"
        )
    entries: dict[str, ReceiptEntry] = {}
    for node in plan.moving:
        component = graph.components[node.component]
        if component.approval_required:
            require_approval(node, approval=approvals.get(node.component))
        staged = lanes.stage(node)
        entries[node.component] = lanes.publish(node, staged)
    return entries


class NoLanes:
    """The .5 state of the world: no lane implementations exist, so release
    execution refuses by name. .2-.4 replace this with real lanes."""

    def has_lane(self, component: str) -> bool:
        return False

    def stage(self, node: PlanNode) -> ReceiptEntry:  # pragma: no cover
        raise LaneUnavailable(node.component)

    def publish(self, node, staged):  # pragma: no cover
        raise LaneUnavailable(node.component)


class GitRepositoryState:
    """Authoritative-state provider for the real repository. Change detection
    diffs against the remote tag OBJECT SHA from ls-remote (never a local tag
    ref), version resolution reads the declared source, and registry truth
    comes through the injectable registry provider."""

    def __init__(self, repo_root: Path = REPO_ROOT, registry=None):
        self.repo_root = repo_root
        self.registry = registry
        self._remote_tag_shas: dict[str, str] | None = None

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def remote_tag_shas(self) -> dict[str, str]:
        """Tag name -> commit SHA from ls-remote; peeled entries (^{}) give
        the commit an annotated tag points at and win over the tag object."""
        if self._remote_tag_shas is None:
            shas: dict[str, str] = {}
            for line in self._git("ls-remote", "--tags", "origin").splitlines():
                sha, _, ref = line.partition("\trefs/tags/")
                if not ref:
                    continue
                if ref.endswith("^{}"):
                    shas[ref[:-3]] = sha
                else:
                    shas.setdefault(ref, sha)
            self._remote_tag_shas = shas
        return self._remote_tag_shas

    def _last_published(self, component: Component) -> tuple[str, str] | None:
        """(tag, remote commit SHA) of the highest published version tag."""
        if not component.tag_format:
            return None
        prefix = component.tag_format.split("{version}", 1)[0]
        best: tuple[tuple[int, ...], str, str] | None = None
        for tag, sha in self.remote_tag_shas().items():
            if tag.startswith(prefix):
                parts = tag[len(prefix) :].split(".")
                if parts and all(p.isdigit() for p in parts):
                    key = tuple(int(p) for p in parts)
                    if best is None or key > best[0]:
                        best = (key, tag, sha)
        if best is None:
            return None
        return best[1], best[2]

    def _changed_since(self, sha: str, paths: tuple[str, ...]) -> bool:
        out = self._git("diff", "--name-only", f"{sha}..origin/main", "--", *paths)
        return bool(out.strip())

    def component_changed(self, component: Component) -> bool:
        if not component.source_paths:
            return False
        published = self._last_published(component)
        if published is None:
            return True
        return self._changed_since(published[1], component.source_paths)

    def bundled_input_changed_for(
        self, bundled: Component, consumer: Component
    ) -> bool:
        if not bundled.source_paths:
            return False
        published = self._last_published(consumer)
        if published is None:
            return True
        return self._changed_since(published[1], bundled.source_paths)

    def source_version(self, component: Component) -> str | None:
        import re

        source = component.version_source
        if source is None:
            return None
        kind = source["type"]
        if kind == "pyproject":
            text = (self.repo_root / source["path"]).read_text(encoding="utf-8")
            found = re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', text)
            return found.group(1) if found else None
        if kind == "package-json":
            data = json.loads(
                (self.repo_root / source["path"]).read_text(encoding="utf-8")
            )
            return data.get("version")
        if kind == "tag-history":
            out = subprocess.run(
                [str(self.repo_root / source["script"]), "next"],
                check=True,
                capture_output=True,
                text=True,
                cwd=self.repo_root,
            ).stdout.strip()
            return out or None
        return None

    def tag_version(self, component: Component) -> str | None:
        published = self._last_published(component)
        if published is None or not component.tag_format:
            return None
        prefix = component.tag_format.split("{version}", 1)[0]
        return published[0][len(prefix) :]

    def published_version(self, component: Component) -> str | None:
        if self.registry is None:
            return self.tag_version(component)
        return self.registry.published_version(component)

    def env_value(self, name: str) -> str | None:
        import os

        return os.environ.get(name)

    def path_exists(self, path: str) -> bool:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.repo_root / path
        return candidate.exists()

    def pin_sha(self, pin_file: str) -> str | None:
        candidate = Path(pin_file)
        if not candidate.is_absolute():
            candidate = self.repo_root / pin_file
        if not candidate.is_file():
            return None
        with open(candidate, "rb") as handle:
            data = tomllib.load(handle)
        for section in data.values():
            if isinstance(section, dict) and "git_sha" in section:
                return section["git_sha"]
        return None

    def checkout_head(self, path: str) -> str | None:
        try:
            return subprocess.run(
                ["git", "-C", path, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def checkout_remote(self, path: str) -> str | None:
        try:
            url = subprocess.run(
                ["git", "-C", path, "remote", "get-url", "origin"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
        return (
            url.removeprefix("https://")
            .removeprefix("git@")
            .replace(".com:", ".com/")
            .removesuffix(".git")
        )


class RegistryProviders:
    """Latest registry-visible version per component, from the registry its
    publish lane declares. A tag is not a published artifact; these are the
    calls that tell them apart."""

    def published_version(self, component: Component) -> str | None:
        import urllib.request

        lane = component.publish_lane or {}
        registry = lane.get("registry", {})
        kind = registry.get("type")
        try:
            if kind == "pypi":
                with urllib.request.urlopen(
                    f"https://pypi.org/pypi/{registry['package']}/json", timeout=30
                ) as response:
                    return json.load(response)["info"]["version"]
            if kind == "npm":
                with urllib.request.urlopen(
                    f"https://registry.npmjs.org/{registry['package']}/latest",
                    timeout=30,
                ) as response:
                    return json.load(response)["version"]
            if kind == "github-release":
                with urllib.request.urlopen(
                    f"https://api.github.com/repos/{registry['repo']}/releases/latest",
                    timeout=30,
                ) as response:
                    tag = json.load(response)["tag_name"]
                    return tag.removeprefix("v")
        except Exception as exc:  # noqa: BLE001 - fail closed with the cause
            raise GraphError(
                f"registry read failed for {component.name}: {exc}"
            ) from exc
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("plan", help="diagnostic plan from authoritative remote state")
    sub.add_parser(
        "release-run",
        help="execute the plan over available lanes; fails closed on any gap",
    )
    receipt_parser = sub.add_parser(
        "release-receipt", help="verify a sealed receipt against this run"
    )
    receipt_parser.add_argument("--receipt", required=True)
    receipt_parser.add_argument(
        "--expected-digest",
        required=True,
        help="the digest recorded with the external authority at seal time",
    )
    args = parser.parse_args(argv)

    graph = Graph.load()
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "fetch", "origin", "--quiet"], check=True
    )
    state = GitRepositoryState(registry=RegistryProviders())
    plan = compute_plan(graph, state)
    problems = check_declared_inputs(graph, plan, state)
    source_sha = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "origin/main"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    if args.verb == "plan":
        print(
            json.dumps(
                {
                    "source_sha": source_sha,
                    "moving": [
                        {
                            "component": n.component,
                            "reason": n.reason,
                            "candidate_version": n.version,
                            "published_version": n.published_version,
                        }
                        for n in plan.moving
                    ],
                    "runtime_contract_edges": [
                        {
                            "a": e.a,
                            "b": e.b,
                            "journey": e.journey,
                            "declared_incomplete": e.declared_incomplete,
                        }
                        for e in plan.runtime_contract_edges
                    ],
                    "declared_input_problems": problems,
                    "plan_digest": plan_digest(plan, graph),
                },
                indent=2,
            )
        )
        return 1 if problems else 0

    if args.verb == "release-run":
        try:
            run_plan(
                plan, graph, NoLanes(), source_sha=source_sha, approvals={}, state=state
            )
        except (LaneUnavailable, BlockedByDeclaredInputs, ApprovalRequired) as exc:
            print(f"BLOCKED: {exc}")
            return 1
        print("release-run completed")
        return 0

    if args.verb == "release-receipt":
        try:
            receipt = load_sealed_receipt(
                Path(args.receipt).read_bytes(), expected_digest=args.expected_digest
            )
        except ReceiptError as exc:
            print(f"REFUSED: {exc}")
            return 1
        ok, why = receipt_matches_run(receipt, plan, graph, source_sha=source_sha)
        print(("MATCH: " if ok else "MISMATCH: ") + why)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
