"""Release driver: computes what must ship from the declared component graph,
freezes that plan into an immutable artifact before any outward effect, and
executes it as a four-phase barrier protocol - preflight everything, stage
every candidate and bind exact digests, run every touched version-skew matrix
against those bytes, then publish topologically from those same digests and
verify against authoritative registry state. Receipts seal to an external
authority; reruns resume from the frozen plan, never from re-planned live
state.

The graph is release/components.toml. Every edge type is parsed, validated,
and acted on; unknown types, unknown references, cycles, and spoofable
support declarations refuse to load. Lane internals belong to aweb-abbe.2-.4
and skew journeys to .7; their interfaces are mandatory here and their
absence blocks by name before anything runs.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
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
CONTRACT_DIRECTIONS = frozenset({"both", "a-to-b", "b-to-a", "persisted-state-both"})
CONTRACT_POLICIES = frozenset({"additive-only", "breaking-with-approved-deprecation"})


class GraphError(Exception):
    pass


class ApprovalRequired(Exception):
    pass


class ReceiptError(Exception):
    pass


class LaneUnavailable(Exception):
    pass


class SkewUnavailable(Exception):
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
    lane: dict | None = None  # delivery lane for non-registry nodes (sites)
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
        """Complete support names a measurement or an approved deprecation
        with a nonempty identity. Anything else blocks execution when touched.
        Floors are never invented here (G5)."""
        declared = self.supported.get("set", "")
        return not (
            (declared.startswith("measured:") and len(declared) > len("measured:"))
            or (
                declared.startswith("approved-deprecation:")
                and len(declared) > len("approved-deprecation:")
            )
        )


def _validate_contract(edge: dict) -> None:
    for required in ("journey", "artifacts", "direction"):
        if required not in edge:
            raise GraphError(
                f"runtime-contract {edge.get('a')}<->{edge.get('b')} lacks "
                f"required field {required!r}"
            )
    if edge["direction"] not in CONTRACT_DIRECTIONS:
        raise GraphError(
            f"runtime-contract direction {edge['direction']!r} is not one of "
            f"{sorted(CONTRACT_DIRECTIONS)}"
        )
    artifacts = edge["artifacts"]
    for side in ("a", "b"):
        if not artifacts.get(side):
            raise GraphError(
                f"runtime-contract {edge['a']}<->{edge['b']}: empty artifact "
                f"locator for side {side!r}"
            )
    supported = edge.get("supported", {})
    policy = supported.get("policy", "")
    if policy not in CONTRACT_POLICIES:
        raise GraphError(
            f"runtime-contract {edge['a']}<->{edge['b']}: policy {policy!r} is "
            f"not one of {sorted(CONTRACT_POLICIES)}"
        )
    declared = supported.get("set")
    if declared is not None:
        valid = (
            declared.startswith("measured:") and len(declared) > len("measured:")
        ) or (
            declared.startswith("approved-deprecation:")
            and len(declared) > len("approved-deprecation:")
        )
        if not valid:
            raise GraphError(
                f"runtime-contract {edge['a']}<->{edge['b']}: supported.set "
                f"{declared!r} is neither measured:<id> nor "
                "approved-deprecation:<id> with a nonempty identity"
            )
        record = supported.get("record", {})
        if not (
            record.get("authority") and record.get("artifact_id") and record.get("digest")
        ):
            raise GraphError(
                f"runtime-contract {edge['a']}<->{edge['b']}: a declared support "
                "set requires a structured record reference (authority, "
                "artifact_id, digest); a bare string is not checkable identity"
            )
        if policy == "breaking-with-approved-deprecation" and not declared.startswith(
            "approved-deprecation:"
        ):
            raise GraphError(
                f"runtime-contract {edge['a']}<->{edge['b']}: breaking policy "
                "requires an approved-deprecation record, not a measurement"
            )


@dataclass
class Graph:
    components: dict[str, Component]
    bundled_into: dict[str, tuple[str, ...]]
    prerequisites: dict[str, tuple[str, ...]]
    pointer_targets: dict[str, tuple[str, ...]]
    runtime_contracts: tuple[RuntimeContractEdge, ...]
    canonical: dict

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
                lane=spec.get("lane"),
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
                _validate_contract(
                    {**edge, "a": known(edge["a"], "runtime-contract"),
                     "b": known(edge["b"], "runtime-contract")}
                )
                contracts.append(
                    RuntimeContractEdge(
                        a=edge["a"],
                        b=edge["b"],
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
        graph._refuse_cycles("publication-prerequisite", graph.prerequisites)
        graph._refuse_cycles("pointer", dict(pointer_targets))
        # The execution DAG is the UNION of ordering constraints: a pointer
        # target runs after its source, a dependent after its prerequisite.
        # A cycle across the two types is just as unexecutable as within one.
        combined: dict[str, tuple[str, ...]] = {}
        for dependent, prereqs in graph.prerequisites.items():
            for prereq in prereqs:
                combined[dependent] = combined.get(dependent, ()) + (prereq,)
        for source, targets in pointer_targets.items():
            for target in targets:
                combined[target] = combined.get(target, ()) + (source,)
        graph._refuse_cycles("combined pointer/prerequisite", combined)
        return graph

    def _refuse_cycles(self, kind: str, adjacency: dict[str, tuple[str, ...]]) -> None:
        seen: dict[str, int] = {}

        def visit(name: str, chain: tuple[str, ...]) -> None:
            state = seen.get(name)
            if state == 1:
                return
            if state == 0:
                raise GraphError(f"{kind} cycle: " + " -> ".join(chain + (name,)))
            seen[name] = 0
            for neighbor in adjacency.get(name, ()):
                visit(neighbor, chain + (name,))
            seen[name] = 1

        for name in self.components:
            visit(name, ())

    @classmethod
    def load(cls, path: Path = GRAPH_PATH) -> "Graph":
        with open(path, "rb") as handle:
            return cls.from_dict(tomllib.load(handle))


@dataclass
class FixtureState:
    changed_components: dict[str, bool] = field(default_factory=dict)
    bundled_changed_for: dict[tuple[str, str], bool] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    published_versions: dict[str, str] = field(default_factory=dict)
    tag_versions: dict[str, str] = field(default_factory=dict)
    registry_unavailable: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    existing_paths: set[str] = field(default_factory=set)
    pin_values: dict[str, str] = field(default_factory=dict)
    checkout_heads: dict[str, str] = field(default_factory=dict)
    checkout_remotes: dict[str, str] = field(default_factory=dict)
    delivery_baselines: dict[str, str] = field(default_factory=dict)

    def component_changed(self, component: Component) -> bool:
        return self.changed_components.get(component.name, False)

    def bundled_input_changed_for(self, bundled, consumer) -> bool:
        key = (bundled.name, consumer.name)
        if key in self.bundled_changed_for:
            return self.bundled_changed_for[key]
        return self.changed_components.get(bundled.name, False)

    def source_version(self, component: Component) -> str | None:
        return self.versions.get(component.name)

    def published_version(self, component: Component) -> str | None:
        return self.published_versions.get(component.name)

    def registry_unavailable_reason(self, component: Component) -> str | None:
        return self.registry_unavailable.get(component.name)

    def tag_version(self, component: Component) -> str | None:
        return self.tag_versions.get(component.name)

    def env_value(self, name: str) -> str | None:
        return self.env.get(name)

    def path_exists(self, path: str) -> bool:
        return path in self.existing_paths

    def pin_sha(self, pin: dict) -> str | None:
        return self.pin_values.get(pin["pin_file"])

    def checkout_head(self, path: str) -> str | None:
        return self.checkout_heads.get(path)

    def checkout_remote(self, path: str) -> str | None:
        return self.checkout_remotes.get(path)

    def delivery_baseline(self, component: Component) -> str | None:
        return self.delivery_baselines.get(component.name)


@dataclass(frozen=True)
class PlanNode:
    component: str
    reason: str
    version: str | None = None
    published_version: str | None = None


@dataclass
class Plan:
    moving: list[PlanNode]
    runtime_contract_edges: list[RuntimeContractEdge]


def compute_plan(graph: Graph, state) -> Plan:
    reasons: dict[str, str] = {}
    for name, component in graph.components.items():
        moves_on_change = component.publishable or component.lane is not None
        if moves_on_change and component.source_paths and state.component_changed(
            component
        ):
            reasons[name] = "changed"
    for source, consumers in graph.bundled_into.items():
        for consumer in consumers:
            if state.bundled_input_changed_for(
                graph.components[source], graph.components[consumer]
            ):
                reasons.setdefault(consumer, f"bundled-input:{source}")

    # Closure FIRST: pointer targets are forced transitively into the moving
    # set. Ordering happens after, over the complete set.
    frontier = list(reasons)
    while frontier:
        next_frontier: list[str] = []
        for source in frontier:
            for target in graph.pointer_targets.get(source, ()):
                if target not in reasons:
                    reasons[target] = f"pointer:{source}"
                    next_frontier.append(target)
        frontier = next_frontier

    # Topo-sort of the union ordering DAG (prerequisite AND pointer edges)
    # restricted to the moving set; load-time validation guarantees acyclicity.
    after: dict[str, set[str]] = {name: set() for name in reasons}
    for dependent, prereqs in graph.prerequisites.items():
        if dependent in reasons:
            after[dependent].update(p for p in prereqs if p in reasons)
    for source, targets in graph.pointer_targets.items():
        if source in reasons:
            for target in targets:
                if target in reasons:
                    after[target].add(source)

    ordered: list[str] = []
    placed: set[str] = set()

    def place(name: str) -> None:
        if name in placed:
            return
        placed.add(name)
        for earlier in sorted(after[name]):
            place(earlier)
        ordered.append(name)

    for name in sorted(reasons):
        place(name)

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
        e for e in graph.runtime_contracts if e.a in moving_names or e.b in moving_names
    ]
    return Plan(moving=moving, runtime_contract_edges=contracts)


def check_declared_inputs(
    graph: Graph, plan: Plan, state, adopted: set | None = None
) -> list[str]:
    """Everything a release needs, checked BEFORE anything runs, each failure
    named. Credential paths are presence-only: contents are never read.
    Unknown registry truth is unavailable, and unavailable blocks."""
    problems: list[str] = []
    for node in plan.moving:
        component = graph.components[node.component]

        adopted_component = node.component in (adopted or set())
        if component.publishable and component.version_source and not adopted_component:
            # For an ADOPTED component, only its own registry/tag movement to
            # the staged candidate identity is the named expected transition;
            # its credentials, pins and baselines still validate below, as
            # does everything about every other component.
            unavailable = state.registry_unavailable_reason(component)
            if unavailable is not None:
                problems.append(
                    f"{component.name}: registry truth unavailable - {unavailable}"
                )
            else:
                source_version = state.source_version(component)
                published = state.published_version(component)
                if source_version is not None and published is not None:
                    if source_version == published:
                        problems.append(
                            f"{component.name}: version not advanced - source "
                            f"version {source_version} is already published"
                        )
                    tag_version = state.tag_version(component)
                    if tag_version is not None and tag_version != published:
                        problems.append(
                            f"{component.name}: tag {tag_version} disagrees with "
                            f"registry-visible {published}; a tag is not a "
                            "published artifact"
                        )

        for credential in component.credential_paths:
            env_name = credential["env"]
            value = state.env_value(env_name)
            if not value:
                problems.append(
                    f"{component.name}: required credential path variable "
                    f"{env_name} is unset "
                    f"({credential.get('purpose', 'declared input')})"
                )
            elif not state.path_exists(value):
                problems.append(
                    f"{component.name}: {env_name} names a path that does not exist"
                )

        for pin in component.sibling_pins:
            kind = pin.get("kind", "sha-pin")
            pinned = state.pin_sha(pin)
            if pinned is None:
                problems.append(
                    f"{component.name}: pin {pin['pin_file']} "
                    f"({kind}) is unreadable in its declared repository context"
                )
                continue
            if kind == "lock-version":
                # A lock pin records a VERSION of the pinned component; it can
                # never be compared with a git HEAD. Satisfied when it names
                # the CANDIDATE this plan will publish - a stale lock fails
                # and a correctly advanced one passes before publication.
                target = graph.components[pin["component"]]
                candidate = state.source_version(target)
                if candidate is not None and pinned != candidate:
                    problems.append(
                        f"{component.name}: lock {pin['pin_file']} records "
                        f"{pin.get('package', target.name)} {pinned} but the "
                        f"candidate version is {candidate}"
                    )
                continue
            checkout = pin["checkout"]
            if not state.path_exists(checkout):
                problems.append(
                    f"{component.name}: sibling checkout {checkout} (pin file "
                    f"{pin['pin_file']}, component {pin['component']}) is absent"
                )
                continue
            head = state.checkout_head(checkout)
            if head != pinned:
                problems.append(
                    f"{component.name}: checkout {checkout} HEAD {head} does not "
                    f"equal pinned {pinned}"
                )
            declared_repo = pin.get("repository")
            if declared_repo:
                remote = state.checkout_remote(checkout)
                if remote != declared_repo:
                    problems.append(
                        f"{component.name}: checkout {checkout} remote {remote} "
                        f"is not the declared repository {declared_repo}"
                    )



    for component in graph.components.values():
        if component.lane is not None and component.source_paths:
            baseline = None
            if hasattr(state, "delivery_baseline"):
                baseline = state.delivery_baseline(component)
            if baseline is None:
                problems.append(
                    f"{component.name}: delivered baseline is unobservable; a "
                    "changed decision needs an authoritative baseline, and "
                    "movement is never fabricated from its absence"
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


# ── frozen plan artifact (G4) ────────────────────────────────────────


def _resolved_snapshot(plan: Plan, graph: Graph, state) -> dict:
    """Everything external the plan resolved, bound into the frozen artifact:
    registry versions and digest sets, pin values and checkout identities,
    delivery baselines. Secrets are never included - pins and baselines are
    public metadata, credential contents never flow through state."""
    if state is None:
        return {}
    snapshot: dict = {"components": {}, "pins": {}, "baselines": {}, "tags": {}}
    if hasattr(state, "remote_tag_shas"):
        tags = state.remote_tag_shas()
        for node in plan.moving:
            component = graph.components[node.component]
            if component.tag_format:
                prefix = component.tag_format.split("{version}", 1)[0]
                # Keyed per component so a resumed candidate's own planned tag
                # classifies as the expected transition without suppressing
                # unrelated tag drift.
                snapshot["tags"][node.component] = {
                    t: s for t, s in tags.items() if t.startswith(prefix)
                }
    for node in plan.moving:
        component = graph.components[node.component]
        entry: dict = {}
        if hasattr(state, "published_version"):
            entry["published_version"] = state.published_version(component)
        if hasattr(state, "registry_digests"):
            entry["registry_digests"] = state.registry_digests(component)
        snapshot["components"][node.component] = entry
        for pin in component.sibling_pins:
            key = f"{node.component}:{pin['pin_file']}:{pin.get('package', pin.get('field', ''))}"
            record = {"value": state.pin_sha(pin)}
            checkout = pin.get("checkout")
            if checkout and hasattr(state, "checkout_head"):
                record["checkout_head"] = state.checkout_head(checkout)
                record["checkout_remote"] = state.checkout_remote(checkout)
                record["declared_repository"] = pin.get("repository")
            record["pin_repository"] = pin.get("pin_repository")
            snapshot["pins"][key] = record
        if component.lane is not None and hasattr(state, "delivery_baseline"):
            snapshot["baselines"][node.component] = state.delivery_baseline(component)
    return snapshot


def freeze_plan(
    plan: Plan, graph: Graph, *, source_sha: str, state=None, measurement=None
) -> tuple[bytes, str]:
    """The plan that will execute, sealed BEFORE any outward effect, binding
    the resolved external state it was computed from. Reruns take this
    artifact's id; live drift cannot rewrite a release in flight."""
    resolved = _resolved_snapshot(plan, graph, state)
    complete_edges = [
        e for e in plan.runtime_contract_edges if not e.declared_incomplete
    ]
    if complete_edges:
        if measurement is None:
            raise BlockedByDeclaredInputs(
                "a plan with complete runtime-contract records cannot be "
                "anchored without a measurement authority to resolve them"
            )
        record_problems = check_measurement_records(complete_edges, measurement)
        if record_problems:
            raise BlockedByDeclaredInputs("; ".join(record_problems))
        resolved["measurements"] = {
            f"{e.a}<->{e.b}": measurement.resolve(e.supported.get("record", {}), e)
            for e in complete_edges
        }
    content = {
        "source_sha": source_sha,
        "plan_digest": plan_digest(plan, graph),
        "graph": graph.canonical,
        "resolved": resolved,
        "moving": [
            {
                "component": n.component,
                "reason": n.reason,
                "version": n.version,
                "published_version": n.published_version,
            }
            for n in plan.moving
        ],
        "contracts": [
            {
                "a": e.a,
                "b": e.b,
                "journey": e.journey,
                "artifacts": e.artifacts,
                "direction": e.direction,
                "supported": e.supported,
            }
            for e in plan.runtime_contract_edges
        ],
    }
    content_digest = hashlib.sha256(
        json.dumps(content, sort_keys=True).encode()
    ).hexdigest()
    body = json.dumps(
        {"content": content, "content_digest": content_digest}, sort_keys=True
    ).encode()
    return body, hashlib.sha256(body).hexdigest()


@dataclass
class FrozenPlan:
    """The typed frozen truth a release executes against: never substituted
    by current resolved state."""

    plan: Plan
    source_sha: str
    plan_digest: str
    resolved: dict
    graph_canonical: dict
    frozen_id: str

    @property
    def graph(self) -> Graph:
        return Graph.from_dict(self.graph_canonical)


def load_frozen_plan(data: bytes, *, expected_id: str) -> FrozenPlan:
    """Two independent defenses: semantic recomputation catches an edited
    digest even when every wrapper hash is recomputed, and a consistently
    rewritten plan carries a NEW id the trusted authority never recorded."""
    if hashlib.sha256(data).hexdigest() != expected_id:
        raise ReceiptError("frozen plan bytes do not match the recorded plan id")
    parsed = json.loads(data)
    content = parsed.get("content")
    declared = parsed.get("content_digest")
    if content is None or declared is None:
        raise ReceiptError("frozen plan lacks its content binding")
    actual = hashlib.sha256(
        json.dumps(content, sort_keys=True).encode()
    ).hexdigest()
    if actual != declared:
        raise ReceiptError("frozen plan content does not match its content digest")
    plan = Plan(
        moving=[
            PlanNode(
                component=n["component"],
                reason=n["reason"],
                version=n["version"],
                published_version=n["published_version"],
            )
            for n in content["moving"]
        ],
        runtime_contract_edges=[
            RuntimeContractEdge(
                a=c["a"],
                b=c["b"],
                journey=c["journey"],
                artifacts=c["artifacts"],
                direction=c["direction"],
                supported=c["supported"],
            )
            for c in content["contracts"]
        ],
    )
    frozen_graph = Graph.from_dict(content["graph"])
    recomputed = plan_digest(plan, frozen_graph)
    if recomputed != content["plan_digest"]:
        raise ReceiptError(
            "frozen plan digest does not recompute from its own canonical "
            "graph and moving set; the content is semantically inconsistent"
        )
    return FrozenPlan(
        plan=plan,
        source_sha=content["source_sha"],
        plan_digest=content["plan_digest"],
        resolved=content.get("resolved", {}),
        graph_canonical=content["graph"],
        frozen_id=expected_id,
    )


def resume_remaining(
    plan: Plan,
    partial: dict[str, "ReceiptEntry"],
    *,
    observed: dict[str, "ReceiptEntry"],
) -> list[PlanNode]:
    """Nodes still to run. A partial entry is accepted only when the observed
    authoritative state matches it exactly; drift fails closed."""
    for component, entry in partial.items():
        seen = observed.get(component)
        if seen is None:
            raise ReceiptError(
                f"partial receipt claims {component} published but nothing is observed"
            )
        if seen.version != entry.version or seen.digest != entry.digest:
            raise ReceiptError(
                f"{component}: observed state {seen.version}/{seen.digest} does "
                f"not match the partial receipt {entry.version}/{entry.digest}"
            )
    return [n for n in plan.moving if n.component not in partial]


# ── approvals and receipts ───────────────────────────────────────────


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
    phase: str = "staged"  # staged | published | verified
    pointer_state: str | None = None
    # The structured delivery proof validate_delivery_proof enforces:
    # {"obligation": str, "evidence_id": str, "digest": str, ...extensions}.
    delivery_proof: dict | None = None
    digest_set: dict | None = None  # complete artifact set for registry components
    # The structured lane stage reference (LaneRef.to_dict()), persisted
    # unchanged so resume and continuation always name the original
    # run/artifact/source/digest.
    lane_ref: dict | None = None


@dataclass
class Receipt:
    plan_digest: str
    source_sha: str
    entries: dict[str, ReceiptEntry]
    approvals: tuple = ()
    frozen_plan_id: str = ""
    staged_manifest_id: str = ""
    partial: bool = False


def seal_receipt(
    plan: Plan,
    graph: Graph,
    *,
    source_sha: str,
    entries: dict[str, ReceiptEntry],
    approvals: dict[str, Approval],
    frozen_plan_id: str = "",
    staged_manifest_id: str = "",
    partial: bool = False,
) -> tuple[bytes, str]:
    """Returns (sealed bytes, digest). The digest MUST be recorded with an
    external authority; beside the receipt it is only a checksum. Entries
    equal the planned set (subset allowed only for partial); pointer nodes
    carry pointer state; delivery nodes - delivery_restart components AND
    delivery-lane components - carry proof; every approval-required node maps
    to ITS OWN structured approval."""
    planned = {n.component for n in plan.moving}
    extra = set(entries) - planned
    if extra:
        raise ReceiptError(f"receipt entries outside the planned set: {sorted(extra)}")
    if not partial and set(entries) != planned:
        missing = planned - set(entries)
        raise ReceiptError(
            f"receipt entries must equal the planned set; missing={sorted(missing)}"
        )
    if partial and not entries:
        raise ReceiptError("a partial receipt with no entries records nothing")
    if not partial:
        unverified = [n for n, e in entries.items() if e.phase != "verified"]
        if unverified:
            raise ReceiptError(
                f"a final receipt requires every entry verified; not verified: "
                f"{sorted(unverified)}"
            )
    for node in plan.moving:
        if node.component not in entries:
            continue
        entry = entries[node.component]
        if node.reason.startswith("pointer:") and not entry.pointer_state:
            raise ReceiptError(
                f"{node.component}: pointer node sealed without pointer_state"
            )
        component = graph.components.get(node.component)
        needs_delivery = component is not None and (
            component.delivery_restart is not None or component.lane is not None
        )
        if needs_delivery:
            if not entry.delivery_proof:
                raise ReceiptError(
                    f"{node.component}: delivery node sealed without delivery_proof"
                )
            validate_delivery_proof(
                entry.delivery_proof,
                _delivery_obligation(graph, node.component),
                node.component,
            )
        if component is not None and component.approval_required:
            approval = approvals.get(node.component)
            if (
                not isinstance(approval, Approval)
                or not approval.who
                or not approval.when
            ):
                raise ReceiptError(
                    f"{node.component}: approval-required node sealed without its "
                    "own structured approval record"
                )
    body = json.dumps(
        {
            "plan_digest": plan_digest(plan, graph),
            "frozen_plan_id": frozen_plan_id,
            "staged_manifest_id": staged_manifest_id,
            "partial": partial,
            "source_sha": source_sha,
            "entries": {
                name: {
                    "version": e.version,
                    "digest": e.digest,
                    "digest_set": e.digest_set,
                    "phase": e.phase,
                    "pointer_state": e.pointer_state,
                    "delivery_proof": e.delivery_proof,
                    "lane_ref": e.lane_ref,
                }
                for name, e in sorted(entries.items())
            },
            "approvals": {
                component: {"who": a.who, "when": a.when}
                for component, a in sorted(approvals.items())
            },
        },
        sort_keys=True,
    )
    seal = hashlib.sha256(body.encode()).hexdigest()
    sealed = json.dumps({"body": body, "seal": seal}).encode()
    return sealed, hashlib.sha256(sealed).hexdigest()


def load_sealed_receipt(data: bytes, *, expected_digest: str) -> Receipt:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ReceiptError("receipt bytes do not match the externally recorded digest")
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
        frozen_plan_id=parsed.get("frozen_plan_id", ""),
        staged_manifest_id=parsed.get("staged_manifest_id", ""),
        partial=parsed.get("partial", False),
        entries={
            name: ReceiptEntry(
                version=e["version"],
                digest=e["digest"],
                phase=e.get("phase", "staged"),
                pointer_state=e.get("pointer_state"),
                delivery_proof=e.get("delivery_proof"),
                digest_set=e.get("digest_set"),
                lane_ref=e.get("lane_ref"),
            )
            for name, e in parsed["entries"].items()
        },
        approvals=tuple(sorted(parsed.get("approvals", {}).items())),
    )


def receipt_matches_run(
    receipt: Receipt, plan: Plan, graph: Graph, *, source_sha: str
) -> tuple[bool, str]:
    if receipt.source_sha != source_sha:
        return False, f"source mismatch: receipt {receipt.source_sha}, run {source_sha}"
    current = plan_digest(plan, graph)
    if receipt.plan_digest != current:
        return False, (
            f"plan digest mismatch: receipt {receipt.plan_digest}, run {current}"
        )
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


# ── durable artifact store and digest authority ──────────────────────


class FileArtifactStore:
    """Immutable content store: an artifact id is written once, ever."""

    def __init__(self, root: Path):
        self.root = Path(root) / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, artifact_id: str) -> Path:
        safe = artifact_id.replace("/", "_").replace(":", "__")
        return self.root / safe

    def put(self, artifact_id: str, data: bytes) -> None:
        path = self._path(artifact_id)
        if path.exists():
            raise ReceiptError(f"artifact {artifact_id} already exists; immutable")
        path.write_bytes(data)

    def get(self, artifact_id: str) -> bytes:
        path = self._path(artifact_id)
        if not path.exists():
            raise ReceiptError(f"no artifact stored under {artifact_id}")
        return path.read_bytes()


class FileDigestAuthority:
    """Append-only digest records. Suitable for local development and the
    process-restart demonstration; it is CALLER-WRITABLE, so its trust class
    is local-development and the real release path refuses it. An external
    immutable authority (workflow/release artifact metadata) advertises
    external-immutable."""

    trust_class = "local-development"

    def __init__(self, root: Path):
        self.path = Path(root) / "digest-authority.jsonl"
        self._records: dict[str, str] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                entry = json.loads(line)
                self._records[entry["artifact_id"]] = entry["digest"]

    def record(self, artifact_id: str, digest: str) -> None:
        if artifact_id in self._records:
            raise ReceiptError(
                f"digest for {artifact_id} already recorded; append-only"
            )
        with open(self.path, "a") as handle:
            handle.write(
                json.dumps({"artifact_id": artifact_id, "digest": digest}) + "\n"
            )
        self._records[artifact_id] = digest

    def expected_digest(self, artifact_id: str) -> str | None:
        return self._records.get(artifact_id)

    def recorded_ids(self) -> list[str]:
        return list(self._records)


# ── external workflow-artifact store and authority (awebai/aw lane) ──
#
# Artifact bytes and their expected digest resolve through SEPARATE
# capabilities of the same external system: the blob download endpoint and
# the server-computed digest field of the artifacts metadata API. GitHub
# writes the digest at upload and no caller can rewrite it afterwards.
# Neither capability is writable from here.

AW_LANE_WORKFLOW_PATH = ".github/workflows/aw-release.yml"
# Each lane binds its exact artifact source: the repository whose reviewed
# dispatch workflow stages it, and that workflow's exact path. This is the
# whole allowlist - no other repository or workflow is a lane source.
LANE_ARTIFACT_SOURCES = {
    "aw": ("awebai/aw", AW_LANE_WORKFLOW_PATH),
    "server": ("awebai/aweb", ".github/workflows/pypi-release.yml"),
    "awid-pypi": ("awebai/aweb", ".github/workflows/pypi-release.yml"),
    "awid-image": ("awebai/aweb", ".github/workflows/awid-image-release.yml"),
}
GITHUB_ARTIFACT_REPO_ALLOWLIST = tuple(sorted(
    {repo for repo, _ in LANE_ARTIFACT_SOURCES.values()}
))
ANCHOR_REPO = "awebai/aweb"
ANCHOR_WORKFLOW_PATH = ".github/workflows/release-anchor.yml"
ANCHOR_WORKFLOW_FILE = "release-anchor.yml"
# GitHub bounds the TOTAL workflow-dispatch payload at 65,535 characters;
# the check bounds the ENCODED body plus the other input fields with margin,
# both here before dispatch and again inside the workflow.
ANCHOR_DISPATCH_LIMIT = 64000


def _run_gh_api(path: str) -> bytes:
    import subprocess

    result = subprocess.run(["gh", "api", path], capture_output=True)
    if result.returncode != 0:
        raise ReceiptError(
            f"gh api {path} failed: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def _parse_gh_artifact_id(artifact_id: str) -> tuple[str, str, str]:
    parts = artifact_id.split(":")
    if len(parts) != 4 or parts[0] != "gh-artifact" or not all(parts):
        raise ReceiptError(
            f"external artifact id must be gh-artifact:<repo>:<run>:<artifact>,"
            f" got {artifact_id!r}"
        )
    _, repo, run_id, gh_artifact_id = parts
    if repo not in GITHUB_ARTIFACT_REPO_ALLOWLIST:
        raise ReceiptError(
            f"repository {repo} is not an allowlisted artifact source "
            f"({', '.join(GITHUB_ARTIFACT_REPO_ALLOWLIST)})"
        )
    return repo, run_id, gh_artifact_id


def _gh_artifact_metadata(api, artifact_id: str) -> tuple[dict, str, str, str]:
    repo, run_id, gh_artifact_id = _parse_gh_artifact_id(artifact_id)
    meta = json.loads(api(f"repos/{repo}/actions/artifacts/{gh_artifact_id}"))
    if str(meta.get("workflow_run", {}).get("id")) != run_id:
        raise ReceiptError(
            f"{artifact_id}: artifact does not belong to run {run_id}"
        )
    if meta.get("expired") is not False:
        raise ReceiptError(
            f"{artifact_id}: staged artifact is expired; re-stage, never rebuild"
        )
    digest = meta.get("digest") or ""
    if not digest.startswith("sha256:"):
        raise ReceiptError(
            f"{artifact_id}: API digest is {digest!r}, expected sha256:<hex>"
        )
    return meta, repo, run_id, gh_artifact_id


def _validated_aw_artifact_meta(
    api, artifact_id: str, *, expected_repo: str = "awebai/aw",
    workflow_path: str = AW_LANE_WORKFLOW_PATH,
):
    """Metadata plus producing-run validation shared by every lane's store
    and digest authority: the lane's exact repository and reviewed workflow
    path, successful non-fork run, unexpired artifact."""
    meta, repo, run_id, gh_artifact_id = _gh_artifact_metadata(api, artifact_id)
    if repo != expected_repo:
        raise ReceiptError(
            f"{artifact_id}: repository {repo} is not this lane's source "
            f"{expected_repo}"
        )
    run = json.loads(api(f"repos/{repo}/actions/runs/{run_id}"))
    if run.get("path") != workflow_path:
        raise ReceiptError(
            f"{artifact_id}: staging run used workflow "
            f"{run.get('path')!r}, not the reviewed {workflow_path}"
        )
    if run.get("conclusion") != "success":
        raise ReceiptError(
            f"{artifact_id}: staging run concluded "
            f"{run.get('conclusion')!r}, not success"
        )
    if run.get("head_repository", {}).get("full_name") != repo:
        raise ReceiptError(
            f"{artifact_id}: staging run came from "
            f"{run.get('head_repository', {}).get('full_name')!r}, not {repo}"
        )
    return meta, repo, run_id, gh_artifact_id


class GithubArtifactStore:
    """Read-only exact-bytes retrieval of a staged workflow artifact,
    bound to one lane's exact repository and workflow."""

    def __init__(self, api=None, *, repo: str = "awebai/aw",
                 workflow_path: str = AW_LANE_WORKFLOW_PATH):
        self._api = api or _run_gh_api
        self._repo = repo
        self._workflow_path = workflow_path

    def get(self, artifact_id: str) -> bytes:
        meta, repo, run_id, gh_artifact_id = _validated_aw_artifact_meta(
            self._api, artifact_id,
            expected_repo=self._repo, workflow_path=self._workflow_path,
        )
        data = self._api(
            f"repos/{repo}/actions/artifacts/{gh_artifact_id}/zip"
        )
        actual = hashlib.sha256(data).hexdigest()
        expected = meta["digest"].removeprefix("sha256:")
        if actual != expected:
            raise ReceiptError(
                f"{artifact_id}: downloaded zip digest {actual} does not "
                f"equal the API-recorded digest {expected}"
            )
        return data

    def put(self, artifact_id: str, data: bytes) -> None:
        raise ReceiptError(
            "the external workflow-artifact store is read-only; artifacts are "
            "written by the staging workflow, never from here"
        )


class GithubArtifactDigestAuthority:
    """Expected digests resolve from the server-computed metadata field."""

    trust_class = "external-immutable"

    def __init__(self, api=None, *, repo: str = "awebai/aw",
                 workflow_path: str = AW_LANE_WORKFLOW_PATH):
        self._api = api or _run_gh_api
        self._repo = repo
        self._workflow_path = workflow_path

    def expected_digest(self, artifact_id: str) -> str:
        meta, _, _, _ = _validated_aw_artifact_meta(
            self._api, artifact_id,
            expected_repo=self._repo, workflow_path=self._workflow_path,
        )
        return meta["digest"].removeprefix("sha256:")

    def record(self, artifact_id: str, digest: str) -> None:
        raise ReceiptError(
            "the external digest authority is not caller-writable; GitHub "
            "records the digest at upload"
        )


class GithubAnchorTransport:
    """Real transport over the anchors repository: paginated artifact
    listing, raw ZIP download, and the dispatch of the checked-in anchor
    workflow. Inputs reach the dispatch as literal fields, never shell."""

    def __init__(self, api=None, repo: str = ANCHOR_REPO):
        self._api = api or _run_gh_api
        self.repo = repo

    def list_artifacts(self) -> list[dict]:
        collected: list[dict] = []
        page = 1
        while True:
            body = json.loads(self._api(
                f"repos/{self.repo}/actions/artifacts?per_page=100&page={page}"
            ))
            artifacts = body.get("artifacts", [])
            if not artifacts:
                return collected
            collected.extend(artifacts)
            page += 1

    def artifact_zip(self, artifact_id) -> bytes:
        return self._api(
            f"repos/{self.repo}/actions/artifacts/{artifact_id}/zip"
        )

    def anchor_run(self, run_id) -> dict:
        return json.loads(self._api(f"repos/{self.repo}/actions/runs/{run_id}"))

    def dispatch_anchor(self, logical_id: str, digest: str, body_gzip_b64: str):
        import subprocess

        result = subprocess.run(
            [
                "gh", "workflow", "run", ANCHOR_WORKFLOW_FILE,
                "--repo", self.repo,
                "-f", f"logical_id={logical_id}",
                "-f", f"digest={digest}",
                "-f", f"body_gzip_b64={body_gzip_b64}",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            raise ReceiptError(
                "anchor dispatch failed: "
                + result.stderr.decode(errors="replace").strip()
            )


def _anchor_name(logical_id: str, digest: str) -> str:
    # Collision-resistant hash of the EXACT logical id; the artifact itself
    # carries the exact id for verification, the name only locates it.
    id_hash = hashlib.sha256(logical_id.encode()).hexdigest()
    return f"anchor--{id_hash}--{digest}"


def _validate_anchor_artifact(transport, artifact: dict) -> tuple[str, str, bytes]:
    """Full validation of one anchor artifact: producing run provenance
    (exact release-anchor.yml, success, this repository), raw ZIP hashed
    against GitHub's API digest before extraction, name hash bound to the
    exact recorded logical id, and body hashed against the declared digest.
    Returns (logical_id, digest, body)."""
    import zipfile

    name = artifact.get("name", "")
    run_id = (artifact.get("workflow_run") or {}).get("id")
    run = transport.anchor_run(run_id)
    if run.get("path") != ANCHOR_WORKFLOW_PATH:
        raise ReceiptError(
            f"anchor {name}: produced by workflow {run.get('path')!r}, not "
            f"the reviewed {ANCHOR_WORKFLOW_PATH} (release-anchor.yml)"
        )
    if run.get("conclusion") != "success":
        raise ReceiptError(
            f"anchor {name}: producing run concluded "
            f"{run.get('conclusion')!r}, not success"
        )
    if run.get("head_repository", {}).get("full_name") != ANCHOR_REPO:
        raise ReceiptError(
            f"anchor {name}: producing run came from "
            f"{run.get('head_repository', {}).get('full_name')!r}"
        )
    zip_bytes = transport.artifact_zip(artifact["id"])
    api_digest = (artifact.get("digest") or "").removeprefix("sha256:")
    if hashlib.sha256(zip_bytes).hexdigest() != api_digest:
        raise ReceiptError(
            f"anchor {name}: ZIP bytes do not hash to the API digest"
        )
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        record = json.loads(archive.read("record.json"))
        body = archive.read("body")
    logical_id = record.get("logical_id")
    declared = record.get("digest")
    expected_name = _anchor_name(logical_id or "", declared or "")
    if name != expected_name:
        raise ReceiptError(
            f"anchor {name}: name does not derive from the recorded logical "
            f"id and digest"
        )
    actual = hashlib.sha256(body).hexdigest()
    if actual != declared:
        raise ReceiptError(
            f"anchor {name}: body digest {actual} does not equal the "
            f"declared {declared}"
        )
    return logical_id, declared, body


def _validated_anchor_candidates(transport, logical_id: str) -> dict[str, bytes]:
    """All anchors for the logical id, fully validated by the shared
    validator. A matching EXPIRED identity refuses: its evidence is
    unreadable and must never be silently re-anchored. Returns
    {digest: body}."""
    prefix = f"anchor--{hashlib.sha256(logical_id.encode()).hexdigest()}--"
    found: dict[str, bytes] = {}
    for artifact in transport.list_artifacts():
        name = artifact.get("name", "")
        if not name.startswith(prefix):
            continue
        if artifact.get("expired") is not False:
            raise ReceiptError(
                f"{logical_id}: anchor {name} is expired; its evidence is "
                "unreadable and the identity must not be re-anchored"
            )
        found_id, declared, body = _validate_anchor_artifact(transport, artifact)
        if found_id != logical_id:
            raise ReceiptError(
                f"anchor {name}: record names {found_id!r}, not the "
                f"requested {logical_id!r}"
            )
        if declared in found and found[declared] != body:
            raise ReceiptError(
                f"anchor {name}: duplicate anchors disagree on content"
            )
        found[declared] = body
    if len(found) > 1:
        raise ReceiptError(
            f"{logical_id}: conflicting anchors record digests "
            f"{sorted(found)}; refusing"
        )
    return found


class GithubAnchorStore:
    """Writable external anchor store: put dispatches the checked-in anchor
    workflow when no exact anchor exists and reconciles by deterministic
    identity; get returns validated anchored bytes."""

    POLL_ATTEMPTS = 60

    def __init__(self, transport=None, waiter=None):
        self._transport = transport or GithubAnchorTransport()
        self._waiter = waiter if waiter is not None else (
            lambda: __import__("time").sleep(5)
        )

    def get(self, artifact_id: str) -> bytes:
        found = _validated_anchor_candidates(self._transport, artifact_id)
        if not found:
            raise ReceiptError(f"no anchor recorded for {artifact_id}")
        return next(iter(found.values()))

    def put(self, artifact_id: str, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        found = _validated_anchor_candidates(self._transport, artifact_id)
        if found:
            if digest in found:
                return  # reconciled: the exact anchor already exists
            raise ReceiptError(
                f"{artifact_id} is anchored with digest {sorted(found)[0]}, "
                f"refusing different bytes {digest}"
            )
        import base64
        import gzip

        encoded = base64.b64encode(gzip.compress(data)).decode()
        total = len(encoded) + len(artifact_id) + len(digest)
        if total > ANCHOR_DISPATCH_LIMIT:
            raise ReceiptError(
                f"{artifact_id}: encoded dispatch payload of {total} "
                f"characters exceeds the bound of {ANCHOR_DISPATCH_LIMIT}; "
                "GitHub rejects oversize dispatches before the workflow runs"
            )
        self._transport.dispatch_anchor(artifact_id, digest, encoded)
        for _ in range(self.POLL_ATTEMPTS):
            found = _validated_anchor_candidates(self._transport, artifact_id)
            if digest in found:
                return
            self._waiter()
        raise ReceiptError(
            f"{artifact_id}: anchor did not appear after dispatch; a repeated "
            "put reconciles by deterministic identity before dispatching again"
        )


class GithubAnchorDigestAuthority:
    """Digest records resolve from validated anchor artifacts; record()
    verifies the already-uploaded anchor and never dispatches or writes."""

    trust_class = "external-immutable"

    def __init__(self, transport=None):
        self._transport = transport or GithubAnchorTransport()

    def expected_digest(self, artifact_id: str) -> str | None:
        found = _validated_anchor_candidates(self._transport, artifact_id)
        if not found:
            return None
        return next(iter(found))

    def record(self, artifact_id: str, digest: str) -> None:
        found = _validated_anchor_candidates(self._transport, artifact_id)
        if not found:
            raise ReceiptError(
                f"{artifact_id}: no anchor uploaded; record verifies, the "
                "store's put dispatches"
            )
        if digest not in found:
            raise ReceiptError(
                f"{artifact_id}: anchor records {sorted(found)[0]}, not the "
                f"expected {digest}"
            )

    def recorded_ids(self) -> list[str]:
        ids: set[str] = set()
        for artifact in self._transport.list_artifacts():
            name = artifact.get("name", "")
            if not name.startswith("anchor--"):
                continue
            if artifact.get("expired") is not False:
                # An expired anchor is unreadable evidence; reads of its
                # identity refuse loudly through the candidate validator.
                continue
            logical_id, _, _ = _validate_anchor_artifact(
                self._transport, artifact
            )
            ids.add(logical_id)
        return sorted(ids)


@dataclass(frozen=True)
class LaneRef:
    """A lane's structured stage reference: the exact external artifact, the
    INDEPENDENTLY SUPPLIED lane source SHA (never read from the artifact's
    own manifest), and the artifact's outer ZIP digest as the caller binds
    it. Persisted unchanged through staging, publication, verification,
    receipts, and resume."""

    artifact: str
    aw_source_sha: str
    zip_digest: str

    def __post_init__(self):
        _parse_gh_artifact_id(self.artifact)
        if not re.fullmatch(r"[0-9a-f]{40}", self.aw_source_sha or ""):
            raise ReceiptError(
                f"lane source must be exactly 40 lowercase hex characters, "
                f"got {self.aw_source_sha!r}"
            )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.zip_digest or ""):
            raise ReceiptError(
                f"lane zip digest must be sha256:<64 hex>, got {self.zip_digest!r}"
            )

    def to_dict(self) -> dict:
        return {
            "artifact": self.artifact,
            "aw_source_sha": self.aw_source_sha,
            "zip_digest": self.zip_digest,
        }

    @classmethod
    def from_dict(cls, data) -> "LaneRef":
        if not isinstance(data, dict) or set(data) != {
            "artifact", "aw_source_sha", "zip_digest"
        }:
            raise ReceiptError(
                f"lane reference must carry exactly artifact/aw_source_sha/"
                f"zip_digest, got {data!r}"
            )
        return cls(**data)


def parse_stage_artifact_argument(value: str) -> tuple[str, LaneRef]:
    """--stage-artifact component=<name>,ref=<gh-artifact:...>,source=<40hex>,
    digest=sha256:<64hex> - literal-validated before anything uses it."""
    fields = {}
    for part in value.split(","):
        key, _, item = part.partition("=")
        fields[key] = item
    if set(fields) != {"component", "ref", "source", "digest"} or not all(
        fields.values()
    ):
        raise ReceiptError(
            "--stage-artifact must be component=<name>,ref=<gh-artifact:...>,"
            f"source=<sha>,digest=<sha256:hex>, got {value!r}"
        )
    return fields["component"], LaneRef(
        artifact=fields["ref"],
        aw_source_sha=fields["source"],
        zip_digest=fields["digest"],
    )


def expected_lane_payload_names(version: str) -> tuple[list[str], list[str]]:
    """The aw lane's exact payload basenames for a version: six archives +
    checksums.txt under dist/, seven npm tgz under npm/."""
    dist = []
    for platform in ("linux_amd64", "linux_arm64", "darwin_amd64",
                     "darwin_arm64", "windows_amd64", "windows_arm64"):
        ext = "zip" if platform.startswith("windows") else "tar.gz"
        dist.append(f"aw_{version}_{platform}.{ext}")
    dist.append("checksums.txt")
    npm = [f"awebai-aw-{version}.tgz"] + [
        f"awebai-aw-{p}-{version}.tgz"
        for p in ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64",
                  "windows-x64", "windows-arm64")
    ]
    return dist, npm


def parse_stage_artifact_arguments(values: list[str]) -> dict[str, LaneRef]:
    refs: dict[str, LaneRef] = {}
    for value in values:
        component, ref = parse_stage_artifact_argument(value)
        if component in refs:
            raise ReceiptError(
                f"--stage-artifact names component {component} more than once"
            )
        refs[component] = ref
    return refs


def validate_lane_staged_artifact(
    zip_bytes: bytes, *, expected_source_sha: str, expected_version: str
) -> dict:
    """Semantic validation of a lane's staged artifact ZIP: the typed
    manifest must bind the declared source and version, record mode
    stage-only (verify-only evidence is never publishable), and its files
    map must name exactly the payload members present, each matching its
    digest, with a canonical set digest that recomputes."""
    import zipfile

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        if "manifest.json" not in names:
            raise ReceiptError("staged artifact carries no manifest.json")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("mode") != "stage-only":
            raise ReceiptError(
                f"staged artifact mode is {manifest.get('mode')!r}; only "
                "stage-only artifacts continue to publication"
            )
        if manifest.get("source_sha") != expected_source_sha:
            raise ReceiptError(
                f"staged manifest binds source {manifest.get('source_sha')}, "
                f"expected {expected_source_sha}"
            )
        if manifest.get("candidate_version") != expected_version:
            raise ReceiptError(
                f"staged manifest binds version "
                f"{manifest.get('candidate_version')}, expected {expected_version}"
            )
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise ReceiptError("staged manifest has no files map")
        recomputed = hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()
        ).hexdigest()
        if manifest.get("canonical_set_digest") != recomputed:
            raise ReceiptError(
                "staged manifest canonical set digest does not recompute "
                "from its files map"
            )
        # The real reviewed protocol: manifest files keys are exactly the
        # 14 basenames; each exists as exactly one dist/ or npm/ member.
        dist_names, npm_names = expected_lane_payload_names(expected_version)
        expected_keys = set(dist_names) | set(npm_names)
        if set(files) != expected_keys:
            raise ReceiptError(
                f"staged manifest binds {sorted(files)}, expected exactly the "
                f"{len(expected_keys)} protocol payloads for {expected_version}"
            )
        member_for = {}
        payload_names = [n for n in names if n != "manifest.json"]
        for member in payload_names:
            prefix, _, base = member.partition("/")
            if prefix not in ("dist", "npm") or not base or base not in files:
                raise ReceiptError(
                    f"staged artifact carries {member}, which the manifest "
                    "does not bind"
                )
            expected_prefix = "dist" if base in dist_names else "npm"
            if prefix != expected_prefix:
                raise ReceiptError(
                    f"staged artifact places {base} under {prefix}/, the "
                    f"protocol places it under {expected_prefix}/"
                )
            if base in member_for:
                raise ReceiptError(
                    f"staged artifact carries {base} more than once "
                    f"({member_for[base]} and {member})"
                )
            member_for[base] = member
        for base, digest in files.items():
            member = member_for.get(base)
            if member is None:
                raise ReceiptError(
                    f"staged manifest binds {base}, missing from the artifact"
                )
            actual = hashlib.sha256(archive.read(member)).hexdigest()
            if actual != digest:
                raise ReceiptError(
                    f"{base}: payload digest {actual} does not equal the "
                    f"manifest's {digest}"
                )
    return manifest


def _fetch_aw_release_asset(name: str, version: str) -> bytes | None:
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            ["gh", "release", "download", f"v{version}",
             "--repo", GITHUB_ARTIFACT_REPO_ALLOWLIST[0],
             "--pattern", name, "--output", f"{tmp}/{name}"],
            capture_output=True,
        )
        if result.returncode != 0:
            return None
        return Path(f"{tmp}/{name}").read_bytes()


def _fetch_npm_tarball(package: str, version: str) -> bytes | None:
    import subprocess
    import urllib.request

    result = subprocess.run(
        ["npm", "view", f"{package}@{version}", "dist.tarball"],
        capture_output=True, text=True,
    )
    tarball = result.stdout.strip()
    if result.returncode != 0 or not tarball:
        return None
    with urllib.request.urlopen(tarball) as response:
        return response.read()


class AwLaneRuns:
    """The aw-release.yml runs surface used for continuation correlation.
    The listing reads the newest page, which bounds the snapshot window the
    exactly-one-new-run check operates over; the reviewed workflow's
    non-cancelling concurrency group serializes runs."""

    def __init__(self, api=None, *, repo: str = "awebai/aw",
                 workflow_file: str = "aw-release.yml"):
        self._api = api or _run_gh_api
        self.repo = repo
        self.workflow_file = workflow_file

    def list_run_ids(self) -> list[int]:
        body = json.loads(self._api(
            f"repos/{self.repo}/actions/workflows/{self.workflow_file}/runs"
            "?per_page=100"
        ))
        return [run["id"] for run in body.get("workflow_runs", [])]

    def dispatch(self, inputs: dict) -> None:
        import subprocess

        command = ["gh", "workflow", "run", self.workflow_file,
                   "--repo", self.repo]
        for key, value in sorted(inputs.items()):
            command += ["-f", f"{key}={value}"]
        result = subprocess.run(command, capture_output=True)
        if result.returncode != 0:
            raise ReceiptError(
                "continuation dispatch failed: "
                + result.stderr.decode(errors="replace").strip()
            )

    def run_conclusion(self, run_id) -> str | None:
        body = json.loads(self._api(
            f"repos/{self.repo}/actions/runs/{run_id}"
        ))
        return body.get("conclusion")


class AwWorkflowLane:
    """The aw component's lane over the reviewed three-mode workflow.
    stage() loads the referenced staged bytes; publish() dispatches the
    reviewed continuation and requires the complete set observed; observe()
    reports real remote state from the ANCHORED staged entry; verify()
    re-observes. Nothing here rebuilds or repacks."""

    POLL_ATTEMPTS = 240

    def __init__(self, *, reader, lane_authority, refs, release_fetch,
                 npm_fetch, runs, waiter=None):
        self._reader = reader
        self._lane_authority = lane_authority
        self._refs = refs  # component -> LaneRef
        self._release_fetch = release_fetch  # (asset_name, version) -> bytes|None
        self._npm = NpmRegistryObserver(fetch=npm_fetch)
        self._runs = runs
        self._waiter = waiter if waiter is not None else (
            lambda: __import__("time").sleep(15)
        )

    def has_lane(self, component: str) -> bool:
        return component in self._refs

    def stage(self, node) -> "ReceiptEntry":
        ref = self._refs[node.component]
        # Independent capability first: the expected digest resolves through
        # the separately constructed lane authority and must equal the
        # caller binding BEFORE any blob is read.
        independent = self._lane_authority.expected_digest(ref.artifact)
        if f"sha256:{independent}" != ref.zip_digest:
            raise ReceiptError(
                f"{node.component}: independent authority records "
                f"sha256:{independent}, not the caller-bound {ref.zip_digest}"
            )
        data = self._reader.get(ref.artifact)
        actual = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if actual != ref.zip_digest:
            raise ReceiptError(
                f"{node.component}: staged bytes hash {actual}, not the "
                f"caller-bound {ref.zip_digest}"
            )
        manifest = validate_lane_staged_artifact(
            data,
            expected_source_sha=ref.aw_source_sha,
            expected_version=node.version,
        )
        files = manifest["files"]
        return ReceiptEntry(
            version=node.version,
            digest=canonical_digest_of_set(files),
            digest_set=files,
            lane_ref=ref.to_dict(),
        )

    def _observe_set(self, staged: "ReceiptEntry") -> dict[str, str | None]:
        """One real observation per staged identity; never an expectation."""
        observed: dict[str, str | None] = {}
        npm_names = []
        release_names = []
        for name in staged.digest_set:
            base = name.rsplit("/", 1)[-1]
            if base.endswith(".tgz"):
                npm_names.append((name, base))
            else:
                release_names.append((name, base))
        release = GithubReleaseObserver(
            fetch=lambda base: self._release_fetch(base, staged.version)
        )
        release_observed = release.observe([base for _, base in release_names])
        for name, base in release_names:
            observed[name] = release_observed[base]
        for name, base in npm_names:
            stem = base.removesuffix(".tgz")
            package, _, version = stem.replace("awebai-", "@awebai/", 1
                ).rpartition("-")
            observed[name] = self._npm.observe(package, version)
        return observed

    def observe(self, node, staged: "ReceiptEntry | None" = None):
        if staged is None or staged.digest_set is None:
            raise ReceiptError(
                f"{node.component}: observation requires the anchored staged "
                "entry; expected values are never re-derived"
            )
        observed = self._observe_set(staged)
        adopted, missing = classify_remote_state(staged.digest_set, observed)
        if missing:
            return None
        return ReceiptEntry(
            version=staged.version,
            digest=canonical_digest_of_set(
                {name: observed[name] for name in staged.digest_set}
            ),
            phase="published",
            digest_set={name: observed[name] for name in staged.digest_set},
            lane_ref=staged.lane_ref,
        )

    def publish(self, node, staged: "ReceiptEntry") -> "ReceiptEntry":
        ref = LaneRef.from_dict(staged.lane_ref)
        _, run_id, gh_artifact_id = _parse_gh_artifact_id(ref.artifact)
        before = set(self._runs.list_run_ids())
        self._runs.dispatch({
            "mode": "publish-continuation",
            "version": staged.version,
            "source_sha": ref.aw_source_sha,
            "stage_run_id": run_id,
            "stage_artifact_id": gh_artifact_id,
            "stage_zip_digest": ref.zip_digest,
        })
        new_runs: list = []
        for _ in range(self.POLL_ATTEMPTS):
            new_runs = [r for r in self._runs.list_run_ids() if r not in before]
            if new_runs:
                break
            self._waiter()
        if len(new_runs) != 1:
            raise ReceiptError(
                f"{node.component}: expected exactly one new continuation run, "
                f"identified {len(new_runs)}; refusing"
            )
        conclusion = None
        for _ in range(self.POLL_ATTEMPTS):
            conclusion = self._runs.run_conclusion(new_runs[0])
            if conclusion is not None:
                break
            self._waiter()
        if conclusion != "success":
            raise ReceiptError(
                f"{node.component}: continuation run {new_runs[0]} concluded "
                f"{conclusion!r}, not success"
            )
        observed = self.observe(node, staged)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: items missing after publication; a "
                "successful continuation must leave the complete exact set"
            )
        return observed

    def verify(self, node, published: "ReceiptEntry") -> None:
        observed = self.observe(node, published)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: verification observes an incomplete "
                "published set"
            )


def _lane_manifest_common(
    archive, *, expected_source_sha: str, expected_version: str,
    expected_package: str | None = None,
) -> dict:
    names = [n for n in archive.namelist() if not n.endswith("/")]
    for name in set(names):
        if names.count(name) != 1:
            raise ReceiptError(
                f"staged artifact carries {name} more than once; every "
                "entry must appear exactly once"
            )
    if "manifest.json" not in names:
        raise ReceiptError("staged artifact carries no manifest.json")
    manifest = json.loads(archive.read("manifest.json"))
    if manifest.get("mode") != "stage-only":
        raise ReceiptError(
            f"staged artifact mode is {manifest.get('mode')!r}; only "
            "stage-only artifacts continue to publication"
        )
    if manifest.get("source_sha") != expected_source_sha:
        raise ReceiptError(
            f"staged manifest binds source {manifest.get('source_sha')}, "
            f"expected {expected_source_sha}"
        )
    if manifest.get("candidate_version") != expected_version:
        raise ReceiptError(
            f"staged manifest binds version "
            f"{manifest.get('candidate_version')}, expected {expected_version}"
        )
    if expected_package is not None and manifest.get("package") != expected_package:
        raise ReceiptError(
            f"staged manifest is for package {manifest.get('package')!r}, "
            f"not {expected_package!r}"
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ReceiptError("staged manifest has no files map")
    recomputed = hashlib.sha256(
        json.dumps(files, sort_keys=True).encode()
    ).hexdigest()
    if manifest.get("canonical_set_digest") != recomputed:
        raise ReceiptError(
            "staged manifest canonical set digest does not recompute from "
            "its files map"
        )
    return manifest


def _validate_lane_members(
    archive, files: dict, member_for_base: dict[str, str]
) -> None:
    """Exact member placement and digests: every manifest basename present
    exactly once at its protocol location, no extras."""
    names = [n for n in archive.namelist() if not n.endswith("/")]
    payload_names = [n for n in names if n != "manifest.json"]
    expected_members = set(member_for_base.values())
    for member in payload_names:
        if member not in expected_members:
            raise ReceiptError(
                f"staged artifact carries {member}, which the protocol "
                "does not place"
            )
    for base, member in member_for_base.items():
        if member not in payload_names:
            raise ReceiptError(
                f"staged manifest binds {base}, missing from the artifact"
            )
        actual = hashlib.sha256(archive.read(member)).hexdigest()
        if actual != files[base]:
            raise ReceiptError(
                f"{base}: payload digest {actual} does not equal the "
                f"manifest's {files[base]}"
            )


def validate_pypi_lane_artifact(
    zip_bytes: bytes, *, expected_source_sha: str, expected_version: str,
    package: str, pypi_name: str,
) -> dict:
    """The PyPI lane protocol: exactly one sdist and one wheel for the
    version, members under dist/, manifest keys the two basenames."""
    import zipfile

    normalized = pypi_name.replace("-", "_")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        manifest = _lane_manifest_common(
            archive, expected_source_sha=expected_source_sha,
            expected_version=expected_version, expected_package=package,
        )
        files = manifest["files"]
        sdists = [b for b in files
                  if b == f"{normalized}-{expected_version}.tar.gz"]
        wheels = [b for b in files
                  if b.startswith(f"{normalized}-{expected_version}-")
                  and b.endswith(".whl")]
        if len(sdists) != 1 or len(wheels) != 1 or len(files) != 2:
            raise ReceiptError(
                f"staged manifest must bind exactly one sdist and one wheel "
                f"for {normalized} {expected_version}; bound {sorted(files)}"
            )
        _validate_lane_members(
            archive, files, {b: f"dist/{b}" for b in files}
        )
    return manifest


def flatten_oci_identities(identities: dict) -> dict[str, str]:
    """The registry's complete identity as a flat digest set: the index
    plus every platform manifest, config, and layer digest."""
    flat = {"index": identities["index"]}
    for key, ids in sorted(identities.get("platforms", {}).items()):
        flat[f"platform:{key}:manifest"] = ids["manifest"]
        flat[f"platform:{key}:config"] = ids["config"]
        for i, layer in enumerate(ids["layers"]):
            flat[f"platform:{key}:layer:{i}"] = layer
    return flat


def validate_image_lane_artifact(
    zip_bytes: bytes, *, expected_source_sha: str, expected_version: str,
) -> tuple[dict, dict]:
    """The awid-image lane protocol: exactly the OCI archive and its
    identities file at the artifact root. The archive is REINSPECTED with
    the reviewed .4 inspector (platforms, blobs, version/revision labels),
    and its derived identities must exactly equal the digest-proven
    identities.json. Returns (manifest, identities)."""
    import subprocess
    import tempfile
    import zipfile

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        manifest = _lane_manifest_common(
            archive, expected_source_sha=expected_source_sha,
            expected_version=expected_version, expected_package="awid-image",
        )
        files = manifest["files"]
        if set(files) != {"awid-oci.tar", "identities.json"}:
            raise ReceiptError(
                f"staged manifest must bind exactly the OCI archive and its "
                f"identities; bound {sorted(files)}"
            )
        _validate_lane_members(archive, files, {b: b for b in files})
        identities = json.loads(archive.read("identities.json"))
        oci_tar = archive.read("awid-oci.tar")
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "awid-oci.tar"
        out_path = Path(tmp) / "reinspected.json"
        tar_path.write_bytes(oci_tar)
        result = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts/oci-exact-publish.sh"),
             "inspect-staged", "--archive", str(tar_path),
             "--version", expected_version,
             "--source-sha", expected_source_sha,
             "--out", str(out_path)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise ReceiptError(
                "staged OCI archive fails the reviewed inspection: "
                + result.stderr.decode(errors="replace").strip()
            )
        reinspected = json.loads(out_path.read_bytes())
    if reinspected != identities:
        raise ReceiptError(
            "staged identities do not equal the archive's reinspected "
            "identities; the digest-proven identities.json must be exactly "
            "what the reviewed inspector derives"
        )
    return manifest, identities


class _WorkflowLaneBase:
    """Shared lane lifecycle over a reviewed three-mode dispatch workflow:
    independent-authority-gated staging, exactly-one-run continuation
    correlation, and observation from the anchored staged entry."""

    POLL_ATTEMPTS = 240

    def __init__(self, *, component, reader, lane_authority, refs, runs,
                 waiter=None):
        self.component = component
        self._reader = reader
        self._lane_authority = lane_authority
        self._refs = refs
        self._runs = runs
        self._waiter = waiter if waiter is not None else (
            lambda: __import__("time").sleep(15)
        )

    def has_lane(self, component: str) -> bool:
        return component in self._refs

    def _fetch_staged(self, ref: "LaneRef") -> bytes:
        independent = self._lane_authority.expected_digest(ref.artifact)
        if f"sha256:{independent}" != ref.zip_digest:
            raise ReceiptError(
                f"{self.component}: independent authority records "
                f"sha256:{independent}, not the caller-bound {ref.zip_digest}"
            )
        data = self._reader.get(ref.artifact)
        actual = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if actual != ref.zip_digest:
            raise ReceiptError(
                f"{self.component}: staged bytes hash {actual}, not the "
                f"caller-bound {ref.zip_digest}"
            )
        return data

    def _continuation_inputs(self, staged: "ReceiptEntry") -> dict:
        ref = LaneRef.from_dict(staged.lane_ref)
        _, run_id, gh_artifact_id = _parse_gh_artifact_id(ref.artifact)
        return {
            "mode": "publish-continuation",
            "version": staged.version,
            "source_sha": ref.aw_source_sha,
            "stage_run_id": run_id,
            "stage_artifact_id": gh_artifact_id,
            "stage_zip_digest": ref.zip_digest,
        }

    def _dispatch_and_wait(self, inputs: dict) -> None:
        before = set(self._runs.list_run_ids())
        self._runs.dispatch(inputs)
        new_runs: list = []
        for _ in range(self.POLL_ATTEMPTS):
            new_runs = [r for r in self._runs.list_run_ids() if r not in before]
            if new_runs:
                break
            self._waiter()
        if len(new_runs) != 1:
            raise ReceiptError(
                f"{self.component}: expected exactly one new continuation "
                f"run, identified {len(new_runs)}; refusing"
            )
        conclusion = None
        for _ in range(self.POLL_ATTEMPTS):
            conclusion = self._runs.run_conclusion(new_runs[0])
            if conclusion is not None:
                break
            self._waiter()
        if conclusion != "success":
            raise ReceiptError(
                f"{self.component}: continuation run {new_runs[0]} concluded "
                f"{conclusion!r}, not success"
            )

    def publish(self, node, staged: "ReceiptEntry") -> "ReceiptEntry":
        self._dispatch_and_wait(self._continuation_inputs(staged))
        observed = self.observe(node, staged)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: items missing after publication; a "
                "successful continuation must leave the complete exact set"
            )
        return observed

    def verify(self, node, published: "ReceiptEntry") -> None:
        observed = self.observe(node, published)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: verification observes an incomplete "
                "published set"
            )


class PypiWorkflowLane(_WorkflowLaneBase):
    """server / awid-pypi over pypi-release.yml. Observation is PyPI's
    per-file JSON truth: 404 is absence, exact adopts, missing continues,
    extra or mismatched files refuse permanently, outages refuse."""

    def __init__(self, *, pypi_name, pypi_observe, **kwargs):
        super().__init__(**kwargs)
        self._pypi_name = pypi_name
        self._pypi_observe = pypi_observe  # (package, version) -> (status, {file: sha})

    def stage(self, node) -> "ReceiptEntry":
        ref = self._refs[node.component]
        data = self._fetch_staged(ref)
        manifest = validate_pypi_lane_artifact(
            data,
            expected_source_sha=ref.aw_source_sha,
            expected_version=node.version,
            package=node.component,
            pypi_name=self._pypi_name,
        )
        files = manifest["files"]
        return ReceiptEntry(
            version=node.version,
            digest=canonical_digest_of_set(files),
            digest_set=files,
            lane_ref=ref.to_dict(),
        )

    def _continuation_inputs(self, staged):
        inputs = super()._continuation_inputs(staged)
        return {"package": self.component, **inputs}

    def observe(self, node, staged: "ReceiptEntry | None" = None):
        if staged is None or staged.digest_set is None:
            raise ReceiptError(
                f"{node.component}: observation requires the anchored staged "
                "entry; expected values are never re-derived"
            )
        status, observed = self._pypi_observe(self._pypi_name, staged.version)
        if status == 404:
            return None
        if status != 200:
            raise ReceiptError(
                f"{node.component}: PyPI observation returned status "
                f"{status}; unavailability is never an observation"
            )
        extra = sorted(set(observed) - set(staged.digest_set))
        if extra:
            raise ReceiptError(
                f"{node.component}: PyPI serves files not in the staged set: "
                f"{extra}; permanent"
            )
        missing = False
        for name, digest in staged.digest_set.items():
            remote = observed.get(name)
            if remote is None:
                missing = True
            elif remote != digest:
                raise ReceiptError(
                    f"{node.component}: {name}: PyPI serves sha256 {remote}, "
                    f"staged is {digest}; permanent"
                )
        if missing:
            return None
        observed_set = {name: observed[name] for name in staged.digest_set}
        return ReceiptEntry(
            version=staged.version,
            digest=canonical_digest_of_set(observed_set),
            phase="published",
            digest_set=observed_set,
            lane_ref=staged.lane_ref,
        )


class AwidImageWorkflowLane(_WorkflowLaneBase):
    """awid-image over awid-image-release.yml. Observation binds the
    immutable version tag to the staged index digest (mismatch refuses)
    and treats latest as the one planned mutable pointer (not yet
    transitioned continues); an unavailable observation refuses."""

    def __init__(self, *, repository, tag_observe, **kwargs):
        super().__init__(**kwargs)
        self.repository = repository
        self._tag_observe = tag_observe  # (tag) -> index digest | None; raises when unavailable

    def stage(self, node) -> "ReceiptEntry":
        ref = self._refs[node.component]
        data = self._fetch_staged(ref)
        _, identities = validate_image_lane_artifact(
            data,
            expected_source_sha=ref.aw_source_sha,
            expected_version=node.version,
        )
        # The registry's complete identity - never the transport payload
        # checksums: a registry publishes the index and every platform
        # manifest/config/layer, not the OCI tar container.
        registry_set = flatten_oci_identities(identities)
        return ReceiptEntry(
            version=node.version,
            digest=canonical_digest_of_set(registry_set),
            digest_set=registry_set,
            lane_ref=ref.to_dict(),
        )

    def _staged_identities(self, staged: "ReceiptEntry") -> dict:
        ref = LaneRef.from_dict(staged.lane_ref)
        data = self._fetch_staged(ref)
        _, identities = validate_image_lane_artifact(
            data,
            expected_source_sha=ref.aw_source_sha,
            expected_version=staged.version,
        )
        return identities

    def observe(self, node, staged: "ReceiptEntry | None" = None):
        if staged is None or staged.digest_set is None:
            raise ReceiptError(
                f"{node.component}: observation requires the anchored staged "
                "entry; expected values are never re-derived"
            )
        identities = self._staged_identities(staged)
        registry_set = flatten_oci_identities(identities)
        if registry_set != staged.digest_set:
            raise ReceiptError(
                f"{node.component}: staged registry identity does not equal "
                "the anchored entry's set"
            )
        index = identities["index"]
        version_digest = self._tag_observe(staged.version)
        if version_digest is None:
            return None
        if version_digest != index:
            raise ReceiptError(
                f"{node.component}: {self.repository}:{staged.version} "
                f"resolves to {version_digest}, staged index is {index}; an "
                "immutable version tag is never rewritten"
            )
        latest_digest = self._tag_observe("latest")
        if latest_digest != index:
            # latest is the planned mutable pointer; continuation transitions it.
            return None
        return ReceiptEntry(
            version=staged.version,
            digest=canonical_digest_of_set(registry_set),
            phase="published",
            digest_set=registry_set,
            lane_ref=staged.lane_ref,
        )


class WorkflowLanes:
    """Per-component delegation over the composed lane objects."""

    def __init__(self, lanes: dict):
        self._lanes = lanes

    def has_lane(self, component: str) -> bool:
        return component in self._lanes

    def stage(self, node):
        return self._lanes[node.component].stage(node)

    def publish(self, node, staged):
        return self._lanes[node.component].publish(node, staged)

    def verify(self, node, published):
        return self._lanes[node.component].verify(node, published)

    def observe(self, node, staged=None):
        lane = self._lanes.get(node.component)
        return lane.observe(node, staged) if lane is not None else None


def _observe_pypi(package: str, version: str):
    import urllib.error
    import urllib.request

    url = f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        with urllib.request.urlopen(url) as response:
            body = json.load(response)
            status = response.status
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except Exception as exc:
        raise ReceiptError(f"PyPI observation failed: {exc}") from exc
    return status, {
        u["filename"]: u["digests"]["sha256"] for u in body.get("urls", [])
    }


def _observe_ghcr_tag_factory(repository: str):
    import subprocess

    def observe(tag: str):
        listing = subprocess.run(
            ["skopeo", "list-tags", f"docker://{repository}"],
            capture_output=True,
        )
        if listing.returncode != 0:
            raise ReceiptError(
                f"{repository}: tag listing unavailable; observation failure "
                "is never an observation"
            )
        classify = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts/oci-exact-publish.sh"),
             "classify-listing", "--tag", tag],
            input=listing.stdout, capture_output=True,
        )
        if classify.returncode != 0:
            raise ReceiptError(
                f"{repository}: "
                + classify.stderr.decode(errors="replace").strip()
            )
        if classify.stdout.decode().strip() != "yes":
            return None
        raw = subprocess.run(
            ["skopeo", "inspect", "--raw", f"docker://{repository}:{tag}"],
            capture_output=True,
        )
        if raw.returncode != 0:
            raise ReceiptError(
                f"{repository}:{tag}: digest unavailable for a present tag"
            )
        return "sha256:" + hashlib.sha256(raw.stdout).hexdigest()

    return observe


def compose_workflow_lanes(graph: "Graph", refs: dict) -> WorkflowLanes:
    """Fresh-process lane composition, gated by the typed graph: a lane
    composes only for a component whose publish_lane declares the exact
    allowlisted provider, repository, workflow, and the three reviewed
    modes matching LANE_ARTIFACT_SOURCES."""
    lanes: dict = {}
    modes = ["stage-only", "publish-continuation", "verify-only"]
    for component, ref in refs.items():
        source = LANE_ARTIFACT_SOURCES.get(component)
        declared = (
            graph.components[component].publish_lane or {}
            if component in graph.components else {}
        )
        if (
            source is None
            or declared.get("provider") != "github-workflow-artifacts"
            or declared.get("repository") != source[0]
            or declared.get("workflow") != source[1]
            or declared.get("modes") != modes
        ):
            raise ReceiptError(
                f"--stage-artifact names {component}, whose graph lane does "
                "not declare the allowlisted provider/repository/workflow/"
                "modes surface"
            )
        repo, workflow_path = source
        reader = GithubArtifactStore(repo=repo, workflow_path=workflow_path)
        authority = GithubArtifactDigestAuthority(
            repo=repo, workflow_path=workflow_path
        )
        runs = AwLaneRuns(
            repo=repo, workflow_file=workflow_path.rsplit("/", 1)[-1]
        )
        if component == "aw":
            lanes[component] = AwWorkflowLane(
                reader=reader, lane_authority=authority,
                refs={component: ref},
                release_fetch=_fetch_aw_release_asset,
                npm_fetch=_fetch_npm_tarball,
                runs=runs,
            )
        elif component in ("server", "awid-pypi"):
            registry = (declared.get("registry") or {})
            lanes[component] = PypiWorkflowLane(
                component=component,
                pypi_name=registry.get("package", component),
                reader=reader, lane_authority=authority,
                refs={component: ref}, runs=runs,
                pypi_observe=_observe_pypi,
            )
        else:
            registry = (declared.get("registry") or {})
            repository = f"ghcr.io/{registry.get('package', 'awebai/awid')}"
            lanes[component] = AwidImageWorkflowLane(
                component=component,
                repository=repository,
                reader=reader, lane_authority=authority,
                refs={component: ref}, runs=runs,
                tag_observe=_observe_ghcr_tag_factory(repository),
            )
    return WorkflowLanes(lanes)


# ── G5 skew matrix runner (aweb-abbe.7 runner slice) ─────────────────
#
# The runner computes deterministic skew cells for every runtime-contract
# edge the plan touches and invokes a child harness per cell; the four
# journey harnesses (.7.1-.7.4) implement the SMALL invocation contract
# below without changing runner semantics:
#
#   harness.has_journey(edge) -> bool
#   harness.run(cell)         -> None on green; raise on red
#
# A cell binds the exact staged identities on candidate sides and the
# measured supported published versions on the other; declared-incomplete
# or unmeasured support refuses - floors are never invented.


@dataclass(frozen=True)
class SkewCell:
    edge_a: str
    edge_b: str
    journey: str
    direction: str  # a-to-b | b-to-a
    a_kind: str  # candidate | published-latest | published-floor | published
    b_kind: str
    a: dict  # {component, version, digest?, digest_set?}
    b: dict


def _candidate_side(component: str, staged: dict) -> dict:
    entry = staged.get(component)
    if entry is None or not entry.digest:
        raise ReceiptError(
            f"skew requires the exact staged identity for touched "
            f"{component}; none is staged"
        )
    if entry.lane_ref is None:
        raise ReceiptError(
            f"skew requires the structured lane reference for touched "
            f"{component}: a digest-only candidate gives a harness no way "
            "to retrieve the exact staged bytes"
        )
    LaneRef.from_dict(entry.lane_ref)
    return {
        "component": component,
        "version": entry.version,
        "digest": entry.digest,
        "digest_set": entry.digest_set,
        "lane_ref": dict(entry.lane_ref),
    }


def _published_side(component: str, version: str, kind: str) -> dict:
    return {"component": component, "version": version, "kind": kind}


def compute_skew_cells(
    edge: "RuntimeContractEdge", *, moving: set, staged: dict,
    support: dict, published_versions: dict,
) -> list[SkewCell]:
    """The joint-spec matrix, deterministically ordered. Both-sides-touched:
    candidate x candidate, candidate x published latest/floor, published
    latest/floor x candidate. One-side-touched: candidate x the complete
    measured supported published set."""
    supported = (support or {}).get("supported_versions", {})

    def version_key(version):
        try:
            return tuple(int(part) for part in version.split("."))
        except (AttributeError, ValueError):
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: supported set entry "
                f"{version!r} is not a dotted-numeric version"
            ) from None

    def supported_for(component: str) -> list[str]:
        versions = supported.get(component) or []
        if not versions:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: no measured supported "
                f"set for {component}; a floor is never invented"
            )
        if any(not isinstance(v, str) or not v for v in versions):
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: supported set for "
                f"{component} must be nonempty strings"
            )
        keys = [version_key(v) for v in versions]
        if len(set(versions)) != len(versions) or keys != sorted(keys):
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: supported set for "
                f"{component} must be strictly ordered and unique, got "
                f"{versions}"
            )
        authoritative = published_versions.get(component)
        if not authoritative:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: no authoritative "
                f"published latest for {component}; the measured set cannot "
                "self-certify"
            )
        if versions[-1] != authoritative:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: measured latest "
                f"{versions[-1]} does not equal the authoritative published "
                f"latest {authoritative} for {component}; the record is stale"
            )
        return list(versions)

    directions = (
        ["a-to-b", "b-to-a"]
        if edge.direction in ("both", "persisted-state-both")
        else [edge.direction]
    )
    a_touched = edge.a in moving
    b_touched = edge.b in moving
    pairs: list[tuple[str, dict, str, dict]] = []
    if a_touched and b_touched:
        cand_a = _candidate_side(edge.a, staged)
        cand_b = _candidate_side(edge.b, staged)
        pairs.append(("candidate", cand_a, "candidate", cand_b))
        for component, cand, cand_first in (
            (edge.b, cand_a, True), (edge.a, cand_b, False),
        ):
            versions = supported_for(component)
            latest, floor = published_versions[component], versions[0]
            kinds = [("published-latest", latest)]
            if floor != latest:
                kinds.append(("published-floor", floor))
            for kind, version in kinds:
                pub = _published_side(component, version, kind)
                if cand_first:
                    pairs.append(("candidate", cand, kind, pub))
                else:
                    pairs.append((kind, pub, "candidate", cand))
    elif a_touched or b_touched:
        touched, other = (edge.a, edge.b) if a_touched else (edge.b, edge.a)
        cand = _candidate_side(touched, staged)
        for version in supported_for(other):
            pub = _published_side(other, version, "published")
            if a_touched:
                pairs.append(("candidate", cand, "published", pub))
            else:
                pairs.append(("published", pub, "candidate", cand))
    cells: list[SkewCell] = []
    for a_kind, a_side, b_kind, b_side in pairs:
        for direction in directions:
            cells.append(SkewCell(
                edge_a=edge.a, edge_b=edge.b, journey=edge.journey,
                direction=direction, a_kind=a_kind, b_kind=b_kind,
                a=dict(a_side), b=dict(b_side),
            ))
    return cells


class MatrixSkewRunner:
    """The skew provider run_plan executes between staging and the first
    publish: every accepted edge is ordered and invoked cell by cell, and
    any red raises before a single continuation dispatch."""

    def __init__(self, *, harness, support, published_versions, moving):
        self._harness = harness
        self._support = support
        self._published = dict(published_versions)
        self._moving = set(moving)

    def has_matrix(self, edge) -> bool:
        return self._harness.has_journey(edge)

    def execute(self, edge, staged: dict) -> None:
        if edge.declared_incomplete:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b} is declared-incomplete;"
                " skew never runs on unmeasured support"
            )
        support = self._support.resolve(edge.supported.get("record", {}), edge)
        cells = compute_skew_cells(
            edge, moving=self._moving, staged=staged,
            support=support, published_versions=self._published,
        )
        for cell in cells:
            try:
                self._harness.run(cell)
            except ReceiptError:
                raise
            except Exception as exc:
                raise ReceiptError(
                    f"skew red on {cell.edge_a}<->{cell.edge_b} "
                    f"[{cell.a_kind} x {cell.b_kind}, {cell.direction}]: {exc}"
                ) from exc


# ── lane observers: one SHA-256 per published item ───────────────────


class GithubReleaseObserver:
    """Downloads release assets and reports one SHA-256 each, or None for
    an asset the release does not carry."""

    def __init__(self, fetch):
        self._fetch = fetch  # fetch(asset_name) -> bytes | None

    def observe(self, names: list[str]) -> dict[str, str | None]:
        observed: dict[str, str | None] = {}
        for name in names:
            data = self._fetch(name)
            observed[name] = (
                hashlib.sha256(data).hexdigest() if data is not None else None
            )
        return observed


class NpmRegistryObserver:
    """Downloads the registry tarball for a version and reports one
    SHA-256, or None when the version is not published."""

    def __init__(self, fetch):
        self._fetch = fetch  # fetch(package, version) -> bytes | None

    def observe(self, package: str, version: str) -> str | None:
        data = self._fetch(package, version)
        return hashlib.sha256(data).hexdigest() if data is not None else None


def classify_remote_state(
    staged: dict[str, str], observed: dict[str, str | None]
) -> tuple[list[str], list[str]]:
    """Adopt exact remote bytes, identify missing items, refuse anything
    else: a digest mismatch, or staged evidence with no observation."""
    adopted: list[str] = []
    missing: list[str] = []
    for name, digest in staged.items():
        if name not in observed:
            raise ReceiptError(
                f"{name}: no observation produced for staged evidence"
            )
        seen = observed[name]
        if seen is None:
            missing.append(name)
        elif seen == digest:
            adopted.append(name)
        else:
            raise ReceiptError(
                f"{name}: remote bytes {seen} do not equal staged {digest}"
            )
    return adopted, missing


@dataclass
class Providers:
    store: object
    authority: object
    lanes: object = None
    skew: object = None
    state: object = None
    source_sha: str | None = None
    measurement: object = None
    # Established by trusted composition (build_providers with an allowlisted
    # registration), never by an attribute a caller-writable implementation
    # asserts about itself.
    authority_trust: str = "local-development"


@dataclass(frozen=True)
class AuthorityRegistration:
    """An allowlisted provider kind: configuration selects one of these by
    name; arbitrary import-by-path composition does not exist. A registration
    constructs the ARTIFACT STORE and the DIGEST AUTHORITY as separate
    capabilities (an external release workflow stores bytes where other
    runners can fetch them, and digests where an independent authority
    attests them); lane observers join when .2-.4 provide them."""

    kind: str
    trust_class: str
    factory: object  # digest-authority factory
    store_factory: object = None

    def __post_init__(self):
        if self.trust_class == "external-immutable" and self.store_factory is None:
            raise ReceiptError(
                f"registration {self.kind!r}: external-immutable trust requires "
                "an independent external store capability; a caller-local store "
                "can only ever be an evidence copy"
            )


AUTHORITY_ALLOWLIST: dict[str, AuthorityRegistration] = {}


def register_authority(registration: AuthorityRegistration) -> None:
    if registration.kind in AUTHORITY_ALLOWLIST:
        raise ReceiptError(f"authority kind {registration.kind} already registered")
    AUTHORITY_ALLOWLIST[registration.kind] = registration


def build_providers(
    *,
    store,
    authority_registration: AuthorityRegistration,
    lanes=None,
    skew=None,
    state=None,
    source_sha: str | None = None,
    measurement=None,
) -> Providers:
    if authority_registration.trust_class == "external-immutable":
        if authority_registration.store_factory is None:
            raise ReceiptError(
                "external-immutable composition requires the registration's own "
                "store capability"
            )
        store = authority_registration.store_factory()
    elif authority_registration.store_factory is not None:
        store = authority_registration.store_factory()
    return Providers(
        store=store,
        authority=authority_registration.factory(),
        lanes=lanes,
        skew=skew,
        state=state,
        source_sha=source_sha,
        measurement=measurement,
        authority_trust=authority_registration.trust_class,
    )


# ── staged manifest ──────────────────────────────────────────────────


def seal_staged_manifest(
    plan: Plan,
    *,
    frozen_plan_id: str,
    source_sha: str,
    entries: dict[str, ReceiptEntry],
    graph: Graph | None = None,
) -> tuple[bytes, str]:
    """The complete staged-artifact digest set, sealed after ALL stage calls
    and before any skew or publish. It is the only digest source for skew,
    publication, and crash recovery; recovery never rebuilds."""
    planned = {n.component for n in plan.moving}
    if set(entries) != planned:
        raise ReceiptError("staged manifest must cover exactly the planned set")
    for name, entry in entries.items():
        if not entry.digest or not entry.version:
            raise ReceiptError(
                f"{name}: staged entry needs a nonempty digest and version"
            )
    body = json.dumps(
        {
            "frozen_plan_id": frozen_plan_id,
            "source_sha": source_sha,
            "entries": {
                name: {
                    "version": e.version,
                    "digest": e.digest,
                    "digest_set": e.digest_set,
                    "pointer_state": e.pointer_state,
                    "lane_ref": e.lane_ref,
                    # A delivery proof cannot exist before publication; the
                    # manifest declares the OBLIGATION and the receipt carries
                    # the post-publication proof the observer validates.
                    "delivery_obligation": _delivery_obligation(graph, name),
                }
                for name, e in sorted(entries.items())
            },
        },
        sort_keys=True,
    ).encode()
    return body, hashlib.sha256(body).hexdigest()


def _delivery_obligation(graph: "Graph | None", component_name: str) -> str | None:
    if graph is None or component_name not in graph.components:
        return None
    component = graph.components[component_name]
    if component.delivery_restart is not None:
        return "delivery-restart-proof"
    if component.lane is not None:
        return "delivery-lane-proof"
    return None


def validate_staged_manifest(
    manifest: dict,
    *,
    plan: Plan | None = None,
    graph: Graph | None = None,
    frozen_plan_id: str | None = None,
    source_sha: str | None = None,
) -> None:
    """Semantic validation of a staged manifest: an authority proves which
    bytes were recorded, not that those bytes satisfy the schema. Used before
    seal AND after every load, before observation or any lane call."""
    entries = manifest.get("entries")
    if not isinstance(entries, dict) or not entries:
        raise ReceiptError("staged manifest has no entry map")
    if frozen_plan_id is not None and manifest.get("frozen_plan_id") != frozen_plan_id:
        raise ReceiptError("staged manifest does not bind this frozen plan")
    if source_sha is not None and manifest.get("source_sha") != source_sha:
        raise ReceiptError("staged manifest does not bind this source")
    if plan is not None:
        planned = {n.component for n in plan.moving}
        if set(entries) != planned:
            raise ReceiptError(
                "staged manifest entry set does not equal the planned set"
            )
        for node in plan.moving:
            entry = entries[node.component]
            if node.version is not None and entry.get("version") != node.version:
                raise ReceiptError(
                    f"{node.component}: manifest version {entry.get('version')} "
                    f"does not equal the frozen candidate {node.version}"
                )
            if node.reason.startswith("pointer:") and not entry.get("pointer_state"):
                raise ReceiptError(
                    f"{node.component}: pointer candidate state missing from "
                    "the staged manifest"
                )
    for name, entry in entries.items():
        if not entry.get("digest") or not entry.get("version"):
            raise ReceiptError(f"{name}: manifest entry needs digest and version")
        lane_ref = entry.get("lane_ref")
        if lane_ref is not None:
            LaneRef.from_dict(lane_ref)
        digest_set = entry.get("digest_set")
        if digest_set is not None:
            if not isinstance(digest_set, dict) or not digest_set or not all(
                isinstance(k, str) and k and isinstance(v, str) and v
                for k, v in digest_set.items()
            ):
                raise ReceiptError(
                    f"{name}: manifest digest_set is not a schema-valid "
                    "nonempty map"
                )
            if entry["digest"] != canonical_digest_of_set(digest_set):
                raise ReceiptError(
                    f"{name}: manifest scalar digest is not the canonical "
                    "digest of its stored set"
                )
        if graph is not None and name in graph.components:
            expected_obligation = _delivery_obligation(graph, name)
            if entry.get("delivery_obligation") != expected_obligation:
                raise ReceiptError(
                    f"{name}: manifest delivery obligation "
                    f"{entry.get('delivery_obligation')!r} does not derive from "
                    f"the frozen graph ({expected_obligation!r})"
                )
            component = graph.components[name]
            if (component.publish_lane or {}).get("registry") and digest_set is None:
                raise ReceiptError(
                    f"{name}: a registry component's manifest entry requires "
                    "its complete digest set"
                )


def load_staged_manifest(data: bytes, *, expected_digest: str) -> dict:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ReceiptError("staged manifest does not match its recorded digest")
    return json.loads(data)


def adopt_observed(manifest: dict, component: str, observed: ReceiptEntry) -> None:
    """A restart may adopt an observed publication only when it exactly equals
    the anchored staged manifest entry."""
    entry = manifest["entries"].get(component)
    if entry is None:
        raise ReceiptError(f"{component} is not in the staged manifest")
    if observed.version != entry["version"] or observed.digest != entry["digest"]:
        raise ReceiptError(
            f"{component}: observed {observed.version}/{observed.digest} does not "
            f"equal the anchored staged manifest {entry['version']}/{entry['digest']}"
        )
    if entry.get("lane_ref") is not None and observed.lane_ref != entry["lane_ref"]:
        raise ReceiptError(
            f"{component}: lane reference does not equal the anchored staged "
            "manifest reference"
        )


def _frozen_drift(
    frozen_resolved: dict,
    current: dict,
    skip_components: set,
    allowed_tag_transitions: dict | None = None,
) -> list[str]:
    """Named differences between the frozen snapshot and the currently
    resolved execution inputs. Components already published in a resume are
    the only named expected transition and are skipped."""
    def canon(value):
        return json.loads(json.dumps(value, sort_keys=True, default=str))

    frozen_resolved = canon(frozen_resolved)
    current = canon(current)
    drift: list[str] = []
    allowed_tags = allowed_tag_transitions or {}
    for section in ("pins", "baselines", "tags", "measurements"):
        frozen_section = frozen_resolved.get(section, {}) or {}
        current_section = current.get(section, {}) or {}
        for key in sorted(set(frozen_section) | set(current_section)):
            if section == "tags" and key in skip_components:
                # The allowed delta is EXACTLY the frozen map plus the one
                # planned candidate tag bound to the frozen source object.
                # Missing, rewritten, additional, or wrong-SHA tags are drift.
                expected = dict(frozen_section.get(key) or {})
                expected.update(allowed_tags.get(key, {}))
                observed = current_section.get(key) or {}
                if observed != expected:
                    drift.append(
                        f"tags[{key}]: allowed exactly {expected!r}, "
                        f"observed {observed!r}"
                    )
                continue
            if frozen_section.get(key) != current_section.get(key):
                drift.append(
                    f"{section}[{key}]: frozen {frozen_section.get(key)!r} vs "
                    f"current {current_section.get(key)!r}"
                )
    frozen_components = frozen_resolved.get("components", {}) or {}
    current_components = current.get("components", {}) or {}
    for name in sorted(set(frozen_components) | set(current_components)):
        if name in skip_components:
            continue
        if frozen_components.get(name) != current_components.get(name):
            drift.append(
                f"components[{name}]: frozen {frozen_components.get(name)!r} vs "
                f"current {current_components.get(name)!r}"
            )
    return drift


def check_measurement_records(contracts, measurement_provider) -> list[str]:
    """Preflight resolution of declared support records: the record must exist
    at its authority and apply to this exact edge."""
    problems: list[str] = []
    for edge in contracts:
        if edge.declared_incomplete:
            continue
        record = edge.supported.get("record", {})
        resolved = measurement_provider.resolve(record, edge)
        if resolved is None:
            problems.append(
                f"runtime-contract {edge.a}<->{edge.b}: measurement record "
                f"{record.get('artifact_id')} is unresolvable at its authority"
            )
    return problems


# ── four-phase execution ─────────────────────────────────────────────


def run_plan(
    plan: Plan,
    graph: Graph,
    lanes=None,
    *,
    providers: Providers | None = None,
    skew=None,
    authority=None,
    store=None,
    source_sha: str,
    approvals: dict[str, Approval],
    state=None,
    require_external_authority: bool = False,
    frozen: "FrozenPlan | None" = None,
    _resume_manifest: dict | None = None,
    _resume_published: dict | None = None,
) -> dict[str, ReceiptEntry]:
    """PREFLIGHT everything (zero lane or outward-authority calls before it
    passes) -> anchor the frozen plan (the pre-effect boundary) -> STAGE all
    candidates -> anchor the staged manifest -> run every touched SKEW matrix
    against those staged bytes -> PUBLISH topologically, anchoring each
    transition immediately -> VERIFY (a red is anchored) -> seal and anchor
    the final receipt."""
    authority_trust = "local-development"
    measurement = None
    if providers is not None:
        lanes = lanes or providers.lanes
        skew = skew or providers.skew
        authority = authority or providers.authority
        store = store or providers.store
        state = state if state is not None else providers.state
        authority_trust = providers.authority_trust
        measurement = providers.measurement
    if store is None:
        store = _MemoryStore()

    if require_external_authority and authority_trust != "external-immutable":
        raise ReceiptError(
            "the release path requires an external-immutable digest authority "
            "established by trusted composition; the configured trust class is "
            f"{authority_trust!r}"
        )
    if frozen is not None and frozen.source_sha != source_sha:
        raise ReceiptError(
            f"frozen plan source {frozen.source_sha} does not equal the "
            f"execution source {source_sha}; frozen truth is never substituted"
        )
    if frozen is not None and state is not None:
        current = _resolved_snapshot(plan, graph, state)
        if measurement is not None:
            complete = [
                e for e in plan.runtime_contract_edges if not e.declared_incomplete
            ]
            current["measurements"] = {
                f"{e.a}<->{e.b}": measurement.resolve(
                    e.supported.get("record", {}), e
                )
                for e in complete
            }
        skip_components = set(_resume_published or {})
        allowed_tags = {}
        for name in skip_components:
            component = graph.components.get(name)
            node = next((n for n in plan.moving if n.component == name), None)
            if component and component.tag_format and node and node.version:
                allowed_tags[name] = {
                    component.tag_format.format(version=node.version): source_sha
                }
        drift = _frozen_drift(
            frozen.resolved, current, skip_components,
            allowed_tag_transitions=allowed_tags,
        )
        if drift:
            raise ReceiptError(
                "declared execution inputs drifted from the frozen snapshot: "
                + "; ".join(drift)
            )
    if state is not None:
        problems = check_declared_inputs(
            graph, plan, state, adopted=set(_resume_published or {})
        )
        if problems:
            raise BlockedByDeclaredInputs("; ".join(problems))
    complete_edges = [
        e for e in plan.runtime_contract_edges if not e.declared_incomplete
    ]
    if complete_edges:
        if measurement is None:
            raise BlockedByDeclaredInputs(
                "runtime-contract support records are declared complete but no "
                "measurement authority is configured to resolve them"
            )
        record_problems = check_measurement_records(complete_edges, measurement)
        if record_problems:
            raise BlockedByDeclaredInputs("; ".join(record_problems))
    missing_lanes = [
        n.component for n in plan.moving if not lanes.has_lane(n.component)
    ]
    if missing_lanes:
        raise LaneUnavailable(
            "no publish lane available for: "
            + ", ".join(missing_lanes)
            + " (lanes arrive with aweb-abbe.2-.4)"
        )
    missing_skew = [
        f"{e.a}<->{e.b}"
        for e in plan.runtime_contract_edges
        if not skew.has_matrix(e)
    ]
    if missing_skew:
        raise SkewUnavailable(
            "no skew matrix available for: "
            + ", ".join(missing_skew)
            + " (journeys arrive with aweb-abbe.7)"
        )
    for node in plan.moving:
        if graph.components[node.component].approval_required:
            require_approval(node, approval=approvals.get(node.component))

    if frozen is not None:
        frozen_plan_id = frozen.frozen_id
    else:
        frozen_bytes, frozen_plan_id = freeze_plan(
            plan, graph, source_sha=source_sha, state=state,
            measurement=measurement,
        )
        plan_artifact_id = f"plan:{source_sha}:{frozen_plan_id}"
        _put_content_addressed(
            store, authority, plan_artifact_id, frozen_bytes, frozen_plan_id
        )

    if _resume_manifest is not None:
        manifest = _resume_manifest
        manifest_id = manifest["_artifact_id"]
        staged = {
            name: ReceiptEntry(
                version=e["version"],
                digest=e["digest"],
                phase="staged",
                pointer_state=e.get("pointer_state"),
                digest_set=e.get("digest_set"),
                lane_ref=e.get("lane_ref"),
            )
            for name, e in manifest["entries"].items()
        }
    else:
        staged = {}
        for node in plan.moving:
            entry = lanes.stage(node)
            if not entry.digest or not entry.version:
                raise ReceiptError(
                    f"{node.component}: staged entry needs digest and version"
                )
            if node.version is not None and entry.version != node.version:
                raise ReceiptError(
                    f"{node.component}: staged version {entry.version} does not "
                    f"equal the frozen candidate {node.version}"
                )
            if (graph.components[node.component].publish_lane or {}).get("registry"):
                if not entry.digest_set or not all(
                    isinstance(k, str) and k and isinstance(v, str) and v
                    for k, v in entry.digest_set.items()
                ):
                    raise ReceiptError(
                        f"{node.component}: a registry component stages a "
                        "schema-valid complete digest_set, never an opaque scalar"
                    )
                if entry.digest != canonical_digest_of_set(entry.digest_set):
                    raise ReceiptError(
                        f"{node.component}: staged digest is not the canonical "
                        "digest of its complete set"
                    )
            staged[node.component] = entry

        manifest_bytes, manifest_digest = seal_staged_manifest(
            plan,
            frozen_plan_id=frozen_plan_id,
            source_sha=source_sha,
            entries=staged,
            graph=graph,
        )
        # The manifest object validates BEFORE serialization reaches the
        # store or the authority: an authority must never attest bytes the
        # schema forbids. The exact validated bytes are what anchor;
        # after-load validation remains the second boundary.
        manifest = json.loads(manifest_bytes)
        validate_staged_manifest(
            manifest, plan=plan, graph=graph,
            frozen_plan_id=frozen_plan_id, source_sha=source_sha,
        )
        manifest_id = f"staged-manifest:{frozen_plan_id}:{manifest_digest}"
        _put_content_addressed(
            store, authority, manifest_id, manifest_bytes, manifest_digest
        )
        manifest["_artifact_id"] = manifest_id

    for edge in plan.runtime_contract_edges:
        skew.execute(edge, staged)

    def anchor_transition(
        component: str, entry: ReceiptEntry, sequence: int, kind: str
    ) -> None:
        body = json.dumps(
            {
                "frozen_plan_id": frozen_plan_id,
                "staged_manifest_id": manifest_id,
                "sequence": sequence,
                "component": component,
                "kind": kind,
                "entry": {
                    "version": entry.version,
                    "digest": entry.digest,
                    "phase": entry.phase,
                    "pointer_state": entry.pointer_state,
                    "delivery_proof": entry.delivery_proof,
                    "lane_ref": entry.lane_ref,
                    "digest_set": entry.digest_set,
                },
            },
            sort_keys=True,
        ).encode()
        digest = hashlib.sha256(body).hexdigest()
        artifact_id = (
            f"transition:{frozen_plan_id}:{sequence:03d}:{kind}:"
            f"{component}:{digest}"
        )
        _put_content_addressed(store, authority, artifact_id, body, digest)

    published: dict[str, ReceiptEntry] = dict(_resume_published or {})
    sequence = len(published)
    for node in plan.moving:
        if node.component in published:
            continue
        staged_entry = staged[node.component]
        result = lanes.publish(node, staged_entry)
        manifest_entry = manifest["entries"][node.component]
        if result.digest != manifest_entry["digest"]:
            raise ReceiptError(
                f"{node.component}: published digest {result.digest} does not "
                f"equal the anchored staged manifest digest"
            )
        if result.version != manifest_entry["version"]:
            raise ReceiptError(
                f"{node.component}: published version {result.version} does not "
                f"equal the anchored staged manifest version"
            )
        if result.pointer_state != manifest_entry.get("pointer_state"):
            raise ReceiptError(
                f"{node.component}: published pointer state "
                f"{result.pointer_state!r} does not equal the staged "
                f"{manifest_entry.get('pointer_state')!r}"
            )
        if manifest_entry.get("digest_set") is not None:
            if result.digest_set != manifest_entry["digest_set"]:
                raise ReceiptError(
                    f"{node.component}: published digest set does not equal the "
                    "anchored staged manifest set"
                )
        if manifest_entry.get("delivery_obligation"):
            # Delivery evidence at the moment of effect: missing or malformed
            # proof stops the run BEFORE this node anchors or any downstream
            # node publishes - never discovered at final sealing.
            if not result.delivery_proof:
                raise ReceiptError(
                    f"{node.component}: publish produced no delivery proof for "
                    f"its declared {manifest_entry['delivery_obligation']}"
                )
            validate_delivery_proof(
                result.delivery_proof,
                manifest_entry["delivery_obligation"],
                node.component,
            )
        entry = ReceiptEntry(
            version=result.version,
            digest=result.digest,
            phase="published",
            pointer_state=result.pointer_state,
            delivery_proof=result.delivery_proof,
            digest_set=result.digest_set,
            lane_ref=result.lane_ref,
        )
        published[node.component] = entry
        sequence += 1
        anchor_transition(node.component, entry, sequence, "published")

    verified: dict[str, ReceiptEntry] = {}
    for node in plan.moving:
        try:
            lanes.verify(node, published[node.component])
        except Exception:
            sequence += 1
            anchor_transition(
                node.component, published[node.component], sequence, "verify-red"
            )
            raise
        entry = ReceiptEntry(
            version=published[node.component].version,
            digest=published[node.component].digest,
            phase="verified",
            pointer_state=published[node.component].pointer_state,
            delivery_proof=published[node.component].delivery_proof,
            digest_set=published[node.component].digest_set,
            lane_ref=published[node.component].lane_ref,
        )
        verified[node.component] = entry

    sealed, digest = seal_receipt(
        plan,
        graph,
        source_sha=source_sha,
        entries=verified,
        approvals=approvals,
        frozen_plan_id=frozen_plan_id,
        staged_manifest_id=manifest_id,
    )
    receipt_id = f"receipt:{frozen_plan_id}:{digest}"
    _put_content_addressed(store, authority, receipt_id, sealed, digest)
    return verified


def resume_plan(
    plan: Plan,
    graph: Graph,
    *,
    lanes,
    skew,
    store,
    authority,
    source_sha: str,
    approvals: dict[str, Approval],
    state=None,
    frozen: "FrozenPlan | None" = None,
    measurement=None,
    require_external_authority: bool = False,
    authority_trust: str = "local-development",
    manifest_id: str | None = None,
) -> dict[str, ReceiptEntry]:
    """Resume from the ORIGINAL anchored staged manifest: fetch it by id,
    verify it through the authority, stage NOTHING, observe every claimed
    publication against authoritative lane state, and adopt only on exact
    manifest match. Skew re-runs against the manifest bytes (a crash may
    have interrupted it), then the remainder publishes from those digests."""
    if require_external_authority and authority_trust != "external-immutable":
        raise ReceiptError(
            "the release path requires an external-immutable digest authority "
            "established by trusted composition; resume is not exempt (trust "
            f"class {authority_trust!r})"
        )
    if frozen is None:
        raise ReceiptError("resume requires the anchored frozen plan")
    planned = {n.component for n in plan.moving}
    manifest = None
    candidate_ids = (
        [manifest_id]
        if manifest_id is not None
        else [
            a
            for a in authority.recorded_ids()
            if a.startswith(f"staged-manifest:{frozen.frozen_id}:")
        ]
    )
    if manifest_id is None and len(candidate_ids) > 1:
        raise ReceiptError(
            "multiple staged manifests are anchored for this exact frozen plan; "
            "pass the explicit --manifest-id instead of relying on iteration order"
        )
    for artifact_id in candidate_ids:
        expected = authority.expected_digest(artifact_id)
        if expected is None:
            raise ReceiptError(f"manifest {artifact_id} has no authority record")
        candidate = load_staged_manifest(
            store.get(artifact_id), expected_digest=expected
        )
        validate_staged_manifest(
            candidate, plan=plan, graph=graph,
            frozen_plan_id=frozen.frozen_id, source_sha=source_sha,
        )
        if candidate["frozen_plan_id"] != frozen.frozen_id:
            raise ReceiptError(
                f"manifest {artifact_id} binds frozen plan "
                f"{candidate['frozen_plan_id']}, not {frozen.frozen_id}"
            )
        if (
            candidate["source_sha"] == source_sha
            and set(candidate["entries"]) == planned
            and all(
                candidate["entries"][n.component]["version"] == n.version
                for n in plan.moving
                if n.version is not None
            )
        ):
            manifest = candidate
            manifest["_artifact_id"] = artifact_id
            break
    if manifest is None:
        raise ReceiptError(
            "no anchored staged manifest binds this exact frozen plan, source, "
            "component set and versions; resume is only possible from the "
            "original anchored staging"
        )
    published: dict[str, ReceiptEntry] = {}
    claimed: set[str] = set()
    for artifact_id in authority.recorded_ids():
        prefix = f"transition:{manifest['frozen_plan_id']}:"
        if artifact_id.startswith(prefix):
            body = store.get(artifact_id)
            expected = authority.expected_digest(artifact_id)
            if hashlib.sha256(body).hexdigest() != expected:
                raise ReceiptError(
                    f"transition {artifact_id} does not match its anchored digest"
                )
            record = json.loads(body)
            if record["kind"] == "published":
                if record.get("frozen_plan_id") != manifest["frozen_plan_id"]:
                    raise ReceiptError(
                        f"transition {artifact_id} binds frozen plan "
                        f"{record.get('frozen_plan_id')!r}, not the loaded "
                        "manifest's plan"
                    )
                if record.get("staged_manifest_id") != manifest["_artifact_id"]:
                    raise ReceiptError(
                        f"transition {artifact_id} binds staged manifest "
                        f"{record.get('staged_manifest_id')!r}, not the loaded "
                        f"manifest {manifest['_artifact_id']!r}"
                    )
                if record.get("entry", {}).get("phase") != "published":
                    raise ReceiptError(
                        f"transition {artifact_id} claims publication with "
                        f"entry phase {record.get('entry', {}).get('phase')!r}"
                    )
                component = record["component"]
                manifest_entry = manifest["entries"].get(component)
                if manifest_entry is None:
                    raise ReceiptError(
                        f"transition {artifact_id} claims publication of "
                        f"{component}, absent from the staged manifest"
                    )
                claimed_entry = record.get("entry", {})
                for field_name in ("version", "digest", "digest_set", "lane_ref"):
                    if claimed_entry.get(field_name) != manifest_entry.get(
                        field_name
                    ):
                        raise ReceiptError(
                            f"transition {artifact_id}: claimed {field_name} "
                            "does not equal the anchored staged manifest entry"
                        )
                claimed.add(component)
    for node in plan.moving:
        manifest_entry = manifest["entries"][node.component]
        anchored = ReceiptEntry(
            version=manifest_entry["version"],
            digest=manifest_entry["digest"],
            phase="staged",
            pointer_state=manifest_entry.get("pointer_state"),
            digest_set=manifest_entry.get("digest_set"),
            lane_ref=manifest_entry.get("lane_ref"),
        )
        observed = (
            lanes.observe(node, anchored) if hasattr(lanes, "observe") else None
        )
        if observed is None:
            if node.component in claimed:
                raise ReceiptError(
                    f"{node.component}: a transition claims publication but the "
                    "lane observes nothing; refusing to adopt"
                )
            continue
        adopt_observed(manifest, node.component, observed)
        manifest_entry = manifest["entries"][node.component]
        if manifest_entry.get("pointer_state") is not None:
            if observed.pointer_state is None:
                raise ReceiptError(
                    f"{node.component}: the observer cannot produce the "
                    "required pointer state; missing evidence is never filled "
                    "from the expected value"
                )
            if observed.pointer_state != manifest_entry["pointer_state"]:
                raise ReceiptError(
                    f"{node.component}: observed pointer state "
                    f"{observed.pointer_state!r} does not equal the staged "
                    f"{manifest_entry['pointer_state']!r}"
                )
        if manifest_entry.get("digest_set") is not None:
            if observed.digest_set is None:
                raise ReceiptError(
                    f"{node.component}: the observer cannot produce the "
                    "complete registry artifact digest set required for "
                    "adoption"
                )
            if observed.digest_set != manifest_entry["digest_set"]:
                raise ReceiptError(
                    f"{node.component}: observed digest set does not equal the "
                    "anchored staged manifest set"
                )
        if manifest_entry.get("delivery_obligation"):
            if not observed.delivery_proof:
                raise ReceiptError(
                    f"{node.component}: adoption requires observed delivery "
                    f"evidence for its declared "
                    f"{manifest_entry['delivery_obligation']}"
                )
            validate_delivery_proof(
                observed.delivery_proof,
                manifest_entry["delivery_obligation"],
                node.component,
            )
        published[node.component] = ReceiptEntry(
            version=observed.version,
            digest=observed.digest,
            phase="published",
            pointer_state=observed.pointer_state,
            delivery_proof=observed.delivery_proof,
            digest_set=observed.digest_set,
            lane_ref=observed.lane_ref,
        )
    return run_plan(
        plan,
        graph,
        lanes,
        skew=skew,
        authority=authority,
        store=store,
        source_sha=source_sha,
        approvals=approvals,
        state=state,
        frozen=frozen,
        providers=Providers(
            store=store, authority=authority, measurement=measurement
        ),
        _resume_manifest=manifest,
        _resume_published=published,
    )


def _put_content_addressed(store, authority, artifact_id, data, digest) -> None:
    """Content-addressed ids are idempotent, and store-then-authority crash
    windows RECONCILE explicitly: identical bytes with a missing authority
    record completes the record; a recorded digest must match; different
    bytes under an existing id fail closed. Nothing is silently skipped."""
    try:
        store.put(artifact_id, data)
    except ReceiptError:
        if store.get(artifact_id) != data:
            raise ReceiptError(
                f"{artifact_id} exists with DIFFERENT bytes; refusing"
            ) from None
    recorded = authority.expected_digest(artifact_id)
    if recorded is None:
        authority.record(artifact_id, digest)
    elif recorded != digest:
        raise ReceiptError(
            f"{artifact_id}: authority records digest {recorded}, computed {digest}"
        )


def validate_delivery_proof(proof, obligation: str, component: str) -> None:
    """Delivery proof is a STRUCTURED record - the declared obligation type
    plus an immutable evidence identity and digest - never nonempty free
    text. Missing fields, wrong obligation type, or empty identity/digest
    refuse immediately after publish. Lane tasks may extend the record."""
    if not isinstance(proof, dict):
        raise ReceiptError(
            f"{component}: delivery proof must be a structured record for its "
            f"declared {obligation}, not {type(proof).__name__}"
        )
    if proof.get("obligation") != obligation:
        raise ReceiptError(
            f"{component}: delivery proof declares obligation "
            f"{proof.get('obligation')!r}, expected {obligation!r}"
        )
    for field_name in ("obligation", "evidence_id", "digest"):
        value = proof.get(field_name)
        if isinstance(value, bool) or not isinstance(value, str) or not value:
            raise ReceiptError(
                f"{component}: delivery proof field {field_name} must be a "
                f"nonempty string, got {type(value).__name__}"
            )


def canonical_digest_of_set(digest_set: dict) -> str:
    """The canonical digest whose preimage is the COMPLETE artifact digest
    set (filenames/assets/platform manifests to immutable digests). Registry
    components stage and verify this form - never an opaque scalar detached
    from the set."""
    return hashlib.sha256(
        json.dumps(digest_set, sort_keys=True).encode()
    ).hexdigest()


class _MemoryStore:
    def __init__(self):
        self._data: dict[str, bytes] = {}

    def put(self, artifact_id: str, data: bytes) -> None:
        if artifact_id in self._data:
            raise ReceiptError(f"artifact {artifact_id} already exists; immutable")
        self._data[artifact_id] = data

    def get(self, artifact_id: str) -> bytes:
        if artifact_id not in self._data:
            raise ReceiptError(f"no artifact stored under {artifact_id}")
        return self._data[artifact_id]


class NoLanes:
    def has_lane(self, component: str) -> bool:
        return False


class NoSkew:
    def has_matrix(self, edge) -> bool:
        return False


def canonical_remote(url: str) -> str:
    """One identity for HTTPS/SCP/SSH remote spellings, including port-form
    SSH endpoints and provider SSH host aliases (ssh.github.com)."""
    canonical = url.strip()
    for prefix in ("ssh://git@", "ssh://", "https://", "http://", "git@"):
        if canonical.startswith(prefix):
            canonical = canonical[len(prefix) :]
            break
    first_slash = canonical.find("/")
    first_colon = canonical.find(":")
    if first_colon != -1 and (first_slash == -1 or first_colon < first_slash):
        host, path = canonical.split(":", 1)
        head, _, rest = path.partition("/")
        if head.isdigit():
            path = rest
    else:
        host, _, path = canonical.partition("/")
    if host == "ssh.github.com":
        host = "github.com"
    return f"{host}/{path}".removesuffix(".git")


class GitRepositoryState:
    """Authoritative-state provider for the real repository: remote tag object
    SHAs from ls-remote, registry truth through the injectable provider (an
    unreadable registry is UNAVAILABLE, which blocks), pins resolved from
    declared external-repo contexts."""

    def __init__(
        self,
        repo_root: Path = REPO_ROOT,
        registry=None,
        external_contexts: dict[str, str] | None = None,
    ):
        self.repo_root = repo_root
        self.registry = registry
        self.external_contexts = external_contexts or {}
        self._remote_tag_shas: dict[str, str] | None = None

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo_root), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def remote_tag_shas(self) -> dict[str, str]:
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
        if component.tag_format is None:
            # Delivery nodes: their baseline is the declared delivered ref
            # (for sites, the deploy branch), not a version tag.
            baseline = (component.lane or {}).get("baseline_ref")
            if baseline is None:
                return False
            try:
                out = self._git(
                    "diff", "--name-only", f"{baseline}..origin/main", "--",
                    *component.source_paths,
                )
            except subprocess.CalledProcessError:
                # Movement is never fabricated: an unresolvable baseline is a
                # named declared-input problem, not a phantom change.
                return False
            return bool(out.strip())
        published = self._last_published(component)
        if published is None:
            return True
        return self._changed_since(published[1], component.source_paths)

    def bundled_input_changed_for(self, bundled, consumer) -> bool:
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
        result = self._registry_result(component)
        return result[0] if isinstance(result, tuple) else None

    def registry_digests(self, component: Component) -> dict | None:
        result = self._registry_result(component)
        return result[1] if isinstance(result, tuple) else None

    def registry_unavailable_reason(self, component: Component) -> str | None:
        lane = component.publish_lane or {}
        if "registry" not in lane:
            return None
        if self.registry is None:
            return "no registry provider configured"
        result = self._registry_result(component)
        if isinstance(result, str):
            return result
        if result[0] is None:
            return "registry returned no version"
        return None

    def _registry_result(self, component: Component):
        """Cached (version, digest) tuple, or the unavailability reason as a
        string; never raises into planning."""
        if not hasattr(self, "_registry_cache"):
            self._registry_cache = {}
        if component.name not in self._registry_cache:
            lane = component.publish_lane or {}
            if "registry" not in lane or self.registry is None:
                self._registry_cache[component.name] = (None, None)
            else:
                try:
                    result = self.registry.published(component)
                    version, digests = result
                    if not version or not isinstance(digests, dict) or not digests or not all(
                        isinstance(k, str) and isinstance(v, str) and v
                        for k, v in digests.items()
                    ):
                        # Schema enforcement at the STATE boundary: a version
                        # without a complete digest set is unavailable no
                        # matter which provider produced it.
                        self._registry_cache[component.name] = (
                            f"registry returned no schema-valid digest set for "
                            f"{component.name}"
                        )
                    else:
                        self._registry_cache[component.name] = result
                except RegistryUnavailable as exc:
                    self._registry_cache[component.name] = str(exc)
        return self._registry_cache[component.name]

    def env_value(self, name: str) -> str | None:
        import os

        return os.environ.get(name)

    def path_exists(self, path: str) -> bool:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.repo_root / path
        return candidate.exists()

    def pin_sha(self, pin: dict) -> str | None:
        """Resolves a pin by its declared kind inside its declared repository
        context. sha-pin reads [section].field; lock-version finds the named
        package in a uv.lock [[package]] array and returns its version. No
        context, no read: environment-relative guessing produced
        unsatisfiable checks."""
        repo = pin.get("pin_repository")
        root = self.external_contexts.get(repo) if repo else str(self.repo_root)
        if root is None:
            return None
        candidate = Path(root) / pin["pin_file"]
        if not candidate.is_file():
            return None
        with open(candidate, "rb") as handle:
            data = tomllib.load(handle)
        if pin.get("kind") == "lock-version":
            wanted = pin.get("package")
            for entry in data.get("package", []):
                if isinstance(entry, dict) and entry.get("name") == wanted:
                    version = entry.get("version")
                    return version if isinstance(version, str) else None
            return None
        section = data.get(pin.get("section", ""), {})
        value = section.get(pin.get("field", ""))
        return value if isinstance(value, str) else None

    def delivery_baseline(self, component: Component) -> str | None:
        baseline = (component.lane or {}).get("baseline_ref")
        if baseline is None:
            return None
        try:
            return self._git("rev-parse", baseline).strip()
        except subprocess.CalledProcessError:
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
        return canonical_remote(url)


class RegistryUnavailable(Exception):
    pass


class RegistryProviders:
    """(version, digest_set) of the latest registry-visible artifact, or a
    named RegistryUnavailable. digest_set maps every file/asset name to its
    immutable digest; a version without a complete digest set is UNAVAILABLE,
    never quietly acceptable. GHCR/image digests belong to the .4 image lane
    and remain a named blocker here."""

    def published(self, component: Component) -> tuple[str, dict]:
        import urllib.request

        lane = component.publish_lane or {}
        registry = lane.get("registry", {})
        kind = registry.get("type")
        try:
            if kind == "pypi":
                with urllib.request.urlopen(
                    f"https://pypi.org/pypi/{registry['package']}/json", timeout=30
                ) as response:
                    info = json.load(response)
                    version = info["info"]["version"]
                    files = info["releases"].get(version, [])
                    digests = {
                        f["filename"]: f["digests"]["sha256"] for f in files
                    }
                    if not digests:
                        raise RegistryUnavailable(
                            f"pypi lists no files for {registry['package']} {version}"
                        )
                    return version, digests
            if kind == "npm":
                with urllib.request.urlopen(
                    f"https://registry.npmjs.org/{registry['package']}/latest",
                    timeout=30,
                ) as response:
                    data = json.load(response)
                    dist = data.get("dist", {})
                    integrity = dist.get("integrity") or dist.get("shasum")
                    if not integrity:
                        raise RegistryUnavailable(
                            f"npm reports no integrity for {registry['package']}"
                        )
                    return data["version"], {data.get("dist", {}).get("tarball", "tarball"): integrity}
            if kind == "github-release":
                with urllib.request.urlopen(
                    f"https://api.github.com/repos/{registry['repo']}/releases/latest",
                    timeout=30,
                ) as response:
                    data = json.load(response)
                    digests = {}
                    for asset in data.get("assets", []):
                        digest = asset.get("digest")
                        if not digest:
                            raise RegistryUnavailable(
                                f"github release asset {asset.get('name')} has no "
                                "digest; artifact truth is incomplete"
                            )
                        digests[asset["name"]] = digest
                    if not digests:
                        raise RegistryUnavailable(
                            f"github release for {registry['repo']} has no assets"
                        )
                    return data["tag_name"].removeprefix("v"), digests
        except RegistryUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - named unavailability
            raise RegistryUnavailable(
                f"{kind} read failed for {component.name}: {exc}"
            ) from exc
        raise RegistryUnavailable(
            f"no registry reader for kind {kind!r} ({component.name}); "
            "aweb-abbe.4 provides the image lane's digest authority"
        )


def _parse_approvals(raw: list[str]) -> dict[str, Approval]:
    approvals: dict[str, Approval] = {}
    for item in raw:
        parts = item.split(":", 2)
        if len(parts) != 3 or not all(parts):
            raise SystemExit(f"--approval must be component:who:when, got {item!r}")
        approvals[parts[0]] = Approval(who=parts[1], when=parts[2])
    return approvals


register_authority(
    AuthorityRegistration(
        kind="local-development",
        trust_class="local-development",
        factory=None,  # constructed with the store root at build time
    )
)

register_authority(
    AuthorityRegistration(
        kind="github-workflow-artifacts",
        trust_class="external-immutable",
        # The writable anchors pair carries the driver's own evidence
        # (plan/manifest/transitions/receipt); the aw lane's staged bytes
        # are read through the separate read-only GithubArtifactStore.
        factory=GithubAnchorDigestAuthority,
        store_factory=GithubAnchorStore,
    )
)


def main(argv: list[str] | None = None, providers: Providers | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", default=str(GRAPH_PATH))
    parser.add_argument("--store-root", default=str(REPO_ROOT / ".release-runs"))
    parser.add_argument(
        "--external-context",
        action="append",
        default=[],
        help="repository=absolute-checkout mapping for external pin contexts; "
        "the checkout's remote identity must equal the repository",
    )
    parser.add_argument(
        "--authority",
        default="local-development",
        choices=sorted(AUTHORITY_ALLOWLIST),
        help="allowlisted authority kind; external kinds are registered by "
        "lane tasks and are the only production-acceptable ones",
    )
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("plan", help="freeze and anchor a diagnostic plan")
    run_parser = sub.add_parser("release-run")
    run_parser.add_argument("--plan-id")
    run_parser.add_argument("--plan-artifact-id")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--approval", action="append", default=[])
    run_parser.add_argument("--allow-local-authority", action="store_true")
    run_parser.add_argument(
        "--manifest-id",
        help="explicit full staged-manifest artifact id for resume binding",
    )
    run_parser.add_argument(
        "--stage-artifact",
        action="append",
        default=[],
        help="component=<name>,ref=gh-artifact:<repo>:<run>:<artifact>,"
        "source=<lane source sha>,digest=sha256:<artifact zip digest>",
    )
    receipt_parser = sub.add_parser("release-receipt")
    receipt_parser.add_argument("--artifact-id", required=True)
    receipt_parser.add_argument("--plan-id", required=True)
    receipt_parser.add_argument("--plan-artifact-id", required=True)
    args = parser.parse_args(argv)

    graph = Graph.load(Path(args.graph))
    if providers is None:
        root = Path(args.store_root)
        root.mkdir(parents=True, exist_ok=True)
        registration = AUTHORITY_ALLOWLIST[args.authority]
        if registration.kind == "local-development":
            authority = FileDigestAuthority(root)
            store = FileArtifactStore(root)
        else:
            if registration.store_factory is None:
                raise SystemExit(
                    f"authority kind {registration.kind!r} is externally trusted "
                    "but supplies no store capability; refusing a local fallback"
                )
            authority = registration.factory()
            store = registration.store_factory()
        lanes = None
        if registration.kind == "github-workflow-artifacts":
            refs = parse_stage_artifact_arguments(
                getattr(args, "stage_artifact", [])
            )
            if refs:
                lanes = compose_workflow_lanes(graph, refs)
        providers = Providers(
            store=store,
            authority=authority,
            lanes=lanes,
            authority_trust=registration.trust_class,
        )
        if args.verb in ("plan", "release-run"):
            declared_repos = {
                pin.get("pin_repository")
                for component in graph.components.values()
                for pin in component.sibling_pins
                if pin.get("pin_repository")
            }
            external_contexts: dict[str, str] = {}
            for item in args.external_context:
                repo, _, checkout = item.partition("=")
                if not repo or not checkout:
                    raise SystemExit(
                        f"--external-context must be repository=checkout, got {item!r}"
                    )
                if not Path(checkout).is_absolute():
                    raise SystemExit(
                        f"--external-context checkout must be an absolute path "
                        f"(got {checkout!r}); a relative path lets the working "
                        "directory change pin-source identity"
                    )
                if repo not in declared_repos:
                    raise SystemExit(
                        f"--external-context repository {repo!r} is not declared "
                        f"by any pin in the graph (allowlist: {sorted(declared_repos)})"
                    )
                remote = subprocess.run(
                    ["git", "-C", checkout, "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                )
                if remote.returncode != 0 or canonical_remote(
                    remote.stdout.strip()
                ) != repo:
                    raise SystemExit(
                        f"--external-context checkout {checkout} remote "
                        f"{remote.stdout.strip()!r} is not the declared repository {repo}"
                    )
                external_contexts[repo] = checkout
            subprocess.run(
                [
                    "git", "-C", str(REPO_ROOT), "fetch", "origin", "--quiet",
                    "+refs/heads/*:refs/remotes/origin/*",
                ],
                check=True,
            )
            providers.state = GitRepositoryState(
                registry=RegistryProviders(), external_contexts=external_contexts
            )
            providers.source_sha = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "rev-parse", "origin/main"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
    state = providers.state
    source_sha = providers.source_sha or "unknown"

    if args.verb == "plan":
        plan = compute_plan(graph, state)
        problems = check_declared_inputs(graph, plan, state)
        frozen_bytes, frozen_id = freeze_plan(
            plan, graph, source_sha=source_sha, state=state,
            measurement=providers.measurement,
        )
        plan_artifact_id = f"plan:{source_sha}:{frozen_id}"
        _put_content_addressed(
            providers.store, providers.authority, plan_artifact_id,
            frozen_bytes, frozen_id,
        )
        print(
            json.dumps(
                {
                    "source_sha": source_sha,
                    "frozen_plan_id": frozen_id,
                    "plan_artifact_id": plan_artifact_id,
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
        if not args.plan_id or not args.plan_artifact_id:
            print(
                "BLOCKED: release-run requires --plan-id and --plan-artifact-id; "
                "a release executes an anchored frozen plan, never a fresh one"
            )
            return 1
        expected = providers.authority.expected_digest(args.plan_artifact_id)
        if expected != args.plan_id:
            print(
                "BLOCKED: the authority's recorded digest for "
                f"{args.plan_artifact_id} does not match --plan-id"
            )
            return 1
        frozen = load_frozen_plan(
            providers.store.get(args.plan_artifact_id), expected_id=args.plan_id
        )
        # Frozen truth executes; current providers are declared execution
        # inputs compared against it, never substitutes for it.
        plan = frozen.plan
        frozen_graph = frozen.graph
        lanes = providers.lanes if providers.lanes is not None else NoLanes()
        skew = providers.skew if providers.skew is not None else NoSkew()
        run_providers = Providers(
            store=providers.store,
            authority=providers.authority,
            lanes=lanes,
            skew=skew,
            state=state,
            measurement=providers.measurement,
            authority_trust=providers.authority_trust,
        )
        try:
            if args.resume:
                resume_plan(
                    plan,
                    frozen_graph,
                    lanes=lanes,
                    skew=skew,
                    store=providers.store,
                    authority=providers.authority,
                    source_sha=frozen.source_sha,
                    approvals=_parse_approvals(args.approval),
                    state=state,
                    frozen=frozen,
                    measurement=providers.measurement,
                    require_external_authority=not args.allow_local_authority,
                    authority_trust=providers.authority_trust,
                    manifest_id=args.manifest_id,
                )
            else:
                run_plan(
                    plan,
                    frozen_graph,
                    providers=run_providers,
                    source_sha=source_sha,
                    approvals=_parse_approvals(args.approval),
                    state=state,
                    require_external_authority=not args.allow_local_authority,
                    frozen=frozen,
                )
        except (
            LaneUnavailable,
            SkewUnavailable,
            BlockedByDeclaredInputs,
            ApprovalRequired,
            ReceiptError,
        ) as exc:
            print(f"BLOCKED: {exc}")
            return 1
        print("release-run completed")
        return 0

    if args.verb == "release-receipt":
        expected_plan = providers.authority.expected_digest(args.plan_artifact_id)
        if expected_plan != args.plan_id:
            print("REFUSED: plan artifact does not match its anchored digest")
            return 1
        frozen = load_frozen_plan(
            providers.store.get(args.plan_artifact_id), expected_id=args.plan_id
        )
        expected_digest = providers.authority.expected_digest(args.artifact_id)
        if expected_digest is None:
            print(f"REFUSED: the authority has no record of {args.artifact_id}")
            return 1
        try:
            receipt = load_sealed_receipt(
                providers.store.get(args.artifact_id),
                expected_digest=expected_digest,
            )
        except ReceiptError as exc:
            print(f"REFUSED: {exc}")
            return 1
        if receipt.frozen_plan_id != args.plan_id:
            print("MISMATCH: receipt does not bind this frozen plan")
            return 1
        if receipt.source_sha != frozen.source_sha:
            print(
                f"MISMATCH: receipt source {receipt.source_sha} does not equal "
                f"the frozen plan source {frozen.source_sha}"
            )
            return 1
        if receipt.plan_digest != frozen.plan_digest:
            print("MISMATCH: receipt plan digest does not equal the frozen plan")
            return 1
        planned = {n.component for n in frozen.plan.moving}
        if set(receipt.entries) != planned:
            print("MISMATCH: receipt entry set does not equal the frozen plan")
            return 1
        unverified = [
            name for name, e in receipt.entries.items() if e.phase != "verified"
        ]
        if unverified:
            print(f"MISMATCH: entries not verified: {sorted(unverified)}")
            return 1
        manifest_digest = providers.authority.expected_digest(
            receipt.staged_manifest_id
        )
        if manifest_digest is None:
            print("MISMATCH: the receipt's staged manifest is not anchored")
            return 1
        manifest = load_staged_manifest(
            providers.store.get(receipt.staged_manifest_id),
            expected_digest=manifest_digest,
        )
        try:
            validate_staged_manifest(
                manifest, plan=frozen.plan, graph=frozen.graph,
                frozen_plan_id=args.plan_id, source_sha=frozen.source_sha,
            )
        except ReceiptError as exc:
            print(f"MISMATCH: {exc}")
            return 1
        if manifest["frozen_plan_id"] != args.plan_id:
            print("MISMATCH: the staged manifest does not bind this frozen plan")
            return 1
        if manifest["source_sha"] != frozen.source_sha:
            print("MISMATCH: the staged manifest source differs from the frozen plan")
            return 1
        frozen_components = frozen.graph.components
        approvals = dict(receipt.approvals)
        lanes = providers.lanes
        if lanes is None or not hasattr(lanes, "observe"):
            print(
                "BLOCKED: receipt verification requires authoritative lane "
                "observers for published/pointer/delivery state; none configured"
            )
            return 1
        for node in frozen.plan.moving:
            component = frozen_components[node.component]
            entry = receipt.entries[node.component]
            manifest_entry = manifest["entries"].get(node.component)
            if manifest_entry is None:
                print(f"MISMATCH: {node.component} missing from the staged manifest")
                return 1
            if (
                entry.version != manifest_entry["version"]
                or entry.digest != manifest_entry["digest"]
            ):
                print(
                    f"MISMATCH: {node.component} receipt "
                    f"{entry.version}/{entry.digest} does not equal staged "
                    f"manifest {manifest_entry['version']}/{manifest_entry['digest']}"
                )
                return 1
            if entry.pointer_state != manifest_entry.get("pointer_state"):
                print(
                    f"MISMATCH: {node.component} pointer state differs from the "
                    "staged manifest's immutable candidate identity"
                )
                return 1
            if manifest_entry.get("delivery_obligation") and not entry.delivery_proof:
                print(
                    f"MISMATCH: {node.component} carries no post-publication "
                    f"proof for its declared {manifest_entry['delivery_obligation']}"
                )
                return 1
            if component.approval_required:
                approval = approvals.get(node.component)
                if (
                    not isinstance(approval, dict)
                    or not approval.get("who")
                    or not approval.get("when")
                ):
                    print(
                        f"MISMATCH: {node.component} lacks a structurally valid "
                        "approval record"
                    )
                    return 1
            observed = lanes.observe(node, receipt.entries[node.component])
            if observed is None:
                print(
                    f"MISMATCH: {node.component}: no authoritative observation "
                    "of published state"
                )
                return 1
            if (
                observed.version != entry.version
                or observed.digest != entry.digest
            ):
                print(
                    f"MISMATCH: {node.component}: observed "
                    f"{observed.version}/{observed.digest} does not equal the "
                    f"receipt {entry.version}/{entry.digest}"
                )
                return 1
            if node.reason.startswith("pointer:"):
                if observed.pointer_state is None:
                    print(
                        f"BLOCKED: {node.component}: the observer cannot "
                        "produce the required pointer state"
                    )
                    return 1
                if observed.pointer_state != entry.pointer_state:
                    print(
                        f"MISMATCH: {node.component}: observed pointer state "
                        f"{observed.pointer_state!r} does not equal the receipt "
                        f"{entry.pointer_state!r}"
                    )
                    return 1
            if (component.publish_lane or {}).get("registry"):
                manifest_set = manifest_entry.get("digest_set")
                if manifest_set is not None and entry.digest_set != manifest_set:
                    print(
                        f"MISMATCH: {node.component}: receipt digest set does "
                        "not equal the anchored staged manifest set"
                    )
                    return 1
                if observed.digest_set is None:
                    print(
                        f"BLOCKED: {node.component}: the observer cannot "
                        "produce the complete registry artifact digest set"
                    )
                    return 1
                if canonical_digest_of_set(observed.digest_set) != entry.digest:
                    print(
                        f"MISMATCH: {node.component}: the canonical digest of "
                        "the observed complete artifact set does not equal the "
                        "receipt digest"
                    )
                    return 1
                if manifest_set is not None and observed.digest_set != manifest_set:
                    print(
                        f"MISMATCH: {node.component}: the observed digest set "
                        "does not equal the anchored staged manifest set"
                    )
                    return 1
            if manifest_entry.get("delivery_obligation"):
                try:
                    validate_delivery_proof(
                        entry.delivery_proof,
                        manifest_entry["delivery_obligation"],
                        node.component,
                    )
                except ReceiptError as exc:
                    print(f"MISMATCH: {exc}")
                    return 1
                if observed.delivery_proof is None:
                    print(
                        f"BLOCKED: {node.component}: the observer cannot "
                        "produce the required delivery state for its declared "
                        f"{manifest_entry['delivery_obligation']}"
                    )
                    return 1
                try:
                    validate_delivery_proof(
                        observed.delivery_proof,
                        manifest_entry["delivery_obligation"],
                        node.component,
                    )
                except ReceiptError as exc:
                    print(f"BLOCKED: {exc}")
                    return 1
                if (
                    observed.delivery_proof.get("evidence_id")
                    != entry.delivery_proof.get("evidence_id")
                    or observed.delivery_proof.get("digest")
                    != entry.delivery_proof.get("digest")
                ):
                    print(
                        f"MISMATCH: {node.component}: observed delivery "
                        "evidence identity does not equal the receipt's proof"
                    )
                    return 1
        print(
            "MATCH: receipt is anchored, bound to its frozen plan and staged "
            "manifest, entry-identical to the manifest, structurally approved, "
            "and equal to authoritative lane observation"
        )
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
