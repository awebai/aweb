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
    delivery_proof: str | None = None
    digest_set: dict | None = None  # complete artifact set for registry components


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
        if needs_delivery and not entry.delivery_proof:
            raise ReceiptError(
                f"{node.component}: delivery node sealed without delivery_proof"
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
        manifest_id = f"staged-manifest:{frozen_plan_id}:{manifest_digest}"
        _put_content_addressed(
            store, authority, manifest_id, manifest_bytes, manifest_digest
        )
        manifest = load_staged_manifest(
            manifest_bytes, expected_digest=manifest_digest
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
        entry = ReceiptEntry(
            version=result.version,
            digest=result.digest,
            phase="published",
            pointer_state=result.pointer_state,
            delivery_proof=result.delivery_proof,
            digest_set=result.digest_set,
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
                claimed.add(record["component"])
    for node in plan.moving:
        observed = lanes.observe(node) if hasattr(lanes, "observe") else None
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
        if manifest_entry.get("delivery_obligation") and not observed.delivery_proof:
            raise ReceiptError(
                f"{node.component}: adoption requires observed delivery "
                f"evidence for its declared {manifest_entry['delivery_obligation']}"
            )
        published[node.component] = ReceiptEntry(
            version=observed.version,
            digest=observed.digest,
            phase="published",
            pointer_state=observed.pointer_state,
            delivery_proof=observed.delivery_proof,
            digest_set=observed.digest_set,
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
        providers = Providers(
            store=store,
            authority=authority,
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
            observed = lanes.observe(node)
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
                if observed.delivery_proof is None:
                    print(
                        f"BLOCKED: {node.component}: the observer cannot "
                        "produce the required delivery state for its declared "
                        f"{manifest_entry['delivery_obligation']}"
                    )
                    return 1
                if observed.delivery_proof != entry.delivery_proof:
                    print(
                        f"MISMATCH: {node.component}: observed delivery state "
                        "does not equal the receipt's proof"
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
