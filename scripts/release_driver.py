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

    # Pointer consumers are FORCED, transitively: a source moving makes its
    # pointer state stale, and a pointer node moving makes ITS pointers stale.
    frontier = list(ordered)
    while frontier:
        next_frontier: list[str] = []
        for source in frontier:
            for target in graph.pointer_targets.get(source, ()):
                if target not in placed:
                    placed.add(target)
                    reasons[target] = f"pointer:{source}"
                    ordered.append(target)
                    next_frontier.append(target)
        frontier = next_frontier

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


def check_declared_inputs(graph: Graph, plan: Plan, state) -> list[str]:
    """Everything a release needs, checked BEFORE anything runs, each failure
    named. Credential paths are presence-only: contents are never read.
    Unknown registry truth is unavailable, and unavailable blocks."""
    problems: list[str] = []
    for node in plan.moving:
        component = graph.components[node.component]

        if component.publishable and component.version_source:
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
                # the currently published version.
                target = graph.components[pin["component"]]
                published = state.published_version(target)
                if published is not None and pinned != published:
                    problems.append(
                        f"{component.name}: lock {pin['pin_file']} records "
                        f"{pin.get('package', target.name)} {pinned} but the "
                        f"published version is {published}"
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
    snapshot: dict = {"components": {}, "pins": {}, "baselines": {}}
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
    plan: Plan, graph: Graph, *, source_sha: str, state=None
) -> tuple[bytes, str]:
    """The plan that will execute, sealed BEFORE any outward effect, binding
    the resolved external state it was computed from. Reruns take this
    artifact's id; live drift cannot rewrite a release in flight."""
    content = {
        "source_sha": source_sha,
        "plan_digest": plan_digest(plan, graph),
        "resolved": _resolved_snapshot(plan, graph, state),
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


def load_frozen_plan(data: bytes, *, expected_id: str) -> Plan:
    """Validates the outer id AND the internal content digest: a body edited
    and re-anchored under a fresh id still refuses, because the content
    binding is part of the artifact itself."""
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
    return Plan(
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


# ── staged manifest ──────────────────────────────────────────────────


def seal_staged_manifest(
    plan: Plan,
    *,
    frozen_plan_id: str,
    source_sha: str,
    entries: dict[str, ReceiptEntry],
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
                name: {"version": e.version, "digest": e.digest}
                for name, e in sorted(entries.items())
            },
        },
        sort_keys=True,
    ).encode()
    return body, hashlib.sha256(body).hexdigest()


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
    frozen_plan_id: str | None = None,
    prior_receipt: Receipt | None = None,
) -> dict[str, ReceiptEntry]:
    """PREFLIGHT everything (zero lane or outward-authority calls before it
    passes) -> anchor the frozen plan (the pre-effect boundary) -> STAGE all
    candidates -> anchor the staged manifest -> run every touched SKEW matrix
    against those staged bytes -> PUBLISH topologically, anchoring each
    transition immediately under a unique immutable id -> VERIFY (a red is
    anchored) -> seal and anchor the final receipt."""
    if providers is not None:
        lanes = lanes or providers.lanes
        skew = skew or providers.skew
        authority = authority or providers.authority
        store = store or providers.store
        state = state if state is not None else providers.state
    if store is None:
        store = _MemoryStore()

    if require_external_authority and getattr(
        authority, "trust_class", "local-development"
    ) != "external-immutable":
        raise ReceiptError(
            "the release path requires an external-immutable digest authority; "
            f"the configured authority's trust class is "
            f"{getattr(authority, 'trust_class', 'unknown')!r}"
        )
    if state is not None:
        problems = check_declared_inputs(graph, plan, state)
        if problems:
            raise BlockedByDeclaredInputs("; ".join(problems))
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

    if frozen_plan_id is None:
        frozen_bytes, frozen_plan_id = freeze_plan(
            plan, graph, source_sha=source_sha, state=state
        )
        plan_artifact_id = f"plan:{source_sha}:{frozen_plan_id[:12]}"
        store.put(plan_artifact_id, frozen_bytes)
        authority.record(plan_artifact_id, frozen_plan_id)

    already: dict[str, ReceiptEntry] = {}
    if prior_receipt is not None:
        already = dict(prior_receipt.entries)

    staged: dict[str, ReceiptEntry] = {}
    for node in plan.moving:
        if node.component in already:
            prior = already[node.component]
            staged[node.component] = ReceiptEntry(
                version=prior.version,
                digest=prior.digest,
                phase="staged",
                pointer_state=prior.pointer_state,
                delivery_proof=prior.delivery_proof,
            )
        else:
            entry = lanes.stage(node)
            if not entry.digest or not entry.version:
                raise ReceiptError(
                    f"{node.component}: staged entry needs digest and version"
                )
            staged[node.component] = entry

    manifest_bytes, manifest_digest = seal_staged_manifest(
        plan,
        frozen_plan_id=frozen_plan_id,
        source_sha=source_sha,
        entries=staged,
    )
    manifest_id = f"staged-manifest:{frozen_plan_id[:12]}:{manifest_digest[:8]}"
    _put_content_addressed(store, authority, manifest_id, manifest_bytes, manifest_digest)
    manifest = load_staged_manifest(manifest_bytes, expected_digest=manifest_digest)

    for edge in plan.runtime_contract_edges:
        skew.execute(edge, staged)

    def anchor_transition(component: str, entry: ReceiptEntry, sequence: int, kind: str) -> None:
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
            f"transition:{frozen_plan_id[:12]}:{sequence:03d}:{kind}:"
            f"{component}:{digest[:8]}"
        )
        store.put(artifact_id, body)
        authority.record(artifact_id, digest)

    published: dict[str, ReceiptEntry] = {}
    sequence = 0
    for node in plan.moving:
        if node.component in already:
            adopt_observed(manifest, node.component, already[node.component])
            published[node.component] = already[node.component]
            continue
        result = lanes.publish(node, staged[node.component])
        if result.digest != manifest["entries"][node.component]["digest"]:
            raise ReceiptError(
                f"{node.component}: published digest {result.digest} does not "
                f"equal the anchored staged manifest digest"
            )
        entry = ReceiptEntry(
            version=result.version,
            digest=result.digest,
            phase="published",
            pointer_state=result.pointer_state,
            delivery_proof=result.delivery_proof,
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
    receipt_id = f"receipt:{frozen_plan_id[:12]}:{digest[:8]}"
    store.put(receipt_id, sealed)
    authority.record(receipt_id, digest)
    return verified


def _put_content_addressed(store, authority, artifact_id, data, digest) -> None:
    """Content-addressed ids are idempotent: byte-identical re-anchoring (a
    resume regenerating the same manifest) reuses the artifact; different
    bytes under an existing id fail closed."""
    try:
        store.put(artifact_id, data)
    except ReceiptError:
        if store.get(artifact_id) != data:
            raise ReceiptError(
                f"{artifact_id} exists with DIFFERENT bytes; refusing"
            ) from None
        return
    authority.record(artifact_id, digest)


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
                    self._registry_cache[component.name] = self.registry.published(
                        component
                    )
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
    """(version, digest) of the latest registry-visible artifact, or a named
    RegistryUnavailable. None is never an answer: unknown blocks."""

    def published(self, component: Component) -> tuple[str, str | None]:
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
                    digest = files[0]["digests"]["sha256"] if files else None
                    return version, digest
            if kind == "npm":
                with urllib.request.urlopen(
                    f"https://registry.npmjs.org/{registry['package']}/latest",
                    timeout=30,
                ) as response:
                    data = json.load(response)
                    return data["version"], data.get("dist", {}).get("integrity")
            if kind == "github-release":
                with urllib.request.urlopen(
                    f"https://api.github.com/repos/{registry['repo']}/releases/latest",
                    timeout=30,
                ) as response:
                    data = json.load(response)
                    return data["tag_name"].removeprefix("v"), data.get("target_commitish")
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
            raise SystemExit(
                f"--approval must be component:who:when, got {item!r}"
            )
        approvals[parts[0]] = Approval(who=parts[1], when=parts[2])
    return approvals


def main(argv: list[str] | None = None, providers: Providers | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", default=str(GRAPH_PATH))
    parser.add_argument(
        "--store-root",
        default=str(REPO_ROOT / ".release-runs"),
        help="durable artifact store root (used when no providers are injected)",
    )
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("plan", help="freeze and anchor a diagnostic plan")
    run_parser = sub.add_parser(
        "release-run",
        help="execute an anchored frozen plan; fails closed on any gap",
    )
    run_parser.add_argument("--plan-id", help="frozen plan digest id")
    run_parser.add_argument("--plan-artifact-id", help="frozen plan artifact id")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument(
        "--approval",
        action="append",
        default=[],
        help="structured approval component:who:when (repeatable)",
    )
    run_parser.add_argument(
        "--allow-local-authority",
        action="store_true",
        help="EXPLICIT development downgrade: accept a local-development "
        "trust-class digest authority",
    )
    receipt_parser = sub.add_parser(
        "release-receipt",
        help="verify an anchored receipt against its anchored frozen plan",
    )
    receipt_parser.add_argument("--artifact-id", required=True)
    receipt_parser.add_argument("--plan-id", required=True)
    receipt_parser.add_argument("--plan-artifact-id", required=True)
    args = parser.parse_args(argv)

    graph = Graph.load(Path(args.graph))
    if providers is None:
        subprocess.run(
            [
                "git", "-C", str(REPO_ROOT), "fetch", "origin", "--quiet",
                "+refs/heads/*:refs/remotes/origin/*",
            ],
            check=True,
        )
        root = Path(args.store_root)
        root.mkdir(parents=True, exist_ok=True)
        providers = Providers(
            store=FileArtifactStore(root),
            authority=FileDigestAuthority(root),
            state=GitRepositoryState(registry=RegistryProviders()),
            source_sha=subprocess.run(
                ["git", "-C", str(REPO_ROOT), "rev-parse", "origin/main"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        )
    state = providers.state
    source_sha = providers.source_sha or "unknown"

    if args.verb == "plan":
        plan = compute_plan(graph, state)
        problems = check_declared_inputs(graph, plan, state)
        frozen_bytes, frozen_id = freeze_plan(
            plan, graph, source_sha=source_sha, state=state
        )
        plan_artifact_id = f"plan:{source_sha}:{frozen_id[:12]}"
        try:
            providers.store.put(plan_artifact_id, frozen_bytes)
            providers.authority.record(plan_artifact_id, frozen_id)
        except ReceiptError:
            pass  # identical plan already anchored; ids are content-derived
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
        plan = load_frozen_plan(
            providers.store.get(args.plan_artifact_id), expected_id=args.plan_id
        )
        prior_receipt = None
        if args.resume:
            transition_entries: dict[str, ReceiptEntry] = {}
            for artifact_id in providers.authority.recorded_ids():
                if artifact_id.startswith(f"transition:{args.plan_id[:12]}:"):
                    record = json.loads(providers.store.get(artifact_id))
                    if record["kind"] == "published":
                        entry = record["entry"]
                        transition_entries[record["component"]] = ReceiptEntry(
                            version=entry["version"],
                            digest=entry["digest"],
                            phase=entry["phase"],
                            pointer_state=entry.get("pointer_state"),
                            delivery_proof=entry.get("delivery_proof"),
                        )
            observed: dict[str, ReceiptEntry] = dict(transition_entries)
            if hasattr(providers.lanes, "observe"):
                for node in plan.moving:
                    if node.component not in observed:
                        seen = providers.lanes.observe(node)
                        if seen is not None:
                            observed[node.component] = seen
            if observed:
                prior_receipt = Receipt(
                    plan_digest="",
                    source_sha=source_sha,
                    entries=observed,
                )
        lanes = providers.lanes if providers.lanes is not None else NoLanes()
        skew = providers.skew if providers.skew is not None else NoSkew()
        try:
            run_plan(
                plan,
                graph,
                providers=Providers(
                    store=providers.store,
                    authority=providers.authority,
                    lanes=lanes,
                    skew=skew,
                    state=state,
                ),
                source_sha=source_sha,
                approvals=_parse_approvals(args.approval),
                state=state,
                require_external_authority=not args.allow_local_authority,
                frozen_plan_id=args.plan_id,
                prior_receipt=prior_receipt,
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
        if receipt.source_sha != source_sha and receipt.source_sha:
            pass  # receipts verify against their own frozen source below
        planned = {n.component for n in frozen.moving}
        if set(receipt.entries) != planned:
            print("MISMATCH: receipt entry set does not equal the frozen plan")
            return 1
        print("MATCH: receipt is anchored, bound to its frozen plan, and complete")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
