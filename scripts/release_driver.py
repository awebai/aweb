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
        pointer_adjacency = {
            source: targets for source, targets in pointer_targets.items()
        }
        graph._refuse_cycles("pointer", pointer_adjacency)
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
            checkout = pin["checkout"]
            if not state.path_exists(checkout):
                problems.append(
                    f"{component.name}: sibling checkout {checkout} (pin file "
                    f"{pin['pin_file']}, component {pin['component']}) is absent"
                )
                continue
            pinned = state.pin_sha(pin)
            head = state.checkout_head(checkout)
            if pinned is None:
                problems.append(
                    f"{component.name}: pin {pin['pin_file']} "
                    f"[{pin.get('section', '?')}].{pin.get('field', '?')} is "
                    "unreadable in its declared repository context"
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
                        f"{component.name}: checkout {checkout} remote {remote} "
                        f"is not the declared repository {declared_repo}"
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


def freeze_plan(plan: Plan, graph: Graph, *, source_sha: str) -> tuple[bytes, str]:
    """The plan that will execute, sealed BEFORE any outward effect. Reruns
    take this artifact's ID; live registry drift cannot rewrite a release in
    flight. Binds resolved versions and the full canonical graph; no secret
    contents."""
    body = json.dumps(
        {
            "source_sha": source_sha,
            "plan_digest": plan_digest(plan, graph),
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
        },
        sort_keys=True,
    ).encode()
    return body, hashlib.sha256(body).hexdigest()


def load_frozen_plan(data: bytes, *, expected_id: str) -> Plan:
    if hashlib.sha256(data).hexdigest() != expected_id:
        raise ReceiptError("frozen plan bytes do not match the recorded plan id")
    parsed = json.loads(data)
    return Plan(
        moving=[
            PlanNode(
                component=n["component"],
                reason=n["reason"],
                version=n["version"],
                published_version=n["published_version"],
            )
            for n in parsed["moving"]
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
            for c in parsed["contracts"]
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
    pointer_state: str | None = None
    delivery_proof: str | None = None


@dataclass
class Receipt:
    plan_digest: str
    source_sha: str
    entries: dict[str, ReceiptEntry]
    approvals: tuple[dict, ...] = ()
    frozen_plan_id: str = ""
    partial: bool = False


def seal_receipt(
    plan: Plan,
    graph: Graph,
    *,
    source_sha: str,
    entries: dict[str, ReceiptEntry],
    approvals: tuple[Approval, ...],
    frozen_plan_id: str = "",
    partial: bool = False,
) -> tuple[bytes, str]:
    """Returns (sealed bytes, digest). The digest MUST be recorded with an
    external authority; beside the receipt it is only a checksum. The entry
    set must equal the planned set; pointer nodes must carry pointer state;
    delivery nodes must carry their proof; approval-required nodes must be
    covered by structured approvals."""
    planned = {n.component for n in plan.moving}
    extra = set(entries) - planned
    if extra:
        raise ReceiptError(f"receipt entries outside the planned set: {sorted(extra)}")
    if not partial and set(entries) != planned:
        missing = planned - set(entries)
        raise ReceiptError(
            f"receipt entries must equal the planned set; missing={sorted(missing)}"
            f" extra=[]"
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
        if (
            component is not None
            and component.delivery_restart is not None
            and not entry.delivery_proof
        ):
            raise ReceiptError(
                f"{node.component}: delivery node sealed without delivery_proof"
            )
        if component is not None and component.approval_required:
            if not approvals or not all(a.who and a.when for a in approvals):
                raise ReceiptError(
                    f"{node.component}: approval-required node sealed without a "
                    "structured approval record"
                )
    body = json.dumps(
        {
            "plan_digest": plan_digest(plan, graph),
            "frozen_plan_id": frozen_plan_id,
            "partial": partial,
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
            "approvals": [{"who": a.who, "when": a.when} for a in approvals],
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
        partial=parsed.get("partial", False),
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


# The .5 receipt store: sealed bytes by artifact identity, readable by the
# verification verb. Lane tasks replace this with workflow-artifact storage.
_RECEIPT_STORE: dict[str, bytes] = {}


def read_receipt_bytes(artifact_id: str) -> bytes:
    if artifact_id not in _RECEIPT_STORE:
        raise ReceiptError(f"no receipt stored under {artifact_id}")
    return _RECEIPT_STORE[artifact_id]


# ── four-phase execution ─────────────────────────────────────────────


def run_plan(
    plan: Plan,
    graph: Graph,
    lanes,
    *,
    skew,
    authority,
    source_sha: str,
    approvals: dict[str, Approval],
    state=None,
) -> dict[str, ReceiptEntry]:
    """PREFLIGHT everything -> STAGE every candidate (bind digests) -> run
    every touched SKEW matrix against those bytes -> PUBLISH topologically
    from those same digests, verifying published == staged -> VERIFY, then
    seal the receipt and record its digest with the external authority.
    Nothing executes until every gap is named and absent."""
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

    # The frozen plan, anchored through the authority, is the deliberate
    # pre-effect boundary: everything after this line is an outward effect
    # executed against this exact immutable plan.
    frozen_bytes, frozen_id = freeze_plan(plan, graph, source_sha=source_sha)
    plan_artifact_id = f"plan:{source_sha}:{frozen_id[:12]}"
    _RECEIPT_STORE[plan_artifact_id] = frozen_bytes
    authority.record(plan_artifact_id, frozen_id)

    def anchor(entries: dict[str, ReceiptEntry], *, partial: bool) -> None:
        sealed, digest = seal_receipt(
            plan,
            graph,
            source_sha=source_sha,
            entries=entries,
            approvals=tuple(approvals.values()),
            frozen_plan_id=frozen_id,
            partial=partial,
        )
        kind = "receipt-partial" if partial else "receipt"
        artifact_id = f"{kind}:{source_sha}:{frozen_id[:12]}"
        _RECEIPT_STORE[artifact_id] = sealed
        authority.record(artifact_id, digest)

    staged: dict[str, ReceiptEntry] = {}
    for node in plan.moving:
        staged[node.component] = lanes.stage(node)

    for edge in plan.runtime_contract_edges:
        skew.execute(edge, staged)

    published: dict[str, ReceiptEntry] = {}
    try:
        for node in plan.moving:
            result = lanes.publish(node, staged[node.component])
            if result.digest != staged[node.component].digest:
                raise ReceiptError(
                    f"{node.component}: published digest {result.digest} does "
                    f"not equal staged digest {staged[node.component].digest}"
                )
            published[node.component] = result
    except Exception:
        # Every receipt transition is externally anchored before a later
        # rerun may trust it - including the partial state at failure.
        if published:
            anchor(published, partial=True)
        raise

    for node in plan.moving:
        lanes.verify(node, published[node.component])

    anchor(published, partial=False)
    return published


class NoLanes:
    def has_lane(self, component: str) -> bool:
        return False


class NoSkew:
    def has_matrix(self, edge) -> bool:
        return False


def canonical_remote(url: str) -> str:
    """One identity for HTTPS/SCP/SSH remote spellings."""
    canonical = url.strip()
    for prefix in ("ssh://git@", "ssh://", "https://", "http://", "git@"):
        if canonical.startswith(prefix):
            canonical = canonical[len(prefix) :]
            break
    canonical = canonical.replace(":", "/", 1) if ":" in canonical.split("/")[0] else canonical
    return canonical.removesuffix(".git")


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
                return True
            try:
                out = self._git(
                    "diff", "--name-only", f"{baseline}..origin/main", "--",
                    *component.source_paths,
                )
            except subprocess.CalledProcessError:
                # An unresolvable baseline plans the node conservatively; its
                # lane will name the misconfiguration loudly if it is real.
                return True
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
        """Reads the named section/field of the pin file, resolved inside the
        pin's declared repository context. No context, no read: environment-
        relative guessing produced unsatisfiable checks."""
        repo = pin.get("pin_repository")
        root = self.external_contexts.get(repo) if repo else str(self.repo_root)
        if root is None:
            return None
        candidate = Path(root) / pin["pin_file"]
        if not candidate.is_file():
            return None
        with open(candidate, "rb") as handle:
            data = tomllib.load(handle)
        section = data.get(pin.get("section", ""), {})
        value = section.get(pin.get("field", ""))
        return value if isinstance(value, str) else None

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("plan", help="diagnostic plan from authoritative remote state")
    sub.add_parser(
        "release-run",
        help="freeze the plan and execute the four-phase protocol; fails closed",
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
        [
            "git", "-C", str(REPO_ROOT), "fetch", "origin", "--quiet",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
        check=True,
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
        frozen_bytes, frozen_id = freeze_plan(plan, graph, source_sha=source_sha)
        print(
            json.dumps(
                {
                    "source_sha": source_sha,
                    "frozen_plan_id": frozen_id,
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
        class RefusingAuthority:
            def record(self, artifact_id: str, digest: str) -> None:
                raise ReceiptError(
                    "no external receipt authority is configured; lanes provide one"
                )

        try:
            run_plan(
                plan,
                graph,
                NoLanes(),
                skew=NoSkew(),
                authority=RefusingAuthority(),
                source_sha=source_sha,
                approvals={},
                state=state,
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
