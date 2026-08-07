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
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

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


class _GitHubApiTimeout(ReceiptError):
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

        seen_identities: dict[str, str] = {}
        for contract in contracts:
            identity = edge_identity(contract)
            label = f"{contract.a}<->{contract.b} ({contract.journey})"
            if identity in seen_identities:
                raise GraphError(
                    f"duplicate runtime-contract edge: {label} declares the "
                    f"same identity as {seen_identities[identity]}"
                )
            seen_identities[identity] = label

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



    # Scoped to the moving set. A delivery node nobody is releasing must not
    # block someone else's release: sites declares a lane and no baseline_ref,
    # so asking this of every component made every plan of every component
    # unsatisfiable. Releasing such a node still refuses - absence of a
    # baseline is never movement.
    for node in plan.moving:
        component = graph.components[node.component]
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

    # An incomplete runtime edge is deliberately NOT a declared-input problem.
    # A plan is the diagnostic that tells an operator which measurement is
    # owed, so it has to be freezable while the answer is still "unmeasured".
    # Execution is where support must be measured or its absence explicitly
    # accepted - see require_runtime_support.
    return problems


def require_runtime_support(
    plan: Plan,
    *,
    defer_g5: bool,
    authorization,
    source_sha: str | None = None,
    frozen_plan_id: str | None = None,
) -> None:
    """Measured support, or a human who accepted its absence, before publishing.

    Deferral never declares support: the edge stays declared-incomplete in the
    frozen plan and the receipt records who accepted the risk. A bare flag is
    not an authorization - without a record naming someone there is nothing to
    hold, so an unrecorded deferral is refused rather than honored.

    The record is bound to this source, this frozen plan and exactly the edges
    being deferred, so it cannot be reused for another release or stretched
    over an edge nobody read. Every mismatch refuses before any effect.
    """
    incomplete = [e for e in plan.runtime_contract_edges if e.declared_incomplete]
    if not incomplete:
        return
    touched = frozenset(edge_identity(e) for e in incomplete)
    named = ", ".join(sorted(touched))
    if not defer_g5:
        raise BlockedByDeclaredInputs(
            f"runtime-contract {named}: support is declared-incomplete (no "
            "fleet measurement or approved deprecation). Measure it, or accept "
            "the risk explicitly with DEFER_G5=1 and a G5 authorization record"
        )
    if not isinstance(authorization, G5Authorization):
        raise ReceiptError(
            f"deferring runtime support for {named} requires an explicit G5 "
            "authorization recording who accepted the risk and when. DEFER_G5 "
            "alone records nothing, and a risk record that accepted something "
            "else - a runner outage - is not acceptance of an unmeasured "
            "runtime contract"
        )
    if source_sha is not None and authorization.source_sha != source_sha:
        raise ReceiptError(
            "G5 authorization is bound to source "
            f"{authorization.source_sha} and this release is {source_sha}"
        )
    if frozen_plan_id is not None and authorization.frozen_plan_id != frozen_plan_id:
        raise ReceiptError(
            "G5 authorization is bound to frozen plan "
            f"{authorization.frozen_plan_id} and this release is {frozen_plan_id}"
        )
    if authorization.edges != touched:
        missing = sorted(touched - authorization.edges)
        extra = sorted(authorization.edges - touched)
        detail = []
        if missing:
            detail.append("does not cover " + ", ".join(missing))
        if extra:
            detail.append("names unrelated " + ", ".join(extra))
        raise ReceiptError(
            "G5 authorization " + "; ".join(detail) + f" (this release defers {named})"
        )


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
    # Delivery observability is recorded even with no state provider at all.
    # Returning {} here reported "nothing undecidable" for a graph whose lane
    # components had never been looked at - the false all-clear this record
    # exists to prevent.
    if state is None:
        return {"delivery": _delivery_observability(graph, None)}
    snapshot: dict = {"components": {}, "pins": {}, "baselines": {}, "tags": {}, "delivery": {}}
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

    # Delivery observability for EVERY lane component, not only the moving
    # ones. An undecidable delivery node is by definition absent from
    # plan.moving, so recording it per moving node left frozen bytes identical
    # whether the node was observable or not - and a disclosure that does not
    # change the sealed artifact is decoration, not something a later reader
    # can verify against. None means "could not be decided at freeze time".
    snapshot["delivery"] = _delivery_observability(graph, state)
    return snapshot


def _delivery_observability(graph: Graph, state) -> dict:
    """Every lane component, always, whether or not it could be decided.

    A provider that cannot answer is not evidence that there is nothing to
    answer, so an absent capability, an absent result and a raised lookup all
    record None - explicitly unobservable - rather than omitting the component.
    Omission and "observed fine" were previously indistinguishable in the
    frozen artifact, and the disclosure derived from it reported neither.
    """
    observability: dict = {}
    for name, component in sorted(graph.components.items()):
        if component.lane is None or not component.source_paths:
            continue
        baseline = None
        if state is not None and hasattr(state, "delivery_baseline"):
            try:
                baseline = state.delivery_baseline(component)
            except Exception:
                baseline = None
        observability[name] = baseline
    return observability


def delivery_disclosures(resolved: dict) -> list[str]:
    """Delivery nodes the frozen plan could not decide, read from frozen truth.

    Derived from the sealed snapshot rather than recomputed against live state,
    so what an operator reads is what the artifact records. A second computation
    could disagree with the thing it claims to describe.
    """
    disclosures = []
    for name, baseline in sorted((resolved or {}).get("delivery", {}).items()):
        if baseline is None:
            disclosures.append(
                f"{name}: delivered baseline is unobservable; this plan cannot "
                "tell you whether it is current, and movement is never "
                "fabricated from its absence"
            )
    return disclosures


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
            edge_identity(e): measurement.resolve(
                e.supported.get("record", {}), e
            )
            for e in complete_edges
        }
    if plan.runtime_contract_edges and state is not None:
        # Bind the authoritative published version of EVERY touched runtime
        # endpoint - including untouched sides - so execution can refuse
        # drift instead of substituting live values for frozen truth.
        endpoints = sorted({
            name for e in plan.runtime_contract_edges for name in (e.a, e.b)
        })
        resolved["runtime_published"] = {
            name: state.published_version(graph.components[name])
            if name in graph.components else None
            for name in endpoints
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
    risk: str | None = None
    g5_deferred: bool = False


@dataclass(frozen=True)
class G5Authorization:
    """A human accepting unmeasured runtime support, for one exact release.

    Bound to the source, the frozen plan and the exact set of incomplete edges
    being deferred, so the record cannot be carried to a different release or
    stretched to cover an edge nobody read. Deliberately not an Approval: a
    record that accepted a runner outage is not G5 acceptance, and the type
    keeps the two from being substituted for one another by accident.
    """

    who: str
    when: str
    source_sha: str
    frozen_plan_id: str
    edges: frozenset
    risk: str

    def as_record(self) -> dict:
        return {
            "who": self.who,
            "when": self.when,
            "source_sha": self.source_sha,
            "frozen_plan_id": self.frozen_plan_id,
            "edges": sorted(self.edges),
            "risk": self.risk,
        }


def parse_g5_authorization(value: str | None) -> G5Authorization | None:
    """--g5-authorization who=<w>,when=<t>,source=<40hex>,plan=<64hex>,
    edges=<64hex>[+<64hex>],risk=<text>

    Edges are canonical edge identities - the sha256 of an edge's structured
    preimage, as `release-plan` prints under deferrable_runtime_contracts. A
    display string like a<->b would alias the two server<->server edges, which
    is exactly the confusion an authorization must not permit.

    Authority-independent: hosted, local-development and local-runnerless all
    accept the same record, because who may defer runtime support is a question
    about the human, not about which runner built the artifact.
    """
    if not value:
        return None
    fields: dict[str, str] = {}
    for part in value.split(","):
        key, _, item = part.partition("=")
        key = key.strip()
        if key in fields:
            raise ReceiptError(f"--g5-authorization repeats field {key!r}")
        fields[key] = item.strip()
    required = {"who", "when", "source", "plan", "edges", "risk"}
    if set(fields) != required or not all(fields.values()):
        raise ReceiptError(
            "--g5-authorization must be who=<w>,when=<t>,source=<40hex>,"
            f"plan=<64hex>,edges=<64hex>[+<64hex>],risk=<text>, got {value!r}"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", fields["source"]):
        raise ReceiptError(
            f"--g5-authorization source must be a 40-hex SHA, got {fields['source']!r}"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", fields["plan"]):
        raise ReceiptError(
            "--g5-authorization plan must be a 64-hex frozen plan id, got "
            f"{fields['plan']!r}"
        )
    edges = frozenset(e for e in fields["edges"].split("+") if e)
    if not edges:
        raise ReceiptError("--g5-authorization must name the deferred edges")
    malformed = sorted(e for e in edges if not re.fullmatch(r"[0-9a-f]{64}", e))
    if malformed:
        raise ReceiptError(
            "--g5-authorization edges must be canonical 64-hex edge identities "
            f"as printed by release-plan, got {malformed}"
        )
    return G5Authorization(
        who=fields["who"],
        when=fields["when"],
        source_sha=fields["source"],
        frozen_plan_id=fields["plan"],
        edges=edges,
        risk=fields["risk"],
    )


def runnerless_risk_approval(value: str | None) -> Approval:
    """One explicit human record selecting local authority.

    It does NOT carry G5 acceptance. Accepting a runner outage and accepting an
    unmeasured runtime contract are different judgments that happen to arrive in
    the same troubled release; G5Authorization is the record for the second.
    """
    parts = value.split(",", 2) if value else []
    if len(parts) != 3 or not all(parts):
        raise ReceiptError(
            "runnerless local authority requires one explicit risk authorization "
            "as who,when,risk"
        )
    return Approval(who=parts[0], when=parts[1], risk=parts[2])


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
    # Typed, so the sealed acceptance can be checked rather than merely
    # carried. Written into the body but dropped on load, it was bytes nobody
    # read - and validation that never asks for it is not validation.
    g5_authorization: G5Authorization | None = None


def _g5_from_record(record) -> "G5Authorization | None":
    """Exact schema on the way back in: a malformed or partial record is a
    refusal, never a silently weaker acceptance."""
    if record is None:
        return None
    if not isinstance(record, dict):
        raise ReceiptError("sealed g5_authorization must be an object")
    required = {"who", "when", "source_sha", "frozen_plan_id", "edges", "risk"}
    if set(record) != required:
        raise ReceiptError(
            "sealed g5_authorization fields must be exactly "
            f"{sorted(required)}, got {sorted(record)}"
        )
    edges = record["edges"]
    if not isinstance(edges, list) or not edges or not all(
        isinstance(e, str) and re.fullmatch(r"[0-9a-f]{64}", e) for e in edges
    ):
        raise ReceiptError(
            "sealed g5_authorization edges must be canonical 64-hex identities"
        )
    return G5Authorization(
        who=record["who"], when=record["when"],
        source_sha=record["source_sha"],
        frozen_plan_id=record["frozen_plan_id"],
        edges=frozenset(edges), risk=record["risk"],
    )


def require_sealed_g5_authorization(
    plan: Plan, receipt: "Receipt", *, source_sha: str, frozen_plan_id: str
) -> None:
    """A receipt for a plan with incomplete edges must carry the acceptance.

    Checked wherever a receipt is trusted - final validation, release-receipt,
    resume and archive restore - because a receipt that records a release of
    unmeasured support without naming who accepted it is exactly the artifact
    an audit needs and would not find.
    """
    incomplete = frozenset(
        edge_identity(e) for e in plan.runtime_contract_edges if e.declared_incomplete
    )
    if not incomplete:
        return
    record = receipt.g5_authorization
    if record is None:
        raise ReceiptError(
            "receipt covers a plan with declared-incomplete runtime contracts "
            f"({len(incomplete)}) but carries no G5 authorization"
        )
    if source_sha and record.source_sha != source_sha:
        raise ReceiptError(
            f"sealed G5 authorization names source {record.source_sha}, "
            f"receipt is for {source_sha}"
        )
    if frozen_plan_id and record.frozen_plan_id != frozen_plan_id:
        raise ReceiptError(
            f"sealed G5 authorization names frozen plan {record.frozen_plan_id}, "
            f"receipt is for {frozen_plan_id}"
        )
    if record.edges != incomplete:
        raise ReceiptError(
            "sealed G5 authorization does not name exactly the deferred edges"
        )


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
    g5_authorization=None,
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
                component: {
                    "who": a.who,
                    "when": a.when,
                    **({"risk": a.risk} if a.risk is not None else {}),
                    **({"g5_deferred": True} if a.g5_deferred else {}),
                }
                for component, a in sorted(approvals.items())
            },
            # Who accepted unmeasured runtime support for this exact release.
            # Sealed, so the acceptance is auditable afterwards rather than
            # living only in the shell history of whoever ran the release.
            **(
                {"g5_authorization": g5_authorization.as_record()}
                if g5_authorization is not None
                else {}
            ),
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
        g5_authorization=_g5_from_record(parsed.get("g5_authorization")),
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


def validate_final_receipt(
    receipt: Receipt,
    *,
    plan: Plan,
    graph: Graph,
    frozen_plan_id: str,
    staged_manifest_id: str,
    source_sha: str,
) -> None:
    """Validate a loaded receipt against the complete final-seal contract.

    Loading proves the outer digest and seal. This validator proves that the
    loaded document is the non-partial final receipt for this exact frozen
    plan, graph, source, staged manifest, and moving component set.
    """
    if receipt.partial:
        raise ReceiptError("a partial receipt cannot authorize a final release set")
    if receipt.frozen_plan_id != frozen_plan_id:
        raise ReceiptError("final receipt does not bind this frozen plan")
    require_sealed_g5_authorization(
        plan, receipt, source_sha=source_sha, frozen_plan_id=frozen_plan_id
    )
    if receipt.staged_manifest_id != staged_manifest_id:
        raise ReceiptError("final receipt does not bind this staged manifest")
    matches, reason = receipt_matches_run(
        receipt, plan, graph, source_sha=source_sha)
    if not matches:
        raise ReceiptError(f"final receipt {reason}")

    approvals = dict(receipt.approvals)
    for node in plan.moving:
        entry = receipt.entries[node.component]
        if entry.phase != "verified":
            raise ReceiptError(
                f"final receipt entry {node.component} is not verified")
        if node.reason.startswith("pointer:") and not entry.pointer_state:
            raise ReceiptError(
                f"{node.component}: final receipt pointer state is absent")
        component = graph.components[node.component]
        needs_delivery = (
            component.delivery_restart is not None or component.lane is not None
        )
        if needs_delivery:
            if not entry.delivery_proof:
                raise ReceiptError(
                    f"{node.component}: final receipt delivery proof is absent")
            validate_delivery_proof(
                entry.delivery_proof,
                _delivery_obligation(graph, node.component),
                node.component,
            )
        if component.approval_required:
            approval = approvals.get(node.component)
            if not isinstance(approval, dict) or not approval.get(
                "who"
            ) or not approval.get("when"):
                raise ReceiptError(
                    f"{node.component}: final receipt lacks its approval record")


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
    "channel": ("awebai/aweb", ".github/workflows/npm-release.yml"),
    "pi": ("awebai/aweb", ".github/workflows/npm-release.yml"),
    "skills": ("awebai/aweb", ".github/workflows/npm-release.yml"),
}
GITHUB_ARTIFACT_REPO_ALLOWLIST = tuple(sorted(
    {repo for repo, _ in LANE_ARTIFACT_SOURCES.values()}
))
NPM_LANE_COMPONENTS = ("channel", "pi", "skills")
# The npm lane is the only composed lane that consumes delivery evidence;
# composition refuses a proof for any component outside this set so no
# caller-supplied proof is ever accepted and ignored.
DELIVERY_PROOF_CONSUMERS = NPM_LANE_COMPONENTS
ANCHOR_REPO = "awebai/aweb"
ANCHOR_WORKFLOW_PATH = ".github/workflows/release-anchor.yml"
ANCHOR_WORKFLOW_FILE = "release-anchor.yml"
RECOVERY_ATTEMPT_EVIDENCE_NAME = "recovery-attempt-identity"
RECOVERY_ATTEMPT_EVIDENCE_MEMBER = "recovery-attempt.json"
RECOVERY_ATTEMPT_EVIDENCE_SCHEMA = (
    "aweb.release.recovery-continuation-attempt.v1"
)
RECOVERY_RUN_MARKER_PREFIX = "aweb-npm|publish-continuation"
# GitHub bounds the TOTAL workflow-dispatch payload at 65,535 characters;
# the check bounds the ENCODED body plus the other input fields with margin,
# both here before dispatch and again inside the workflow.
ANCHOR_DISPATCH_LIMIT = 64000


def recovery_run_marker(component: str, attempt_artifact_id: str) -> str:
    return (
        f"{RECOVERY_RUN_MARKER_PREFIX}|{component}|{attempt_artifact_id}"
    )


GH_API_DEFAULT_TIMEOUT = 60.0


def _default_gh_api(path: str) -> bytes:
    """Single-argument default for the artifact store/authority/run reader.

    _run_gh_api takes a required keyword-only timeout, but those consumers call
    their injected api with the path alone -- an injected fake has that
    signature too. Storing _run_gh_api directly therefore raised TypeError on
    every real use while every test passed, because tests inject fakes.
    """
    return _run_gh_api(path, timeout=GH_API_DEFAULT_TIMEOUT)


def _run_gh_api(path: str, *, timeout: float) -> bytes:
    import subprocess

    if timeout <= 0:
        raise ValueError("gh api timeout must be positive")
    try:
        result = subprocess.run(
            ["gh", "api", path], capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise _GitHubApiTimeout(
            f"gh api {path} exceeded its {timeout:g}-second deadline"
        ) from exc
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
        self._api = api or _default_gh_api
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
        self._api = api or _default_gh_api
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
        self._api = api or _default_gh_api
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


def parse_delivery_proof_arguments(values: list[str]) -> dict[str, dict]:
    """--delivery-proof component=<c>,obligation=<o>,evidence_id=<e>,
    digest=<d> - the separately supplied structured delivery evidence.
    Literal-validated; publication never fabricates what is not supplied."""
    proofs: dict[str, dict] = {}
    for value in values:
        fields: dict[str, str] = {}
        for part in value.split(","):
            key, _, item = part.partition("=")
            if key in fields:
                raise ReceiptError(
                    f"--delivery-proof repeats field {key!r} in {value!r}"
                )
            fields[key] = item
        if set(fields) != {"component", "obligation", "evidence_id",
                           "digest"} or not all(fields.values()):
            raise ReceiptError(
                "--delivery-proof must be component=<c>,obligation=<o>,"
                f"evidence_id=<e>,digest=<d>, got {value!r}"
            )
        component = fields.pop("component")
        if component in proofs:
            raise ReceiptError(
                f"--delivery-proof names component {component} more than once"
            )
        proofs[component] = fields
    return proofs


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


@dataclass
class _RunCorrelationBudget:
    clock: object
    deadline: float
    requests_remaining: int
    request_limit: int
    per_request_timeout: float

    def refuse(self, reason: str) -> None:
        raise ReceiptError(
            "incomplete workflow-run correlation; state is uncertain: " + reason
        )

    def take_request(self, context: str) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            self.refuse(f"deadline expired before {context}")
        if self.requests_remaining <= 0:
            self.refuse(
                f"total request bound of {self.request_limit} was exhausted "
                f"before {context}"
            )
        self.requests_remaining -= 1
        return min(remaining, self.per_request_timeout)

    def check_request(
        self, context: str, *, started: float, timeout: float,
    ) -> None:
        now = self.clock()
        if now - started >= timeout:
            self.refuse(f"per-request deadline expired during {context}")
        if self.deadline - now <= 0:
            self.refuse(f"lifecycle deadline expired during {context}")


class AwLaneRuns:
    """The workflow-run surface used for continuation correlation.

    Recovery persists the newest pre-dispatch run as a high-water boundary,
    then paginates until that exact boundary (or the empty-history terminator)
    so a busy shared workflow cannot push the owned run out of view.
    """

    MAX_RUN_HISTORY_PAGES_PER_PASS = 20
    MAX_RUN_HISTORY_PASSES = 4
    MAX_EVIDENCE_PAGES_PER_PASS = 20
    MAX_EVIDENCE_PASSES = 4
    MAX_CORRELATION_REQUESTS = 256
    MAX_CORRELATION_SECONDS = 30.0
    MAX_REQUEST_SECONDS = 30.0
    RUN_HISTORY_PAGE_SIZE = 100

    def __init__(self, api=None, *, repo: str = "awebai/aw",
                 workflow_file: str = "aw-release.yml", clock=None):
        self._api = api
        self._uses_default_api = api is None
        self._clock = time.monotonic if clock is None else clock
        self.repo = repo
        self.workflow_file = workflow_file

    def new_correlation_budget(
        self, *, max_seconds: float | None = None,
        max_requests: int | None = None,
    ) -> _RunCorrelationBudget:
        started = self._clock()
        seconds = (
            self.MAX_CORRELATION_SECONDS
            if max_seconds is None
            else max_seconds
        )
        requests = (
            self.MAX_CORRELATION_REQUESTS
            if max_requests is None
            else max_requests
        )
        return _RunCorrelationBudget(
            clock=self._clock,
            deadline=started + seconds,
            requests_remaining=requests,
            request_limit=requests,
            per_request_timeout=self.MAX_REQUEST_SECONDS,
        )

    def _request(
        self, path: str, *, budget: _RunCorrelationBudget, context: str,
    ) -> bytes:
        timeout = budget.take_request(context)
        request_started = budget.clock()
        try:
            data = (
                _run_gh_api(path, timeout=timeout)
                if self._uses_default_api
                else self._api(path)
            )
        except _GitHubApiTimeout as exc:
            budget.refuse(f"{context} exceeded the correlation deadline")
            raise AssertionError("unreachable") from exc
        except ReceiptError as exc:
            budget.refuse(f"{context} failed: {exc}")
            raise AssertionError("unreachable") from exc
        budget.check_request(
            context, started=request_started, timeout=timeout
        )
        return data

    def _run_ids_page(
        self, *, per_page: int, page: int,
        budget: _RunCorrelationBudget | None = None,
    ) -> list[int]:
        budget = budget or self.new_correlation_budget()
        path = (
            f"repos/{self.repo}/actions/workflows/{self.workflow_file}/runs"
            f"?per_page={per_page}&page={page}"
        )
        body = json.loads(self._request(
            path, budget=budget, context=f"workflow run history page {page}"
        ))
        if not isinstance(body, dict):
            raise ReceiptError(
                f"{self.workflow_file}: workflow run page {page} is not "
                "an object"
            )
        runs = body.get("workflow_runs")
        if not isinstance(runs, list):
            raise ReceiptError(
                f"{self.workflow_file}: workflow run page {page} has no "
                "workflow_runs list"
            )
        run_ids = []
        for index, run in enumerate(runs):
            run_id = run.get("id") if isinstance(run, dict) else None
            if (
                not isinstance(run_id, int)
                or isinstance(run_id, bool)
                or run_id <= 0
            ):
                raise ReceiptError(
                    f"{self.workflow_file}: workflow run page {page} entry "
                    f"{index} has invalid id {run_id!r}"
                )
            run_ids.append(run_id)
        return run_ids

    def list_run_ids(
        self, *, budget: _RunCorrelationBudget | None = None,
    ) -> list[int]:
        """Newest page for ordinary non-recovery lane correlation."""
        return self._run_ids_page(
            per_page=self.RUN_HISTORY_PAGE_SIZE, page=1, budget=budget
        )

    def high_water_run_id(self) -> int | None:
        run_ids = self._run_ids_page(per_page=1, page=1)
        return run_ids[0] if run_ids else None

    def list_run_ids_after(
        self, boundary_run_id, *, budget: _RunCorrelationBudget | None = None,
    ) -> list[int]:
        """Return a stable, completely enumerated window newer than boundary.

        GitHub's workflow-run listing is mutable and offset-paginated. Each
        pass therefore starts again at page one, validates newest-first ID
        order after overlap deduplication, and reaches the persisted boundary
        (or empty-history terminator). Only two consecutive identical complete
        passes establish a window from which "no owned run" may be concluded.
        """
        if boundary_run_id is None:
            boundary = None
        elif (
            isinstance(boundary_run_id, int)
            and not isinstance(boundary_run_id, bool)
            and boundary_run_id > 0
        ):
            boundary = boundary_run_id
        elif (
            isinstance(boundary_run_id, str)
            and re.fullmatch(r"[1-9][0-9]*", boundary_run_id)
        ):
            boundary = int(boundary_run_id)
        else:
            raise ReceiptError(
                f"{self.workflow_file}: incomplete workflow-run enumeration; "
                f"boundary {boundary_run_id!r} is not a canonical numeric ID"
            )

        budget = budget or self.new_correlation_budget()
        previous: list[int] | None = None

        def refuse(reason: str) -> None:
            raise ReceiptError(
                f"{self.workflow_file}: incomplete workflow-run enumeration; "
                + reason
            )

        for _pass in range(1, self.MAX_RUN_HISTORY_PASSES + 1):
            seen: set[int] = set()
            collected: list[int] = []
            last_unique: int | None = None
            complete = False
            for page in range(1, self.MAX_RUN_HISTORY_PAGES_PER_PASS + 1):
                run_ids = self._run_ids_page(
                    per_page=self.RUN_HISTORY_PAGE_SIZE,
                    page=page,
                    budget=budget,
                )
                if not run_ids:
                    if boundary is None:
                        complete = True
                        break
                    refuse(
                        f"boundary {str(boundary)!r} was not reached before "
                        "empty history"
                    )
                for run_id in run_ids:
                    if run_id in seen:
                        continue
                    if last_unique is not None and run_id >= last_unique:
                        refuse(
                            f"page {page} violates strictly descending "
                            "workflow-run ID order after deduplication"
                        )
                    seen.add(run_id)
                    last_unique = run_id
                    if complete:
                        continue
                    if run_id == boundary:
                        complete = True
                    else:
                        collected.append(run_id)
                if complete:
                    break
            if not complete:
                refuse(
                    f"boundary {str(boundary)!r} was not reached within the "
                    "explicit "
                    f"{self.MAX_RUN_HISTORY_PAGES_PER_PASS}-page per-pass bound"
                )
            if previous == collected:
                return collected
            previous = collected

        refuse(
            "two consecutive complete passes did not agree within the "
            f"explicit {self.MAX_RUN_HISTORY_PASSES}-pass/"
            f"{self.MAX_CORRELATION_REQUESTS}-request/"
            f"{self.MAX_CORRELATION_SECONDS:g}-second bounds"
        )
        raise AssertionError("unreachable")

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

    def run_conclusion(
        self, run_id, *, budget: _RunCorrelationBudget | None = None,
    ) -> str | None:
        budget = budget or self.new_correlation_budget()
        body = json.loads(self._request(
            f"repos/{self.repo}/actions/runs/{run_id}",
            budget=budget,
            context=f"continuation run {run_id} conclusion",
        ))
        if not isinstance(body, dict):
            raise ReceiptError(
                f"continuation run {run_id} response is not an object"
            )
        return body.get("conclusion")

    def run_display_title(
        self, run_id, *, budget: _RunCorrelationBudget | None = None,
    ) -> str:
        budget = budget or self.new_correlation_budget()
        body = json.loads(self._request(
            f"repos/{self.repo}/actions/runs/{run_id}",
            budget=budget,
            context=f"continuation run {run_id} display title",
        ))
        title = body.get("display_title") if isinstance(body, dict) else None
        if not isinstance(title, str) or not title:
            raise ReceiptError(
                f"continuation run {run_id} has no display title"
            )
        return title

    def _artifact_listing_pass(
        self, run_id, *, budget: _RunCorrelationBudget,
        name_filter: str | None,
    ) -> list[dict] | None:
        expected_total = None
        artifacts_by_id: dict[int, dict] = {}
        ordered_ids: list[int] = []
        for page in range(1, self.MAX_EVIDENCE_PAGES_PER_PASS + 1):
            query = ""
            if name_filter is not None:
                query = f"name={name_filter}&"
            path = (
                f"repos/{self.repo}/actions/runs/{run_id}/artifacts?"
                f"{query}per_page=100&page={page}"
            )
            body = json.loads(self._request(
                path,
                budget=budget,
                context=(
                    f"continuation run {run_id} artifact listing page {page}"
                ),
            ))
            if not isinstance(body, dict):
                raise ReceiptError(
                    f"continuation run {run_id} artifact page {page} is not "
                    "an object"
                )
            total = body.get("total_count")
            page_artifacts = body.get("artifacts")
            if (
                not isinstance(total, int)
                or isinstance(total, bool)
                or total < 0
                or not isinstance(page_artifacts, list)
            ):
                raise ReceiptError(
                    f"continuation run {run_id} artifact page {page} has "
                    "invalid total_count/artifacts"
                )
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise ReceiptError(
                    f"continuation run {run_id} artifact total_count drifted"
                )
            for index, artifact in enumerate(page_artifacts):
                if not isinstance(artifact, dict):
                    raise ReceiptError(
                        f"continuation run {run_id} artifact page {page} "
                        f"entry {index} is not an object"
                    )
                if (
                    name_filter is not None
                    and artifact.get("name") != name_filter
                ):
                    return None
                artifact_id = artifact.get("id")
                if (
                    not isinstance(artifact_id, int)
                    or isinstance(artifact_id, bool)
                    or artifact_id <= 0
                ):
                    raise ReceiptError(
                        f"continuation run {run_id} artifact page {page} "
                        f"entry {index} has invalid id {artifact_id!r}"
                    )
                prior = artifacts_by_id.get(artifact_id)
                if prior is not None:
                    if prior != artifact:
                        raise ReceiptError(
                            f"continuation run {run_id} artifact {artifact_id} "
                            "changed across duplicate page entries"
                        )
                    continue
                artifacts_by_id[artifact_id] = artifact
                ordered_ids.append(artifact_id)
            if len(ordered_ids) > expected_total:
                raise ReceiptError(
                    f"continuation run {run_id} artifact listing exceeds "
                    f"total_count {expected_total}"
                )
            if len(ordered_ids) == expected_total:
                return [artifacts_by_id[item] for item in ordered_ids]
            if not page_artifacts:
                raise ReceiptError(
                    f"continuation run {run_id} artifact listing ended before "
                    f"total_count {expected_total}"
                )
        raise ReceiptError(
            f"continuation run {run_id} artifact listing did not complete "
            f"within {self.MAX_EVIDENCE_PAGES_PER_PASS} pages"
        )

    def _stable_artifact_listing(
        self, run_id, *, budget: _RunCorrelationBudget,
        name_filter: str | None,
    ) -> list[dict] | None:
        previous_ids = None
        for _pass in range(self.MAX_EVIDENCE_PASSES):
            artifacts = self._artifact_listing_pass(
                run_id, budget=budget, name_filter=name_filter
            )
            if artifacts is None:
                return None
            artifact_ids = [artifact["id"] for artifact in artifacts]
            if previous_ids == artifact_ids:
                return artifacts
            previous_ids = artifact_ids
        raise ReceiptError(
            f"continuation run {run_id} artifact listing did not stabilize "
            f"within {self.MAX_EVIDENCE_PASSES} passes"
        )

    def run_attempt_artifact_id(
        self, run_id, *, budget: _RunCorrelationBudget | None = None,
    ) -> str | None:
        """Read immutable attempt identity from an artifact owned by this run."""
        import zipfile

        budget = budget or self.new_correlation_budget()
        artifacts = self._stable_artifact_listing(
            run_id, budget=budget,
            name_filter=RECOVERY_ATTEMPT_EVIDENCE_NAME,
        )
        if artifacts is None:
            artifacts = self._stable_artifact_listing(
                run_id, budget=budget, name_filter=None
            )
            artifacts = [
                artifact for artifact in artifacts
                if artifact.get("name") == RECOVERY_ATTEMPT_EVIDENCE_NAME
            ]
        if not artifacts:
            return None
        if len(artifacts) != 1:
            raise ReceiptError(
                f"continuation run {run_id} carries {len(artifacts)} "
                "recovery-attempt evidence artifacts, not exactly one"
            )
        artifact = artifacts[0]
        if str(artifact.get("workflow_run", {}).get("id")) != str(run_id):
            raise ReceiptError(
                f"continuation run {run_id} evidence belongs to another run"
            )
        if artifact.get("expired") is not False:
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence is expired"
            )
        digest = artifact.get("digest") or ""
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence has invalid "
                f"API digest {digest!r}"
            )
        data = self._request(
            f"repos/{self.repo}/actions/artifacts/{artifact.get('id')}/zip",
            budget=budget,
            context=f"continuation run {run_id} attempt-evidence ZIP",
        )
        actual = hashlib.sha256(data).hexdigest()
        if f"sha256:{actual}" != digest:
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence ZIP digest "
                "differs from the GitHub API"
            )
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = [name for name in archive.namelist()
                         if not name.endswith("/")]
                if names != [RECOVERY_ATTEMPT_EVIDENCE_MEMBER]:
                    raise ReceiptError(
                        f"continuation run {run_id} attempt evidence carries "
                        f"members {names!r}"
                    )
                evidence_bytes = archive.read(
                    RECOVERY_ATTEMPT_EVIDENCE_MEMBER
                )
        except zipfile.BadZipFile as exc:
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence is not a ZIP"
            ) from exc
        try:
            evidence = json.loads(evidence_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence is not JSON"
            ) from exc
        if canonical_json_bytes(evidence) != evidence_bytes:
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence is not canonical"
            )
        _exact_keys(
            evidence,
            {"schema", "attempt_artifact_id", "continuation_run_id"},
            f"continuation run {run_id} attempt evidence",
        )
        if (
            evidence["schema"] != RECOVERY_ATTEMPT_EVIDENCE_SCHEMA
            or str(evidence["continuation_run_id"]) != str(run_id)
        ):
            raise ReceiptError(
                f"continuation run {run_id} attempt evidence binding mismatch"
            )
        return _nonempty_text(
            evidence["attempt_artifact_id"],
            f"continuation run {run_id} attempt artifact id",
        )


class AwWorkflowLane:
    """The aw component's lane over the reviewed three-mode workflow.
    stage() loads the referenced staged bytes; publish() dispatches the
    reviewed continuation and requires the complete set observed; observe()
    reports real remote state from the ANCHORED staged entry; verify()
    re-observes. Nothing here rebuilds or repacks."""

    POLL_ATTEMPTS = 240
    POLL_INTERVAL_SECONDS = 15.0
    SYNC_REQUEST_OVERHEAD_SECONDS = 30.0
    SYNC_CORRELATION_REQUESTS = 2048

    def __init__(self, *, reader, lane_authority, refs, release_fetch,
                 npm_fetch, runs, waiter=None):
        self._reader = reader
        self._lane_authority = lane_authority
        self._refs = refs  # component -> LaneRef
        self._release_fetch = release_fetch  # (asset_name, version) -> bytes|None
        self._npm = NpmRegistryObserver(fetch=npm_fetch)
        self._runs = runs
        self._waiter = waiter if waiter is not None else (
            lambda: __import__("time").sleep(self.POLL_INTERVAL_SECONDS)
        )

    def _new_correlation_budget(self):
        factory = getattr(self._runs, "new_correlation_budget", None)
        if factory is None:
            return None
        return factory(
            max_seconds=(
                self.POLL_ATTEMPTS * self.POLL_INTERVAL_SECONDS
                + self.SYNC_REQUEST_OVERHEAD_SECONDS
            ),
            max_requests=self.SYNC_CORRELATION_REQUESTS,
        )

    def _run_call(self, name, *args, budget=None):
        method = getattr(self._runs, name)
        if budget is None:
            return method(*args)
        return method(*args, budget=budget)

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
        budget = self._new_correlation_budget()
        before = set(self._run_call("list_run_ids", budget=budget))
        self._runs.dispatch({
            "mode": "publish-continuation",
            "version": staged.version,
            "source_sha": ref.aw_source_sha,
            "stage_run_id": run_id,
            "stage_artifact_id": gh_artifact_id,
            "stage_zip_digest": ref.zip_digest,
        })
        new_runs: list = []
        for attempt in range(self.POLL_ATTEMPTS):
            new_runs = [
                run_id for run_id in self._run_call(
                    "list_run_ids", budget=budget
                )
                if run_id not in before
            ]
            if new_runs:
                break
            if attempt + 1 < self.POLL_ATTEMPTS:
                self._waiter()
        if not new_runs:
            raise ReceiptError(
                f"{node.component}: incomplete workflow-run correlation; "
                "continuation run remains uncertain after the polling window"
            )
        if len(new_runs) != 1:
            raise ReceiptError(
                f"{node.component}: expected exactly one new continuation run, "
                f"identified {len(new_runs)}; refusing"
            )
        conclusion = None
        for attempt in range(self.POLL_ATTEMPTS):
            conclusion = self._run_call(
                "run_conclusion", new_runs[0], budget=budget
            )
            if conclusion is not None:
                break
            if attempt + 1 < self.POLL_ATTEMPTS:
                self._waiter()
        if conclusion is None:
            raise ReceiptError(
                f"{node.component}: incomplete workflow-run correlation; "
                f"continuation run {new_runs[0]} conclusion remains uncertain"
            )
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
    expected_package: str | None = None, required_mode: str = "stage-only",
) -> dict:
    """Common lane-manifest protocol for one artifact.

    `required_mode` is explicit because the same protocol governs two different
    consumers. A stage-only artifact continues to publication; a verify-only
    artifact never does, and is what a measurement consumes. Everything else --
    member uniqueness, source, version, package, and the canonical set digest
    recomputed from the exact files map -- is identical, so the two must not be
    validated by separate near-copies that can drift.
    """
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
    if manifest.get("mode") != required_mode:
        detail = (
            "only stage-only artifacts continue to publication"
            if required_mode == "stage-only"
            else f"this consumer requires a {required_mode} artifact"
        )
        raise ReceiptError(
            f"staged artifact mode is {manifest.get('mode')!r}; {detail}"
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
    package: str, pypi_name: str, required_mode: str = "stage-only",
) -> dict:
    """The PyPI lane protocol: exactly one sdist and one wheel for the
    version, members under dist/, manifest keys the two basenames."""
    import zipfile

    normalized = pypi_name.replace("-", "_")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        manifest = _lane_manifest_common(
            archive, expected_source_sha=expected_source_sha,
            expected_version=expected_version, expected_package=package,
            required_mode=required_mode,
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
    POLL_INTERVAL_SECONDS = 15.0
    SYNC_REQUEST_OVERHEAD_SECONDS = 30.0
    SYNC_CORRELATION_REQUESTS = 2048

    def __init__(self, *, component, reader, lane_authority, refs, runs,
                 waiter=None):
        self.component = component
        self._reader = reader
        self._lane_authority = lane_authority
        self._refs = refs
        self._runs = runs
        self._waiter = waiter if waiter is not None else (
            lambda: __import__("time").sleep(self.POLL_INTERVAL_SECONDS)
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

    def continuation_snapshot(self, node) -> list[str]:
        """Persist the stable pre-dispatch high-water run boundary."""
        high_water = self._runs.high_water_run_id()
        return [] if high_water is None else [str(high_water)]

    def _new_correlation_budget(self, *, synchronous=False):
        factory = getattr(self._runs, "new_correlation_budget", None)
        if factory is None:
            return None
        if not synchronous:
            return factory()
        return factory(
            max_seconds=(
                self.POLL_ATTEMPTS * self.POLL_INTERVAL_SECONDS
                + self.SYNC_REQUEST_OVERHEAD_SECONDS
            ),
            max_requests=self.SYNC_CORRELATION_REQUESTS,
        )

    def _run_call(self, name, *args, budget=None):
        method = getattr(self._runs, name)
        if budget is None:
            return method(*args)
        return method(*args, budget=budget)

    def _new_continuation_runs(
        self, before_run_ids, *, budget=None,
    ) -> list[tuple[str, object]]:
        if len(before_run_ids) > 1:
            raise ReceiptError(
                f"{self.component}: continuation snapshot must contain at "
                "most one high-water run boundary"
            )
        boundary = before_run_ids[0] if before_run_ids else None
        return [
            (str(run_id), run_id)
            for run_id in self._run_call(
                "list_run_ids_after", boundary, budget=budget
            )
        ]

    def _continuation_runs_for_attempt(
        self, before_run_ids, expected_attempt_artifact_id,
        *, evidence_cache=None, marker_cache=None, budget=None,
    ) -> tuple[list[tuple[str, object, str]], bool]:
        """Filter a complete run window by marker, then owned evidence.

        The immutable GitHub-observed display title cheaply excludes ordinary
        stage/verify runs. An exact title is only a prefilter: ownership still
        requires the unique digest-verified run artifact, whose absence is
        pending and is never cached as unrelated.
        """
        evidence = evidence_cache if evidence_cache is not None else {}
        markers = marker_cache if marker_cache is not None else {}
        candidates = self._new_continuation_runs(
            before_run_ids, budget=budget
        )
        marker_method = getattr(self._runs, "run_display_title", None)
        expected_marker = recovery_run_marker(
            self.component, expected_attempt_artifact_id
        )
        exact_marker_runs = []
        for run_id, native_run_id in candidates:
            if marker_method is None:
                exact_marker_runs.append((run_id, native_run_id))
                continue
            if native_run_id not in markers:
                markers[native_run_id] = self._run_call(
                    "run_display_title", native_run_id, budget=budget
                )
            if markers[native_run_id] == expected_marker:
                exact_marker_runs.append((run_id, native_run_id))
        if len(exact_marker_runs) > 1:
            raise ReceiptError(
                f"{self.component}: expected exactly one or zero exact "
                f"recovery run marker {expected_marker!r}, identified "
                f"{len(exact_marker_runs)}; refusing"
            )
        if not exact_marker_runs:
            return [], False

        run_id, native_run_id = exact_marker_runs[0]
        if native_run_id in evidence:
            observed_attempt_artifact_id = evidence[native_run_id]
        else:
            observed_attempt_artifact_id = self._run_call(
                "run_attempt_artifact_id", native_run_id, budget=budget
            )
            if observed_attempt_artifact_id is None:
                return [], True
            evidence[native_run_id] = observed_attempt_artifact_id
        if observed_attempt_artifact_id != expected_attempt_artifact_id:
            raise ReceiptError(
                f"{self.component}: exact recovery run marker binds attempt "
                f"{expected_attempt_artifact_id!r}, but run-owned evidence "
                f"binds {observed_attempt_artifact_id!r}"
            )
        return [(
            run_id, native_run_id, observed_attempt_artifact_id
        )], False

    def _wait_for_continuation(
        self, before_run_ids, *, expected_attempt_artifact_id=None
    ) -> tuple[str, str | None]:
        budget = self._new_correlation_budget(synchronous=True)
        if expected_attempt_artifact_id is not None:
            evidence_cache = {}
            marker_cache = {}
            matching_runs: list[tuple[str, object, str]] = []
            evidence_pending = False
            for attempt in range(self.POLL_ATTEMPTS):
                matching_runs, evidence_pending = (
                    self._continuation_runs_for_attempt(
                        before_run_ids,
                        expected_attempt_artifact_id,
                        evidence_cache=evidence_cache,
                        marker_cache=marker_cache,
                        budget=budget,
                    )
                )
                if len(matching_runs) > 1:
                    raise ReceiptError(
                        f"{self.component}: expected exactly one continuation "
                        f"run owned by attempt {expected_attempt_artifact_id!r}, "
                        f"identified {len(matching_runs)}; refusing"
                    )
                if matching_runs:
                    (run_id, native_run_id,
                     observed_attempt_artifact_id) = matching_runs[0]
                    conclusion = self._run_call(
                        "run_conclusion", native_run_id, budget=budget
                    )
                    if conclusion is not None:
                        if conclusion != "success":
                            raise ReceiptError(
                                f"{self.component}: continuation run {run_id} "
                                f"owned by the attempt concluded "
                                f"{conclusion!r}, not success"
                            )
                        return run_id, observed_attempt_artifact_id
                if attempt + 1 < self.POLL_ATTEMPTS:
                    self._waiter()
            if evidence_pending:
                raise ReceiptError(
                    f"{self.component}: incomplete workflow-run correlation; "
                    "exact recovery marker evidence remains uncertain"
                )
            raise ReceiptError(
                f"{self.component}: incomplete workflow-run correlation; "
                f"owned run for attempt {expected_attempt_artifact_id!r} "
                "remains uncertain after the polling window"
            )

        new_runs: list[tuple[str, object]] = []
        for attempt in range(self.POLL_ATTEMPTS):
            new_runs = self._new_continuation_runs(
                before_run_ids, budget=budget
            )
            if new_runs:
                break
            if attempt + 1 < self.POLL_ATTEMPTS:
                self._waiter()
        if not new_runs:
            raise ReceiptError(
                f"{self.component}: incomplete workflow-run correlation; "
                "continuation run remains uncertain after the polling window"
            )
        if len(new_runs) != 1:
            raise ReceiptError(
                f"{self.component}: expected exactly one new continuation "
                f"run, identified {len(new_runs)}; refusing"
            )
        run_id, native_run_id = new_runs[0]
        conclusion = None
        for attempt in range(self.POLL_ATTEMPTS):
            conclusion = self._run_call(
                "run_conclusion", native_run_id, budget=budget
            )
            if conclusion is not None:
                break
            if attempt + 1 < self.POLL_ATTEMPTS:
                self._waiter()
        if conclusion is None:
            raise ReceiptError(
                f"{self.component}: incomplete workflow-run correlation; "
                f"continuation run {run_id} conclusion remains uncertain"
            )
        if conclusion != "success":
            raise ReceiptError(
                f"{self.component}: continuation run {run_id} concluded "
                f"{conclusion!r}, not success"
            )
        return run_id, None

    def _dispatch_and_wait(
        self, inputs: dict, *, before_run_ids=None,
        expected_attempt_artifact_id=None,
    ) -> tuple[str, str | None]:
        before = (
            list(before_run_ids)
            if before_run_ids is not None
            else self.continuation_snapshot(None)
        )
        if set(before) != set(self.continuation_snapshot(None)):
            raise ReceiptError(
                f"{self.component}: continuation run set drifted before dispatch"
            )
        self._runs.dispatch(inputs)
        return self._wait_for_continuation(
            before,
            expected_attempt_artifact_id=expected_attempt_artifact_id,
        )

    def _recovery_continuation_inputs(
        self, staged: "ReceiptEntry", attempt_artifact_id: str
    ) -> dict:
        raise ReceiptError(
            f"{self.component}: workflow lane has no persistently observable "
            "recovery-attempt identity surface"
        )

    def publish_recovery(
        self, node, staged: "ReceiptEntry", *, before_run_ids,
        attempt_artifact_id,
    ) -> "RecoveryContinuation":
        if self.observe(node, staged) is not None:
            raise ReceiptError(
                f"{node.component}: recovery action is no longer unused; "
                "exact existing state must be adopted before an attempt"
            )
        run_id, observed_attempt_artifact_id = self._dispatch_and_wait(
            self._recovery_continuation_inputs(
                staged, attempt_artifact_id
            ),
            before_run_ids=before_run_ids,
            expected_attempt_artifact_id=attempt_artifact_id,
        )
        observed = self.observe(node, staged)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: successful continuation left no exact state"
            )
        return RecoveryContinuation(
            entry=observed,
            continuation_run_id=run_id,
            attempt_artifact_id=observed_attempt_artifact_id,
        )

    def recover_recovery_attempt(
        self, node, staged: "ReceiptEntry", *, before_run_ids,
        attempt_artifact_id,
    ) -> "RecoveryContinuation | None":
        budget = self._new_correlation_budget()
        evidence_cache = {}
        marker_cache = {}
        matching_runs = []
        evidence_pending = False
        for attempt in range(self.POLL_ATTEMPTS):
            matching_runs, evidence_pending = (
                self._continuation_runs_for_attempt(
                    before_run_ids,
                    attempt_artifact_id,
                    evidence_cache=evidence_cache,
                    marker_cache=marker_cache,
                    budget=budget,
                )
            )
            if matching_runs or not evidence_pending:
                break
            if attempt + 1 < self.POLL_ATTEMPTS:
                self._waiter()
        if not matching_runs:
            if evidence_pending:
                raise ReceiptError(
                    f"{node.component}: incomplete workflow-run correlation; "
                    "exact recovery marker evidence remains uncertain"
                )
            return None
        if len(matching_runs) != 1:
            raise ReceiptError(
                f"{node.component}: expected exactly one attempted "
                f"continuation run owned by {attempt_artifact_id!r}, "
                f"identified {len(matching_runs)}"
            )
        (run_id, native_run_id,
         observed_attempt_artifact_id) = matching_runs[0]
        conclusion = self._run_call(
            "run_conclusion", native_run_id, budget=budget
        )
        if conclusion != "success":
            raise ReceiptError(
                f"{node.component}: attempted continuation run {run_id} "
                f"concluded {conclusion!r}, not success"
            )
        observed = self.observe(node, staged)
        if observed is None:
            raise ReceiptError(
                f"{node.component}: successful attempted run has no exact effect"
            )
        return RecoveryContinuation(
            entry=observed,
            continuation_run_id=run_id,
            attempt_artifact_id=observed_attempt_artifact_id,
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


def validate_npm_lane_artifact(
    zip_bytes: bytes, *, expected_source_sha: str, expected_version: str,
    package: str, profile: str,
) -> tuple[dict, str, bytes]:
    """The npm lane protocol: exactly one tgz payload (skills may add its
    release ZIPs), manifest/canonical binding, and the reviewed .3 package
    profile validated against the UNPACKED tgz through the exact reviewed
    checker (scripts/npm-exact-publish.sh). Returns (manifest, tgz name,
    tgz bytes)."""
    import subprocess
    import tempfile
    import zipfile

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        manifest = _lane_manifest_common(
            archive, expected_source_sha=expected_source_sha,
            expected_version=expected_version, expected_package=package,
        )
        files = manifest["files"]
        tgzs = [name for name in files if name.endswith(".tgz")]
        if len(tgzs) != 1:
            raise ReceiptError(
                f"staged manifest must bind exactly one tgz payload; bound "
                f"{sorted(tgzs)}"
            )
        extras = [name for name in files
                  if name != tgzs[0] and not name.endswith(".zip")]
        if extras or (package != "skills" and len(files) != 1):
            raise ReceiptError(
                f"staged manifest binds payloads outside the protocol: "
                f"{sorted(set(files) - {tgzs[0]})}"
            )
        _validate_lane_members(archive, files, {b: b for b in files})
        tgz_bytes = archive.read(tgzs[0])
    with tempfile.TemporaryDirectory() as tmp:
        tgz_path = Path(tmp) / tgzs[0]
        tgz_path.write_bytes(tgz_bytes)
        result = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts/npm-exact-publish.sh"),
             "inspect-tgz", "--tgz", str(tgz_path),
             "--version", expected_version,
             "--profile", profile, "--source-root", str(REPO_ROOT)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise ReceiptError(
                "staged tgz fails the reviewed package profile: "
                + result.stderr.decode(errors="replace").strip()
            )
    return manifest, tgzs[0], tgz_bytes


class NpmWorkflowLane(_WorkflowLaneBase):
    """channel / pi / skills over npm-release.yml. Observation is the
    registry tarball's one SHA-256: absent continues, exact adopts,
    mismatch and outage refuse. Delivery evidence for obligated components
    is SEPARATELY SUPPLIED structured proof, validated at the moment of
    effect; publication alone never fabricates delivery."""

    def __init__(self, *, npm_name, npm_observe, expected_obligation=None,
                 delivery_proofs=None, **kwargs):
        super().__init__(**kwargs)
        self._npm_name = npm_name
        self._npm_observe = npm_observe  # (package, version) -> sha|None; raises when unavailable
        self._expected_obligation = expected_obligation
        self._delivery_proofs = dict(delivery_proofs or {})

    def _require_valid_proof(self, component: str):
        """The graph-derived obligation gates BEFORE any outward call:
        missing, malformed, or wrong-obligation proof refuses, and a proof
        supplied for an unobligated component refuses too."""
        proof = self._delivery_proofs.get(component)
        if self._expected_obligation is None:
            if proof is not None:
                raise ReceiptError(
                    f"{component} carries no delivery obligation; an "
                    "unexpected supplied proof is refused, never ignored"
                )
            return None
        if proof is None:
            raise ReceiptError(
                f"{component}: its declared {self._expected_obligation} "
                "requires separately supplied delivery evidence BEFORE any "
                "outward call; none was supplied"
            )
        validate_delivery_proof(proof, self._expected_obligation, component)
        return proof

    def publish(self, node, staged: "ReceiptEntry") -> "ReceiptEntry":
        self._require_valid_proof(node.component)
        # Observe FIRST: exact existing registry bytes adopt with zero
        # dispatches; mismatch and outage refuse; only proven absence
        # permits one continuation.
        observed = self.observe(node, staged)
        if observed is not None:
            return observed
        return super().publish(node, staged)

    def publish_recovery(
        self, node, staged, *, before_run_ids, attempt_artifact_id
    ):
        # Delivery remains a pre-effect gate on the dedicated recovery path.
        self._require_valid_proof(node.component)
        return super().publish_recovery(
            node, staged, before_run_ids=before_run_ids,
            attempt_artifact_id=attempt_artifact_id,
        )

    def _read_adoptable_stage(self, node) -> "AdoptedStageEntry":
        import zipfile

        ref = self._refs[node.component]
        data = self._fetch_staged(ref)
        manifest, _, _ = validate_npm_lane_artifact(
            data,
            expected_source_sha=ref.aw_source_sha,
            expected_version=node.version,
            package=node.component,
            profile=node.component,
        )
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            manifest_digest = (
                "sha256:" + hashlib.sha256(
                    archive.read("manifest.json")
                ).hexdigest()
            )
        files = manifest["files"]
        return AdoptedStageEntry(
            entry=ReceiptEntry(
                version=node.version,
                digest=canonical_digest_of_set(files),
                digest_set=files,
                lane_ref=ref.to_dict(),
            ),
            manifest_digest=manifest_digest,
        )

    def adopt_preplan(self, node) -> "AdoptedStageEntry":
        return self._read_adoptable_stage(node)

    def stage(self, node) -> "ReceiptEntry":
        # Ordinary Plan -> Stage keeps its own phase semantics even though the
        # read-only semantic validator is shared with adopted evidence.
        return self._read_adoptable_stage(node).entry

    def _continuation_inputs(self, staged):
        inputs = super()._continuation_inputs(staged)
        return {"package": self.component, **inputs}

    def _recovery_continuation_inputs(self, staged, attempt_artifact_id):
        return {
            **self._continuation_inputs(staged),
            "recovery_attempt_artifact_id": attempt_artifact_id,
        }

    def observe(self, node, staged: "ReceiptEntry | None" = None):
        if staged is None or staged.digest_set is None:
            raise ReceiptError(
                f"{node.component}: observation requires the anchored staged "
                "entry; expected values are never re-derived"
            )
        tgz_name = next(
            name for name in staged.digest_set if name.endswith(".tgz")
        )
        remote = self._npm_observe(self._npm_name, staged.version)
        if remote is None:
            return None
        if remote != staged.digest_set[tgz_name]:
            raise ReceiptError(
                f"{node.component}: registry serves sha256 {remote}, staged "
                f"is {staged.digest_set[tgz_name]}; permanent"
            )
        return ReceiptEntry(
            version=staged.version,
            digest=staged.digest,
            phase="published",
            digest_set=dict(staged.digest_set),
            delivery_proof=self._require_valid_proof(node.component),
            lane_ref=staged.lane_ref,
        )


class SubprocessPointerAdapter:
    """The pointer protocol, as an executable, so the driver never pushes to
    another repository itself.

      <exe> intent --component C --updates '{"channel":"1.7.4"}'
      <exe> apply  --component C --updates '{...}'
      <exe> read   --component C

    Each prints JSON; intent and read print {"advertised": {component: version}}.
    """

    def __init__(self, executable: Path):
        self.executable = str(Path(executable).resolve())

    def _run(self, operation, component, updates=None):
        command = [self.executable, operation, "--component", component]
        if updates is not None:
            command += ["--updates", json.dumps(updates, sort_keys=True)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise ReceiptError(
                f"{component}: pointer adapter {operation} failed: "
                f"{result.stderr.strip()}"
            )
        return json.loads(result.stdout or "{}")

    def intent(self, component, updates):
        return self._run("intent", component, updates)

    def apply(self, component, updates, intent):
        return self._run("apply", component, updates)

    def read(self, component):
        return self._run("read", component)


def pointer_updates(plan: Plan, graph: Graph) -> dict[str, dict]:
    """What each moving pointer node must advertise: the planned versions of
    the sources that forced it. A pointer forced by channel@1.7.4 advertises
    exactly that, so the record cannot claim more than the release published."""
    moving = {n.component: n for n in plan.moving}
    updates: dict[str, dict] = {}
    for source, targets in graph.pointer_targets.items():
        if source not in moving:
            continue
        version = moving[source].version
        if version is None:
            continue
        for target in targets:
            if target in moving:
                updates.setdefault(target, {})[source] = version
    return updates


class SubprocessLocalAdapter:
    """Tiny checked-in protocol for existing component/direct release scripts."""

    def __init__(self, executable: Path):
        self.executable = str(Path(executable).resolve())

    def _run(self, operation, node, stage, source_sha=None):
        command = [
            self.executable, operation,
            "--component", node.component,
            "--version", node.version,
            "--stage", str(stage),
        ]
        if source_sha is not None:
            command += ["--source-sha", source_sha]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise ReceiptError(
                f"{node.component}: local adapter {operation} failed: "
                f"{result.stderr.strip()}"
            )
        return json.loads(result.stdout or "{}")

    def stage(self, node, output, source_sha):
        self._run("stage", node, output, source_sha)

    def publish(self, node, stage, files):
        return self._run("publish", node, stage)

    def observe(self, node, stage, files):
        result = self._run("observe", node, stage)
        return result.get("files")


class PointerLane:
    """Advertise published versions in another repository's pointer file.

    Publishing bytes is not delivering them. Claude Code re-resolves an npm
    plugin only when the marketplace entry advertises the new version, and
    aweb-cloud picks up a server only when its pin moves - so a release that
    publishes the package and stops has not finished, and the pointer is a real
    effect with a real lane rather than a note to do something later.

    The git work lives in a small adapter with three operations, so the driver
    never shells out to another repository itself:

      intent(component, updates)          what the pointer should say
      apply(component, updates, intent)   edit, commit, push
      read(component)                     what the remote says now

    publish re-reads the remote and refuses unless it advertises exactly what
    was staged. The failure this exists to catch is silent: the package is on
    the registry, the pointer was never updated, and nothing said so.
    """

    def __init__(self, component: str, *, adapter, updates: dict, repository: str):
        self.component = component
        self.adapter = adapter
        self.updates = dict(updates)
        self.repository = repository

    def has_lane(self, component):
        return component == self.component

    @staticmethod
    def _digest(advertised: dict) -> str:
        return hashlib.sha256(
            json.dumps(advertised, sort_keys=True).encode()
        ).hexdigest()

    def _label(self) -> str:
        return ",".join(f"{k}={v}" for k, v in sorted(self.updates.items()))

    def _intent(self) -> dict:
        if not self.updates:
            raise ReceiptError(
                f"{self.component}: a pointer with nothing to advertise is not "
                "a release effect; the moving set names no source version"
            )
        intent = self.adapter.intent(self.component, self.updates)
        advertised = (intent or {}).get("advertised")
        if advertised != self.updates:
            raise ReceiptError(
                f"{self.component}: adapter intent {advertised!r} does not equal "
                f"the planned advertisement {self.updates!r}"
            )
        return advertised

    def stage(self, node) -> "ReceiptEntry":
        advertised = self._intent()
        return ReceiptEntry(
            version=self._label(),
            digest=self._digest(advertised),
            phase="staged",
            pointer_state="intended",
        )

    def publish(self, node, staged) -> "ReceiptEntry":
        advertised = self._intent()
        if self._digest(advertised) != staged.digest:
            raise ReceiptError(
                f"{self.component}: intent changed between stage and publish"
            )
        self.adapter.apply(self.component, self.updates, advertised)
        landed = (self.adapter.read(self.component) or {}).get("advertised")
        if landed != advertised:
            raise ReceiptError(
                f"{self.component}: {self.repository} advertises {landed!r} "
                f"after publishing, expected {advertised!r}"
            )
        return ReceiptEntry(
            version=self._label(),
            digest=staged.digest,
            phase="published",
            pointer_state="advertised",
        )

    def observe(self, node, staged=None) -> "ReceiptEntry":
        landed = (self.adapter.read(self.component) or {}).get("advertised") or {}
        matches = landed == self.updates
        return ReceiptEntry(
            version=",".join(f"{k}={v}" for k, v in sorted(landed.items())),
            digest=self._digest(landed),
            phase="published" if matches else "staged",
            pointer_state="advertised" if matches else "stale",
        )

    def verify(self, node, published) -> "ReceiptEntry":
        observed = self.observe(node)
        if observed.pointer_state != "advertised":
            raise ReceiptError(
                f"{self.component}: {self.repository} does not advertise the "
                f"published versions ({observed.version or 'nothing'})"
            )
        return ReceiptEntry(
            version=published.version,
            digest=published.digest,
            phase="verified",
            pointer_state="advertised",
        )


class LocalRunnerlessLane:
    """Build once locally, then publish exactly the recorded files.

    The adapter is deliberately small: stage writes files into the supplied
    directory; publish consumes those paths; observe returns registry digests.
    Git/tag hosting is a continuation and may be deferred after registry
    success. The durable local manifest makes resume reuse bytes, never build.
    """

    def __init__(self, component: str, root: Path, adapter, source_sha: str):
        self.component = component
        self.root = Path(root).resolve()
        self.adapter = adapter
        self.source_sha = source_sha
        self._metadata = {}

    def has_lane(self, component):
        return component == self.component

    def _stage_dir(self, node):
        return self.root / self.source_sha / node.component / node.version

    @staticmethod
    def _inventory(stage: Path) -> dict[str, str]:
        return {
            path.relative_to(stage).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(stage.rglob("*"))
            if path.is_file() and path != stage / "manifest.json"
        }

    def stage(self, node):
        stage = self._stage_dir(node)
        manifest_path = stage / "manifest.json"
        if not manifest_path.exists():
            stage.mkdir(parents=True, exist_ok=False)
            self.adapter.stage(node, stage, self.source_sha)
            files = self._inventory(stage)
            if not files:
                raise ReceiptError(f"{node.component}: local stage produced no files")
            manifest = {
                "schema": "aweb.release.local-stage.v1",
                "component": node.component,
                "version": node.version,
                "source_sha": self.source_sha,
                "files": files,
            }
            manifest_path.write_bytes(canonical_json_bytes(manifest))
        manifest = json.loads(manifest_path.read_bytes())
        files = self._inventory(stage)
        if manifest != {
            "schema": "aweb.release.local-stage.v1",
            "component": node.component,
            "version": node.version,
            "source_sha": self.source_sha,
            "files": files,
        }:
            raise ReceiptError(f"{node.component}: local staged bytes changed")
        return ReceiptEntry(
            version=node.version,
            digest=canonical_digest_of_set(files),
            digest_set=files,
            lane_ref={
                "kind": "local-runnerless",
                "stage": str(stage),
                "source_sha": self.source_sha,
                "manifest_sha256": hashlib.sha256(
                    manifest_path.read_bytes()
                ).hexdigest(),
            },
        )

    def _checked_stage(self, node, entry):
        ref = entry.lane_ref or {}
        if ref.get("kind") != "local-runnerless":
            raise ReceiptError(f"{node.component}: not a local runnerless stage")
        stage = Path(ref["stage"])
        files = self._inventory(stage)
        if files != entry.digest_set or canonical_digest_of_set(files) != entry.digest:
            raise ReceiptError(f"{node.component}: local stage no longer matches receipt")
        return stage, files

    def publish(self, node, staged):
        stage, files = self._checked_stage(node, staged)
        result = self.adapter.publish(node, stage, files) or {}
        observed = self.adapter.observe(node, stage, files)
        if observed != files:
            raise ReceiptError(f"{node.component}: registry does not equal staged bytes")
        hosting = result.get("hosting", "complete")
        if hosting not in {"complete", "deferred"}:
            raise ReceiptError(f"{node.component}: invalid hosting result {hosting!r}")
        self._metadata[node.component] = {
            "status": hosting,
            "continuation": result.get("continuation"),
        }
        return ReceiptEntry(
            version=staged.version, digest=staged.digest, phase="published",
            digest_set=dict(files), lane_ref=staged.lane_ref,
        )

    def verify(self, node, published):
        stage, files = self._checked_stage(node, published)
        if self.adapter.observe(node, stage, files) != files:
            raise ReceiptError(f"{node.component}: registry verification differs")

    def observe(self, node, staged=None):
        if staged is None:
            return None
        stage, files = self._checked_stage(node, staged)
        observed = self.adapter.observe(node, stage, files)
        if observed != files:
            return None
        return ReceiptEntry(
            version=staged.version, digest=staged.digest, phase="published",
            digest_set=dict(files), lane_ref=staged.lane_ref,
        )

    def receipt_metadata(self):
        return dict(self._metadata)


class WorkflowLanes:
    """Per-component delegation over the composed lane objects."""

    def __init__(self, lanes: dict, *, recovery_tag_names=None,
                 recovery_tag_observe=None):
        self._lanes = lanes
        self._recovery_tag_names = dict(recovery_tag_names or {})
        self._recovery_tag_observe = recovery_tag_observe

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

    def receipt_metadata(self):
        return {
            component: metadata
            for component, lane in self._lanes.items()
            for component, metadata in getattr(
                lane, "receipt_metadata", lambda: {}
            )().items()
        }

    def observe_recovery(self, node, staged):
        if (
            node.component not in self._recovery_tag_names
            or self._recovery_tag_observe is None
        ):
            raise ReceiptError(
                f"{node.component}: no authoritative recovery tag observer "
                "is composed"
            )
        template = self._recovery_tag_names[node.component]
        tag_name = template.format(version=node.version)
        tag_sha = self._recovery_tag_observe(tag_name)
        lane_entry = self.observe(node, staged)
        return ObservedRecoveryState(
            public={
                "tag": {
                    "name": tag_name,
                    "status": "present" if tag_sha is not None else "absent",
                    "source_sha": tag_sha,
                },
                "registry": {
                    "status": "exact" if lane_entry is not None else "absent",
                    "digest_set": (
                        dict(lane_entry.digest_set)
                        if lane_entry is not None else None
                    ),
                },
            },
            entry=lane_entry,
        )

    def adopt_preplan(self, node):
        lane = self._lanes[node.component]
        adopt = getattr(lane, "adopt_preplan", None)
        if adopt is None:
            raise ReceiptError(
                f"{node.component}: lane has no adopted-preplan semantic loader"
            )
        return adopt(node)

    def continuation_snapshot(self, node):
        return self._lanes[node.component].continuation_snapshot(node)

    def publish_recovery(
        self, node, staged, *, before_run_ids, attempt_artifact_id
    ):
        return self._lanes[node.component].publish_recovery(
            node, staged, before_run_ids=before_run_ids,
            attempt_artifact_id=attempt_artifact_id,
        )

    def recover_recovery_attempt(
        self, node, staged, *, before_run_ids, attempt_artifact_id
    ):
        return self._lanes[node.component].recover_recovery_attempt(
            node, staged, before_run_ids=before_run_ids,
            attempt_artifact_id=attempt_artifact_id,
        )


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


def _observe_npm_registry(package: str, version: str, http=None):
    """Authoritative tri-state registry observation: HTTP 404 alone proves
    absence; a present version resolves and hashes its exact tarball;
    transport failure, 5xx, or malformed metadata BLOCKS - an outage is
    never permission to treat a version as absent."""
    if http is None:
        import urllib.error
        import urllib.request

        def http(url):
            try:
                with urllib.request.urlopen(url) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as exc:
                return exc.code, b""
            except Exception as exc:
                raise ReceiptError(
                    f"npm registry observation failed for {url}: {exc}"
                ) from exc
    encoded = package.replace("/", "%2F")
    status, body = http(f"https://registry.npmjs.org/{encoded}/{version}")
    if status == 404:
        return None
    if status != 200:
        raise ReceiptError(
            f"{package}@{version}: registry returned status {status}; an "
            "outage is never proof of absence"
        )
    try:
        tarball = json.loads(body)["dist"]["tarball"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReceiptError(
            f"{package}@{version}: malformed registry metadata ({exc}); "
            "malformed evidence is never an observation"
        ) from exc
    status, data = http(tarball)
    if status != 200:
        raise ReceiptError(
            f"{package}@{version}: tarball download returned status {status}"
        )
    return hashlib.sha256(data).hexdigest()


def _observe_git_version_tag(tag: str) -> str | None:
    """Authoritative exact-tag observation from origin.

    A nonzero ls-remote is unavailable, never absence. Annotated tags bind the
    peeled commit; lightweight tags bind their direct object.
    """
    result = subprocess.run(
        [
            "git", "-C", str(REPO_ROOT), "ls-remote", "--tags", "origin",
            f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReceiptError(
            f"tag {tag}: remote observation unavailable: "
            f"{result.stderr.strip()}"
        )
    direct = None
    peeled = None
    for line in result.stdout.splitlines():
        sha, _, ref = line.partition("\t")
        if ref == f"refs/tags/{tag}":
            direct = sha
        elif ref == f"refs/tags/{tag}^{{}}":
            peeled = sha
        else:
            raise ReceiptError(f"tag {tag}: unexpected remote ref {ref!r}")
    observed = peeled or direct
    if observed is not None and not re.fullmatch(r"[0-9a-f]{40}", observed):
        raise ReceiptError(f"tag {tag}: remote returned invalid SHA {observed!r}")
    return observed


def compose_workflow_lanes(
    graph: "Graph", refs: dict, delivery_proofs: dict | None = None
) -> WorkflowLanes:
    """Fresh-process lane composition, gated by the typed graph: a lane
    composes only for a component whose publish_lane declares the exact
    allowlisted provider, repository, workflow, and the three reviewed
    modes matching LANE_ARTIFACT_SOURCES."""
    lanes: dict = {}
    delivery_proofs = dict(delivery_proofs or {})
    foreign = sorted(set(delivery_proofs) - set(refs))
    if foreign:
        raise ReceiptError(
            f"--delivery-proof names components not composed in this run: "
            f"{foreign}"
        )
    for component, proof in delivery_proofs.items():
        obligation = _delivery_obligation(graph, component)
        if obligation is None:
            raise ReceiptError(
                f"{component} has no delivery obligation in the graph; a "
                "supplied delivery proof is refused, never ignored"
            )
        if component not in DELIVERY_PROOF_CONSUMERS:
            raise ReceiptError(
                f"{component}'s composed lane does not consume delivery "
                "evidence; a supplied delivery proof is refused, never ignored"
            )
        validate_delivery_proof(proof, obligation, component)
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
        elif component in NPM_LANE_COMPONENTS:
            registry = (declared.get("registry") or {})
            lanes[component] = NpmWorkflowLane(
                component=component,
                npm_name=registry.get("package", component),
                expected_obligation=_delivery_obligation(graph, component),
                reader=reader, lane_authority=authority,
                refs={component: ref}, runs=runs,
                npm_observe=_observe_npm_registry,
                delivery_proofs=delivery_proofs,
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
    return WorkflowLanes(
        lanes,
        recovery_tag_names={
            component: graph.components[component].tag_format
            for component in refs
            if graph.components[component].tag_format
        },
        recovery_tag_observe=_observe_git_version_tag,
    )


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


def edge_identity(edge: "RuntimeContractEdge") -> str:
    """The canonical content identity of a runtime-contract edge: the
    sha256 of its structured preimage (endpoints, journey, artifacts,
    direction). Two edges between the same endpoints - the checked-in
    federation and persisted-state server<->server pair - have distinct
    identities; a display string would alias them."""
    preimage = json.dumps({
        "a": edge.a, "b": edge.b, "journey": edge.journey,
        "artifacts": edge.artifacts, "direction": edge.direction,
    }, sort_keys=True)
    return hashlib.sha256(preimage.encode()).hexdigest()


@dataclass(frozen=True)
class SkewCell:
    # The canonical edge identity and its immutable structured preimage
    # ride every cell unchanged, so a harness distinguishes edges sharing
    # endpoints and journey and selects the DECLARED published artifact
    # locators without guessing.
    edge_id: str
    edge_a: str
    edge_b: str
    journey: str
    artifacts: dict  # the edge's declared artifact locators, per side
    declared_direction: str  # both | persisted-state-both | a-to-b | b-to-a
    direction: str  # this cell's request direction: a-to-b | b-to-a
    a_kind: str  # candidate | published-latest | published-floor | published
    b_kind: str
    a: dict  # {component, version, digest?, digest_set?, lane_ref?}
    b: dict


def canonical_json_bytes(value) -> bytes:
    """The one byte representation used by typed release evidence.

    Documents which authorize or receipt effects must not have a second
    whitespace/key-order identity beside the bytes an authority records.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def canonical_json_digest(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def skew_cell_preimage(cell: SkewCell) -> dict:
    return {
        "edge_id": cell.edge_id,
        "edge_a": cell.edge_a,
        "edge_b": cell.edge_b,
        "journey": cell.journey,
        "artifacts": dict(cell.artifacts),
        "declared_direction": cell.declared_direction,
        "direction": cell.direction,
        "a_kind": cell.a_kind,
        "b_kind": cell.b_kind,
        "a": dict(cell.a),
        "b": dict(cell.b),
    }


def skew_cell_identity(cell: SkewCell) -> str:
    return canonical_json_digest(skew_cell_preimage(cell))


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
    if (
        edge.direction == "persisted-state-both"
        and edge.a == edge.b
        and a_touched
    ):
        # Persisted-state skew is temporal, not two independent network peers.
        # One exact candidate is tested against EVERY measured published
        # version in the canonical a=candidate/b=published layout. Generic
        # both-side expansion would invent candidate×candidate and duplicate
        # aliases of the same actor, neither of which can prove upgrade or
        # non-atomic rollback compatibility.
        candidate = _candidate_side(edge.a, staged)
        versions = supported_for(edge.a)
        latest = published_versions[edge.a]
        for index, version in enumerate(versions):
            kind = (
                "published-latest" if version == latest
                else "published-floor" if index == 0
                else "published"
            )
            pairs.append((
                "candidate", candidate, kind,
                _published_side(edge.b, version, kind),
            ))
    elif a_touched and b_touched:
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
                edge_id=edge_identity(edge),
                edge_a=edge.a, edge_b=edge.b, journey=edge.journey,
                artifacts=dict(edge.artifacts),
                declared_direction=edge.direction,
                direction=direction, a_kind=a_kind, b_kind=b_kind,
                a=dict(a_side), b=dict(b_side),
            ))
    return cells


def _staged_skew_identity(entry: ReceiptEntry) -> dict:
    return {
        "version": entry.version,
        "digest": entry.digest,
        "digest_set": entry.digest_set,
        "lane_ref": entry.lane_ref,
    }


def freeze_skew_matrix(
    edge: "RuntimeContractEdge", *, moving: set, staged: dict,
    support: dict, published_versions: dict, staged_manifest_digest: str,
) -> dict:
    """Seal the complete ordered matrix preimage before any child executes.

    The document is self-recomputing: it carries exactly the edge, endpoint
    staged identities, ordered measured support, frozen publication truth, and
    every full cell preimage. A child consumes this identity instead of
    reconstructing completeness from whatever report files happen to exist.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", staged_manifest_digest or ""):
        raise ReceiptError(
            "skew matrix requires the exact 64-hex staged-manifest digest"
        )
    endpoint_names = sorted({edge.a, edge.b})
    relevant_staged = {
        name: _staged_skew_identity(staged[name])
        for name in endpoint_names
        if name in moving and name in staged
    }
    cells = compute_skew_cells(
        edge, moving=set(moving), staged=staged, support=support,
        published_versions=published_versions,
    )
    preimage = {
        "schema": "aweb.release-skew-matrix.v1",
        "edge_id": edge_identity(edge),
        "edge": {
            "a": edge.a,
            "b": edge.b,
            "journey": edge.journey,
            "artifacts": dict(edge.artifacts),
            "direction": edge.direction,
        },
        "moving": sorted(set(moving)),
        "staged_manifest_digest": staged_manifest_digest,
        "staged": relevant_staged,
        "support": json.loads(json.dumps(support, sort_keys=True)),
        "published_versions": {
            name: published_versions.get(name) for name in endpoint_names
        },
        "cells": [
            {
                "cell_id": skew_cell_identity(cell),
                "preimage": skew_cell_preimage(cell),
            }
            for cell in cells
        ],
    }
    return {
        "matrix_id": canonical_json_digest(preimage),
        "preimage": preimage,
    }


def validate_skew_matrix_document(document: dict) -> list[SkewCell]:
    if not isinstance(document, dict) or set(document) != {"matrix_id", "preimage"}:
        raise ReceiptError("skew matrix document must contain matrix_id and preimage")
    preimage = document.get("preimage")
    required = {
        "schema", "edge_id", "edge", "moving", "staged_manifest_digest",
        "staged", "support", "published_versions", "cells",
    }
    if not isinstance(preimage, dict) or set(preimage) != required:
        raise ReceiptError("skew matrix preimage has the wrong schema")
    if preimage.get("schema") != "aweb.release-skew-matrix.v1":
        raise ReceiptError("skew matrix schema is not supported")
    expected_matrix_id = canonical_json_digest(preimage)
    if document.get("matrix_id") != expected_matrix_id:
        raise ReceiptError("skew matrix identity does not equal its full preimage")
    if not re.fullmatch(
        r"[0-9a-f]{64}", preimage.get("staged_manifest_digest") or ""
    ):
        raise ReceiptError("skew matrix staged-manifest digest is malformed")
    edge_data = preimage.get("edge")
    if not isinstance(edge_data, dict) or set(edge_data) != {
        "a", "b", "journey", "artifacts", "direction"
    }:
        raise ReceiptError("skew matrix edge preimage is malformed")
    edge = RuntimeContractEdge(
        a=edge_data["a"], b=edge_data["b"], journey=edge_data["journey"],
        artifacts=edge_data["artifacts"], direction=edge_data["direction"],
        supported={"policy": "additive-only"},
    )
    if preimage.get("edge_id") != edge_identity(edge):
        raise ReceiptError("skew matrix edge identity does not equal its preimage")
    moving = preimage.get("moving")
    if (
        not isinstance(moving, list)
        or any(not isinstance(name, str) or not name for name in moving)
        or moving != sorted(set(moving))
    ):
        raise ReceiptError("skew matrix moving set is malformed")
    staged_data = preimage.get("staged")
    staged_fields = {"version", "digest", "digest_set", "lane_ref"}
    if (
        not isinstance(staged_data, dict)
        or any(
            not isinstance(name, str)
            or not isinstance(identity, dict)
            or set(identity) != staged_fields
            for name, identity in staged_data.items()
        )
    ):
        raise ReceiptError("skew matrix staged identities are malformed")
    if not isinstance(preimage.get("support"), dict) or not isinstance(
        preimage.get("published_versions"), dict
    ):
        raise ReceiptError("skew matrix support/publication truth is malformed")
    if not isinstance(preimage.get("cells"), list):
        raise ReceiptError("skew matrix cell list is malformed")
    try:
        staged = {
            name: ReceiptEntry(**identity)
            for name, identity in staged_data.items()
        }
    except (TypeError, AttributeError) as exc:
        raise ReceiptError("skew matrix staged identity is malformed") from exc
    recomputed = compute_skew_cells(
        edge, moving=set(moving), staged=staged,
        support=preimage.get("support"),
        published_versions=preimage.get("published_versions"),
    )
    declared_cells = preimage.get("cells")
    expected_cells = [
        {"cell_id": skew_cell_identity(cell),
         "preimage": skew_cell_preimage(cell)}
        for cell in recomputed
    ]
    if declared_cells != expected_cells:
        raise ReceiptError(
            "skew matrix cells do not equal the coordinator's recomputed matrix"
        )
    return recomputed


class MatrixSkewRunner:
    """The skew provider run_plan executes between staging and the first
    publish: every accepted edge is ordered and invoked cell by cell, and
    any red raises before a single continuation dispatch."""

    def __init__(self, *, harness, support, published_versions, moving):
        self._harness = harness
        self._support = support
        self._published = dict(published_versions)
        self._moving = set(moving)
        self._frozen_matrices: dict[str, tuple[dict, list[SkewCell]]] = {}

    def has_matrix(self, edge) -> bool:
        return self._harness.has_journey(edge)

    def freeze_matrix(
        self, edge, staged: dict, *, staged_manifest_digest: str
    ) -> dict:
        if edge.declared_incomplete:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b} is declared-incomplete;"
                " skew never runs on unmeasured support"
            )
        support = self._support.resolve(edge.supported.get("record", {}), edge)
        document = freeze_skew_matrix(
            edge, moving=self._moving, staged=staged, support=support,
            published_versions=self._published,
            staged_manifest_digest=staged_manifest_digest,
        )
        freeze = getattr(self._harness, "freeze_matrix", None)
        if freeze is None:
            raise ReceiptError(
                f"skew harness for {edge.journey!r} cannot persist the exact "
                "frozen matrix before cell execution"
            )
        freeze(document)
        cells = validate_skew_matrix_document(document)
        self._frozen_matrices[edge_identity(edge)] = (document, cells)
        return document

    def execute(self, edge, staged: dict) -> None:
        frozen = self._frozen_matrices.get(edge_identity(edge))
        if frozen is None:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b} matrix is not frozen; "
                "cell execution cannot infer completeness"
            )
        document, cells = frozen
        expected_staged = document["preimage"]["staged"]
        current_staged = {
            name: _staged_skew_identity(staged[name])
            for name in expected_staged
            if name in staged
        }
        if current_staged != expected_staged:
            raise ReceiptError(
                "staged identities changed after the skew matrix was frozen"
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
        finish = getattr(self._harness, "finish_matrix", None)
        if finish is not None:
            finish(document)


def _validate_measurement_document(body: bytes, edge, *, require_schema=False):
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement body is "
            f"not valid UTF-8 JSON ({exc})"
        ) from exc
    if not isinstance(doc, dict):
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement body must be "
            "a JSON object"
        )
    if (
        require_schema
        and doc.get("schema") != "aweb.runtime-support-measurement.v1"
    ):
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: repository measurement "
            f"schema is {doc.get('schema')!r}, not "
            "'aweb.runtime-support-measurement.v1'"
        )
    if doc.get("edge") != {"a": edge.a, "b": edge.b}:
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement binds "
            f"edge {doc.get('edge')!r}, not this edge"
        )
    if doc.get("journey") != edge.journey:
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement binds "
            f"journey {doc.get('journey')!r}, not {edge.journey!r}"
        )
    if doc.get("artifacts") != edge.artifacts:
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement binds "
            f"artifacts {doc.get('artifacts')!r}, not this edge's "
            f"{edge.artifacts!r}"
        )
    if doc.get("direction") != edge.direction:
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement binds "
            f"direction {doc.get('direction')!r}, not {edge.direction!r}"
        )
    supported = doc.get("supported_versions")
    if not isinstance(supported, dict) or not supported or not all(
        isinstance(k, str) and isinstance(v, list)
        and all(isinstance(item, str) for item in v)
        for k, v in supported.items()
    ):
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: measurement "
            "supported_versions must map components to version lists"
        )
    return doc


class AnchoredMeasurementAuthority:
    """Resolve measurement bytes through an artifact store and its authority."""

    def __init__(
        self, *, store, authority,
        accepted_authorities=("workflow-artifacts",),
    ):
        self._store = store
        self._authority = authority
        self._accepted_authorities = frozenset(accepted_authorities)

    def resolve(self, record, edge):
        if (
            not isinstance(record, dict)
            or record.get("authority") not in self._accepted_authorities
            or not record.get("artifact_id")
            or not isinstance(record.get("artifact_id"), str)
            or not record.get("digest")
            or not isinstance(record.get("digest"), str)
        ):
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: support record must "
                f"name one of {sorted(self._accepted_authorities)} with a "
                f"nonempty artifact_id and digest, got {record!r}"
            )
        recorded = self._authority.expected_digest(record["artifact_id"])
        if recorded is None:
            return None  # unresolvable at the authority; blocked, not invented
        if recorded != record["digest"]:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: the authority records "
                f"digest {recorded}, the edge declares {record['digest']}"
            )
        body = self._store.get(record["artifact_id"])
        actual = hashlib.sha256(body).hexdigest()
        if actual != record["digest"]:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: measurement bytes "
                f"hash {actual}, not the declared {record['digest']}"
            )
        return _validate_measurement_document(body, edge)


class RepositoryMeasurementAuthority:
    """Resolve reviewed measurement bytes from the exact source commit."""

    def __init__(self, *, repo_root: Path, source_sha: str):
        if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
            raise ReceiptError(
                f"repository measurement source must be a 40-hex SHA, got "
                f"{source_sha!r}"
            )
        self._repo_root = repo_root
        self._source_sha = source_sha

    def resolve(self, record, edge):
        raw_path = record.get("path") if isinstance(record, dict) else None
        path = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
        if (
            not isinstance(record, dict)
            or record.get("authority") != "repository"
            or not isinstance(record.get("artifact_id"), str)
            or not record.get("artifact_id")
            or not isinstance(record.get("digest"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record.get("digest", ""))
            or path is None
            or path.is_absolute()
            or path.parts[:2] != ("release", "measurements")
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: repository support "
                "record needs authority repository, artifact_id, SHA-256 "
                "digest, and a safe path under release/measurements"
            )
        try:
            result = subprocess.run(
                [
                    "git", "-C", str(self._repo_root), "cat-file", "blob",
                    f"{self._source_sha}:{path.as_posix()}",
                ],
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: cannot read "
                f"repository measurement from exact source: {exc}"
            ) from exc
        if result.returncode != 0:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: repository measurement "
                f"{path.as_posix()} is absent from exact source "
                f"{self._source_sha}"
            )
        body = result.stdout
        actual = hashlib.sha256(body).hexdigest()
        if actual != record["digest"]:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b}: repository measurement "
                f"hash {actual}, not the declared digest {record['digest']}"
            )
        return _validate_measurement_document(body, edge, require_schema=True)


class RepositoryMeasurementRouter:
    """Route repository records explicitly; preserve the configured authority."""

    def __init__(self, repository, fallback=None):
        self._repository = repository
        self._fallback = fallback

    def resolve(self, record, edge):
        if isinstance(record, dict) and record.get("authority") == "repository":
            return self._repository.resolve(record, edge)
        if self._fallback is not None:
            return self._fallback.resolve(record, edge)
        raise ReceiptError(
            f"runtime-contract {edge.a}<->{edge.b}: unsupported measurement "
            f"authority {record.get('authority') if isinstance(record, dict) else None!r}"
        )


class _FrozenSupport:
    """Support resolution from the sealed frozen snapshot: the matrix is
    driven by frozen truth, never by a live resolver."""

    def __init__(self, measurements: dict):
        self._measurements = measurements

    def resolve(self, record, edge):
        sealed = self._measurements.get(edge_identity(edge))
        if sealed is None:
            raise ReceiptError(
                f"runtime-contract {edge.a}<->{edge.b} "
                f"({edge.journey}): no measurement is sealed in the frozen "
                "plan; execution never resolves support live"
            )
        return sealed


class SkewHarnessRouter:
    """Routes a frozen matrix and all its cells to ONE checked-in child.

    Reusing the child instance preserves the exact matrix identity across cell
    calls; creating a fresh factory result per cell would strand completeness
    in process-local state and force the child to guess from directory contents.
    """

    def __init__(self):
        self._instances: dict[str, object] = {}

    def has_journey(self, edge) -> bool:
        import release_skew_harnesses

        return edge.journey in release_skew_harnesses.REGISTRY

    def _instance(self, journey: str):
        import release_skew_harnesses

        factory = release_skew_harnesses.REGISTRY.get(journey)
        if factory is None:
            raise ReceiptError(
                f"no skew harness is registered for journey {journey!r}"
            )
        if journey not in self._instances:
            self._instances[journey] = factory()
        return self._instances[journey]

    def freeze_matrix(self, document) -> None:
        validate_skew_matrix_document(document)
        journey = document["preimage"]["edge"]["journey"]
        harness = self._instance(journey)
        freeze = getattr(harness, "freeze_matrix", None)
        if freeze is None:
            raise ReceiptError(
                f"skew harness for {journey!r} cannot persist a frozen matrix"
            )
        freeze(document)

    def run(self, cell) -> None:
        self._instance(cell.journey).run(cell)

    def finish_matrix(self, document) -> None:
        journey = document["preimage"]["edge"]["journey"]
        harness = self._instance(journey)
        finish = getattr(harness, "finish_matrix", None)
        if finish is not None:
            finish(document)


def build_production_skew(frozen: "FrozenPlan", *, state, measurement,
                          harness=None):
    """The skew provider ordinary release-run composes in a fresh process.
    FROZEN TRUTH DRIVES THE MATRIX: support cells come from the sealed
    measurements and endpoint versions in the frozen snapshot. Before any
    harness runs, the CURRENT observations - live measurement resolution
    and live authoritative published versions - must equal those frozen
    values; drift refuses. A plan touching no runtime edge needs no
    matrix; missing state or measurement refuses."""
    plan = frozen.plan
    if not plan.runtime_contract_edges:
        return NoSkew()
    if measurement is None:
        raise ReceiptError(
            "the plan touches runtime-contract edges but no measurement "
            "authority is configured; skew never runs on unmeasured support"
        )
    if state is None:
        raise ReceiptError(
            "the plan touches runtime-contract edges but no repository state "
            "is configured to supply authoritative published versions"
        )
    frozen_measurements = frozen.resolved.get("measurements") or {}
    frozen_published = frozen.resolved.get("runtime_published")
    if frozen_published is None:
        raise ReceiptError(
            "the frozen plan seals no runtime endpoint versions; refusing to "
            "substitute live values for frozen truth"
        )
    graph = frozen.graph

    def canon(value):
        return json.loads(json.dumps(value, sort_keys=True, default=str))

    for edge in plan.runtime_contract_edges:
        if edge.declared_incomplete:
            continue
        label = f"{edge.a}<->{edge.b} ({edge.journey})"
        live = measurement.resolve(edge.supported.get("record", {}), edge)
        if canon(live) != canon(frozen_measurements.get(edge_identity(edge))):
            raise ReceiptError(
                f"runtime-contract {label}: the live measurement no longer "
                "equals the frozen sealed record; refusing drifted support"
            )
        candidates = {
            n.component: n.version for n in plan.moving if n.version
        }
        for name in (edge.a, edge.b):
            component = graph.components.get(name)
            current = (
                state.published_version(component)
                if component is not None else None
            )
            allowed = {frozen_published.get(name)}
            if name in candidates:
                # A moving endpoint may already have published its exact
                # candidate (crash-resume); anything else is drift.
                allowed.add(candidates[name])
            if current not in allowed:
                raise ReceiptError(
                    f"runtime-contract {label}: published {name} is now "
                    f"{current!r}, the frozen plan sealed "
                    f"{frozen_published.get(name)!r}; refusing drift"
                )
    return MatrixSkewRunner(
        harness=harness if harness is not None else SkewHarnessRouter(),
        support=_FrozenSupport(frozen_measurements),
        published_versions=frozen_published,
        moving={n.component for n in plan.moving},
    )


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
    runnerless_risk: Approval | None = None
    defer_g5: bool = False
    # Authority-independent: who may defer runtime support is a question
    # about the human, not about which runner built the artifact.
    g5_authorization: object = None
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


# ── adopted-preplan recovery ─────────────────────────────────────────

ADOPTED_PREPLAN_EXCEPTION_SCHEMA = (
    "aweb.release.adopted-preplan-exception.v1"
)
ADOPTED_PREPLAN_AUTHORIZATION_SCHEMA = (
    "aweb.release.adopted-preplan-authorization.v1"
)
ADOPTED_PREPLAN_PLAN_SCHEMA = "aweb.release.adopted-preplan-plan.v1"
ADOPTED_PREPLAN_MANIFEST_SCHEMA = "aweb.release.adopted-preplan-manifest.v1"
ADOPTED_PREPLAN_RECEIPT_SCHEMA = "aweb.release.adopted-preplan-receipt.v1"


def _exact_keys(value, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        actual = sorted(value) if isinstance(value, dict) else value
        raise ReceiptError(
            f"{label} must carry exactly {sorted(expected)}, got {actual!r}"
        )


def _nonempty_text(value, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReceiptError(f"{label} must be a nonempty string")
    return value


def _sha256_identity(value, label: str, *, prefix: bool = True) -> str:
    pattern = r"sha256:[0-9a-f]{64}" if prefix else r"[0-9a-f]{64}"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        form = "sha256:<64 lowercase hex>" if prefix else "64 lowercase hex"
        raise ReceiptError(f"{label} must be {form}, got {value!r}")
    return value


def runtime_edge_document(edge: RuntimeContractEdge) -> dict:
    """The complete graph-owned edge preimage plus its canonical identity."""
    return {
        "edge_id": edge_identity(edge),
        "a": edge.a,
        "b": edge.b,
        "journey": edge.journey,
        "artifacts": dict(edge.artifacts),
        "direction": edge.direction,
    }


@dataclass(frozen=True)
class AdoptedPreplanException:
    canonical: dict
    canonical_bytes: bytes
    digest: str

    @property
    def source_sha(self) -> str:
        return self.canonical["source_sha"]

    @property
    def components(self) -> dict:
        return self.canonical["components"]

    @property
    def runtime_edges(self) -> list:
        return self.canonical["runtime_edges"]

    @property
    def history(self) -> list:
        return self.canonical["history"]


@dataclass(frozen=True)
class AdoptedStageEntry:
    """Read-only semantic revalidation of an already-created stage.

    It deliberately is not a ReceiptEntry phase: the stage predates this plan
    and may never be represented as if the driver's normal Plan -> Stage
    lifecycle created it.
    """

    entry: ReceiptEntry
    manifest_digest: str


@dataclass(frozen=True)
class ObservedRecoveryState:
    public: dict
    entry: ReceiptEntry | None


@dataclass(frozen=True)
class RecoveryContinuation:
    entry: ReceiptEntry
    continuation_run_id: str
    attempt_artifact_id: str


@dataclass
class AdoptedPreplanHandle:
    exception: AdoptedPreplanException
    exception_artifact_id: str
    plan: dict
    plan_id: str
    plan_artifact_id: str
    manifest: dict
    manifest_id: str
    manifest_artifact_id: str
    staged: dict[str, ReceiptEntry]


@dataclass(frozen=True)
class AdoptedPreplanReceipt:
    document: dict
    digest: str
    artifact_id: str


def _validate_digest_set(value, label: str) -> dict:
    if not isinstance(value, dict) or not value:
        raise ReceiptError(f"{label} must be a nonempty digest map")
    for name, digest in value.items():
        _nonempty_text(name, f"{label} filename")
        _sha256_identity(digest, f"{label}[{name}]", prefix=False)
    return value


def _validate_public_state(value, *, component: str, version: str,
                           source_sha: str, graph: Graph,
                           payload_digests: dict) -> None:
    _exact_keys(value, {"tag", "registry"}, f"{component} public state")
    tag = value["tag"]
    _exact_keys(tag, {"name", "status", "source_sha"}, f"{component} tag")
    declared = graph.components[component]
    if not declared.tag_format:
        raise ReceiptError(
            f"{component}: adopted-preplan recovery requires an immutable "
            "version tag declared by the graph"
        )
    expected_tag = declared.tag_format.format(version=version)
    if tag["name"] != expected_tag:
        raise ReceiptError(
            f"{component}: state names tag {tag['name']!r}, expected "
            f"{expected_tag!r} from the graph and version"
        )
    if tag["status"] not in ("present", "absent"):
        raise ReceiptError(f"{component}: tag status must be present or absent")
    expected_source = source_sha if tag["status"] == "present" else None
    if tag["source_sha"] != expected_source:
        raise ReceiptError(
            f"{component}: {tag['status']} tag must bind source "
            f"{expected_source!r}, got {tag['source_sha']!r}"
        )
    registry = value["registry"]
    _exact_keys(
        registry, {"status", "digest_set"}, f"{component} registry state"
    )
    if registry["status"] == "absent":
        if registry["digest_set"] is not None:
            raise ReceiptError(
                f"{component}: absent registry state cannot carry digests"
            )
    elif registry["status"] == "exact":
        _validate_digest_set(
            registry["digest_set"], f"{component} observed registry digests"
        )
        if registry["digest_set"] != payload_digests:
            raise ReceiptError(
                f"{component}: exact registry state does not equal the "
                "exception's preserved payload identity"
            )
        if tag["status"] != "present":
            raise ReceiptError(
                f"{component}: exact registry bytes without the exact version "
                "tag cannot be adopted from the reviewed continuation lane"
            )
    else:
        raise ReceiptError(
            f"{component}: registry status must be absent or exact"
        )


def load_adopted_preplan_exception(
    data: bytes, *, graph: Graph
) -> AdoptedPreplanException:
    """Load the dedicated recovery exception without weakening normal runs.

    Canonical bytes, a strict closed schema, the checked-in graph, and every
    LaneRef are all validated before the document can reach an authority.
    """
    try:
        document = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReceiptError(f"adopted-preplan exception is not JSON: {exc}") from exc
    if canonical_json_bytes(document) != data:
        raise ReceiptError(
            "adopted-preplan exception is not in canonical JSON byte form"
        )
    _exact_keys(
        document,
        {
            "schema", "exception_authorization", "source_sha", "reason",
            "one_shot", "components", "runtime_edges",
            "observed_partial_state", "history",
        },
        "adopted-preplan exception",
    )
    if document["schema"] != ADOPTED_PREPLAN_EXCEPTION_SCHEMA:
        raise ReceiptError(
            f"adopted-preplan exception schema is {document['schema']!r}"
        )
    if document["one_shot"] is not True:
        raise ReceiptError("adopted-preplan exception scope must be one-shot")
    source_sha = document["source_sha"]
    if not isinstance(source_sha, str) or not re.fullmatch(
        r"[0-9a-f]{40}", source_sha
    ):
        raise ReceiptError(
            "adopted-preplan exception source must be exactly 40 lowercase hex"
        )
    _nonempty_text(document["reason"], "adopted-preplan reason")
    exception_auth = document["exception_authorization"]
    _exact_keys(
        exception_auth, {"authorization_id", "authorized_by"},
        "exception authorization",
    )
    _nonempty_text(exception_auth["authorization_id"], "exception authorization id")
    _nonempty_text(exception_auth["authorized_by"], "exception authorized_by")

    components = document["components"]
    if not isinstance(components, dict) or len(components) != 2:
        raise ReceiptError(
            "adopted-preplan recovery requires exactly two component lanes"
        )
    if list(components) != sorted(components):
        raise ReceiptError("adopted-preplan components must be canonically ordered")
    lane_artifacts: set[str] = set()
    lane_zip_digests: set[str] = set()
    for name, component in components.items():
        _nonempty_text(name, "component name")
        if name not in graph.components:
            raise ReceiptError(f"adopted-preplan component {name!r} is not in graph")
        if graph.components[name].publish_lane is None:
            raise ReceiptError(f"{name}: graph declares no publish lane")
        _exact_keys(
            component,
            {
                "version", "lane_ref", "manifest_digest", "payload_digests",
            },
            f"{name} adopted stage",
        )
        version = _nonempty_text(component["version"], f"{name} version")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ReceiptError(f"{name}: version must be dotted numeric")
        ref = LaneRef.from_dict(component["lane_ref"])
        if ref.aw_source_sha != source_sha:
            raise ReceiptError(
                f"{name}: lane source {ref.aw_source_sha} does not equal "
                f"exception source {source_sha}"
            )
        if ref.artifact in lane_artifacts or ref.zip_digest in lane_zip_digests:
            raise ReceiptError(
                f"{name}: one lane's artifact/digest evidence is reused by "
                "another component"
            )
        lane_artifacts.add(ref.artifact)
        lane_zip_digests.add(ref.zip_digest)
        _sha256_identity(component["manifest_digest"], f"{name} manifest digest")
        _validate_digest_set(component["payload_digests"], f"{name} payload digests")

    expected_edges = sorted(
        (
            runtime_edge_document(edge)
            for edge in graph.runtime_contracts
            if edge.a in components or edge.b in components
        ),
        key=lambda item: item["edge_id"],
    )
    if not expected_edges:
        raise ReceiptError(
            "adopted-preplan components touch no runtime-contract edge"
        )
    if any(
        not edge.declared_incomplete
        for edge in graph.runtime_contracts
        if edge.a in components or edge.b in components
    ):
        raise ReceiptError(
            "adopted-preplan exception is only an incomplete/unmeasured G5 "
            "exception; measured and approved-deprecation edges use normal release-run"
        )
    runtime_edges = document["runtime_edges"]
    if runtime_edges != expected_edges:
        raise ReceiptError(
            "adopted-preplan runtime edge preimages/identities do not equal "
            "the exact touched edges in the checked-in graph"
        )

    partial = document["observed_partial_state"]
    if not isinstance(partial, dict) or set(partial) != set(components):
        raise ReceiptError(
            "observed partial state must cover exactly both recovery components"
        )
    for name, state in partial.items():
        _validate_public_state(
            state,
            component=name,
            version=components[name]["version"],
            source_sha=source_sha,
            graph=graph,
            payload_digests=components[name]["payload_digests"],
        )

    history = document["history"]
    if not isinstance(history, list) or not history:
        raise ReceiptError(
            "adopted-preplan exception requires nonempty non-authorizing history"
        )
    for index, event in enumerate(history):
        _exact_keys(
            event,
            {
                "component", "kind", "run_id", "outcome",
                "authorization_id", "authorizing",
            },
            f"history[{index}]",
        )
        if event["component"] not in components:
            raise ReceiptError(f"history[{index}] names an unrelated component")
        if event["kind"] != "publish-continuation":
            raise ReceiptError(f"history[{index}] is not a continuation run")
        _nonempty_text(event["run_id"], f"history[{index}] run id")
        _nonempty_text(event["outcome"], f"history[{index}] outcome")
        _nonempty_text(
            event["authorization_id"], f"history[{index}] authorization id"
        )
        if event["authorizing"] is not False:
            raise ReceiptError(
                f"history[{index}] must be explicitly non-authorizing"
            )

    return AdoptedPreplanException(
        canonical=document,
        canonical_bytes=data,
        digest=hashlib.sha256(data).hexdigest(),
    )


def _entry_document(entry: ReceiptEntry) -> dict:
    return {
        "version": entry.version,
        "digest": entry.digest,
        "digest_set": entry.digest_set,
        "phase": entry.phase,
        "pointer_state": entry.pointer_state,
        "delivery_proof": entry.delivery_proof,
        "lane_ref": entry.lane_ref,
    }


def _entry_from_document(value: dict) -> ReceiptEntry:
    _exact_keys(
        value,
        {
            "version", "digest", "digest_set", "phase", "pointer_state",
            "delivery_proof", "lane_ref",
        },
        "recovery receipt entry",
    )
    return ReceiptEntry(
        version=value["version"],
        digest=value["digest"],
        digest_set=value["digest_set"],
        phase=value["phase"],
        pointer_state=value["pointer_state"],
        delivery_proof=value["delivery_proof"],
        lane_ref=value["lane_ref"],
    )


def _observe_recovery_component(lanes, node: PlanNode, staged: ReceiptEntry,
                                exception: AdoptedPreplanException,
                                graph: Graph) -> ObservedRecoveryState:
    observed = lanes.observe_recovery(node, staged)
    if not isinstance(observed, ObservedRecoveryState):
        raise ReceiptError(
            f"{node.component}: recovery observer returned no typed observation"
        )
    component = exception.components[node.component]
    _validate_public_state(
        observed.public,
        component=node.component,
        version=component["version"],
        source_sha=exception.source_sha,
        graph=graph,
        payload_digests=component["payload_digests"],
    )
    if observed.public["registry"]["status"] == "exact":
        if observed.entry is None:
            raise ReceiptError(
                f"{node.component}: exact public registry state lacks an "
                "authoritative receipt entry"
            )
        if (
            observed.entry.version != component["version"]
            or observed.entry.digest_set != component["payload_digests"]
            or observed.entry.digest
            != canonical_digest_of_set(component["payload_digests"])
            or observed.entry.lane_ref != component["lane_ref"]
        ):
            raise ReceiptError(
                f"{node.component}: observed exact entry does not equal the "
                "adopted stage identity"
            )
    elif observed.entry is not None:
        raise ReceiptError(
            f"{node.component}: absent public registry state carries an entry"
        )
    return observed


def _expected_final_public(exception: AdoptedPreplanException,
                           component: str) -> dict:
    spec = exception.components[component]
    initial = exception.canonical["observed_partial_state"][component]
    return {
        "tag": {
            "name": initial["tag"]["name"],
            "status": "present",
            "source_sha": exception.source_sha,
        },
        "registry": {
            "status": "exact",
            "digest_set": dict(spec["payload_digests"]),
        },
    }


def prepare_adopted_preplan_recovery(
    exception: AdoptedPreplanException,
    *,
    graph: Graph,
    lanes,
    store,
    authority,
    authority_trust: str,
) -> AdoptedPreplanHandle:
    """Freeze exception/plan, jointly revalidate both preserved stages, then
    anchor an honestly labelled adopted-preplan manifest.

    No continuation adapter is reachable before every read-only and public
    state barrier has passed. Normal run_plan is deliberately not called.
    """
    if authority_trust != "external-immutable":
        raise ReceiptError(
            "adopted-preplan recovery requires an external-immutable digest "
            "authority established by trusted composition"
        )
    validated_exception = load_adopted_preplan_exception(
        exception.canonical_bytes, graph=graph
    )
    if (
        validated_exception.digest != exception.digest
        or validated_exception.canonical != exception.canonical
    ):
        raise ReceiptError(
            "adopted-preplan exception object differs from its validated bytes"
        )
    missing = [name for name in exception.components if not lanes.has_lane(name)]
    if missing:
        raise LaneUnavailable(
            "no adopted-preplan lane available for: " + ", ".join(missing)
        )

    exception_artifact_id = f"adopted-preplan-exception:{exception.digest}"
    _put_content_addressed(
        store, authority, exception_artifact_id,
        exception.canonical_bytes, exception.digest,
    )
    plan = {
        "schema": ADOPTED_PREPLAN_PLAN_SCHEMA,
        "provenance": "adopted-preplan",
        "exception_artifact_id": exception_artifact_id,
        "exception_digest": exception.digest,
        "source_sha": exception.source_sha,
        "graph": graph.canonical,
        "components": {
            name: {"version": spec["version"], "reason": "adopted-preplan"}
            for name, spec in exception.components.items()
        },
        "runtime_edges": list(exception.runtime_edges),
        "support": {
            "status": "incomplete-unmeasured",
            "runtime_edge_ids": [
                edge["edge_id"] for edge in exception.runtime_edges
            ],
        },
    }
    plan_bytes = canonical_json_bytes(plan)
    plan_id = hashlib.sha256(plan_bytes).hexdigest()
    plan_artifact_id = f"adopted-preplan-plan:{plan_id}"
    _put_content_addressed(
        store, authority, plan_artifact_id, plan_bytes, plan_id
    )

    adopted: dict[str, AdoptedStageEntry] = {}
    for name, spec in exception.components.items():
        node = PlanNode(
            component=name, reason="adopted-preplan", version=spec["version"]
        )
        result = lanes.adopt_preplan(node)
        if not isinstance(result, AdoptedStageEntry):
            raise ReceiptError(
                f"{name}: lane returned no typed adopted stage evidence"
            )
        entry = result.entry
        _sha256_identity(result.manifest_digest, f"{name} manifest digest")
        if result.manifest_digest != spec["manifest_digest"]:
            raise ReceiptError(
                f"{name}: semantic manifest digest {result.manifest_digest} "
                f"does not equal exception {spec['manifest_digest']}"
            )
        if (
            entry.version != spec["version"]
            or entry.lane_ref != spec["lane_ref"]
            or entry.digest_set != spec["payload_digests"]
            or entry.digest != canonical_digest_of_set(spec["payload_digests"])
        ):
            raise ReceiptError(
                f"{name}: adopted stage does not equal the exception's exact "
                "version/LaneRef/payload identity"
            )
        adopted[name] = result

    manifest = {
        "schema": ADOPTED_PREPLAN_MANIFEST_SCHEMA,
        "provenance": "adopted-preplan",
        "exception_artifact_id": exception_artifact_id,
        "exception_digest": exception.digest,
        "recovery_plan_id": plan_id,
        "recovery_plan_artifact_id": plan_artifact_id,
        "source_sha": exception.source_sha,
        "entries": {
            name: {
                "provenance": "adopted-preplan",
                "version": adopted[name].entry.version,
                "lane_ref": adopted[name].entry.lane_ref,
                "manifest_digest": adopted[name].manifest_digest,
                "payload_digests": adopted[name].entry.digest_set,
                "digest": adopted[name].entry.digest,
                "delivery_obligation": _delivery_obligation(graph, name),
            }
            for name in exception.components
        },
    }
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_id = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_artifact_id = f"adopted-preplan-manifest:{plan_id}:{manifest_id}"
    _put_content_addressed(
        store, authority, manifest_artifact_id, manifest_bytes, manifest_id
    )
    staged = {name: adopted[name].entry for name in exception.components}

    handle = AdoptedPreplanHandle(
        exception=exception,
        exception_artifact_id=exception_artifact_id,
        plan=plan,
        plan_id=plan_id,
        plan_artifact_id=plan_artifact_id,
        manifest=manifest,
        manifest_id=manifest_id,
        manifest_artifact_id=manifest_artifact_id,
        staged=staged,
    )

    # The frozen state is checked only after both artifacts crossed the joint
    # semantic barrier. On a fresh preparation it must equal the exception.
    # A restarted process may also see one exact final component, but only when
    # pre-effect attempt history is already authority-recorded for it. Execution
    # must then correlate the unique eligible attempt to the authorization being
    # resumed. This admits the crash window without admitting a retrospective
    # receipt for an unrelated/direct publication.
    for name, expected in exception.canonical["observed_partial_state"].items():
        observed = _observe_recovery_component(
            lanes,
            PlanNode(
                component=name, reason="adopted-preplan",
                version=exception.components[name]["version"],
            ),
            staged[name], exception, graph,
        )
        if observed.public == expected:
            continue
        attempts = _attempts(handle, store, authority, name)
        if (
            observed.public == _expected_final_public(exception, name)
            and attempts
        ):
            continue
        raise ReceiptError(
            f"{name}: public state drifted from the exception's exact "
            f"partial-state preimage without persisted attempt history: "
            f"expected {expected!r}, observed {observed.public!r}"
        )

    return handle


def _load_canonical_authority_document(store, authority, artifact_id: str) -> dict:
    expected = authority.expected_digest(artifact_id)
    if expected is None:
        raise ReceiptError(f"{artifact_id}: no digest-authority record")
    if artifact_id.rsplit(":", 1)[-1] != expected:
        raise ReceiptError(
            f"{artifact_id}: content-addressed id does not end in its "
            "authority digest"
        )
    data = store.get(artifact_id)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ReceiptError(f"{artifact_id}: bytes do not match authority digest")
    try:
        document = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"{artifact_id}: invalid JSON ({exc})") from exc
    if canonical_json_bytes(document) != data:
        raise ReceiptError(f"{artifact_id}: evidence bytes are not canonical JSON")
    return document


def _load_adopted_authorization(
    data: bytes, *, handle: AdoptedPreplanHandle
) -> tuple[dict, str]:
    try:
        document = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"adopted-preplan authorization is not JSON: {exc}") from exc
    if canonical_json_bytes(document) != data:
        raise ReceiptError(
            "adopted-preplan authorization is not canonical JSON"
        )
    _exact_keys(
        document,
        {
            "schema", "authorization_id", "authorized_by", "issued_at",
            "one_shot", "exception_digest", "recovery_plan_id", "actions",
        },
        "adopted-preplan authorization",
    )
    if document["schema"] != ADOPTED_PREPLAN_AUTHORIZATION_SCHEMA:
        raise ReceiptError("wrong adopted-preplan authorization schema")
    authorization_id = _nonempty_text(
        document["authorization_id"], "authorization id"
    )
    subject = _nonempty_text(document["authorized_by"], "authorized_by")
    expected_subject = handle.exception.canonical[
        "exception_authorization"
    ]["authorized_by"]
    if subject != expected_subject:
        raise ReceiptError(
            f"authorization subject {subject!r} is not exception authority "
            f"{expected_subject!r}"
        )
    spent_ids = {
        event["authorization_id"] for event in handle.exception.history
    }
    if authorization_id in spent_ids:
        raise ReceiptError(
            f"authorization {authorization_id!r} appears in non-authorizing "
            "history and cannot be reused"
        )
    issued = _nonempty_text(document["issued_at"], "authorization issued_at")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", issued):
        raise ReceiptError("authorization issued_at must be whole-second UTC")
    if document["one_shot"] is not True:
        raise ReceiptError("recovery authorization must be one-shot")
    if document["exception_digest"] != handle.exception.digest:
        raise ReceiptError("authorization does not bind this exception")
    if document["recovery_plan_id"] != handle.plan_id:
        raise ReceiptError("authorization does not bind this recovery plan")
    actions = document["actions"]
    if not isinstance(actions, list) or not actions:
        raise ReceiptError("authorization actions must be a nonempty list")
    seen: set[str] = set()
    for index, action in enumerate(actions):
        _exact_keys(
            action, {"component", "kind", "version", "lane_ref"},
            f"authorization action[{index}]",
        )
        component = action["component"]
        if component in seen:
            raise ReceiptError(f"authorization repeats action for {component}")
        seen.add(component)
        if component not in handle.exception.components:
            raise ReceiptError(f"authorization action names {component!r} outside plan")
        spec = handle.exception.components[component]
        if (
            action["kind"] != "publish-continuation"
            or action["version"] != spec["version"]
            or action["lane_ref"] != spec["lane_ref"]
        ):
            raise ReceiptError(
                f"authorization action for {component} does not exactly bind "
                "the remaining continuation/version/LaneRef"
            )
        LaneRef.from_dict(action["lane_ref"])
    return document, hashlib.sha256(data).hexdigest()


def _record_prefix(kind: str, handle: AdoptedPreplanHandle,
                   component: str) -> str:
    return f"adopted-preplan-{kind}:{handle.plan_id}:{component}:"


def _records_with_prefix(store, authority, prefix: str) -> list[tuple[str, dict]]:
    records = []
    for artifact_id in authority.recorded_ids():
        if artifact_id.startswith(prefix):
            records.append(
                (artifact_id, _load_canonical_authority_document(
                    store, authority, artifact_id
                ))
            )
    return records


def _validate_attempt_record(handle, artifact_id, document, store, authority):
    _exact_keys(
        document,
        {
            "schema", "provenance", "exception_digest", "recovery_plan_id",
            "adopted_manifest_id", "component", "authorization_id",
            "authorization_artifact_id", "authorization_digest", "action",
            "attempt_ordinal", "predecessor_attempt_artifact_ids",
            "continuation_run_ids_before", "public_state_before",
        },
        f"attempt {artifact_id}",
    )
    component = document["component"]
    if (
        document["schema"] != "aweb.release.adopted-preplan-attempt.v1"
        or document["provenance"] != "adopted-preplan"
        or document["exception_digest"] != handle.exception.digest
        or document["recovery_plan_id"] != handle.plan_id
        or document["adopted_manifest_id"] != handle.manifest_id
        or component not in handle.exception.components
    ):
        raise ReceiptError(f"{artifact_id}: attempt binding mismatch")
    authorization_digest = document["authorization_digest"]
    _sha256_identity(
        authorization_digest, f"{artifact_id} authorization digest", prefix=False
    )
    expected_authorization_id = (
        f"adopted-preplan-authorization:{handle.plan_id}:"
        f"{authorization_digest}"
    )
    if document["authorization_artifact_id"] != expected_authorization_id:
        raise ReceiptError(f"{artifact_id}: attempt authorization id mismatch")
    authorization = _load_canonical_authority_document(
        store, authority, expected_authorization_id
    )
    if (
        authorization.get("authorization_id") != document["authorization_id"]
        or document["action"] not in authorization.get("actions", [])
    ):
        raise ReceiptError(
            f"{artifact_id}: attempt action is not in its anchored authorization"
        )
    spec = handle.exception.components[component]
    expected_action = {
        "component": component,
        "kind": "publish-continuation",
        "version": spec["version"],
        "lane_ref": spec["lane_ref"],
    }
    if document["action"] != expected_action:
        raise ReceiptError(f"{artifact_id}: attempt action identity differs")
    ordinal = document["attempt_ordinal"]
    predecessors = document["predecessor_attempt_artifact_ids"]
    attempt_prefix = _record_prefix("attempt", handle, component)
    if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
        raise ReceiptError(f"{artifact_id}: invalid attempt ordinal")
    if (
        not isinstance(predecessors, list)
        or predecessors != sorted(predecessors)
        or len(predecessors) != len(set(predecessors))
        or any(
            not isinstance(item, str)
            or not item.startswith(attempt_prefix)
            or item == artifact_id
            for item in predecessors
        )
    ):
        raise ReceiptError(f"{artifact_id}: invalid predecessor attempt set")
    before = document["continuation_run_ids_before"]
    if (
        not isinstance(before, list)
        or len(before) > 1
        or len(before) != len(set(before))
        or not all(isinstance(item, str) and item for item in before)
    ):
        raise ReceiptError(f"{artifact_id}: invalid pre-attempt run snapshot")
    if document["public_state_before"] != handle.exception.canonical[
        "observed_partial_state"
    ][component]:
        raise ReceiptError(f"{artifact_id}: attempt pre-state differs")


def _validate_transition_record(handle, artifact_id, document, store, authority):
    _exact_keys(
        document,
        {
            "schema", "provenance", "exception_digest", "recovery_plan_id",
            "adopted_manifest_id", "component", "attempt_artifact_id",
            "authorization_id", "authorization_artifact_id",
            "authorization_digest", "continuation_run_id", "published",
            "public_state",
        },
        f"transition {artifact_id}",
    )
    component = document["component"]
    if (
        document["schema"] != "aweb.release.adopted-preplan-transition.v1"
        or document["provenance"] != "adopted-preplan"
        or document["exception_digest"] != handle.exception.digest
        or document["recovery_plan_id"] != handle.plan_id
        or document["adopted_manifest_id"] != handle.manifest_id
        or component not in handle.exception.components
    ):
        raise ReceiptError(f"{artifact_id}: transition binding mismatch")
    attempt_id = document["attempt_artifact_id"]
    if not isinstance(attempt_id, str) or not attempt_id.startswith(
        _record_prefix("attempt", handle, component)
    ):
        raise ReceiptError(f"{artifact_id}: transition attempt id mismatch")
    attempt = _load_canonical_authority_document(
        store, authority, attempt_id
    )
    _validate_attempt_record(handle, attempt_id, attempt, store, authority)
    for field_name in (
        "authorization_id", "authorization_artifact_id",
        "authorization_digest",
    ):
        if document[field_name] != attempt[field_name]:
            raise ReceiptError(
                f"{artifact_id}: transition {field_name} differs from attempt"
            )
    _nonempty_text(
        document["continuation_run_id"],
        f"{artifact_id} continuation run id",
    )
    if document["public_state"] != _expected_final_public(
        handle.exception, component
    ):
        raise ReceiptError(f"{artifact_id}: transition public state is not exact")
    published = _entry_from_document(document["published"])
    spec = handle.exception.components[component]
    if (
        published.version != spec["version"]
        or published.digest_set != spec["payload_digests"]
        or published.digest != canonical_digest_of_set(spec["payload_digests"])
        or published.lane_ref != spec["lane_ref"]
    ):
        raise ReceiptError(f"{artifact_id}: transition entry differs from stage")


def _successful_transitions(handle, store, authority) -> dict[str, tuple[str, dict]]:
    found = {}
    for component in handle.exception.components:
        records = _records_with_prefix(
            store, authority, _record_prefix("transition", handle, component)
        )
        if len(records) > 1:
            raise ReceiptError(
                f"{component}: multiple successful recovery transitions exist"
            )
        if records:
            artifact_id, document = records[0]
            _validate_transition_record(
                handle, artifact_id, document, store, authority
            )
            found[component] = records[0]
    return found


def _attempts(handle, store, authority, component: str,
              authorization_digest: str | None = None) -> list[tuple[str, dict]]:
    records = _records_with_prefix(
        store, authority, _record_prefix("attempt", handle, component)
    )
    for artifact_id, document in records:
        _validate_attempt_record(
            handle, artifact_id, document, store, authority
        )
    records.sort(key=lambda item: (item[1]["attempt_ordinal"], item[0]))
    predecessors: list[str] = []
    for ordinal, (artifact_id, document) in enumerate(records, start=1):
        if (
            document["attempt_ordinal"] != ordinal
            or document["predecessor_attempt_artifact_ids"]
            != sorted(predecessors)
        ):
            raise ReceiptError(
                f"{artifact_id}: attempt order/predecessor binding is not a "
                "single immutable history"
            )
        predecessors.append(artifact_id)
    if authorization_digest is not None:
        records = [
            item for item in records
            if item[1].get("authorization_digest") == authorization_digest
        ]
    return records


def _require_authorization_id_continuity(
    *, handle, authorization, authorization_digest, store, authority
) -> None:
    """One human decision id has exactly one canonical byte identity.

    issued_at and other signed/recorded fields may change a document digest,
    but they must never mint a second attempt budget for the same one-shot
    authorization_id.
    """
    authorization_id = authorization["authorization_id"]
    observed: set[str] = set()
    prefix = f"adopted-preplan-authorization:{handle.plan_id}:"
    for artifact_id in authority.recorded_ids():
        if not artifact_id.startswith(prefix):
            continue
        document = _load_canonical_authority_document(
            store, authority, artifact_id
        )
        _, digest = _load_adopted_authorization(
            canonical_json_bytes(document), handle=handle
        )
        if document["authorization_id"] == authorization_id:
            observed.add(digest)
    for component in handle.exception.components:
        for _, attempt in _attempts(handle, store, authority, component):
            if attempt["authorization_id"] == authorization_id:
                observed.add(attempt["authorization_digest"])
    for _, transition in _successful_transitions(
        handle, store, authority
    ).values():
        if transition["authorization_id"] == authorization_id:
            observed.add(transition["authorization_digest"])
    conflicts = observed - {authorization_digest}
    if conflicts:
        raise ReceiptError(
            f"authorization_id {authorization_id!r} is already bound to "
            f"different canonical bytes/digest(s) {sorted(conflicts)}; a "
            "spent one-shot decision requires a genuinely distinct id"
        )


def _anchor_recovery_transition(
    *, handle, component, continuation, attempt_id, authorization,
    authorization_digest, public, store, authority,
) -> tuple[str, dict]:
    document = {
        "schema": "aweb.release.adopted-preplan-transition.v1",
        "provenance": "adopted-preplan",
        "exception_digest": handle.exception.digest,
        "recovery_plan_id": handle.plan_id,
        "adopted_manifest_id": handle.manifest_id,
        "component": component,
        "attempt_artifact_id": attempt_id,
        "authorization_id": authorization["authorization_id"],
        "authorization_artifact_id": (
            f"adopted-preplan-authorization:{handle.plan_id}:"
            f"{authorization_digest}"
        ),
        "authorization_digest": authorization_digest,
        "continuation_run_id": continuation.continuation_run_id,
        "published": _entry_document(continuation.entry),
        "public_state": public,
    }
    data = canonical_json_bytes(document)
    digest = hashlib.sha256(data).hexdigest()
    artifact_id = (
        _record_prefix("transition", handle, component) + digest
    )
    _put_content_addressed(store, authority, artifact_id, data, digest)
    return artifact_id, document


def _recover_existing_attempt(
    *, handle, component, attempt_id, attempt, lanes, graph, store, authority,
) -> tuple[str, dict]:
    node = PlanNode(
        component=component, reason="adopted-preplan",
        version=handle.exception.components[component]["version"],
    )
    observed = _observe_recovery_component(
        lanes, node, handle.staged[component], handle.exception, graph
    )
    initial = handle.exception.canonical["observed_partial_state"][component]
    final = _expected_final_public(handle.exception, component)
    try:
        continuation = lanes.recover_recovery_attempt(
            node, handle.staged[component],
            before_run_ids=attempt["continuation_run_ids_before"],
            attempt_artifact_id=attempt_id,
        )
    except ReceiptError as exc:
        raise ReceiptError(
            f"{component}: authorization action is spent; its prior attempt "
            f"cannot be inherited ({exc})"
        ) from exc
    if observed.public == initial and continuation is None:
        raise ReceiptError(
            f"{component}: authorization action is spent by an anchored "
            "attempt with no exact completed effect"
        )
    if observed.public != final or continuation is None:
        raise ReceiptError(
            f"{component}: attempted action left unrelated/partial drift; "
            "same authorization cannot dispatch again"
        )
    if not isinstance(continuation, RecoveryContinuation):
        raise ReceiptError(f"{component}: recovery adapter returned no run identity")
    if continuation.attempt_artifact_id != attempt_id:
        raise ReceiptError(
            f"{component}: recovered run evidence belongs to a different attempt"
        )
    if continuation.entry != observed.entry:
        raise ReceiptError(
            f"{component}: recovered run entry differs from public observation"
        )
    return _anchor_recovery_transition(
        handle=handle, component=component, continuation=continuation,
        attempt_id=attempt_id,
        authorization={
            "authorization_id": attempt["authorization_id"]
        },
        authorization_digest=attempt["authorization_digest"],
        public=observed.public, store=store, authority=authority,
    )


def execute_adopted_preplan_recovery(
    handle: AdoptedPreplanHandle,
    authorization_bytes: bytes,
    *,
    graph: Graph,
    lanes,
    store,
    authority,
    authority_trust: str,
    approvals: dict[str, Approval],
) -> AdoptedPreplanReceipt:
    """Run only unused authorized actions, persisting intent first.

    A crash can adopt one exact successful run. An anchored attempt with no
    exact success spends that authorization action and is never redispatched.
    """
    if authority_trust != "external-immutable":
        raise ReceiptError(
            "adopted-preplan execution requires external-immutable authority"
        )
    anchored_exception = _load_canonical_authority_document(
        store, authority, handle.exception_artifact_id
    )
    anchored_plan = _load_canonical_authority_document(
        store, authority, handle.plan_artifact_id
    )
    anchored_manifest = _load_canonical_authority_document(
        store, authority, handle.manifest_artifact_id
    )
    if anchored_exception != handle.exception.canonical:
        raise ReceiptError("recovery handle exception differs from authority")
    if anchored_plan != handle.plan:
        raise ReceiptError("recovery handle plan differs from authority")
    if anchored_manifest != handle.manifest:
        raise ReceiptError("recovery handle adopted manifest differs from authority")
    if (
        anchored_plan.get("schema") != ADOPTED_PREPLAN_PLAN_SCHEMA
        or anchored_plan.get("provenance") != "adopted-preplan"
        or anchored_manifest.get("schema") != ADOPTED_PREPLAN_MANIFEST_SCHEMA
        or anchored_manifest.get("provenance") != "adopted-preplan"
    ):
        raise ReceiptError("anchored recovery plan/manifest provenance is invalid")
    authorization, authorization_digest = _load_adopted_authorization(
        authorization_bytes, handle=handle
    )
    authorization_artifact_id = (
        f"adopted-preplan-authorization:{handle.plan_id}:"
        f"{authorization_digest}"
    )
    _require_authorization_id_continuity(
        handle=handle,
        authorization=authorization,
        authorization_digest=authorization_digest,
        store=store,
        authority=authority,
    )
    actions = {item["component"]: item for item in authorization["actions"]}

    # First recover any exact effect whose transition anchor was the crash
    # window. Prefer the current authorization but do not strand an exact
    # effect made by an older one-shot attempt.
    transitions = _successful_transitions(handle, store, authority)
    for component in handle.exception.components:
        if component in transitions:
            continue
        observed = _observe_recovery_component(
            lanes,
            PlanNode(
                component=component, reason="adopted-preplan",
                version=handle.exception.components[component]["version"],
            ),
            handle.staged[component], handle.exception, graph,
        )
        initial = handle.exception.canonical[
            "observed_partial_state"
        ][component]
        if initial["registry"]["status"] == "exact":
            if observed.public != initial:
                raise ReceiptError(f"{component}: adopted exact state drifted")
            continue
        attempts = _attempts(handle, store, authority, component)
        current = [
            item for item in attempts
            if (
                item[1].get("authorization_id")
                == authorization["authorization_id"]
                and item[1].get("authorization_digest")
                == authorization_digest
            )
        ]
        if len(current) > 1:
            raise ReceiptError(
                f"{component}: authorization has multiple attempt records"
            )
        if current and current[0][0] != attempts[-1][0]:
            raise ReceiptError(
                f"{component}: current authorization attempt was irrevocably "
                "superseded by a later anchored attempt"
            )
        if observed.public == _expected_final_public(handle.exception, component):
            if len(current) != 1:
                raise ReceiptError(
                    f"{component}: exact effect has no unique persisted attempt "
                    "for the current authorization"
                )
            transitions[component] = _recover_existing_attempt(
                handle=handle, component=component,
                attempt_id=current[0][0], attempt=current[0][1],
                lanes=lanes, graph=graph, store=store, authority=authority,
            )
        elif current:
            # Even a known failed run is not permission to dispatch again.
            _recover_existing_attempt(
                handle=handle, component=component,
                attempt_id=current[0][0], attempt=current[0][1],
                lanes=lanes, graph=graph, store=store, authority=authority,
            )
        elif observed.public != initial:
            raise ReceiptError(
                f"{component}: public state drifted outside initial/final states"
            )

    transitions = _successful_transitions(handle, store, authority)
    required = {
        component
        for component, state in handle.exception.canonical[
            "observed_partial_state"
        ].items()
        if state["registry"]["status"] == "absent"
        and component not in transitions
    }
    for component in required:
        if component not in actions:
            raise ReceiptError(
                f"authorization omits still-permitted action {component}"
            )
    for component in actions:
        if component in required:
            continue
        transition = transitions.get(component)
        if (
            transition is None
            or transition[1].get("authorization_digest") != authorization_digest
        ):
            raise ReceiptError(
                f"authorization names action {component} which is not remaining "
                "or already completed by this same one-shot authorization"
            )

    for component in handle.exception.components:
        if graph.components[component].approval_required:
            require_approval(
                PlanNode(component=component, reason="adopted-preplan"),
                approval=approvals.get(component),
            )

    # The complete action set and every graph approval are valid and exact.
    # Anchor these authorization bytes before the first attempt or effect.
    _put_content_addressed(
        store, authority, authorization_artifact_id,
        authorization_bytes, authorization_digest,
    )

    for component in handle.exception.components:
        if component not in required:
            continue
        node = PlanNode(
            component=component, reason="adopted-preplan",
            version=handle.exception.components[component]["version"],
        )
        # Recheck the whole targeted state before each outward call. A prior
        # completed component may move only to its exact final identity; every
        # untouched component remains exactly as frozen.
        for other in handle.exception.components:
            other_observed = _observe_recovery_component(
                lanes,
                PlanNode(
                    component=other, reason="adopted-preplan",
                    version=handle.exception.components[other]["version"],
                ),
                handle.staged[other], handle.exception, graph,
            )
            expected = (
                _expected_final_public(handle.exception, other)
                if other in transitions
                else handle.exception.canonical[
                    "observed_partial_state"
                ][other]
            )
            if other_observed.public != expected:
                raise ReceiptError(
                    f"{other}: public state drifted before {component} effect"
                )

        before = lanes.continuation_snapshot(node)
        if (
            not isinstance(before, list)
            or len(before) > 1
            or len(set(before)) != len(before)
            or not all(isinstance(item, str) and item for item in before)
        ):
            raise ReceiptError(
                f"{component}: continuation snapshot is not one high-water run id"
            )
        predecessor_attempts = _attempts(
            handle, store, authority, component
        )
        attempt = {
            "schema": "aweb.release.adopted-preplan-attempt.v1",
            "provenance": "adopted-preplan",
            "exception_digest": handle.exception.digest,
            "recovery_plan_id": handle.plan_id,
            "adopted_manifest_id": handle.manifest_id,
            "component": component,
            "authorization_id": authorization["authorization_id"],
            "authorization_artifact_id": authorization_artifact_id,
            "authorization_digest": authorization_digest,
            "action": actions[component],
            "attempt_ordinal": len(predecessor_attempts) + 1,
            "predecessor_attempt_artifact_ids": sorted(
                artifact_id for artifact_id, _ in predecessor_attempts
            ),
            "continuation_run_ids_before": list(before),
            "public_state_before": handle.exception.canonical[
                "observed_partial_state"
            ][component],
        }
        attempt_data = canonical_json_bytes(attempt)
        attempt_digest = hashlib.sha256(attempt_data).hexdigest()
        attempt_id = _record_prefix("attempt", handle, component) + attempt_digest
        _put_content_addressed(
            store, authority, attempt_id, attempt_data, attempt_digest
        )

        # This is the sole outward continuation call. The authority already
        # contains exact intent and the pre-dispatch run snapshot.
        continuation = lanes.publish_recovery(
            node, handle.staged[component], before_run_ids=before,
            attempt_artifact_id=attempt_id,
        )
        if not isinstance(continuation, RecoveryContinuation):
            raise ReceiptError(
                f"{component}: continuation returned no typed run receipt"
            )
        _nonempty_text(
            continuation.continuation_run_id,
            f"{component} continuation run id",
        )
        if continuation.attempt_artifact_id != attempt_id:
            raise ReceiptError(
                f"{component}: continuation run evidence belongs to a "
                "different attempt"
            )
        observed = _observe_recovery_component(
            lanes, node, handle.staged[component], handle.exception, graph
        )
        if observed.public != _expected_final_public(
            handle.exception, component
        ) or observed.entry != continuation.entry:
            raise ReceiptError(
                f"{component}: continuation did not leave the exact staged "
                "bytes and tag"
            )
        transitions[component] = _anchor_recovery_transition(
            handle=handle, component=component, continuation=continuation,
            attempt_id=attempt_id, authorization=authorization,
            authorization_digest=authorization_digest,
            public=observed.public, store=store, authority=authority,
        )

    transitions = _successful_transitions(handle, store, authority)
    component_receipts = {}
    for component, spec in handle.exception.components.items():
        node = PlanNode(
            component=component, reason="adopted-preplan", version=spec["version"]
        )
        initial = handle.exception.canonical[
            "observed_partial_state"
        ][component]
        transition = transitions.get(component)
        if initial["registry"]["status"] == "exact":
            observed = _observe_recovery_component(
                lanes, node, handle.staged[component], handle.exception, graph
            )
            if observed.public != initial or observed.entry is None:
                raise ReceiptError(f"{component}: adopted exact state no longer matches")
            published = observed.entry
            attempt_id = None
            run_id = None
            component_authorization_id = None
            component_authorization_digest = None
        else:
            if transition is None:
                raise ReceiptError(f"{component}: no successful transition receipt")
            attempt_id, transition_document = (
                transition[1]["attempt_artifact_id"], transition[1]
            )
            run_id = transition_document["continuation_run_id"]
            component_authorization_id = transition_document["authorization_id"]
            component_authorization_digest = transition_document[
                "authorization_digest"
            ]
            published = _entry_from_document(transition_document["published"])
        lanes.verify(node, published)
        final = _observe_recovery_component(
            lanes, node, handle.staged[component], handle.exception, graph
        )
        if final.public != _expected_final_public(handle.exception, component):
            raise ReceiptError(f"{component}: final state is not exact")
        component_receipts[component] = {
            "stage": {
                "provenance": "adopted-preplan",
                "lane_ref": spec["lane_ref"],
                "manifest_digest": spec["manifest_digest"],
                "payload_digests": spec["payload_digests"],
            },
            "initial_state": initial,
            "attempt_artifact_id": attempt_id,
            "authorization_id": component_authorization_id,
            "authorization_digest": component_authorization_digest,
            "continuation_run_id": run_id,
            "published": _entry_document(published),
            "final_state": final.public,
        }

    # One last joint observation closes races between per-component verifies.
    # The receipt is not sealed from two observations made at different final
    # states.
    for component, spec in handle.exception.components.items():
        final = _observe_recovery_component(
            lanes,
            PlanNode(
                component=component, reason="adopted-preplan",
                version=spec["version"],
            ),
            handle.staged[component], handle.exception, graph,
        )
        if (
            final.public != _expected_final_public(handle.exception, component)
            or _entry_document(final.entry)
            != component_receipts[component]["published"]
        ):
            raise ReceiptError(
                f"{component}: final joint observation drifted before receipt"
            )

    receipt = {
        "schema": ADOPTED_PREPLAN_RECEIPT_SCHEMA,
        "provenance": "adopted-preplan",
        "exception_artifact_id": handle.exception_artifact_id,
        "exception_digest": handle.exception.digest,
        "recovery_plan_artifact_id": handle.plan_artifact_id,
        "recovery_plan_id": handle.plan_id,
        "adopted_manifest_artifact_id": handle.manifest_artifact_id,
        "adopted_manifest_id": handle.manifest_id,
        "authorization_id": authorization["authorization_id"],
        "authorization_artifact_id": authorization_artifact_id,
        "authorization_digest": authorization_digest,
        "source_sha": handle.exception.source_sha,
        "history": handle.exception.history,
        "attempt_history": {
            component: [artifact_id for artifact_id, _ in _attempts(
                handle, store, authority, component
            )]
            for component in handle.exception.components
        },
        "components": component_receipts,
        "support": {
            "status": "incomplete-unmeasured",
            "runtime_edge_ids": [
                edge["edge_id"] for edge in handle.exception.runtime_edges
            ],
        },
    }
    receipt_data = canonical_json_bytes(receipt)
    digest = hashlib.sha256(receipt_data).hexdigest()
    artifact_id = f"adopted-preplan-receipt:{handle.plan_id}:{digest}"
    _put_content_addressed(
        store, authority, artifact_id, receipt_data, digest
    )
    return AdoptedPreplanReceipt(
        document=receipt, digest=digest, artifact_id=artifact_id
    )


def load_adopted_preplan_receipt(
    data: bytes, *, expected_digest: str, handle: AdoptedPreplanHandle
) -> dict:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ReceiptError(
            "adopted-preplan receipt bytes do not match authority digest"
        )
    try:
        receipt = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"adopted-preplan receipt is not JSON: {exc}") from exc
    if canonical_json_bytes(receipt) != data:
        raise ReceiptError("adopted-preplan receipt is not canonical JSON")
    _exact_keys(
        receipt,
        {
            "schema", "provenance", "exception_artifact_id",
            "exception_digest", "recovery_plan_artifact_id",
            "recovery_plan_id", "adopted_manifest_artifact_id",
            "adopted_manifest_id", "authorization_id",
            "authorization_artifact_id", "authorization_digest",
            "source_sha", "history", "attempt_history", "components",
            "support",
        },
        "adopted-preplan receipt",
    )
    if receipt.get("schema") != ADOPTED_PREPLAN_RECEIPT_SCHEMA:
        raise ReceiptError("wrong adopted-preplan receipt schema")
    if (
        receipt.get("provenance") != "adopted-preplan"
        or receipt.get("exception_digest") != handle.exception.digest
        or receipt.get("recovery_plan_id") != handle.plan_id
        or receipt.get("adopted_manifest_id") != handle.manifest_id
        or receipt.get("source_sha") != handle.exception.source_sha
    ):
        raise ReceiptError("adopted-preplan receipt binding mismatch")
    support = receipt.get("support")
    if not isinstance(support, dict) or set(support) != {
        "status", "runtime_edge_ids"
    }:
        raise ReceiptError("adopted-preplan receipt support shape is not closed")
    if support["status"] != "incomplete-unmeasured":
        raise ReceiptError(
            "adopted-preplan receipt may never claim measured support"
        )
    if support["runtime_edge_ids"] != [
        edge["edge_id"] for edge in handle.exception.runtime_edges
    ]:
        raise ReceiptError("adopted-preplan receipt edge identities differ")
    if receipt["history"] != handle.exception.history:
        raise ReceiptError("adopted-preplan receipt rewrites exception history")
    attempt_history = receipt["attempt_history"]
    if not isinstance(attempt_history, dict) or set(attempt_history) != set(
        handle.exception.components
    ):
        raise ReceiptError("adopted-preplan receipt attempt history differs")
    for component, artifact_ids in attempt_history.items():
        if (
            not isinstance(artifact_ids, list)
            or len(artifact_ids) != len(set(artifact_ids))
            or not all(
                isinstance(item, str) and item.startswith(
                    _record_prefix("attempt", handle, component)
                )
                for item in artifact_ids
            )
        ):
            raise ReceiptError(
                f"{component}: receipt attempt history is not exact identities"
            )
    if set(receipt.get("components", {})) != set(handle.exception.components):
        raise ReceiptError("adopted-preplan receipt component set differs")
    graph = Graph.from_dict(handle.plan["graph"])
    for component, spec in handle.exception.components.items():
        record = receipt["components"][component]
        _exact_keys(
            record,
            {
                "stage", "initial_state", "attempt_artifact_id",
                "authorization_id", "authorization_digest",
                "continuation_run_id", "published", "final_state",
            },
            f"{component} recovery receipt",
        )
        stage = record["stage"]
        _exact_keys(
            stage,
            {
                "provenance", "lane_ref", "manifest_digest",
                "payload_digests",
            },
            f"{component} receipt stage",
        )
        if stage != {
            "provenance": "adopted-preplan",
            "lane_ref": spec["lane_ref"],
            "manifest_digest": spec["manifest_digest"],
            "payload_digests": spec["payload_digests"],
        }:
            raise ReceiptError(
                f"{component}: receipt stage is not the exact adopted-preplan "
                "exception evidence"
            )
        initial = handle.exception.canonical[
            "observed_partial_state"
        ][component]
        if record["initial_state"] != initial:
            raise ReceiptError(f"{component}: receipt initial state changed")
        if record["final_state"] != _expected_final_public(
            handle.exception, component
        ):
            raise ReceiptError(f"{component}: receipt final state is not exact")
        published = _entry_from_document(record["published"])
        if (
            published.version != spec["version"]
            or published.digest_set != spec["payload_digests"]
            or published.digest != canonical_digest_of_set(
                spec["payload_digests"]
            )
            or published.lane_ref != spec["lane_ref"]
        ):
            raise ReceiptError(
                f"{component}: receipt published entry differs from adopted stage"
            )
        if initial["registry"]["status"] == "absent":
            _nonempty_text(
                record["attempt_artifact_id"],
                f"{component} attempt artifact id",
            )
            _nonempty_text(
                record["authorization_id"],
                f"{component} authorization id",
            )
            _sha256_identity(
                record["authorization_digest"],
                f"{component} authorization digest", prefix=False,
            )
            _nonempty_text(
                record["continuation_run_id"],
                f"{component} continuation run id",
            )
        elif any(
            record[field] is not None
            for field in (
                "attempt_artifact_id", "authorization_id",
                "authorization_digest", "continuation_run_id",
            )
        ):
            raise ReceiptError(
                f"{component}: already-exact adoption cannot claim a continuation"
            )
        obligation = _delivery_obligation(graph, component)
        if obligation is not None:
            validate_delivery_proof(
                published.delivery_proof, obligation, component
            )
    return receipt


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
            if lane_ref.get("kind") == "local-runnerless":
                if set(lane_ref) != {
                    "kind", "stage", "source_sha", "manifest_sha256"
                }:
                    raise ReceiptError(
                        f"{name}: local runnerless lane reference is malformed"
                    )
            else:
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


TRANSITION_FIELDS = (
    "frozen_plan_id", "staged_manifest_id", "sequence", "component", "kind",
    "entry",
)
TRANSITION_ENTRY_FIELDS = (
    "version", "digest", "phase", "pointer_state", "delivery_proof",
    "lane_ref", "digest_set",
)


def validate_transition_document(document) -> dict:
    """The exact shape anchor_transition seals. One definition, used both when
    sealing and when re-validating an archived transition, so an archived
    transition cannot be accepted in a shape the driver would never write."""
    if not isinstance(document, dict) or set(document) != set(TRANSITION_FIELDS):
        present = set(document) if isinstance(document, dict) else set()
        raise ReceiptError(
            "transition document does not carry exactly "
            f"{sorted(TRANSITION_FIELDS)}; missing "
            f"{sorted(set(TRANSITION_FIELDS) - present)}, unexpected "
            f"{sorted(present - set(TRANSITION_FIELDS))}"
        )
    if not isinstance(document["sequence"], int) or isinstance(
        document["sequence"], bool
    ):
        raise ReceiptError("transition sequence must be an integer")
    for field in ("frozen_plan_id", "staged_manifest_id", "component", "kind"):
        value = document[field]
        if not isinstance(value, str) or not value:
            raise ReceiptError(
                f"transition {field} must be a nonempty string"
            )
    entry = document["entry"]
    if not isinstance(entry, dict) or set(entry) != set(
        TRANSITION_ENTRY_FIELDS
    ):
        present = set(entry) if isinstance(entry, dict) else set()
        raise ReceiptError(
            "transition entry does not carry exactly "
            f"{sorted(TRANSITION_ENTRY_FIELDS)}; missing "
            f"{sorted(set(TRANSITION_ENTRY_FIELDS) - present)}, unexpected "
            f"{sorted(present - set(TRANSITION_ENTRY_FIELDS))}"
        )
    if not isinstance(entry["version"], str) or not entry["version"]:
        raise ReceiptError("transition entry version must be a nonempty string")
    return document


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
    allowed_published_transitions: dict | None = None,
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
    allowed_published = allowed_published_transitions or {}
    for section in ("pins", "baselines", "tags", "measurements",
                    "runtime_published"):
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
            if (
                section == "runtime_published"
                and key in skip_components
                and current_section.get(key) == allowed_published.get(key)
            ):
                # A resumed-published endpoint transitions to EXACTLY its
                # plan candidate version; anything else is drift.
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
            if plan.runtime_contract_edges and state is not None:
                endpoints = sorted({
                    name for e in plan.runtime_contract_edges
                    for name in (e.a, e.b)
                })
                current["runtime_published"] = {
                    name: state.published_version(graph.components[name])
                    if name in graph.components else None
                    for name in endpoints
                }
            current["measurements"] = {
                edge_identity(e): measurement.resolve(
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
        allowed_published = {
            n.component: n.version
            for n in plan.moving
            if n.component in skip_components and n.version is not None
        }
        drift = _frozen_drift(
            frozen.resolved, current, skip_components,
            allowed_tag_transitions=allowed_tags,
            allowed_published_transitions=allowed_published,
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
    runnerless_risk = providers.runnerless_risk if providers is not None else None
    defer_g5 = bool(providers.defer_g5) if providers is not None else False
    if authority_trust == "local-runnerless" and runnerless_risk is None:
        raise ReceiptError(
            "runnerless local authority requires explicit risk authorization"
        )
    g5_authorization = providers.g5_authorization if providers is not None else None
    require_runtime_support(
        plan,
        defer_g5=defer_g5,
        authorization=g5_authorization,
        source_sha=source_sha,
        frozen_plan_id=frozen.frozen_id if frozen is not None else None,
    )
    complete_edges = [
        e for e in plan.runtime_contract_edges if not e.declared_incomplete
    ]
    # Deferral partitions the edge set: it excuses only the incomplete edges an
    # authorization names. A measured edge is never skipped, because nothing was
    # deferred about it - its measurement exists and must still resolve. Gating
    # this on defer_g5 let one accepted gap switch off every measured matrix in
    # the same plan, and on a complete-only plan a bare flag switched them off
    # with no authorization involved at all.
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
    # Same partition for the matrices: a deferred incomplete edge has no matrix
    # to run, but every complete edge still needs one.
    missing_skew = [
        f"{e.a}<->{e.b}"
        for e in plan.runtime_contract_edges
        if not (defer_g5 and e.declared_incomplete) and not skew.has_matrix(e)
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

    # Re-checked against the frozen id that now exists. The earlier call runs
    # before any work so a missing or wrong-risk record refuses early, but on
    # the path that freezes here there was no id to bind to yet, so the plan
    # binding it claimed to check was not checked at all.
    require_runtime_support(
        plan,
        defer_g5=defer_g5,
        authorization=g5_authorization,
        source_sha=source_sha,
        frozen_plan_id=frozen_plan_id,
    )

    if _resume_manifest is not None:
        manifest = _resume_manifest
        manifest_id = manifest["_artifact_id"]
        manifest_digest = manifest_id.rsplit(":", 1)[-1]
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_digest):
            raise ReceiptError(
                "resumed staged-manifest identity carries no exact digest"
            )
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

    if not defer_g5:
        freeze_matrix = getattr(skew, "freeze_matrix", None)
        if freeze_matrix is not None:
            for edge in plan.runtime_contract_edges:
                freeze_matrix(
                    edge, staged, staged_manifest_digest=manifest_digest
                )
        for edge in plan.runtime_contract_edges:
            skew.execute(edge, staged)

    def anchor_transition(
        component: str, entry: ReceiptEntry, sequence: int, kind: str
    ) -> None:
        document = {
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
        }
        # The sealing path validates the same shape the archive re-validates,
        # so a transition can never be written in a form restore would refuse.
        validate_transition_document(document)
        body = json.dumps(document, sort_keys=True).encode()
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

    receipt_approvals = dict(approvals)
    if runnerless_risk is not None:
        receipt_approvals["runnerless-local-authority"] = runnerless_risk
        for component, metadata in getattr(
            lanes, "receipt_metadata", lambda: {}
        )().items():
            if metadata.get("status") == "deferred":
                receipt_approvals[f"deferred-hosting:{component}"] = Approval(
                    who=runnerless_risk.who,
                    when=runnerless_risk.when,
                    risk=(
                        "registry published exact staged bytes; hosting "
                        "continuation deferred: "
                        f"{metadata.get('continuation') or 'tag-and-release'}"
                    ),
                )
    sealed, digest = seal_receipt(
        plan,
        graph,
        source_sha=source_sha,
        entries=verified,
        approvals=receipt_approvals,
        frozen_plan_id=frozen_plan_id,
        staged_manifest_id=manifest_id,
        g5_authorization=g5_authorization,
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
    runnerless_risk: Approval | None = None,
    defer_g5: bool = False,
    g5_authorization=None,
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
            store=store, authority=authority, measurement=measurement,
            authority_trust=authority_trust,
            runnerless_risk=runnerless_risk,
            defer_g5=defer_g5,
            g5_authorization=g5_authorization,
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


def _pointer_repository(component: Component) -> str:
    """Where the pointer lives, for refusal messages. ac-pin names it on its
    sibling pins; marketplace-pointer declares it directly."""
    for pin in component.sibling_pins:
        repository = pin.get("pin_repository")
        if repository:
            return repository
    return (component.lane or {}).get("repository") or component.name


def parse_pointer_adapters(raw: list[str], *, plan: Plan, graph: Graph) -> dict:
    """component=/absolute/pointer-adapter -> {component: PointerLane}.

    What each pointer advertises is derived from the plan, never supplied on
    the command line: an operator who could type the version could advertise a
    version the release did not publish.
    """
    updates = pointer_updates(plan, graph)
    lanes = {}
    for item in raw:
        component, separator, executable = item.partition("=")
        if not separator or not component or not Path(executable).is_absolute():
            raise ReceiptError(
                "--pointer-adapter must be component=/absolute/path/to/adapter"
            )
        if component in lanes:
            raise ReceiptError(f"duplicate pointer adapter for {component}")
        if component not in graph.components:
            raise ReceiptError(f"--pointer-adapter names unknown component {component}")
        lanes[component] = PointerLane(
            component,
            adapter=SubprocessPointerAdapter(Path(executable)),
            updates=updates.get(component, {}),
            repository=_pointer_repository(graph.components[component]),
        )
    return lanes


def parse_local_adapters(raw: list[str], *, root: Path):
    lanes = {}
    for item in raw:
        identity, separator, executable = item.partition("=")
        component, at, source_sha = identity.partition("@")
        if (
            not separator or not at or not component
            or not re.fullmatch(r"[0-9a-f]{40}", source_sha)
            or not Path(executable).is_absolute()
        ):
            raise ReceiptError(
                "--local-adapter must be "
                "component@<40-hex-reviewed-source>=/absolute/path/to/adapter"
            )
        if component in lanes:
            raise ReceiptError(f"duplicate local adapter for {component}")
        lanes[component] = LocalRunnerlessLane(
            component, root, SubprocessLocalAdapter(Path(executable)), source_sha
        )
    return WorkflowLanes(lanes)


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
        kind="local-runnerless",
        trust_class="local-runnerless",
        factory=None,
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


def ship_gate_warning(source_sha: str) -> dict:
    """Informational only: GitHub absence/outage can never block a release."""
    try:
        result = subprocess.run(
            [
                "gh", "run", "list", "--workflow", "ship.yml",
                "--commit", source_sha, "--limit", "1",
                "--json", "conclusion,url",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return {"status": "unknown", "detail": result.stderr.strip()}
        runs = json.loads(result.stdout)
        if not runs:
            return {"status": "none", "detail": "no ship.yml run found"}
        conclusion = runs[0].get("conclusion")
        return {
            "status": "success" if conclusion == "success" else "failure",
            "detail": conclusion or "incomplete",
            "url": runs[0].get("url"),
        }
    except Exception as exc:  # informational warning, never a gate
        return {"status": "unknown", "detail": str(exc)}


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
        "--local-adapter", action="append", default=[],
        help="runnerless component@reviewed-source=/absolute/direct-adapter",
    )
    run_parser.add_argument(
        "--local-risk-authorization",
        help="one explicit who,when,risk record selecting local authority",
    )
    run_parser.add_argument(
        "--defer-g5", action="store_true",
        help="record an explicit human-authorized G5 deferral",
    )
    run_parser.add_argument(
        "--pointer-adapter", action="append", default=[],
        help=(
            "component=/absolute/pointer-adapter - performs the pointer effect "
            "(edit, commit, push, read back) in the target repository"
        ),
    )
    run_parser.add_argument(
        "--g5-authorization",
        help=(
            "who=<w>,when=<t>,source=<40hex>,plan=<64hex>,"
            "edges=<64hex>[+<64hex>],risk=<text> - edge ids as printed by "
            "release-plan; accepted on every authority"
        ),
    )
    run_parser.add_argument(
        "--manifest-id",
        help="explicit full staged-manifest artifact id for resume binding",
    )
    run_parser.add_argument(
        "--delivery-proof",
        action="append",
        default=[],
        help="component=<name>,obligation=<type>,evidence_id=<id>,"
        "digest=<digest> - separately supplied structured delivery evidence",
    )
    run_parser.add_argument(
        "--stage-artifact",
        action="append",
        default=[],
        help="component=<name>,ref=gh-artifact:<repo>:<run>:<artifact>,"
        "source=<lane source sha>,digest=sha256:<artifact zip digest>",
    )
    recovery_parser = sub.add_parser(
        "adopted-preplan-recovery",
        help="recover exactly two preserved pre-plan stages through the "
        "dedicated one-shot state machine (never ordinary release-run)",
    )
    recovery_parser.add_argument("--exception-file", required=True)
    recovery_parser.add_argument("--authorization-file", required=True)
    recovery_parser.add_argument("--approval", action="append", default=[])
    recovery_parser.add_argument(
        "--delivery-proof",
        action="append",
        default=[],
        help="component=<name>,obligation=<type>,evidence_id=<id>,digest=<digest>",
    )
    matrix_parser = sub.add_parser(
        "skew-matrix",
        help="compute (and with --execute run) the frozen plan's "
        "touched-edge skew matrix",
    )
    matrix_parser.add_argument("--plan-id", required=True)
    matrix_parser.add_argument("--plan-artifact-id", required=True)
    matrix_parser.add_argument("--manifest-id")
    matrix_parser.add_argument("--execute", action="store_true")
    receipt_parser = sub.add_parser("release-receipt")
    receipt_parser.add_argument("--artifact-id", required=True)
    receipt_parser.add_argument("--plan-id", required=True)
    receipt_parser.add_argument("--plan-artifact-id", required=True)
    args = parser.parse_args(argv)

    graph = Graph.load(Path(args.graph))
    recovery_exception = None
    if args.verb == "adopted-preplan-recovery":
        try:
            recovery_exception = load_adopted_preplan_exception(
                Path(args.exception_file).read_bytes(), graph=graph
            )
        except (OSError, ReceiptError) as exc:
            print(f"BLOCKED: {exc}")
            return 1
    if (
        providers is not None
        and providers.measurement is None
        and providers.authority_trust == "external-immutable"
    ):
        providers.measurement = AnchoredMeasurementAuthority(
            store=providers.store, authority=providers.authority
        )
    if providers is None:
        root = Path(args.store_root)
        root.mkdir(parents=True, exist_ok=True)
        registration = AUTHORITY_ALLOWLIST[args.authority]
        if registration.kind in {"local-development", "local-runnerless"}:
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
            refs = (
                {
                    name: LaneRef.from_dict(spec["lane_ref"])
                    for name, spec in recovery_exception.components.items()
                }
                if recovery_exception is not None
                else parse_stage_artifact_arguments(
                    getattr(args, "stage_artifact", [])
                )
            )
            if refs:
                lanes = compose_workflow_lanes(
                    graph, refs,
                    delivery_proofs=parse_delivery_proof_arguments(
                        getattr(args, "delivery_proof", [])
                    ),
                )
        measurement = None
        if registration.trust_class == "external-immutable":
            # Production measurement resolution rides the same external
            # store/authority capabilities; there is no local fallback.
            measurement = AnchoredMeasurementAuthority(
                store=store, authority=authority
            )
        providers = Providers(
            store=store,
            authority=authority,
            lanes=lanes,
            measurement=measurement,
            authority_trust=registration.trust_class,
        )
        if args.verb in ("plan", "release-run", "skew-matrix"):
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
        # Carried on every lane, not only the runnerless one. Assigned inside
        # the runnerless branch alone, a hosted --defer-g5 reached nothing and
        # was silently ignored: the operator asked to defer, the driver did not
        # defer, and neither said so. require_runtime_support refuses a
        # deferral with no authorization record behind it, which on a hosted
        # release is a loud refusal rather than a silent no-op.
        if args.verb == "release-run":
            providers.defer_g5 = args.defer_g5
            # Authority-independent by construction: parsed here, outside the
            # runnerless branch, so hosted and local-development reach the same
            # record. Coupling it to the runner-risk authorization would make
            # accepting an outage double as accepting an unmeasured contract.
            try:
                providers.g5_authorization = parse_g5_authorization(
                    args.g5_authorization
                )
            except ReceiptError as exc:
                print(f"BLOCKED: {exc}")
                return 1
        if registration.kind == "local-runnerless" and args.verb == "release-run":
            try:
                providers.runnerless_risk = runnerless_risk_approval(
                    args.local_risk_authorization
                )
                providers.measurement = AnchoredMeasurementAuthority(
                    store=store,
                    authority=authority,
                    accepted_authorities=("local-development",),
                )
                providers.lanes = parse_local_adapters(
                    args.local_adapter,
                    root=root / "local-stages",
                )
            except ReceiptError as exc:
                print(f"BLOCKED: {exc}")
                return 1
    state = providers.state
    source_sha = providers.source_sha or "unknown"
    if source_sha != "unknown":
        providers.measurement = RepositoryMeasurementRouter(
            RepositoryMeasurementAuthority(
                repo_root=REPO_ROOT, source_sha=source_sha
            ),
            fallback=providers.measurement,
        )

    if args.verb == "adopted-preplan-recovery":
        if recovery_exception is None:
            print("BLOCKED: adopted-preplan exception did not load")
            return 1
        if providers.lanes is None:
            print("BLOCKED: adopted-preplan recovery has no composed lanes")
            return 1
        try:
            authorization_bytes = Path(args.authorization_file).read_bytes()
            handle = prepare_adopted_preplan_recovery(
                recovery_exception,
                graph=graph,
                lanes=providers.lanes,
                store=providers.store,
                authority=providers.authority,
                authority_trust=providers.authority_trust,
            )
            receipt = execute_adopted_preplan_recovery(
                handle,
                authorization_bytes,
                graph=graph,
                lanes=providers.lanes,
                store=providers.store,
                authority=providers.authority,
                authority_trust=providers.authority_trust,
                approvals=_parse_approvals(args.approval),
            )
        except (
            OSError, LaneUnavailable, ApprovalRequired, ReceiptError
        ) as exc:
            print(f"BLOCKED: {exc}")
            return 1
        print(json.dumps(receipt.document, indent=2, sort_keys=True))
        return 0

    if args.verb == "plan":
        plan = compute_plan(graph, state)
        problems = check_declared_inputs(graph, plan, state)
        frozen_id = None
        plan_artifact_id = None
        # Read back out of the sealed artifact, so what the operator is shown
        # is what was frozen rather than a second look at live state.
        disclosures: list[str] = []
        try:
            frozen_bytes, frozen_id = freeze_plan(
                plan, graph, source_sha=source_sha, state=state,
                measurement=providers.measurement,
            )
            plan_artifact_id = f"plan:{source_sha}:{frozen_id}"
            _put_content_addressed(
                providers.store, providers.authority, plan_artifact_id,
                frozen_bytes, frozen_id,
            )
            disclosures = delivery_disclosures(
                load_frozen_plan(frozen_bytes, expected_id=frozen_id).resolved
            )
        except (BlockedByDeclaredInputs, ReceiptError) as exc:
            problems.append(str(exc))
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
                            "edge_id": edge_identity(e),
                        }
                        for e in plan.runtime_contract_edges
                    ],
                    # Exactly the ids a G5 authorization must name to defer this
                    # plan. Without them an operator cannot construct the record
                    # at all: the identity is a content hash, not a display
                    # string, because a<->b would alias the two server<->server
                    # edges.
                    "deferrable_runtime_contracts": sorted(
                        edge_identity(e)
                        for e in plan.runtime_contract_edges
                        if e.declared_incomplete
                    ),
                    "declared_input_problems": problems,
                    "delivery_disclosures": disclosures,
                    "ship_gate": ship_gate_warning(source_sha),
                    "plan_digest": plan_digest(plan, graph),
                },
                indent=2,
            )
        )
        return 1 if problems else 0

    if args.verb == "skew-matrix":
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
        plan, frozen_graph = frozen.plan, frozen.graph
        try:
            candidate_ids = (
                [args.manifest_id] if args.manifest_id else [
                    a for a in providers.authority.recorded_ids()
                    if a.startswith(f"staged-manifest:{frozen.frozen_id}:")
                ]
            )
            if len(candidate_ids) != 1:
                raise ReceiptError(
                    f"{len(candidate_ids)} staged manifests are anchored for "
                    "this frozen plan; pass the explicit --manifest-id"
                )
            manifest = load_staged_manifest(
                providers.store.get(candidate_ids[0]),
                expected_digest=providers.authority.expected_digest(
                    candidate_ids[0]
                ),
            )
            validate_staged_manifest(
                manifest, plan=plan, graph=frozen_graph,
                frozen_plan_id=frozen.frozen_id, source_sha=frozen.source_sha,
            )
            staged = {
                name: ReceiptEntry(
                    version=e["version"], digest=e["digest"], phase="staged",
                    pointer_state=e.get("pointer_state"),
                    digest_set=e.get("digest_set"),
                    lane_ref=e.get("lane_ref"),
                )
                for name, e in manifest["entries"].items()
            }
            runner = build_production_skew(
                frozen, state=state, measurement=providers.measurement
            )
            frozen_measurements = frozen.resolved.get("measurements") or {}
            frozen_published = frozen.resolved.get("runtime_published") or {}
            rows = []
            for edge in plan.runtime_contract_edges:
                if edge.declared_incomplete:
                    raise ReceiptError(
                        f"runtime-contract {edge.a}<->{edge.b} is "
                        "declared-incomplete; the matrix never runs on "
                        "unmeasured support"
                    )
                cells = compute_skew_cells(
                    edge,
                    moving={n.component for n in plan.moving},
                    staged=staged,
                    support=frozen_measurements.get(edge_identity(edge)),
                    published_versions=frozen_published,
                )
                for cell in cells:
                    rows.append({
                        "edge": f"{cell.edge_a}<->{cell.edge_b}",
                        "edge_id": cell.edge_id,
                        "journey": cell.journey,
                        "artifacts": cell.artifacts,
                        "declared_direction": cell.declared_direction,
                        "direction": cell.direction,
                        "a": {"kind": cell.a_kind, **cell.a},
                        "b": {"kind": cell.b_kind, **cell.b},
                    })
                if args.execute:
                    runner.execute(edge, staged)
            print(json.dumps({"cells": rows}, indent=2, sort_keys=True))
            return 0
        except (ReceiptError, SkewUnavailable) as exc:
            print(f"BLOCKED: {exc}")
            return 1

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
        # Pointer lanes are composed here rather than with the publish lanes,
        # because what a pointer advertises is derived from the frozen plan and
        # the frozen plan is only loaded now. A pointer node without a lane is
        # the reason channel and skills could not be released at all.
        try:
            pointer_lanes = parse_pointer_adapters(
                getattr(args, "pointer_adapter", []),
                plan=plan, graph=frozen_graph,
            )
        except ReceiptError as exc:
            print(f"BLOCKED: {exc}")
            return 1
        if pointer_lanes:
            lanes = WorkflowLanes({
                **{
                    name: lanes._lanes[name]
                    for name in getattr(lanes, "_lanes", {})
                },
                **pointer_lanes,
            })
        # Ordinary production release-run composes the G5 matrix runner; a
        # touched runtime edge with no registered harness or measured
        # support REFUSES rather than silently selecting NoSkew.
        if providers.defer_g5:
            skew = NoSkew()
        elif providers.skew is not None:
            skew = providers.skew
        else:
            try:
                skew = build_production_skew(
                    frozen, state=state, measurement=providers.measurement
                )
            except ReceiptError as exc:
                print(f"BLOCKED: {exc}")
                return 1
        run_providers = Providers(
            store=providers.store,
            authority=providers.authority,
            lanes=lanes,
            skew=skew,
            state=state,
            measurement=providers.measurement,
            authority_trust=providers.authority_trust,
            runnerless_risk=providers.runnerless_risk,
            defer_g5=providers.defer_g5,
            # Carried on the ordinary path too, not only resume. Omitted here,
            # a valid operator-supplied record reached run_plan as None and the
            # release refused - the flag was threaded and the authorization it
            # requires was not.
            g5_authorization=providers.g5_authorization,
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
                    require_external_authority=(
                        providers.authority_trust != "local-runnerless"
                        and not args.allow_local_authority
                    ),
                    authority_trust=providers.authority_trust,
                    manifest_id=args.manifest_id,
                    runnerless_risk=providers.runnerless_risk,
                    defer_g5=providers.defer_g5,
                    g5_authorization=providers.g5_authorization,
                )
            else:
                run_plan(
                    plan,
                    frozen_graph,
                    providers=run_providers,
                    source_sha=source_sha,
                    approvals=_parse_approvals(args.approval),
                    state=state,
                    require_external_authority=(
                        providers.authority_trust != "local-runnerless"
                        and not args.allow_local_authority
                    ),
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
