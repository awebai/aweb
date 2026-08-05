"""Pure-logic tests for the release driver: graph validation, plan
computation with forced pointer consumers, declared-input satisfaction,
G5 declaration completeness, receipt sealing bound to an external digest,
structured approval, and lane orchestration that fails closed on
unavailable lanes. No network: state and lanes arrive through the same
provider interfaces the real driver uses, filled from fixtures.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd


def fixture_graph_dict() -> dict:
    return {
        "component": {
            "core": {
                "source_paths": ["core/"],
                "publishable": False,
            },
            "client": {
                "source_paths": ["client/"],
                "version_source": {"type": "manifest", "path": "client/version"},
                "tag_format": "client-v{version}",
                "publish_lane": {"workflow": "wf/client.yml"},
                "verify": {"command": "true"},
            },
            "plugin": {
                "source_paths": ["plugin/"],
                "version_source": {"type": "manifest", "path": "plugin/version"},
                "tag_format": "plugin-v{version}",
                "publish_lane": {"workflow": "wf/plugin.yml"},
                "verify": {"command": "true"},
            },
            "server": {
                "source_paths": ["server/"],
                "version_source": {"type": "manifest", "path": "server/version"},
                "tag_format": "server-v{version}",
                "publish_lane": {"workflow": "wf/server.yml"},
                "verify": {"command": "true"},
            },
            "cloud-pin": {
                "publishable": False,
                "credential_paths": [
                    {"env": "FIXTURE_GATE_ENV_FILE", "purpose": "migration gate"}
                ],
                "sibling_pins": [
                    {
                        "pin_file": "release-pin.toml",
                        "component": "server",
                        "checkout": "../server-src",
                        "repository": "github.com/example/server",
                    }
                ],
                "approval_required": True,
            },
            "pointer": {
                "publishable": False,
            },
        },
        "edge": [
            {"type": "bundled-build-input", "from": "core", "to": ["client", "plugin"]},
            {"type": "publication-prerequisite", "from": "client", "to": ["plugin"]},
            {"type": "pointer", "from": "plugin", "to": ["pointer"]},
            {"type": "pointer", "from": "server", "to": ["cloud-pin"]},
            {
                "type": "runtime-contract",
                "a": "client",
                "b": "server",
                "journey": "make fixture-journey",
                "artifacts": {"a": "registry:client", "b": "registry:server"},
                "direction": "both",
                "supported": {
                    "set": "measured:fixture-fleet-2026-08-01",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "measurement:fixture-fleet-2026-08-01",
                        "digest": "fixture-digest",
                    },
                    "policy": "additive-only",
                },
            },
        ],
    }


def fixture_graph() -> rd.Graph:
    return rd.Graph.from_dict(fixture_graph_dict())


class GraphValidationTests(unittest.TestCase):
    def test_unknown_edge_type_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {"a": {"source_paths": ["a/"]}},
                    "edge": [{"type": "casual-suggestion", "from": "a", "to": ["a"]}],
                }
            )
        self.assertIn("casual-suggestion", str(caught.exception))

    def test_edge_naming_unknown_component_is_refused(self) -> None:
        for edge in (
            {"type": "publication-prerequisite", "from": "a", "to": ["ghost"]},
            {"type": "pointer", "from": "a", "to": ["ghost"]},
            {"type": "bundled-build-input", "from": "ghost", "to": ["a"]},
        ):
            with self.assertRaises(rd.GraphError) as caught:
                rd.Graph.from_dict(
                    {"component": {"a": {"source_paths": ["a/"]}}, "edge": [edge]}
                )
            self.assertIn("ghost", str(caught.exception))

    def test_sibling_pin_naming_unknown_component_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {
                            "source_paths": ["a/"],
                            "sibling_pins": [
                                {
                                    "pin_file": "p.toml",
                                    "component": "ghost",
                                    "checkout": "../x",
                                }
                            ],
                        }
                    }
                }
            )
        self.assertIn("ghost", str(caught.exception))

    def test_prerequisite_cycle_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {"source_paths": ["a/"]},
                        "b": {"source_paths": ["b/"]},
                    },
                    "edge": [
                        {"type": "publication-prerequisite", "from": "a", "to": ["b"]},
                        {"type": "publication-prerequisite", "from": "b", "to": ["a"]},
                    ],
                }
            )
        self.assertIn("cycle", str(caught.exception).lower())

    def test_runtime_contract_without_measured_support_is_declared_incomplete(
        self,
    ) -> None:
        """G5 forbids inventing floors: an edge whose support set is not an
        explicit measurement or an explicit approved deprecation loads, but
        carries declared_incomplete and blocks when touched."""
        data = fixture_graph_dict()
        data["edge"].append(
            {
                "type": "runtime-contract",
                "a": "plugin",
                "b": "server",
                "journey": "make other-journey",
                "artifacts": {"a": "registry:plugin", "b": "registry:server"},
                "direction": "both",
                "supported": {"policy": "additive-only"},
            }
        )
        graph = rd.Graph.from_dict(data)
        incomplete = [e for e in graph.runtime_contracts if e.declared_incomplete]
        self.assertEqual([(e.a, e.b) for e in incomplete], [("plugin", "server")])


class PlanTests(unittest.TestCase):
    def plan(self, changed: dict[str, bool], **kwargs) -> rd.Plan:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components=changed, **kwargs)
        return rd.compute_plan(graph, state)

    def test_untouched_graph_plans_nothing(self) -> None:
        self.assertEqual(self.plan({}).moving, [])

    def test_plan_nodes_carry_resolved_versions(self) -> None:
        plan = self.plan({"server": True}, versions={"server": "2.1.0"})
        node = next(n for n in plan.moving if n.component == "server")
        self.assertEqual(node.version, "2.1.0")

    def test_top_level_pointer_edge_forces_consumer_after_source(self) -> None:
        """alice's counterexample: a declared pointer edge whose source moves
        must move the pointer target, ordered after the source."""
        plan = self.plan({"plugin": True, "core": False})
        order = [n.component for n in plan.moving]
        self.assertIn("pointer", order)
        self.assertLess(order.index("plugin"), order.index("pointer"))

    def test_pointer_consumer_moves_when_any_source_moves(self) -> None:
        """server -> cloud-pin is a pointer edge: server moving forces the
        pin consumer. This is the missed-AC-consumer class."""
        plan = self.plan({"server": True})
        order = [n.component for n in plan.moving]
        self.assertIn("cloud-pin", order)
        self.assertLess(order.index("server"), order.index("cloud-pin"))

    def test_bundled_input_change_is_measured_per_consumer_baseline(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={},
            bundled_changed_for={("core", "plugin"): True, ("core", "client"): False},
        )
        plan = rd.compute_plan(graph, state)
        moving = {n.component for n in plan.moving}
        self.assertIn("plugin", moving)
        self.assertNotIn("client", moving)

    def test_order_respects_publication_prerequisites(self) -> None:
        plan = self.plan({"core": True, "client": True, "plugin": True})
        order = [n.component for n in plan.moving]
        self.assertLess(order.index("client"), order.index("plugin"))

    def test_true_prerequisite_alone_does_not_drag_dependent(self) -> None:
        """client -> plugin is a prerequisite, not a pointer: client moving
        does not force an unchanged plugin, it only orders both when both move."""
        plan = self.plan({"client": True})
        self.assertNotIn("plugin", {n.component for n in plan.moving})

    def test_plan_names_touched_runtime_contract_edges(self) -> None:
        plan = self.plan({"client": True})
        touched = {(e.a, e.b) for e in plan.runtime_contract_edges}
        self.assertIn(("client", "server"), touched)


class VersionResolutionTests(unittest.TestCase):
    """Three distinct notions: current source version, latest registry-visible
    version, proposed candidate. A changed component whose source version is
    already published must fail named rather than propose a published version."""

    def test_source_ahead_of_published_becomes_the_candidate(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"client": True},
            versions={"client": "2.1.0"},
            published_versions={"client": "2.0.9"},
        )
        plan = rd.compute_plan(graph, state)
        node = next(n for n in plan.moving if n.component == "client")
        self.assertEqual(node.version, "2.1.0")
        self.assertEqual(node.published_version, "2.0.9")
        version_problems = [
            p for p in rd.check_declared_inputs(graph, plan, state) if "version" in p
        ]
        self.assertEqual(version_problems, [])

    def test_already_published_source_version_fails_named(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"server": True},
            versions={"server": "2.0.9"},
            published_versions={"server": "2.0.9"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("version not advanced" in p and "server" in p for p in problems),
            f"expected a named version-not-advanced failure, got {problems}",
        )

    def test_registry_behind_tag_disagreement_fails_closed(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"server": True},
            versions={"server": "2.1.0"},
            published_versions={"server": "2.0.9"},
            tag_versions={"server": "2.1.0"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("tag" in p and "registry" in p for p in problems),
            f"a tag the registry does not confirm must fail closed, got {problems}",
        )


class PlanDigestTests(unittest.TestCase):
    def test_digest_binds_edge_declarations(self) -> None:
        """alice's counterexample: changing a floor or policy must change the
        digest — the digest binds the full canonical declarations."""
        base = fixture_graph_dict()
        graph_a = rd.Graph.from_dict(base)
        state = rd.FixtureState(changed_components={"client": True})
        digest_a = rd.plan_digest(rd.compute_plan(graph_a, state), graph_a)

        mutated = fixture_graph_dict()
        for edge in mutated["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "approved-deprecation:record-1",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "deprecation:record-1",
                        "digest": "d1",
                    },
                    "policy": "breaking-with-approved-deprecation",
                }
        graph_b = rd.Graph.from_dict(mutated)
        digest_b = rd.plan_digest(rd.compute_plan(graph_b, state), graph_b)
        self.assertNotEqual(digest_a, digest_b)

    def test_digest_is_stable(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components={"client": True})
        a = rd.plan_digest(rd.compute_plan(graph, state), graph)
        b = rd.plan_digest(rd.compute_plan(graph, state), graph)
        self.assertEqual(a, b)


class InputSatisfactionTests(unittest.TestCase):
    def state(self, **kwargs) -> rd.FixtureState:
        return rd.FixtureState(changed_components={"server": True}, **kwargs)

    def problems(self, state: rd.FixtureState) -> list[str]:
        graph = fixture_graph()
        plan = rd.compute_plan(graph, state)
        return rd.check_declared_inputs(graph, plan, state)

    def test_missing_credential_path_fails_closed(self) -> None:
        problems = self.problems(self.state(env={}, existing_paths=set()))
        self.assertTrue(any("FIXTURE_GATE_ENV_FILE" in p for p in problems))

    def test_sibling_pin_requires_exact_checkout_sha(self) -> None:
        """Existence is not enough: the checkout HEAD must equal the pinned
        SHA — the exact abbj staging failure."""
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "deadbeef"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        problems = self.problems(state)
        self.assertTrue(
            any("feedface" in p and "deadbeef" in p for p in problems),
            f"pin/checkout SHA mismatch must be a named failure, got {problems}",
        )

    def test_sibling_pin_requires_declared_remote_identity(self) -> None:
        """A path whose HEAD happens to contain the pinned SHA object is not
        the declared repository: the checkout's remote identity must match."""
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/wrong/repo"},
        )
        problems = self.problems(state)
        self.assertTrue(
            any("remote" in p and "wrong/repo" in p for p in problems),
            f"remote identity mismatch must be a named failure, got {problems}",
        )

    def test_satisfied_inputs_including_exact_pin_pass(self) -> None:
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        self.assertEqual(self.problems(state), [])

    def test_touched_incomplete_runtime_contract_blocks(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {"policy": "additive-only"}
        graph = rd.Graph.from_dict(data)
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(any("declared-incomplete" in p for p in problems))


class ApprovalTests(unittest.TestCase):
    def test_empty_or_unstructured_approval_is_refused(self) -> None:
        graph = fixture_graph()
        plan = rd.compute_plan(graph, rd.FixtureState(changed_components={"server": True}))
        pin = next(n for n in plan.moving if n.component == "cloud-pin")
        for bad in (None, "", "juan"):
            with self.assertRaises(rd.ApprovalRequired):
                rd.require_approval(pin, approval=bad)
        rd.require_approval(pin, approval=rd.Approval(who="juan", when="2026-08-05"))


class ReceiptTests(unittest.TestCase):
    def make_plan(self) -> tuple[rd.Graph, rd.Plan]:
        graph = fixture_graph()
        plan = rd.compute_plan(
            graph, rd.FixtureState(changed_components={"client": True})
        )
        return graph, plan

    def entries_for(self, plan: rd.Plan) -> dict[str, rd.ReceiptEntry]:
        return {
            n.component: rd.ReceiptEntry(
                version=n.version or "0.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                delivery_proof=None,
            )
            for n in plan.moving
        }

    def test_seal_refuses_entry_set_mismatch(self) -> None:
        graph, plan = self.make_plan()
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(plan, graph, source_sha="s1", entries={}, approvals={})
        extra = self.entries_for(plan)
        extra["stowaway"] = rd.ReceiptEntry(version="1.0.0", digest="dx")
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(plan, graph, source_sha="s1", entries=extra, approvals={})

    def test_load_requires_external_expected_digest(self) -> None:
        """The seal is not self-contained: load verifies against a digest the
        caller obtained from an outside authority. Recomputing a checksum
        beside an edited body must not pass."""
        graph, plan = self.make_plan()
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha="s1", entries=self.entries_for(plan), approvals={}
        )
        loaded = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(loaded.source_sha, "s1")

        import hashlib, json

        outer = json.loads(sealed)
        body = outer["body"].replace("s1", "s2")
        forged = json.dumps(
            {"body": body, "seal": hashlib.sha256(body.encode()).hexdigest()}
        ).encode()
        with self.assertRaises(rd.ReceiptError):
            rd.load_sealed_receipt(forged, expected_digest=digest)

    def test_receipt_matches_run_compares_plan_and_source(self) -> None:
        graph, plan = self.make_plan()
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha="s1", entries=self.entries_for(plan), approvals={}
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        ok, _ = rd.receipt_matches_run(receipt, plan, graph, source_sha="s1")
        self.assertTrue(ok)
        ok, why = rd.receipt_matches_run(receipt, plan, graph, source_sha="other")
        self.assertFalse(ok)
        self.assertIn("source", why)


class FixtureLanes:
    """Records every call. Stages produce digests; publish returns what it is
    given so digest identity can be asserted by the driver."""

    def __init__(self, available: set[str]):
        self.available = available
        self.calls: list[tuple[str, str]] = []

    def has_lane(self, component: str) -> bool:
        return component in self.available

    def stage(self, node: rd.PlanNode) -> rd.ReceiptEntry:
        self.calls.append(("stage", node.component))
        return rd.ReceiptEntry(
            version=node.version or "0.0.0",
            digest=f"staged-{node.component}",
            pointer_state="pointer-ok" if node.reason.startswith("pointer:") else None,
            delivery_proof=None,
        )

    def publish(self, node: rd.PlanNode, staged: rd.ReceiptEntry) -> rd.ReceiptEntry:
        self.calls.append(("publish", node.component))
        return staged

    def verify(self, node: rd.PlanNode, published: rd.ReceiptEntry) -> None:
        self.calls.append(("verify", node.component))


class AllRecordsResolve:
    """Fixture measurement authority: every structured record resolves."""

    def resolve(self, record, edge):
        return {"digest": record.get("digest"), "edge": (edge.a, edge.b)}


class FixtureSkew:
    def __init__(self, available: bool = True):
        self.available = available
        self.executed: list[tuple[str, str]] = []

    def has_matrix(self, edge) -> bool:
        return self.available

    def execute(self, edge, staged: dict) -> None:
        self.executed.append((edge.a, edge.b))


class FixtureAuthority:
    """External authority: records digests by artifact identity at seal time
    and resolves them independently of anything the caller presents."""

    def __init__(self):
        self.recorded: dict[str, str] = {}

    def record(self, artifact_id: str, digest: str) -> None:
        self.recorded[artifact_id] = digest

    def expected_digest(self, artifact_id: str) -> str | None:
        return self.recorded.get(artifact_id)


def complete_fixture_graph() -> rd.Graph:
    """Fixture graph whose runtime contract is measured, so orchestration can
    proceed to publish in tests that are not about G5 blocking."""
    return rd.Graph.from_dict(fixture_graph_dict())


def orchestration_state(**kwargs) -> rd.FixtureState:
    defaults = dict(
        changed_components={"client": True, "plugin": True},
        versions={"client": "1.1.0", "plugin": "2.1.0"},
        published_versions={"client": "1.0.0", "plugin": "2.0.0"},
    )
    defaults.update(kwargs)
    return rd.FixtureState(**defaults)


class FourPhaseProtocolTests(unittest.TestCase):
    def run_fixture(self, lanes=None, skew=None, state=None, approvals=None):
        graph = complete_fixture_graph()
        state = state or orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = lanes or FixtureLanes(
            available={n.component for n in plan.moving}
        )
        skew = skew or FixtureSkew()
        authority = FixtureAuthority()
        entries = rd.run_plan(
            plan,
            graph,
            lanes,
            skew=skew,
            authority=authority,
            source_sha="s1",
            approvals=approvals or {},
            state=state,
            providers=rd.Providers(
                store=rd._MemoryStore(),
                authority=authority,
                measurement=AllRecordsResolve(),
            ),
        )
        return graph, plan, lanes, skew, authority, entries

    def test_every_stage_and_skew_precedes_the_first_publish(self) -> None:
        """alice's interleaving counterexample: stage a, publish a, stage b is
        forbidden. All stages bind digests, all touched skew matrices run
        against those bytes, and only then does the first publish happen."""
        graph, plan, lanes, skew, _, _ = self.run_fixture()
        kinds = [kind for kind, _ in lanes.calls]
        first_publish = kinds.index("publish")
        self.assertEqual(
            set(kinds[:first_publish]) & {"stage"},
            {"stage"},
        )
        self.assertNotIn("publish", kinds[:first_publish])
        stage_count = kinds[:first_publish].count("stage")
        self.assertEqual(
            stage_count,
            len(plan.moving),
            f"all {len(plan.moving)} stages must precede the first publish; calls={lanes.calls}",
        )
        self.assertTrue(skew.executed, "touched matrices must run before publish")

    def test_publishes_follow_plan_order_and_verify_follows_publish(self) -> None:
        _, plan, lanes, _, _, _ = self.run_fixture()
        publishes = [c for kind, c in lanes.calls if kind == "publish"]
        self.assertLess(publishes.index("client"), publishes.index("plugin"))
        kinds = [kind for kind, _ in lanes.calls]
        self.assertLess(kinds.index("publish"), kinds.index("verify"))

    def test_missing_skew_provider_blocks_before_any_lane_call(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.SkewUnavailable):
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(available=False),
                authority=FixtureAuthority(),
                providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha="s1", approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [])

    def test_missing_approval_refuses_before_any_lane_call(self) -> None:
        """alice's counterexample: with the approval-required node last, the
        first node was already published before refusal. Approvals preflight."""
        graph = complete_fixture_graph()
        state = orchestration_state(
            changed_components={"server": True, "client": True},
            versions={"server": "3.1.0", "client": "1.1.0"},
            published_versions={"server": "3.0.0", "client": "1.0.0"},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.ApprovalRequired):
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha="s1", approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [], "nothing may run before approvals check out")

    def test_published_digest_must_equal_staged_digest(self) -> None:
        class TamperingLanes(FixtureLanes):
            def publish(self, node, staged):
                self.calls.append(("publish", node.component))
                return rd.ReceiptEntry(
                    version=staged.version,
                    digest="something-else",
                    pointer_state=staged.pointer_state,
                    delivery_proof=staged.delivery_proof,
                )

        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = TamperingLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha="s1", approvals={}, state=state,
            )
        self.assertIn("digest", str(caught.exception))

    def test_run_seals_receipt_and_records_digest_with_authority(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = complete_fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes(available={n.component for n in plan.moving})
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            entries = rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=state,
                providers=rd.Providers(store=store, authority=authority, measurement=AllRecordsResolve()),
            )
            self.assertEqual(set(entries), {n.component for n in plan.moving})
            kinds = {k.split(":")[0] for k in authority.recorded_ids()}
            self.assertLessEqual(
                {"plan", "staged-manifest", "transition", "receipt"},
                kinds,
                "plan, staged manifest, every transition, and the final receipt"
                " must all be anchored",
            )
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )
            receipt = rd.load_sealed_receipt(
                store.get(receipt_id),
                expected_digest=authority.expected_digest(receipt_id),
            )
            ok, why = rd.receipt_matches_run(receipt, plan, graph, source_sha="s1")
            self.assertTrue(ok, why)
            self.assertTrue(receipt.frozen_plan_id)
            self.assertTrue(receipt.staged_manifest_id)
            self.assertTrue(
                all(e.phase == "verified" for e in receipt.entries.values())
            )

    def test_publish_failure_leaves_anchored_transitions(self) -> None:
        """Per-transition anchoring IS the durable partial state: a failure
        after the first publish leaves that transition anchored, with no
        reliance on exception handling for crash consistency."""
        import tempfile

        class FailingSecondPublish(FixtureLanes):
            def publish(self, node, staged):
                if len([c for k, c in self.calls if k == "publish"]) == 1:
                    raise RuntimeError("registry outage mid-run")
                return super().publish(node, staged)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = complete_fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FailingSecondPublish(
                available={n.component for n in plan.moving}
            )
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            with self.assertRaises(RuntimeError):
                rd.run_plan(
                    plan, graph, lanes,
                    skew=FixtureSkew(), authority=authority, store=store,
                    source_sha="s1", approvals={}, state=state,
                    providers=rd.Providers(
                        store=store, authority=authority,
                        measurement=AllRecordsResolve(),
                    ),
                )
            transitions = [
                k
                for k in authority.recorded_ids()
                if k.startswith("transition:") and ":published:" in k
            ]
            self.assertEqual(
                len(transitions),
                1,
                "the successful first publish must be durably anchored",
            )


class ResumeTests(unittest.TestCase):
    def test_frozen_plan_resumes_without_replanning(self) -> None:
        """G4: after a partial publish, live registry state has moved; a rerun
        takes the frozen plan artifact and never recomputes from live state."""
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha="s1")
        moved_state = orchestration_state(
            changed_components={"plugin": True},
        )
        restored = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        self.assertEqual(
            [n.component for n in restored.plan.moving],
            [n.component for n in plan.moving],
            "the frozen plan is the plan; live drift must not rewrite it",
        )

    def test_tampered_frozen_plan_is_refused(self) -> None:
        graph = complete_fixture_graph()
        plan = rd.compute_plan(graph, orchestration_state())
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha="s1")
        with self.assertRaises(rd.ReceiptError):
            rd.load_frozen_plan(frozen_bytes.replace(b"s1", b"s2"), expected_id=frozen_id)

    def test_partial_receipt_resume_skips_exact_matches_only(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        done = rd.ReceiptEntry(version="1.1.0", digest="staged-client", phase="published")
        partial = {"client": done}
        remaining = rd.resume_remaining(plan, partial, observed={"client": done})
        self.assertEqual([n.component for n in remaining], ["plugin", "pointer"])
        drifted = rd.ReceiptEntry(version="1.1.0", digest="other", phase="published")
        with self.assertRaises(rd.ReceiptError):
            rd.resume_remaining(plan, partial, observed={"client": drifted})


class SealValidationTests(unittest.TestCase):
    def test_seal_refuses_pointer_node_without_pointer_state(self) -> None:
        graph = complete_fixture_graph()
        plan = rd.compute_plan(graph, orchestration_state())
        entries = {
            n.component: rd.ReceiptEntry(
                version="1.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state=None,
                delivery_proof=None,
            )
            for n in plan.moving
        }
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.seal_receipt(plan, graph, source_sha="s1", entries=entries, approvals={})
        self.assertIn("pointer_state", str(caught.exception))

    def test_seal_refuses_approval_required_node_without_approvals(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        entries = {
            n.component: rd.ReceiptEntry(
                version="1.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                delivery_proof=None,
            )
            for n in plan.moving
        }
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.seal_receipt(plan, graph, source_sha="s1", entries=entries, approvals={})
        self.assertIn("approval", str(caught.exception))


class G5SchemaTests(unittest.TestCase):
    def test_garbage_completion_is_refused_at_load(self) -> None:
        """alice's one-counterexample-proves-all: empty measurement id, missing
        policy, empty locators, nonsense direction must refuse to load."""
        data = fixture_graph_dict()
        data["edge"].append(
            {
                "type": "runtime-contract",
                "a": "plugin",
                "b": "server",
                "journey": "j",
                "artifacts": {"a": "", "b": ""},
                "direction": "nonsense",
                "supported": {"set": "measured:"},
            }
        )
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_measured_set_requires_nonempty_identity_and_policy(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {"set": "measured:", "policy": "additive-only"}
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_direction_must_be_a_known_enum_value(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["direction"] = "sideways"
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)


class PointerClosureTests(unittest.TestCase):
    def chain_graph(self) -> rd.Graph:
        return rd.Graph.from_dict(
            {
                "component": {
                    "a": {
                        "source_paths": ["a/"],
                        "version_source": {"type": "manifest", "path": "a/v"},
                        "tag_format": "a-v{version}",
                        "publish_lane": {"workflow": "wf/a.yml"},
                        "verify": {"command": "true"},
                    },
                    "b": {"publishable": False},
                    "c": {"publishable": False},
                },
                "edge": [
                    {"type": "pointer", "from": "a", "to": ["b"]},
                    {"type": "pointer", "from": "b", "to": ["c"]},
                ],
            }
        )

    def test_pointer_closure_is_transitive(self) -> None:
        """alice's counterexample: a->b->c must move a, b AND c."""
        plan = rd.compute_plan(
            self.chain_graph(), rd.FixtureState(changed_components={"a": True})
        )
        order = [n.component for n in plan.moving]
        self.assertEqual(order, ["a", "b", "c"])

    def test_pointer_cycle_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {"publishable": False},
                        "b": {"publishable": False},
                    },
                    "edge": [
                        {"type": "pointer", "from": "a", "to": ["b"]},
                        {"type": "pointer", "from": "b", "to": ["a"]},
                    ],
                }
            )
        self.assertIn("cycle", str(caught.exception).lower())


class RegistryTruthTests(unittest.TestCase):
    def test_unknown_published_version_blocks_by_name(self) -> None:
        """alice's counterexample: published None must mean UNAVAILABLE and
        block, never read as no-published-version."""
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"client": True},
            versions={"client": "1.1.0"},
            published_versions={},
            registry_unavailable={"client": "fixture registry has no reader"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("registry" in p and "unavailable" in p and "client" in p for p in problems),
            f"unknown registry truth must be a named blocker, got {problems}",
        )


class RemoteIdentityTests(unittest.TestCase):
    def test_remote_forms_normalize_to_one_canonical_identity(self) -> None:
        for url in (
            "https://github.com/awebai/aweb.git",
            "https://github.com/awebai/aweb",
            "git@github.com:awebai/aweb.git",
            "ssh://git@github.com/awebai/aweb.git",
        ):
            self.assertEqual(
                rd.canonical_remote(url),
                "github.com/awebai/aweb",
                url,
            )


class GraphContractTests(unittest.TestCase):
    """The committed graph must match the repository it describes."""

    def setUp(self) -> None:
        self.graph = rd.Graph.load()

    def test_declared_source_paths_exist(self) -> None:
        for component in self.graph.components.values():
            for source_path in component.source_paths:
                self.assertTrue(
                    (REPO_ROOT / source_path).exists(),
                    f"{component.name} declares missing source path {source_path}",
                )

    def test_publishable_components_declare_lane_and_verify(self) -> None:
        for component in self.graph.components.values():
            if not component.publishable:
                continue
            self.assertTrue(
                component.publish_lane and component.publish_lane.get("workflow"),
                f"{component.name} has no publish-lane workflow declaration",
            )
            workflow = component.publish_lane["workflow"]
            self.assertTrue(
                (REPO_ROOT / workflow).is_file(),
                f"{component.name}: declared workflow {workflow} does not exist",
            )
            self.assertTrue(
                component.verify and component.verify.get("command"),
                f"{component.name} has no verify command declaration",
            )

    def test_version_sources_resolve_to_versions(self) -> None:
        import json as json_module
        import re

        for component in self.graph.components.values():
            source = component.version_source
            if source is None:
                continue
            kind = source["type"]
            if kind == "pyproject":
                text = (REPO_ROOT / source["path"]).read_text(encoding="utf-8")
                self.assertIsNotNone(
                    re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', text),
                    f"{component.name}: no version in {source['path']}",
                )
            elif kind == "package-json":
                data = json_module.loads(
                    (REPO_ROOT / source["path"]).read_text(encoding="utf-8")
                )
                self.assertRegex(data["version"], r"^\d+\.\d+\.\d+$", component.name)
            elif kind == "tag-history":
                self.assertTrue((REPO_ROOT / source["script"]).is_file())
            else:
                self.fail(f"{component.name}: unknown version_source type {kind!r}")

    def test_sites_only_change_plans_sites(self) -> None:
        """alice's counterexample: a sites-only change planned nothing."""
        state = rd.FixtureState(changed_components={"sites": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertIn("sites", {n.component for n in plan.moving})

    def test_ac_gate_carries_approval_and_credentials_ac_pin_does_not(self) -> None:
        """The source pointer update (ac-pin) must not demand production
        credentials; the downstream gate boundary (ac-gate) does."""
        ac_pin = self.graph.components["ac-pin"]
        self.assertFalse(ac_pin.approval_required)
        self.assertFalse(ac_pin.credential_paths)
        self.assertEqual(len(ac_pin.sibling_pins), 2, "server AND awid pins declared")
        ac_gate = self.graph.components["ac-gate"]
        self.assertTrue(ac_gate.approval_required)
        self.assertTrue(
            any(c["env"] == "MIGRATION_GATE_ENV_FILE" for c in ac_gate.credential_paths)
        )

    def test_ac_pin_is_a_forced_pointer_consumer_of_server_and_awid(self) -> None:
        """alice's counterexample: awid moving without ac-pin in the plan is
        the missed-consumer failure the graph exists to prevent."""
        state = rd.FixtureState(changed_components={"awid-pypi": True, "server": True})
        plan = rd.compute_plan(self.graph, state)
        order = [n.component for n in plan.moving]
        self.assertIn("ac-pin", order)
        self.assertLess(order.index("awid-pypi"), order.index("ac-pin"))
        self.assertLess(order.index("server"), order.index("ac-pin"))

    def test_known_couplings_are_declared(self) -> None:
        self.assertEqual(
            set(self.graph.bundled_into.get("channel-core", ())), {"channel", "pi"}
        )
        self.assertIn("awid-pypi", self.graph.prerequisites["server"])
        self.assertIn("aw", self.graph.prerequisites["pi"])
        self.assertEqual(
            set(self.graph.pointer_targets.get("channel", ())), {"marketplace-pointer"}
        )
        ac_pin = self.graph.components["ac-pin"]
        pins = {p["component"]: p for p in ac_pin.sibling_pins}
        self.assertEqual(set(pins), {"server", "awid-pypi"})
        self.assertEqual(pins["server"]["field"], "git_sha")
        self.assertEqual(pins["server"]["section"], "aweb")

    def test_committed_runtime_contracts_are_honestly_incomplete(self) -> None:
        """No fleet measurement exists yet, so every committed edge must carry
        declared_incomplete — the expected state until aweb-abbe.7 measures.
        Fabricating a floor or a measurement to look green is the defect."""
        self.assertTrue(self.graph.runtime_contracts, "edges must be declared")
        for edge in self.graph.runtime_contracts:
            self.assertNotIn("floor", edge.supported, f"{edge.a}->{edge.b}")
            self.assertTrue(
                edge.declared_incomplete,
                f"{edge.a}->{edge.b} claims measured support that does not exist",
            )

    def test_incomplete_contracts_block_execution_but_not_the_plan(self) -> None:
        state = rd.FixtureState(changed_components={"aw": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertTrue(plan.moving, "diagnostic plan still computes")
        problems = rd.check_declared_inputs(self.graph, plan, state)
        self.assertTrue(any("declared-incomplete" in p for p in problems))
        lanes = FixtureLanes(available={"aw"})
        with self.assertRaises(rd.BlockedByDeclaredInputs):
            rd.run_plan(
                plan, self.graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha="s1", approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
