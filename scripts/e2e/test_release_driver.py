"""Pure-logic tests for the release driver: plan computation, forced-consumer
expansion, topological ordering, declared-input satisfaction, receipt matching,
and approval refusal. No network, no subprocesses: authoritative state arrives
through the same provider interface the real driver uses, filled from fixtures.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd


def fixture_graph() -> rd.Graph:
    return rd.Graph.from_dict(
        {
            "component": {
                "core": {
                    "source_paths": ["core/"],
                    "publishable": False,
                },
                "client": {
                    "source_paths": ["client/"],
                    "version_source": {"type": "manifest", "path": "client/version"},
                    "tag_format": "client-v{version}",
                },
                "plugin": {
                    "source_paths": ["plugin/"],
                    "version_source": {"type": "manifest", "path": "plugin/version"},
                    "tag_format": "plugin-v{version}",
                },
                "server": {
                    "source_paths": ["server/"],
                    "version_source": {"type": "manifest", "path": "server/version"},
                    "tag_format": "server-v{version}",
                },
                "cloud": {
                    "source_paths": ["cloud/"],
                    "version_source": {"type": "manifest", "path": "cloud/version"},
                    "tag_format": "v{version}",
                    "approval_required": True,
                    "credential_paths": [
                        {"env": "FIXTURE_GATE_ENV_FILE", "purpose": "migration gate"}
                    ],
                    "sibling_pins": [
                        {
                            "pin_file": "release-pin.toml",
                            "component": "server",
                            "checkout": "../server-src",
                        }
                    ],
                },
                "pointer": {
                    "publishable": False,
                    "pointer_for": ["plugin"],
                },
            },
            "edge": [
                {"type": "bundled-build-input", "from": "core", "to": ["client", "plugin"]},
                {"type": "publication-prerequisite", "from": "client", "to": ["plugin"]},
                {"type": "publication-prerequisite", "from": "server", "to": ["cloud"]},
                {
                    "type": "runtime-contract",
                    "a": "client",
                    "b": "server",
                    "journey": "make fixture-journey",
                    "supported": {"floor": "1.0.0", "policy": "additive-only"},
                },
            ],
        }
    )


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
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {"a": {"source_paths": ["a/"]}},
                    "edge": [
                        {"type": "publication-prerequisite", "from": "a", "to": ["ghost"]}
                    ],
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


class PlanTests(unittest.TestCase):
    def plan(self, changed: dict[str, bool]) -> rd.Plan:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components=changed)
        return rd.compute_plan(graph, state)

    def test_untouched_graph_plans_nothing(self) -> None:
        plan = self.plan({})
        self.assertEqual(plan.moving, [])

    def test_changed_component_moves(self) -> None:
        plan = self.plan({"server": True})
        self.assertEqual([n.component for n in plan.moving], ["server"])

    def test_bundled_input_forces_every_consumer(self) -> None:
        plan = self.plan({"core": True})
        moving = {n.component for n in plan.moving}
        self.assertLessEqual(
            {"client", "plugin"},
            moving,
            "a bundled build input silently ships inside BOTH consumers, so a"
            " change to it must move both",
        )
        self.assertNotIn(
            "core", moving, "the non-publishable input itself never publishes"
        )

    def test_bundled_input_change_is_measured_per_consumer_baseline(self) -> None:
        """A bundled input has no published tag of its own; whether it changed
        is a question PER CONSUMER: since THAT consumer's last published tag.
        Unchanged-for-client but changed-for-plugin moves only plugin."""
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={},
            bundled_changed_for={("core", "plugin"): True, ("core", "client"): False},
        )
        plan = rd.compute_plan(graph, state)
        moving = {n.component for n in plan.moving}
        self.assertIn("plugin", moving)
        self.assertNotIn(
            "client",
            moving,
            "an input unchanged since the consumer's tag must not move it",
        )

    def test_order_respects_publication_prerequisites(self) -> None:
        plan = self.plan({"core": True, "client": True, "plugin": True})
        order = [n.component for n in plan.moving]
        self.assertLess(
            order.index("client"),
            order.index("plugin"),
            "plugin depends on the published client, so client publishes first",
        )

    def test_pointer_follows_its_source(self) -> None:
        plan = self.plan({"plugin": True})
        order = [n.component for n in plan.moving]
        self.assertIn("pointer", order)
        self.assertLess(order.index("plugin"), order.index("pointer"))

    def test_moved_prerequisite_does_not_drag_unchanged_dependent(self) -> None:
        plan = self.plan({"server": True})
        moving = {n.component for n in plan.moving}
        self.assertNotIn(
            "cloud",
            moving,
            "a prerequisite moving does not force an unchanged dependent to"
            " release; it only orders the dependent when both move",
        )

    def test_plan_names_touched_runtime_contract_edges(self) -> None:
        plan = self.plan({"client": True})
        touched = {(e.a, e.b) for e in plan.runtime_contract_edges}
        self.assertIn(("client", "server"), touched)


class InputSatisfactionTests(unittest.TestCase):
    def test_missing_credential_path_fails_closed(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"cloud": True, "server": True},
            env={},
            existing_paths=set(),
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("FIXTURE_GATE_ENV_FILE" in p for p in problems),
            f"missing credential path must be a named failure, got: {problems}",
        )

    def test_present_credential_path_satisfies_without_reading(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"cloud": True, "server": True},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertEqual(problems, [])

    def test_missing_sibling_pin_checkout_is_named(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"cloud": True},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(any("../server-src" in p for p in problems))


class ReceiptTests(unittest.TestCase):
    def test_rerun_accepts_only_exact_digest_match(self) -> None:
        receipt = rd.Receipt(
            plan_digest="abc",
            entries={"client": rd.ReceiptEntry(version="1.2.3", digest="d1")},
        )
        ok, why = rd.receipt_accepts(receipt, "client", version="1.2.3", digest="d1")
        self.assertTrue(ok)
        ok, why = rd.receipt_accepts(receipt, "client", version="1.2.3", digest="d2")
        self.assertFalse(ok)
        self.assertIn("digest", why)

    def test_unknown_component_fails_closed(self) -> None:
        receipt = rd.Receipt(plan_digest="abc", entries={})
        ok, why = rd.receipt_accepts(receipt, "client", version="1.2.3", digest="d1")
        self.assertFalse(ok)


class SealTests(unittest.TestCase):
    def test_seal_binds_plan_digest_and_source_sha(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components={"server": True})
        plan = rd.compute_plan(graph, state)
        sealed = rd.seal_receipt(
            plan,
            source_sha="deadbeef",
            entries={"server": rd.ReceiptEntry(version="2.0.0", digest="d9")},
        )
        loaded = rd.load_sealed_receipt(sealed)
        self.assertEqual(loaded.plan_digest, rd.plan_digest(plan))
        ok, _ = rd.receipt_accepts(loaded, "server", version="2.0.0", digest="d9")
        self.assertTrue(ok)

    def test_tampered_seal_is_refused(self) -> None:
        graph = fixture_graph()
        plan = rd.compute_plan(graph, rd.FixtureState(changed_components={"server": True}))
        sealed = rd.seal_receipt(plan, source_sha="deadbeef", entries={})
        tampered = sealed.replace(b"deadbeef", b"cafebabe")
        with self.assertRaises(rd.ReceiptError):
            rd.load_sealed_receipt(tampered)

    def test_plan_digest_is_stable_and_content_sensitive(self) -> None:
        graph = fixture_graph()
        a = rd.compute_plan(graph, rd.FixtureState(changed_components={"server": True}))
        b = rd.compute_plan(graph, rd.FixtureState(changed_components={"server": True}))
        c = rd.compute_plan(graph, rd.FixtureState(changed_components={"client": True}))
        self.assertEqual(rd.plan_digest(a), rd.plan_digest(b))
        self.assertNotEqual(rd.plan_digest(a), rd.plan_digest(c))


class ApprovalTests(unittest.TestCase):
    def test_approval_required_node_refuses_without_named_approval(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components={"cloud": True, "server": True})
        plan = rd.compute_plan(graph, state)
        cloud = next(n for n in plan.moving if n.component == "cloud")
        with self.assertRaises(rd.ApprovalRequired):
            rd.require_approval(cloud, approval=None)
        rd.require_approval(cloud, approval="juan 2026-08-05 fixture")


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
                found = re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', text)
                self.assertIsNotNone(found, f"{component.name}: no version in {source['path']}")
            elif kind == "package-json":
                data = json_module.loads((REPO_ROOT / source["path"]).read_text(encoding="utf-8"))
                self.assertRegex(data["version"], r"^\d+\.\d+\.\d+$", component.name)
            elif kind == "tag-history":
                self.assertTrue(
                    (REPO_ROOT / source["script"]).is_file(),
                    f"{component.name}: version script missing",
                )
            else:
                self.fail(f"{component.name}: unknown version_source type {kind!r}")

    def test_every_publishable_component_has_a_tag_format(self) -> None:
        for component in self.graph.components.values():
            if component.publishable:
                self.assertTrue(
                    component.tag_format and "{version}" in component.tag_format,
                    f"{component.name} is publishable but has no usable tag_format",
                )

    def test_known_couplings_are_declared(self) -> None:
        """The couplings that produced real incidents must never quietly leave
        the graph: channel-core into both consumers, awid before server, aw
        before pi, and the AC credential/sibling-pin inputs."""
        self.assertEqual(
            set(self.graph.bundled_into.get("channel-core", ())), {"channel", "pi"}
        )
        self.assertIn("awid-pypi", self.graph.prerequisites["server"])
        self.assertIn("aw", self.graph.prerequisites["pi"])
        ac = self.graph.components["ac"]
        self.assertTrue(ac.approval_required)
        self.assertTrue(
            any(c["env"] == "MIGRATION_GATE_ENV_FILE" for c in ac.credential_paths)
        )
        self.assertTrue(any(p["pin_file"] == "release-pin.toml" for p in ac.sibling_pins))
        pointer = self.graph.components["marketplace-pointer"]
        self.assertEqual(set(pointer.pointer_for), {"channel", "skills"})


if __name__ == "__main__":
    unittest.main(verbosity=1)
