"""No-network contract tests for adopted-preplan release recovery.

The historical Channel/Pi incident is only a typed fixture.  Every store,
digest authority, public-state observation, and continuation adapter below is
in-memory; these tests cannot dispatch, tag, publish, anchor, or deploy.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd

SOURCE = "463fd1d6fe25d81af059559f0d1778a733bf2c1d"
MANIFESTS = {
    "channel": "sha256:df3fec7c7b7508c93de49ebc61085a8269776456021a041a720c23f42ab4526c",
    "pi": "sha256:e600b7284658283647497bb1e8d818ceeb4e1dae4ad6faadf19efc850a3028d1",
}
PAYLOADS = {
    "channel": {
        "awebai-claude-channel-1.7.2.tgz":
            "8c924184d9b11803eada3b40d5fc62a0319c04fadb5a8dd18ec570e082c3b975",
    },
    "pi": {
        "awebai-pi-0.3.2.tgz":
            "b20cd45404eb6cea64856e7467fefa52da9714de301e5ab53f70b69508ccba69",
    },
}
VERSIONS = {"channel": "1.7.2", "pi": "0.3.2"}
REFS = {
    "channel": {
        "artifact": "gh-artifact:awebai/aweb:31048187475:8947308273",
        "aw_source_sha": SOURCE,
        "zip_digest": "sha256:9a07e3d86088db7f55a9c8408ef0c803e68c3ead3a7e71afb00e07ce2077f0a1",
    },
    "pi": {
        "artifact": "gh-artifact:awebai/aweb:31048197476:8947313121",
        "aw_source_sha": SOURCE,
        "zip_digest": "sha256:fbf025bc27d0cd5da52b3649dd3afcf653902f7d727afae672d7d06a5c44d221",
    },
}


def edge_document(edge):
    return {
        "edge_id": rd.edge_identity(edge),
        "a": edge.a,
        "b": edge.b,
        "journey": edge.journey,
        "artifacts": dict(edge.artifacts),
        "direction": edge.direction,
    }


def incident_exception(graph):
    edges = [
        edge_document(edge)
        for edge in graph.runtime_contracts
        if edge.a in VERSIONS or edge.b in VERSIONS
    ]
    edges.sort(key=lambda item: item["edge_id"])
    return {
        "schema": "aweb.release.adopted-preplan-exception.v1",
        "exception_authorization": {
            "authorization_id": "exception-decision-2026-08-05",
            "authorized_by": "did:key:release-authority",
        },
        "source_sha": SOURCE,
        "reason": "recover preserved dual-lane stages after a partial immutable effect",
        "one_shot": True,
        "components": {
            name: {
                "version": VERSIONS[name],
                "lane_ref": copy.deepcopy(REFS[name]),
                "manifest_digest": MANIFESTS[name],
                "payload_digests": copy.deepcopy(PAYLOADS[name]),
            }
            for name in ("channel", "pi")
        },
        "runtime_edges": edges,
        "observed_partial_state": {
            "channel": {
                "tag": {
                    "name": "channel-v1.7.2",
                    "status": "present",
                    "source_sha": SOURCE,
                },
                "registry": {"status": "absent", "digest_set": None},
            },
            "pi": {
                "tag": {
                    "name": "pi-v0.3.2",
                    "status": "absent",
                    "source_sha": None,
                },
                "registry": {"status": "absent", "digest_set": None},
            },
        },
        "history": [
            {
                "component": "channel",
                "kind": "publish-continuation",
                "run_id": "31048478751",
                "outcome": "failed",
                "authorization_id": "spent-incident-authorization",
                "authorizing": False,
            }
        ],
    }


def canonical(value):
    return rd.canonical_json_bytes(value)


class MemoryAuthority:
    def __init__(self):
        self.records = {}

    def expected_digest(self, artifact_id):
        return self.records.get(artifact_id)

    def record(self, artifact_id, digest):
        if artifact_id in self.records:
            raise rd.ReceiptError(f"duplicate authority record {artifact_id}")
        self.records[artifact_id] = digest

    def recorded_ids(self):
        return sorted(self.records)


class MemoryStore:
    def __init__(self):
        self.data = {}

    def put(self, artifact_id, data):
        if artifact_id in self.data:
            raise rd.ReceiptError(f"duplicate store record {artifact_id}")
        self.data[artifact_id] = data

    def get(self, artifact_id):
        if artifact_id not in self.data:
            raise rd.ReceiptError(f"missing store record {artifact_id}")
        return self.data[artifact_id]


class SimulatedCrash(RuntimeError):
    pass


class FakeRecoverySurface:
    def __init__(self, document):
        self.document = copy.deepcopy(document)
        self.public = copy.deepcopy(document["observed_partial_state"])
        self.adopt_calls = []
        self.stage_calls = 0
        self.publish_calls = []
        self.verify_calls = []
        self.runs = {name: [] for name in document["components"]}
        self.run_conclusions = {}
        self.run_attempt_artifact_ids = {}
        self.adopt_failure = None
        self.stage_mutation = None
        self.publish_mode = {}

    def has_lane(self, component):
        return component in self.document["components"]

    def stage(self, node):
        self.stage_calls += 1
        raise AssertionError("adopted-preplan recovery must never call stage()")

    def _entry(self, component, phase="staged"):
        spec = self.document["components"][component]
        return rd.ReceiptEntry(
            version=spec["version"],
            digest=rd.canonical_digest_of_set(spec["payload_digests"]),
            phase=phase,
            digest_set=copy.deepcopy(spec["payload_digests"]),
            lane_ref=copy.deepcopy(spec["lane_ref"]),
            delivery_proof={
                "obligation": "delivery-restart-proof",
                "evidence_id": f"restart:{component}",
                # A real content digest: the check now requires the proof to
                # address evidence an authority can confirm, so a placeholder
                # is exactly what must be refused.
                "digest": hashlib.sha256(
                    f"restart evidence for {component}".encode()
                ).hexdigest(),
            },
        )

    def adopt_preplan(self, node):
        self.adopt_calls.append(node.component)
        if self.adopt_failure == node.component:
            raise rd.ReceiptError(f"{node.component}: independent digest mismatch")
        entry = self._entry(node.component)
        manifest_digest = self.document["components"][node.component][
            "manifest_digest"
        ]
        adopted = rd.AdoptedStageEntry(
            entry=entry,
            manifest_digest=manifest_digest,
        )
        if self.stage_mutation is not None:
            adopted = self.stage_mutation(node.component, adopted)
        return adopted

    def observe_recovery(self, node, staged):
        state = copy.deepcopy(self.public[node.component])
        entry = (
            self._entry(node.component, phase="published")
            if state["registry"]["status"] == "exact"
            else None
        )
        return rd.ObservedRecoveryState(public=state, entry=entry)

    def continuation_snapshot(self, node):
        runs = self.runs[node.component]
        return [] if not runs else [runs[-1]]

    def _complete(self, component, run_id):
        self.public[component] = {
            "tag": {
                "name": self.document["observed_partial_state"][component]["tag"]["name"],
                "status": "present",
                "source_sha": SOURCE,
            },
            "registry": {
                "status": "exact",
                "digest_set": copy.deepcopy(PAYLOADS[component]),
            },
        }
        self.run_conclusions[run_id] = "success"

    def publish_recovery(
        self, node, staged, *, before_run_ids, attempt_artifact_id
    ):
        component = node.component
        self.publish_calls.append(component)
        self.assert_snapshot(component, before_run_ids)
        mode = self.publish_mode.get(component, "success")
        if mode == "dispatch-failure":
            raise rd.ReceiptError(f"{component}: dispatch failed before a run existed")
        run_id = f"continuation-{component}-{len(self.runs[component]) + 1}"
        self.runs[component].append(run_id)
        self.run_attempt_artifact_ids[run_id] = attempt_artifact_id
        if mode == "failure":
            self.run_conclusions[run_id] = "failure"
            raise rd.ReceiptError(f"{component}: continuation failed")
        self._complete(component, run_id)
        if mode == "crash":
            raise SimulatedCrash(f"crash after {component} effect")
        return rd.RecoveryContinuation(
            entry=self._entry(component, phase="published"),
            continuation_run_id=run_id,
            attempt_artifact_id=attempt_artifact_id,
        )

    def recover_recovery_attempt(
        self, node, staged, *, before_run_ids, attempt_artifact_id
    ):
        component = node.component
        runs = self.runs[component]
        if before_run_ids:
            if len(before_run_ids) != 1 or before_run_ids[0] not in runs:
                raise rd.ReceiptError(
                    f"{component}: incomplete run enumeration; boundary missing"
                )
            new_runs = runs[runs.index(before_run_ids[0]) + 1:]
        else:
            new_runs = list(runs)
        matching_runs = [
            run_id for run_id in new_runs
            if self.run_attempt_artifact_ids.get(run_id) == attempt_artifact_id
        ]
        if not matching_runs:
            return None
        if len(matching_runs) != 1:
            raise rd.ReceiptError(
                f"{component}: expected exactly one owned continuation run"
            )
        run_id = matching_runs[0]
        if self.run_conclusions.get(run_id) != "success":
            raise rd.ReceiptError(f"{component}: prior continuation was not successful")
        observed = self.observe_recovery(node, staged)
        if observed.entry is None:
            raise rd.ReceiptError(f"{component}: successful run has no exact effect")
        return rd.RecoveryContinuation(
            entry=observed.entry,
            continuation_run_id=run_id,
            attempt_artifact_id=self.run_attempt_artifact_ids.get(run_id),
        )

    def assert_snapshot(self, component, before_run_ids):
        runs = self.runs[component]
        current = [] if not runs else [runs[-1]]
        if list(before_run_ids) != current:
            raise rd.ReceiptError(f"{component}: continuation snapshot drifted")

    def verify(self, node, published):
        self.verify_calls.append(node.component)
        observed = self.observe_recovery(node, published)
        if observed.entry is None or observed.entry.digest != published.digest:
            raise rd.ReceiptError(f"{node.component}: verification failed")


class AdoptedPreplanContractTests(unittest.TestCase):
    def setUp(self):
        self.graph = rd.Graph.load(rd.GRAPH_PATH)
        self.document = incident_exception(self.graph)

    def load(self, document=None):
        return rd.load_adopted_preplan_exception(
            canonical(document or self.document), graph=self.graph
        )

    def test_incident_is_only_a_typed_generic_fixture(self):
        exception = self.load()
        self.assertEqual(exception.source_sha, SOURCE)
        self.assertEqual(list(exception.components), ["channel", "pi"])
        self.assertEqual(
            {item["edge_id"] for item in exception.runtime_edges},
            {
                rd.edge_identity(edge)
                for edge in self.graph.runtime_contracts
                if edge.a in VERSIONS or edge.b in VERSIONS
            },
        )
        self.assertEqual(exception.history[0]["run_id"], "31048478751")
        self.assertFalse(exception.history[0]["authorizing"])

    def test_exception_schema_refuses_missing_extra_wrong_and_reused_identity(self):
        mutations = {}

        missing = copy.deepcopy(self.document)
        missing.pop("reason")
        mutations["missing"] = missing

        extra = copy.deepcopy(self.document)
        extra["supported_versions"] = {"channel": ["1.7.2"]}
        mutations["extra"] = extra

        bad_source = copy.deepcopy(self.document)
        bad_source["source_sha"] = "f" * 39
        mutations["source"] = bad_source

        bad_auth = copy.deepcopy(self.document)
        bad_auth["exception_authorization"]["authorized_by"] = ""
        mutations["auth"] = bad_auth

        bad_scope = copy.deepcopy(self.document)
        bad_scope["one_shot"] = False
        mutations["one-shot"] = bad_scope

        one_lane = copy.deepcopy(self.document)
        one_lane["components"].pop("pi")
        one_lane["observed_partial_state"].pop("pi")
        mutations["one lane"] = one_lane

        reused = copy.deepcopy(self.document)
        reused["components"]["pi"]["lane_ref"] = copy.deepcopy(
            reused["components"]["channel"]["lane_ref"]
        )
        mutations["reused lane"] = reused

        wrong_edge = copy.deepcopy(self.document)
        wrong_edge["runtime_edges"][0]["journey"] = "different journey"
        mutations["edge"] = wrong_edge

        wrong_version = copy.deepcopy(self.document)
        wrong_version["components"]["pi"]["version"] = ""
        mutations["version"] = wrong_version

        bad_digest = copy.deepcopy(self.document)
        bad_digest["components"]["pi"]["manifest_digest"] = "sha256:short"
        mutations["digest"] = bad_digest

        authorizing_history = copy.deepcopy(self.document)
        authorizing_history["history"][0]["authorizing"] = True
        mutations["history"] = authorizing_history

        for name, document in mutations.items():
            with self.subTest(name=name), self.assertRaises(rd.ReceiptError):
                self.load(document)

    def test_versions_runs_and_stage_identities_are_not_incident_hardcoded(self):
        future = copy.deepcopy(self.document)
        future["components"]["channel"].update({
            "version": "1.8.0",
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:41048187475:9947308273",
                "aw_source_sha": SOURCE,
                "zip_digest": "sha256:" + "1" * 64,
            },
            "manifest_digest": "sha256:" + "2" * 64,
            "payload_digests": {"channel-1.8.0.tgz": "3" * 64},
        })
        future["components"]["pi"].update({
            "version": "0.4.0",
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:41048197476:9947313121",
                "aw_source_sha": SOURCE,
                "zip_digest": "sha256:" + "4" * 64,
            },
            "manifest_digest": "sha256:" + "5" * 64,
            "payload_digests": {"pi-0.4.0.tgz": "6" * 64},
        })
        future["observed_partial_state"]["channel"] = {
            "tag": {"name": "channel-v1.8.0", "status": "absent",
                    "source_sha": None},
            "registry": {"status": "absent", "digest_set": None},
        }
        future["observed_partial_state"]["pi"] = {
            "tag": {"name": "pi-v0.4.0", "status": "absent",
                    "source_sha": None},
            "registry": {"status": "absent", "digest_set": None},
        }
        future["history"][0]["run_id"] = "future-failed-run"
        loaded = self.load(future)
        self.assertEqual(loaded.components["channel"]["version"], "1.8.0")
        self.assertEqual(loaded.history[0]["run_id"], "future-failed-run")

    def test_noncanonical_exception_bytes_refuse(self):
        pretty = __import__("json").dumps(self.document, indent=2).encode()
        with self.assertRaises(rd.ReceiptError):
            rd.load_adopted_preplan_exception(pretty, graph=self.graph)


class AdoptedPreplanStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.graph = rd.Graph.load(rd.GRAPH_PATH)
        self.document = incident_exception(self.graph)
        self.exception = rd.load_adopted_preplan_exception(
            canonical(self.document), graph=self.graph
        )
        self.store = MemoryStore()
        self.authority = MemoryAuthority()
        self.surface = FakeRecoverySurface(self.document)

    def prepare(self, **kwargs):
        return rd.prepare_adopted_preplan_recovery(
            self.exception,
            graph=self.graph,
            lanes=kwargs.get("lanes", self.surface),
            store=self.store,
            authority=self.authority,
            authority_trust=kwargs.get("authority_trust", "external-immutable"),
        )

    def authorization(self, handle, *, authorization_id="new-human-decision",
                      components=("channel", "pi")):
        return {
            "schema": "aweb.release.adopted-preplan-authorization.v1",
            "authorization_id": authorization_id,
            "authorized_by": "did:key:release-authority",
            "issued_at": "2026-08-06T00:00:00Z",
            "one_shot": True,
            "exception_digest": self.exception.digest,
            "recovery_plan_id": handle.plan_id,
            "actions": [
                {
                    "component": name,
                    "kind": "publish-continuation",
                    "version": VERSIONS[name],
                    "lane_ref": copy.deepcopy(REFS[name]),
                }
                for name in components
            ],
        }

    def execute(self, handle, authorization=None):
        return rd.execute_adopted_preplan_recovery(
            handle,
            canonical(authorization or self.authorization(handle)),
            graph=self.graph,
            lanes=self.surface,
            store=self.store,
            authority=self.authority,
            authority_trust="external-immutable",
            approvals={},
        )

    def test_prepare_uses_joint_adoption_barrier_and_never_stage(self):
        handle = self.prepare()
        self.assertEqual(self.surface.adopt_calls, ["channel", "pi"])
        self.assertEqual(self.surface.stage_calls, 0)
        self.assertEqual(handle.manifest["provenance"], "adopted-preplan")
        self.assertTrue(handle.exception_artifact_id in self.authority.records)
        self.assertTrue(handle.plan_artifact_id in self.authority.records)
        self.assertTrue(handle.manifest_artifact_id in self.authority.records)

    def test_second_lane_failure_anchors_no_manifest_and_dispatches_nothing(self):
        self.surface.adopt_failure = "pi"
        with self.assertRaises(rd.ReceiptError):
            self.prepare()
        self.assertEqual(self.surface.publish_calls, [])
        self.assertFalse(any(
            item.startswith("adopted-preplan-manifest:")
            for item in self.authority.records
        ))

    def test_stage_evidence_mismatch_refuses_at_joint_barrier(self):
        def mutate(kind, component, adopted):
            if component != "pi":
                return adopted
            if kind == "manifest":
                return rd.AdoptedStageEntry(
                    entry=adopted.entry,
                    manifest_digest="sha256:" + "0" * 64,
                )
            entry = adopted.entry
            values = {
                "version": entry.version,
                "digest": entry.digest,
                "digest_set": copy.deepcopy(entry.digest_set),
                "lane_ref": copy.deepcopy(entry.lane_ref),
            }
            if kind == "version":
                values["version"] = "9.9.9"
            elif kind == "source":
                values["lane_ref"]["aw_source_sha"] = "f" * 40
            else:
                values["digest_set"] = {"wrong.tgz": "0" * 64}
                values["digest"] = rd.canonical_digest_of_set(
                    values["digest_set"]
                )
            return rd.AdoptedStageEntry(
                entry=rd.ReceiptEntry(**values),
                manifest_digest=adopted.manifest_digest,
            )

        for kind in ("manifest", "version", "source", "payload"):
            with self.subTest(kind=kind):
                self.store, self.authority = MemoryStore(), MemoryAuthority()
                self.surface = FakeRecoverySurface(self.document)
                self.surface.stage_mutation = (
                    lambda component, adopted, kind=kind:
                        mutate(kind, component, adopted)
                )
                with self.assertRaises(rd.ReceiptError):
                    self.prepare()
                self.assertEqual(self.surface.publish_calls, [])

    def test_partial_state_drift_refuses_before_attempt(self):
        drifts = []
        wrong_tag = copy.deepcopy(self.surface.public)
        wrong_tag["channel"]["tag"]["source_sha"] = "f" * 40
        drifts.append(wrong_tag)
        pi_tag = copy.deepcopy(self.surface.public)
        pi_tag["pi"]["tag"] = {
            "name": "pi-v0.3.2", "status": "present", "source_sha": SOURCE,
        }
        drifts.append(pi_tag)
        premature_registry = copy.deepcopy(self.surface.public)
        premature_registry["pi"]["registry"] = {
            "status": "exact", "digest_set": copy.deepcopy(PAYLOADS["pi"]),
        }
        drifts.append(premature_registry)
        wrong_registry = copy.deepcopy(self.surface.public)
        wrong_registry["channel"]["registry"] = {
            "status": "exact", "digest_set": {"x.tgz": "0" * 64},
        }
        drifts.append(wrong_registry)

        for public in drifts:
            with self.subTest(public=public):
                store, authority = MemoryStore(), MemoryAuthority()
                surface = FakeRecoverySurface(self.document)
                surface.public = public
                with self.assertRaises(rd.ReceiptError):
                    rd.prepare_adopted_preplan_recovery(
                        self.exception, graph=self.graph, lanes=surface,
                        store=store, authority=authority,
                        authority_trust="external-immutable",
                    )
                self.assertEqual(surface.publish_calls, [])

    def test_local_authority_refuses_before_store_or_lane_calls(self):
        with self.assertRaises(rd.ReceiptError):
            self.prepare(authority_trust="local-development")
        self.assertEqual(self.store.data, {})
        self.assertEqual(self.surface.adopt_calls, [])

    def test_authorization_is_exact_new_and_action_bound(self):
        handle = self.prepare()
        variants = []
        old = self.authorization(
            handle, authorization_id="spent-incident-authorization"
        )
        variants.append(old)
        wrong_subject = self.authorization(handle)
        wrong_subject["authorized_by"] = "did:key:someone-else"
        variants.append(wrong_subject)
        wrong_plan = self.authorization(handle)
        wrong_plan["recovery_plan_id"] = "0" * 64
        variants.append(wrong_plan)
        wrong_exception = self.authorization(handle)
        wrong_exception["exception_digest"] = "0" * 64
        variants.append(wrong_exception)
        missing_action = self.authorization(handle, components=("channel",))
        variants.append(missing_action)
        wrong_version = self.authorization(handle)
        wrong_version["actions"][1]["version"] = "9.9.9"
        variants.append(wrong_version)
        extra = self.authorization(handle)
        extra["actions"][0]["retry"] = True
        variants.append(extra)

        for document in variants:
            with self.subTest(document=document), self.assertRaises(rd.ReceiptError):
                self.execute(handle, document)
        self.assertEqual(self.surface.publish_calls, [])
        self.assertFalse(any(
            item.startswith("adopted-preplan-authorization:")
            for item in self.authority.records
        ), "invalid authorization must fail before authority anchoring")

    def test_tampered_frozen_handle_refuses_before_authorization_or_dispatch(self):
        handle = self.prepare()
        handle.plan["provenance"] = "ordinary-plan-stage"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle)
        self.assertEqual(self.surface.publish_calls, [])
        self.assertFalse(any(
            item.startswith("adopted-preplan-authorization:")
            for item in self.authority.records
        ))

    def test_malformed_authority_transition_cannot_skip_a_lane(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        auth_digest = __import__("hashlib").sha256(
            canonical(authorization)
        ).hexdigest()
        forged = {
            "schema": "aweb.release.adopted-preplan-transition.v1",
            "recovery_plan_id": handle.plan_id,
            "adopted_manifest_id": handle.manifest_id,
            "component": "channel",
            "authorization_digest": auth_digest,
        }
        data = canonical(forged)
        digest = __import__("hashlib").sha256(data).hexdigest()
        artifact_id = (
            f"adopted-preplan-transition:{handle.plan_id}:channel:{digest}"
        )
        self.store.put(artifact_id, data)
        self.authority.record(artifact_id, digest)
        self.surface._complete("channel", "forged-unreceipted-run")
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, authorization)
        self.assertEqual(self.surface.publish_calls, [])

    def test_same_authorization_id_cannot_be_reencoded_for_a_retry(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        self.surface.publish_mode["channel"] = "failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, authorization)
        self.assertEqual(self.surface.publish_calls, ["channel"])

        reencoded = copy.deepcopy(authorization)
        reencoded["issued_at"] = "2026-08-06T00:00:01Z"
        self.surface.publish_mode["channel"] = "success"
        with self.assertRaises(rd.ReceiptError) as caught:
            self.execute(handle, reencoded)
        self.assertIn("authorization_id", str(caught.exception))
        self.assertEqual(
            self.surface.publish_calls, ["channel"],
            "same human decision identity must not dispatch under new bytes",
        )

    def test_genuinely_distinct_authorization_id_can_authorize_a_new_attempt(self):
        handle = self.prepare()
        first = self.authorization(handle, authorization_id="decision-one")
        self.surface.publish_mode["channel"] = "failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, first)
        second = self.authorization(handle, authorization_id="decision-two")
        second["issued_at"] = "2026-08-06T00:00:02Z"
        self.surface.publish_mode["channel"] = "success"
        receipt = self.execute(handle, second)
        self.assertEqual(self.surface.publish_calls, ["channel", "channel", "pi"])
        self.assertEqual(receipt.document["authorization_id"], "decision-two")

    def test_current_authorization_attempt_is_adopted_amid_older_history(self):
        handle = self.prepare()
        first = self.authorization(handle, authorization_id="decision-one")
        self.surface.publish_mode["channel"] = "dispatch-failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, first)
        self.assertEqual(self.surface.runs["channel"], [])

        second = self.authorization(handle, authorization_id="decision-two")
        second["issued_at"] = "2026-08-06T00:00:02Z"
        self.surface.publish_mode["channel"] = "crash"
        with self.assertRaises(SimulatedCrash):
            self.execute(handle, second)
        self.assertEqual(self.surface.publish_calls, ["channel", "channel"])
        attempts = rd._attempts(
            handle, self.store, self.authority, "channel"
        )
        self.assertEqual(
            [document["attempt_ordinal"] for _, document in attempts],
            [1, 2],
        )
        self.assertEqual(
            attempts[1][1]["predecessor_attempt_artifact_ids"],
            [attempts[0][0]],
        )

        resumed_handle = self.prepare()
        self.surface.publish_mode["channel"] = "success"
        with self.assertRaises(rd.ReceiptError) as caught:
            self.execute(resumed_handle, first)
        self.assertIn("superseded", str(caught.exception))
        self.assertEqual(
            self.surface.publish_calls,
            ["channel", "channel"],
            "superseded A must not adopt B's run or dispatch another effect",
        )

        receipt = self.execute(resumed_handle, second)
        self.assertEqual(
            self.surface.publish_calls,
            ["channel", "channel", "pi"],
            "exact current attempt must be adopted without channel redispatch",
        )
        self.assertEqual(receipt.document["authorization_id"], "decision-two")
        self.assertEqual(
            receipt.document["components"]["channel"]["continuation_run_id"],
            "continuation-channel-1",
        )

    def test_owned_crash_run_is_adopted_amid_unrelated_run(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        self.surface.publish_mode["channel"] = "dispatch-failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, authorization)
        attempt_id = rd._attempts(
            handle, self.store, self.authority, "channel"
        )[0][0]

        self.surface.runs["channel"].extend([
            "unrelated-success", "owned-success",
        ])
        self.surface.run_conclusions.update({
            "unrelated-success": "success",
            "owned-success": "success",
        })
        self.surface.run_attempt_artifact_ids.update({
            "unrelated-success": "unrelated-attempt",
            "owned-success": attempt_id,
        })
        self.surface._complete("channel", "owned-success")

        resumed_handle = self.prepare()
        receipt = self.execute(resumed_handle, authorization)
        self.assertEqual(
            self.surface.publish_calls, ["channel", "pi"],
            "owned Channel effect is adopted and Pi completes once",
        )
        self.assertEqual(
            receipt.document["components"]["channel"]["continuation_run_id"],
            "owned-success",
        )

    def test_multiple_owned_runs_refuse_before_transition_or_other_lane(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        self.surface.publish_mode["channel"] = "dispatch-failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, authorization)
        attempt_id = rd._attempts(
            handle, self.store, self.authority, "channel"
        )[0][0]

        self.surface.runs["channel"].extend(["owned-one", "owned-two"])
        self.surface.run_conclusions.update({
            "owned-one": "success", "owned-two": "success",
        })
        self.surface.run_attempt_artifact_ids.update({
            "owned-one": attempt_id, "owned-two": attempt_id,
        })
        self.surface._complete("channel", "owned-one")

        resumed_handle = self.prepare()
        with self.assertRaises(rd.ReceiptError) as caught:
            self.execute(resumed_handle, authorization)
        self.assertIn("exactly one", str(caught.exception))
        self.assertEqual(self.surface.publish_calls, ["channel"])
        self.assertFalse(any(
            artifact_id.startswith("adopted-preplan-transition:")
            or artifact_id.startswith("adopted-preplan-receipt:")
            for artifact_id in self.authority.records
        ))

    def test_unowned_successful_run_cannot_be_adopted_as_current_attempt(self):
        for observed_attempt_id in (None, "different-attempt"):
            with self.subTest(observed_attempt_id=observed_attempt_id):
                self.store, self.authority = MemoryStore(), MemoryAuthority()
                self.surface = FakeRecoverySurface(self.document)
                handle = self.prepare()
                authorization = self.authorization(handle)
                self.surface.publish_mode["channel"] = "dispatch-failure"
                with self.assertRaises(rd.ReceiptError):
                    self.execute(handle, authorization)

                run_id = "sole-unrelated-success"
                self.surface.runs["channel"].append(run_id)
                self.surface._complete("channel", run_id)
                if observed_attempt_id is not None:
                    self.surface.run_attempt_artifact_ids[run_id] = (
                        observed_attempt_id
                    )

                resumed_handle = self.prepare()
                with self.assertRaises(rd.ReceiptError) as caught:
                    self.execute(resumed_handle, authorization)
                self.assertIn("attempt", str(caught.exception))
                self.assertEqual(
                    self.surface.publish_calls, ["channel"],
                    "unowned run evidence must not dispatch Pi",
                )
                self.assertFalse(any(
                    artifact_id.startswith("adopted-preplan-transition:")
                    or artifact_id.startswith("adopted-preplan-receipt:")
                    for artifact_id in self.authority.records
                ), "unowned run must refuse before transition or receipt")

    def test_failure_stops_other_lane_and_same_authorization_is_spent(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        self.surface.publish_mode["channel"] = "failure"
        with self.assertRaises(rd.ReceiptError):
            self.execute(handle, authorization)
        self.assertEqual(self.surface.publish_calls, ["channel"])
        self.assertTrue(any(
            item.startswith(
                f"adopted-preplan-attempt:{handle.plan_id}:channel:"
            )
            for item in self.authority.records
        ), "attempt authority must precede the failed outward call")
        with self.assertRaises(rd.ReceiptError) as caught:
            self.execute(handle, authorization)
        self.assertIn("spent", str(caught.exception))
        self.assertEqual(self.surface.publish_calls, ["channel"])

    def test_crash_resume_adopts_exact_effect_without_redispatch_or_restage(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        self.surface.publish_mode["channel"] = "crash"
        with self.assertRaises(SimulatedCrash):
            self.execute(handle, authorization)
        self.assertEqual(self.surface.publish_calls, ["channel"])
        self.assertEqual(self.surface.stage_calls, 0)

        # Reconstructing preparation in a fresh process revalidates the
        # preserved artifacts but accepts only the exact effect backed by the
        # persisted attempt. It still never calls stage() or redispatches it.
        resumed_handle = self.prepare()
        self.surface.publish_mode["channel"] = "success"
        receipt = self.execute(resumed_handle, authorization)
        self.assertEqual(self.surface.publish_calls, ["channel", "pi"])
        self.assertEqual(self.surface.stage_calls, 0)
        self.assertEqual(
            receipt.document["components"]["channel"]["continuation_run_id"],
            "continuation-channel-1",
        )

    def test_dedicated_cli_command_uses_typed_documents(self):
        handle = self.prepare()
        authorization = self.authorization(handle)
        with tempfile.TemporaryDirectory() as tmp:
            exception_path = Path(tmp) / "exception.json"
            authorization_path = Path(tmp) / "authorization.json"
            exception_path.write_bytes(canonical(self.document))
            authorization_path.write_bytes(canonical(authorization))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = rd.main(
                    [
                        "--graph", str(rd.GRAPH_PATH),
                        "adopted-preplan-recovery",
                        "--exception-file", str(exception_path),
                        "--authorization-file", str(authorization_path),
                    ],
                    providers=rd.Providers(
                        store=self.store,
                        authority=self.authority,
                        lanes=self.surface,
                        authority_trust="external-immutable",
                    ),
                )
        self.assertEqual(result, 0)
        rendered = __import__("json").loads(output.getvalue())
        self.assertEqual(rendered["schema"],
                         "aweb.release.adopted-preplan-receipt.v1")
        self.assertEqual(self.surface.stage_calls, 0)

    def test_final_receipt_is_honest_unmeasured_and_exact(self):
        handle = self.prepare()
        receipt = self.execute(handle)
        body = receipt.document
        self.assertEqual(body["schema"], "aweb.release.adopted-preplan-receipt.v1")
        self.assertEqual(body["provenance"], "adopted-preplan")
        self.assertEqual(body["exception_digest"], self.exception.digest)
        self.assertEqual(body["adopted_manifest_id"], handle.manifest_id)
        self.assertIn(body["authorization_artifact_id"], self.authority.records)
        self.assertEqual(
            self.authority.expected_digest(body["authorization_artifact_id"]),
            body["authorization_digest"],
        )
        self.assertEqual(body["support"]["status"], "incomplete-unmeasured")
        self.assertNotIn("supported_versions", body["support"])
        self.assertEqual(
            set(body["support"]["runtime_edge_ids"]),
            {item["edge_id"] for item in self.document["runtime_edges"]},
        )
        for component in ("channel", "pi"):
            entry = body["components"][component]
            self.assertEqual(entry["stage"]["provenance"], "adopted-preplan")
            self.assertEqual(entry["stage"]["lane_ref"], REFS[component])
            self.assertEqual(entry["stage"]["manifest_digest"], MANIFESTS[component])
            self.assertEqual(entry["published"]["digest_set"], PAYLOADS[component])
            self.assertEqual(entry["final_state"]["tag"]["source_sha"], SOURCE)
            self.assertTrue(entry["continuation_run_id"])
        loaded = rd.load_adopted_preplan_receipt(
            self.store.get(receipt.artifact_id),
            expected_digest=self.authority.expected_digest(receipt.artifact_id),
            handle=handle,
        )
        self.assertEqual(loaded, body)

        for mutation in ("measured", "plan-stage"):
            tampered = copy.deepcopy(body)
            if mutation == "measured":
                tampered["support"]["supported_versions"] = {
                    "channel": ["1.7.2"]
                }
            else:
                tampered["components"]["channel"]["stage"][
                    "provenance"
                ] = "staged-after-plan"
            tampered_bytes = canonical(tampered)
            with self.subTest(mutation=mutation), self.assertRaises(rd.ReceiptError):
                rd.load_adopted_preplan_receipt(
                    tampered_bytes,
                    expected_digest=__import__("hashlib").sha256(
                        tampered_bytes
                    ).hexdigest(),
                    handle=handle,
                )


if __name__ == "__main__":
    unittest.main(verbosity=1)
