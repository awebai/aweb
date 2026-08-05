"""aweb-abbe.2.1: the external workflow-artifact store/authority adapter and
the one-SHA-256 lane observers. No network: the GitHub API and downloads
arrive through injected reader callables, filled from fixtures shaped like
the real API responses measured on awebai/aw.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeGithubApi:
    """Answers the exact API shapes the adapter reads: artifact metadata,
    run metadata, and the raw artifact ZIP."""

    def __init__(self, *, repo="awebai/aw", run_id=30977506589,
                 artifact_id=8918869285, zip_bytes=b"zip-bytes",
                 expired=False, conclusion="success", head_repo=None,
                 owning_run=None, digest=None,
                 workflow_path=".github/workflows/aw-release.yml"):
        self.repo = repo
        self.run_id = run_id
        self.artifact_id = artifact_id
        self.zip_bytes = zip_bytes
        self.expired = expired
        self.conclusion = conclusion
        self.head_repo = head_repo or repo
        self.owning_run = owning_run if owning_run is not None else run_id
        self.digest = digest or f"sha256:{sha256(zip_bytes)}"
        self.workflow_path = workflow_path
        self.calls: list[str] = []

    def __call__(self, path: str) -> bytes:
        self.calls.append(path)
        if path == f"repos/{self.repo}/actions/artifacts/{self.artifact_id}":
            return json.dumps({
                "id": self.artifact_id,
                "workflow_run": {"id": self.owning_run},
                "expired": self.expired,
                "digest": self.digest,
            }).encode()
        if path == f"repos/{self.repo}/actions/runs/{self.run_id}":
            return json.dumps({
                "conclusion": self.conclusion,
                "head_repository": {"full_name": self.head_repo},
                "path": self.workflow_path,
            }).encode()
        if path == f"repos/{self.repo}/actions/artifacts/{self.artifact_id}/zip":
            return self.zip_bytes
        raise AssertionError(f"unexpected API path {path}")


def artifact_id_for(api: FakeGithubApi) -> str:
    return f"gh-artifact:{api.repo}:{api.run_id}:{api.artifact_id}"


class ExternalStoreTests(unittest.TestCase):
    def test_exact_artifact_bytes_are_returned(self) -> None:
        api = FakeGithubApi()
        store = rd.GithubArtifactStore(api=api)
        data = store.get(artifact_id_for(api))
        self.assertEqual(data, api.zip_bytes)

    def test_foreign_repository_is_refused(self) -> None:
        api = FakeGithubApi()
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("gh-artifact:evil/aw:1:2")
        self.assertIn("evil/aw", str(caught.exception))

    def test_expired_artifact_is_refused(self) -> None:
        api = FakeGithubApi(expired=True)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("expired", str(caught.exception))

    def test_unsuccessful_run_is_refused(self) -> None:
        api = FakeGithubApi(conclusion="failure")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("success", str(caught.exception))

    def test_fork_run_is_refused(self) -> None:
        api = FakeGithubApi(head_repo="fork/aw")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError):
            store.get(artifact_id_for(api))

    def test_artifact_of_another_run_is_refused(self) -> None:
        api = FakeGithubApi(owning_run=999)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("belong", str(caught.exception))

    def test_wrong_workflow_path_is_refused(self) -> None:
        """alice's finding: any successful artifact-producing workflow in the
        repo was accepted. The lane binds exactly aw-release.yml."""
        api = FakeGithubApi(workflow_path=".github/workflows/other.yml")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("aw-release.yml", str(caught.exception))

    def test_zip_digest_must_equal_api_digest(self) -> None:
        api = FakeGithubApi(digest="sha256:" + "0" * 64)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("digest", str(caught.exception))

    def test_store_is_never_writable(self) -> None:
        store = rd.GithubArtifactStore(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            store.put("gh-artifact:awebai/aw:1:2", b"data")


class ExternalAuthorityTests(unittest.TestCase):
    def test_expected_digest_is_the_api_digest_bare_hex(self) -> None:
        api = FakeGithubApi()
        authority = rd.GithubArtifactDigestAuthority(api=api)
        self.assertEqual(
            authority.expected_digest(artifact_id_for(api)),
            sha256(api.zip_bytes),
        )

    def test_record_refuses_external_authority_is_not_caller_writable(self) -> None:
        authority = rd.GithubArtifactDigestAuthority(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            authority.record("gh-artifact:awebai/aw:1:2", "d" * 64)

    def test_foreign_repository_is_refused(self) -> None:
        authority = rd.GithubArtifactDigestAuthority(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("gh-artifact:evil/aw:1:2")


class RegistrationTests(unittest.TestCase):
    def test_kind_is_allowlisted_external_immutable_with_own_store(self) -> None:
        registration = rd.AUTHORITY_ALLOWLIST["github-workflow-artifacts"]
        self.assertEqual(registration.trust_class, "external-immutable")
        self.assertIsNotNone(registration.store_factory)

    def test_cli_exposes_the_kind_for_a_fresh_process(self) -> None:
        self.assertIn("github-workflow-artifacts", rd.AUTHORITY_ALLOWLIST)
        providers = rd.build_providers(
            store=None,
            authority_registration=rd.AUTHORITY_ALLOWLIST["github-workflow-artifacts"],
        )
        self.assertEqual(providers.authority_trust, "external-immutable")
        self.assertIsInstance(providers.store, rd.GithubAnchorStore)
        self.assertIsInstance(providers.authority, rd.GithubAnchorDigestAuthority)


def anchor_artifact_zip(logical_id: str, body: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("record.json", json.dumps(
            {"logical_id": logical_id, "digest": sha256(body)}
        ))
        z.writestr("body", body)
    return buffer.getvalue()


class FakeAnchorTransport:
    """In-memory anchors backend honoring the deterministic-name contract:
    dispatch materializes a real artifact ZIP after `latency` polls, the
    listing carries API digests and expiry, and everything is enumerable."""

    def __init__(self, latency: int = 0, *, run_path=None, run_conclusion=None):
        self.artifacts: list[dict] = []
        self.dispatches: list[tuple[str, str]] = []
        self._pending: list[tuple[int, dict]] = []
        self.latency = latency
        self._next_id = 1
        self._run_path = run_path or ".github/workflows/release-anchor.yml"
        self._run_conclusion = run_conclusion or "success"

    def _materialize(self, logical_id: str, body: bytes, *, expired=False):
        digest = sha256(body)
        name = f"anchor--{sha256(logical_id.encode())}--{digest}"
        zip_bytes = anchor_artifact_zip(logical_id, body)
        entry = {
            "id": self._next_id,
            "name": name,
            "digest": f"sha256:{sha256(zip_bytes)}",
            "expired": expired,
            "workflow_run": {"id": 7000 + self._next_id},
            "_zip": zip_bytes,
        }
        self._next_id += 1
        return entry

    def anchor_run(self, run_id) -> dict:
        return {
            "path": self._run_path,
            "conclusion": self._run_conclusion,
            "head_repository": {"full_name": "awebai/aweb"},
        }

    def seed(self, logical_id: str, body: bytes, *, expired=False):
        self.artifacts.append(self._materialize(logical_id, body, expired=expired))

    def list_artifacts(self) -> list[dict]:
        still = []
        for remaining, entry in self._pending:
            if remaining <= 0:
                self.artifacts.append(entry)
            else:
                still.append((remaining - 1, entry))
        self._pending = still
        return [dict(a) for a in self.artifacts]

    def artifact_zip(self, artifact_id: int) -> bytes:
        for a in self.artifacts:
            if a["id"] == artifact_id:
                return a["_zip"]
        raise AssertionError(f"unknown artifact {artifact_id}")

    def dispatch_anchor(self, logical_id: str, digest: str, body_gzip_b64: str):
        import base64
        import gzip

        body = gzip.decompress(base64.b64decode(body_gzip_b64))
        assert sha256(body) == digest
        self.dispatches.append((logical_id, digest))
        self._pending.append((self.latency, self._materialize(logical_id, body)))


def anchor_pair(transport):
    store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
    authority = rd.GithubAnchorDigestAuthority(transport=transport)
    return store, authority


class AnchorStoreTests(unittest.TestCase):
    def test_put_dispatches_once_and_get_returns_the_body(self) -> None:
        transport = FakeAnchorTransport(latency=1)
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        self.assertEqual(len(transport.dispatches), 1)
        self.assertEqual(store.get("plan:s1:abc"), b"body-bytes")

    def test_repeated_put_reconciles_without_a_second_dispatch(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        store.put("plan:s1:abc", b"body-bytes")
        self.assertEqual(len(transport.dispatches), 1)

    def test_different_bytes_for_an_anchored_id_refuse(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        with self.assertRaises(rd.ReceiptError):
            store.put("plan:s1:abc", b"DIFFERENT")

    def test_conflicting_anchor_artifacts_refuse(self) -> None:
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"one")
        transport.artifacts.append(
            {**transport._materialize("plan:s1:abc", b"two"),
             "name": transport.artifacts[0]["name"].rsplit("--", 1)[0]
             + "--" + sha256(b"two")}
        )
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            store.get("plan:s1:abc")
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")

    def test_matching_expired_identity_refuses_reads_and_writes(self) -> None:
        """An identity whose anchor expired is compromised evidence: reads
        refuse naming expiry, and put must NOT re-anchor it."""
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"body", expired=True)
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("expired", str(caught.exception))
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")
        with self.assertRaises(rd.ReceiptError):
            store.put("plan:s1:abc", b"body")
        self.assertEqual(transport.dispatches, [])

    def test_anchor_from_a_foreign_workflow_refuses(self) -> None:
        transport = FakeAnchorTransport(run_path=".github/workflows/other.yml")
        transport.seed("plan:s1:abc", b"body")
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("release-anchor.yml", str(caught.exception))
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")
        _, fresh = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            fresh.recorded_ids()

    def test_anchor_from_a_failed_run_refuses(self) -> None:
        transport = FakeAnchorTransport(run_conclusion="failure")
        transport.seed("plan:s1:abc", b"body")
        store, _ = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            store.get("plan:s1:abc")

    def test_encoded_dispatch_payload_is_bounded(self) -> None:
        """GitHub bounds the TOTAL dispatch payload at 65,535 characters; an
        incompressible body below any raw-byte bound still overflows once
        base64-encoded and must refuse BEFORE any outward dispatch."""
        import os

        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        incompressible = os.urandom(60000)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.put("plan:big", incompressible)
        self.assertEqual(transport.dispatches, [])
        self.assertIn("dispatch payload", str(caught.exception))

    def test_zip_bytes_must_match_the_api_digest(self) -> None:
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"body")
        transport.artifacts[0]["digest"] = "sha256:" + "0" * 64
        store, _ = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("digest", str(caught.exception))

    def test_record_verifies_and_never_dispatches(self) -> None:
        transport = FakeAnchorTransport()
        store, authority = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        before = len(transport.dispatches)
        authority.record("plan:s1:abc", sha256(b"body-bytes"))
        self.assertEqual(len(transport.dispatches), before)
        with self.assertRaises(rd.ReceiptError):
            authority.record("plan:s1:abc", "0" * 64)
        with self.assertRaises(rd.ReceiptError):
            authority.record("plan:never-uploaded", sha256(b"x"))

    def test_recorded_ids_enumerate_after_a_fresh_process(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"one-body")
        store.put("staged-manifest:f:d", b"two-body")
        _, fresh_authority = anchor_pair(transport)
        self.assertEqual(
            sorted(fresh_authority.recorded_ids()),
            ["plan:s1:abc", "staged-manifest:f:d"],
        )

    def test_real_transport_paginates(self) -> None:
        pages = {
            1: {"artifacts": [{"id": 1, "name": "anchor--x--y",
                               "digest": "sha256:d", "expired": False}]},
            2: {"artifacts": [{"id": 2, "name": "anchor--a--b",
                               "digest": "sha256:e", "expired": False}]},
            3: {"artifacts": []},
        }

        def api(path):
            import re
            page = int(re.search(r"&page=(\d+)", path).group(1))
            return json.dumps(pages[page]).encode()

        transport = rd.GithubAnchorTransport(api=api)
        listed = transport.list_artifacts()
        self.assertEqual([a["id"] for a in listed], [1, 2])


def lane_payload_names(version="1.34.3"):
    """The real aw lane protocol: 14 basenames, members under dist/ or npm/."""
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


def lane_payload_bytes(version="1.34.3"):
    dist, npm = lane_payload_names(version)
    members = {f"dist/{n}": f"bytes-of-{n}".encode() for n in dist}
    members.update({f"npm/{n}": f"bytes-of-{n}".encode() for n in npm})
    return members


def lane_zip(*, mode="stage-only", source_sha="a" * 40, version="1.34.3",
             tamper_payload=False, drop_payload=False, extra_payload=False,
             break_canonical=False, duplicate_member=False) -> bytes:
    members = lane_payload_bytes(version)
    # The REAL protocol shape (proven against the run-3 artifact): ZIP
    # members carry dist/ or npm/ prefixes, manifest files keys are the 14
    # basenames.
    files = {
        name.rsplit("/", 1)[-1]: sha256(data)
        for name, data in members.items()
    }
    canonical = sha256(json.dumps(files, sort_keys=True).encode())
    if break_canonical:
        canonical = "0" * 64
    manifest = {
        "mode": mode,
        "tag": f"v{version}",
        "candidate_version": version,
        "source_sha": source_sha,
        "files": files,
        "canonical_set_digest": canonical,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for name, data in members.items():
            if drop_payload and name == f"npm/awebai-aw-{version}.tgz":
                continue
            if tamper_payload and name.endswith("linux_amd64.tar.gz"):
                data = b"tampered"
            z.writestr(name, data)
        if extra_payload:
            z.writestr("dist/uninvited.bin", b"extra")
        if duplicate_member:
            z.writestr("npm/checksums.txt", members["dist/checksums.txt"])
    return buffer.getvalue()


class LaneStagedArtifactTests(unittest.TestCase):
    def test_coherent_stage_only_artifact_validates(self) -> None:
        manifest = rd.validate_lane_staged_artifact(
            lane_zip(), expected_source_sha="a" * 40, expected_version="1.34.3",
        )
        self.assertEqual(manifest["mode"], "stage-only")
        self.assertEqual(len(manifest["files"]), 14)

    def test_verify_only_artifact_is_never_publishable(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(mode="verify-only"),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("stage-only", str(caught.exception))

    def test_source_and_version_must_bind(self) -> None:
        with self.assertRaises(rd.ReceiptError):
            rd.validate_lane_staged_artifact(
                lane_zip(), expected_source_sha="b" * 40, expected_version="1.34.3",
            )
        with self.assertRaises(rd.ReceiptError):
            rd.validate_lane_staged_artifact(
                lane_zip(), expected_source_sha="a" * 40, expected_version="9.9.9",
            )

    def test_payload_digest_mismatch_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(tamper_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("linux_amd64", str(caught.exception))

    def test_duplicate_member_placement_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(duplicate_member=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("checksums.txt", str(caught.exception))

    def test_missing_payload_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(drop_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("tgz", str(caught.exception))

    def test_extra_payload_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(extra_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("uninvited", str(caught.exception))

    def test_canonical_mismatch_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(break_canonical=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("canonical", str(caught.exception))


GOOD_REF = {
    "artifact": "gh-artifact:awebai/aw:30977506589:8918869285",
    "aw_source_sha": "471400cdd011e07e17dbce092b0f837ff655af35",
    "zip_digest": "sha256:" + "8" * 64,
}


class LaneRefTests(unittest.TestCase):
    def test_well_formed_reference_validates(self) -> None:
        ref = rd.LaneRef.from_dict(GOOD_REF)
        self.assertEqual(ref.aw_source_sha, GOOD_REF["aw_source_sha"])
        self.assertEqual(ref.to_dict(), GOOD_REF)

    def test_malformed_references_refuse(self) -> None:
        for field, value in (
            ("artifact", "gh-artifact:evil/aw:1:2"),
            ("artifact", "not-a-ref"),
            ("aw_source_sha", "short"),
            ("aw_source_sha", ""),
            ("zip_digest", "8" * 64),
            ("zip_digest", "sha256:nope"),
        ):
            bad = dict(GOOD_REF)
            bad[field] = value
            with self.assertRaises(rd.ReceiptError, msg=f"{field}={value!r}"):
                rd.LaneRef.from_dict(bad)
        with self.assertRaises(rd.ReceiptError):
            rd.LaneRef.from_dict({"artifact": GOOD_REF["artifact"]})

    def test_cli_argument_parses_to_component_and_reference(self) -> None:
        component, ref = rd.parse_stage_artifact_argument(
            "component=aw,ref=" + GOOD_REF["artifact"]
            + ",source=" + GOOD_REF["aw_source_sha"]
            + ",digest=" + GOOD_REF["zip_digest"]
        )
        self.assertEqual(component, "aw")
        self.assertEqual(ref.to_dict(), GOOD_REF)
        with self.assertRaises(rd.ReceiptError):
            rd.parse_stage_artifact_argument("component=aw,ref=x")


class LaneRefThreadingTests(unittest.TestCase):
    def fixture_entries(self, plan):
        return {
            n.component: rd.ReceiptEntry(
                version=n.version or "0.0.0",
                digest=f"d-{n.component}",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                lane_ref=GOOD_REF if n.component == "client" else None,
            )
            for n in plan.moving
        }

    def plan_and_graph(self):
        from test_release_driver import fixture_graph_dict, orchestration_state
        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state()
        return rd.compute_plan(graph, state), graph

    def test_staged_manifest_carries_and_validates_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        body, digest = rd.seal_staged_manifest(
            plan, frozen_plan_id="F", source_sha="s1",
            entries=self.fixture_entries(plan), graph=graph,
        )
        manifest = rd.load_staged_manifest(body, expected_digest=digest)
        self.assertEqual(manifest["entries"]["client"]["lane_ref"], GOOD_REF)
        rd.validate_staged_manifest(
            manifest, plan=plan, graph=graph,
            frozen_plan_id="F", source_sha="s1",
        )
        manifest["entries"]["client"]["lane_ref"] = {"artifact": "not-a-ref"}
        with self.assertRaises(rd.ReceiptError):
            rd.validate_staged_manifest(
                manifest, plan=plan, graph=graph,
                frozen_plan_id="F", source_sha="s1",
            )

    def test_adoption_requires_the_exact_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        body, digest = rd.seal_staged_manifest(
            plan, frozen_plan_id="F", source_sha="s1",
            entries=self.fixture_entries(plan), graph=graph,
        )
        manifest = rd.load_staged_manifest(body, expected_digest=digest)
        good = rd.ReceiptEntry(
            version=manifest["entries"]["client"]["version"],
            digest=manifest["entries"]["client"]["digest"],
            lane_ref=GOOD_REF,
        )
        rd.adopt_observed(manifest, "client", good)
        tampered = dict(GOOD_REF)
        tampered["aw_source_sha"] = "b" * 40
        with self.assertRaises(rd.ReceiptError):
            rd.adopt_observed(
                manifest, "client",
                rd.ReceiptEntry(
                    version=good.version, digest=good.digest, lane_ref=tampered,
                ),
            )

    def test_receipt_round_trips_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        entries = {
            name: rd.ReceiptEntry(
                version=e.version, digest=e.digest, phase="verified",
                pointer_state=e.pointer_state, lane_ref=e.lane_ref,
            )
            for name, e in self.fixture_entries(plan).items()
        }
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha="s1", entries=entries, approvals={},
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(receipt.entries["client"].lane_ref, GOOD_REF)


class ObserverTests(unittest.TestCase):
    def test_release_observer_reports_one_sha256_per_asset(self) -> None:
        assets = {"aw_1.34.3_linux_amd64.tar.gz": b"archive-bytes"}

        def fetch(name):
            return assets.get(name)

        observer = rd.GithubReleaseObserver(fetch=fetch)
        observed = observer.observe(["aw_1.34.3_linux_amd64.tar.gz", "absent.zip"])
        self.assertEqual(
            observed,
            {"aw_1.34.3_linux_amd64.tar.gz": sha256(b"archive-bytes"),
             "absent.zip": None},
        )

    def test_npm_observer_reports_one_sha256_or_none(self) -> None:
        def fetch(package, version):
            return b"tgz-bytes" if version == "1.34.3" else None

        observer = rd.NpmRegistryObserver(fetch=fetch)
        self.assertEqual(
            observer.observe("@awebai/aw", "1.34.3"), sha256(b"tgz-bytes")
        )
        self.assertIsNone(observer.observe("@awebai/aw", "9.9.9"))

    def test_exact_remote_state_adopts_and_missing_is_identified(self) -> None:
        staged = {"a.tar.gz": sha256(b"one"), "b.tgz": sha256(b"two")}
        observed = {"a.tar.gz": sha256(b"one"), "b.tgz": None}
        adopted, missing = rd.classify_remote_state(staged, observed)
        self.assertEqual(adopted, ["a.tar.gz"])
        self.assertEqual(missing, ["b.tgz"])

    def test_mismatched_remote_bytes_refuse(self) -> None:
        staged = {"a.tar.gz": sha256(b"one")}
        observed = {"a.tar.gz": sha256(b"DIFFERENT")}
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.classify_remote_state(staged, observed)
        self.assertIn("a.tar.gz", str(caught.exception))

    def test_unobserved_evidence_refuses(self) -> None:
        staged = {"a.tar.gz": sha256(b"one")}
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.classify_remote_state(staged, {})
        self.assertIn("a.tar.gz", str(caught.exception))


class FakeAwRuns:
    """The aw-release.yml runs surface: list, dispatch, conclusion."""

    def __init__(self, *, new_runs_per_dispatch=1, conclusion="success"):
        self.run_ids = [100, 101]
        self.dispatched: list[dict] = []
        self.new_runs_per_dispatch = new_runs_per_dispatch
        self.conclusion = conclusion
        self._next = 200

    def list_run_ids(self):
        return list(self.run_ids)

    def dispatch(self, inputs: dict):
        self.dispatched.append(dict(inputs))
        for _ in range(self.new_runs_per_dispatch):
            self.run_ids.append(self._next)
            self._next += 1

    def run_conclusion(self, run_id):
        return self.conclusion


def lane_fixture(*, zip_bytes=None, remote=None, runs=None):
    zip_bytes = zip_bytes if zip_bytes is not None else lane_zip()
    api = FakeGithubApi(zip_bytes=zip_bytes)
    remote = remote if remote is not None else {}

    def release_fetch(name, version):
        return remote.get(name)

    def npm_fetch(package, version):
        return remote.get(f"npm:{package}@{version}")

    lane = rd.AwWorkflowLane(
        reader=rd.GithubArtifactStore(api=api),
        lane_authority=rd.GithubArtifactDigestAuthority(api=api),
        refs={"aw": rd.LaneRef(
            artifact=artifact_id_for(api),
            aw_source_sha="a" * 40,
            zip_digest=f"sha256:{sha256(zip_bytes)}",
        )},
        release_fetch=release_fetch,
        npm_fetch=npm_fetch,
        runs=runs if runs is not None else FakeAwRuns(),
        waiter=lambda: None,
    )
    return lane, api, remote


def aw_node(version="1.34.3"):
    return rd.PlanNode(component="aw", reason="changed", version=version)


def remote_state(*names):
    """Remote publication state keyed the way the lane observes it: release
    assets by basename, npm tarballs by package@version."""
    dist, npm = lane_payload_names()
    full = {n: f"bytes-of-{n}".encode() for n in dist}
    for n in npm:
        stem = n.removesuffix(".tgz")
        package, _, version = stem.replace(
            "awebai-", "@awebai/", 1
        ).rpartition("-")
        full[f"npm:{package}@{version}"] = f"bytes-of-{n}".encode()
    return {k: v for k, v in full.items() if not names or k in names}


class AwWorkflowLaneTests(unittest.TestCase):
    def test_stage_builds_the_complete_entry_from_referenced_bytes(self) -> None:
        lane, _, _ = lane_fixture()
        self.assertTrue(lane.has_lane("aw"))
        self.assertFalse(lane.has_lane("server"))
        entry = lane.stage(aw_node())
        self.assertEqual(entry.version, "1.34.3")
        dist, npm = lane_payload_names()
        self.assertEqual(set(entry.digest_set), set(dist) | set(npm))
        self.assertEqual(
            entry.digest, rd.canonical_digest_of_set(entry.digest_set)
        )
        self.assertEqual(entry.lane_ref["aw_source_sha"], "a" * 40)

    def test_stage_refuses_a_caller_digest_that_does_not_match(self) -> None:
        zip_bytes = lane_zip()
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest="sha256:" + "0" * 64,
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(aw_node())
        self.assertIn("caller", str(caught.exception))

    def test_independent_authority_metadata_gates_the_read(self) -> None:
        """alice's finding: blob retrieval and the expected API digest must
        be independent capabilities. A wrong independent digest refuses
        BEFORE bytes are read, even when the reader would return coherent
        bytes."""
        zip_bytes = lane_zip()
        reader_api = FakeGithubApi(zip_bytes=zip_bytes)
        wrong_meta_api = FakeGithubApi(
            zip_bytes=zip_bytes, digest="sha256:" + "1" * 64
        )
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=reader_api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=wrong_meta_api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(reader_api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(aw_node())
        self.assertIn("independent", str(caught.exception))
        self.assertNotIn(
            f"repos/awebai/aw/actions/artifacts/{reader_api.artifact_id}/zip",
            reader_api.calls,
            "the blob must not be fetched when the authority refuses",
        )

    def test_stage_refuses_a_wrong_lane_source(self) -> None:
        zip_bytes = lane_zip(source_sha="c" * 40)
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError):
            lane.stage(aw_node())

    def test_observe_reports_none_until_everything_is_published(self) -> None:
        lane, _, remote = lane_fixture(remote=remote_state("checksums.txt"))
        staged = lane.stage(aw_node())
        self.assertIsNone(lane.observe(aw_node(), staged))
        remote.update(remote_state())
        observed = lane.observe(aw_node(), staged)
        self.assertEqual(observed.digest, staged.digest)
        self.assertEqual(observed.digest_set, staged.digest_set)
        self.assertEqual(observed.lane_ref, staged.lane_ref)

    def test_observe_refuses_mismatched_remote_bytes(self) -> None:
        remote = remote_state()
        remote["checksums.txt"] = b"DIFFERENT"
        lane, _, _ = lane_fixture(remote=remote)
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError):
            lane.observe(aw_node(), staged)

    def test_publish_dispatches_exact_continuation_inputs_and_observes(self) -> None:
        runs = FakeAwRuns()
        remote = {}
        lane, api, _ = lane_fixture(remote=remote, runs=runs)
        staged = lane.stage(aw_node())

        def fill_remote(inputs):
            remote.update(remote_state())
        runs_dispatch = runs.dispatch
        runs.dispatch = lambda inputs: (runs_dispatch(inputs), fill_remote(inputs))[0]

        published = lane.publish(aw_node(), staged)
        self.assertEqual(published.phase, "published")
        self.assertEqual(runs.dispatched, [{
            "mode": "publish-continuation",
            "version": "1.34.3",
            "source_sha": "a" * 40,
            "stage_run_id": str(api.run_id),
            "stage_artifact_id": str(api.artifact_id),
            "stage_zip_digest": f"sha256:{sha256(api.zip_bytes)}",
        }])

    def test_publish_fails_closed_on_run_correlation(self) -> None:
        for runs in (
            FakeAwRuns(new_runs_per_dispatch=0),
            FakeAwRuns(new_runs_per_dispatch=2),
        ):
            lane, _, _ = lane_fixture(remote=remote_state(), runs=runs)
            staged = lane.stage(aw_node())
            with self.assertRaises(rd.ReceiptError, msg=str(runs.new_runs_per_dispatch)):
                lane.publish(aw_node(), staged)

    def test_publish_refuses_an_unsuccessful_continuation_run(self) -> None:
        lane, _, _ = lane_fixture(
            remote=remote_state(), runs=FakeAwRuns(conclusion="failure")
        )
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError):
            lane.publish(aw_node(), staged)

    def test_missing_after_publication_is_failure(self) -> None:
        lane, _, _ = lane_fixture(remote=remote_state("checksums.txt"))
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.publish(aw_node(), staged)
        self.assertIn("missing", str(caught.exception).lower())

    def test_verify_reobserves_the_complete_set(self) -> None:
        lane, _, remote = lane_fixture(remote=remote_state())
        staged = lane.stage(aw_node())
        published = lane.observe(aw_node(), staged)
        lane.verify(aw_node(), published)
        del remote["checksums.txt"]
        with self.assertRaises(rd.ReceiptError):
            lane.verify(aw_node(), published)


def aw_graph() -> "rd.Graph":
    return rd.Graph.from_dict({
        "component": {
            "aw": {
                "source_paths": ["cli/"],
                "version_source": {"type": "manifest", "path": "cli/version"},
                "tag_format": "aw-v{version}",
                "publish_lane": {
                    "workflow": ".github/workflows/aw-release.yml",
                    "repository": "awebai/aw",
                    "provider": "github-workflow-artifacts",
                    "modes": [
                        "stage-only", "publish-continuation", "verify-only",
                    ],
                    "registry": {"type": "github-release", "repo": "awebai/aw"},
                },
                "verify": {"command": "true"},
            },
        },
        "edge": [],
    })


class CountingLane(rd.AwWorkflowLane):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stage_calls = 0

    def stage(self, node):
        self.stage_calls += 1
        return super().stage(node)


class NoRuntimeSkew:
    def has_matrix(self, edge):
        return True

    def execute(self, edge, staged):
        pass


class EndToEndProductionCompositionTests(unittest.TestCase):
    """alice's decisive acceptance: every anchor operation runs through the
    reconstructed external production composition - no memory or file store
    anywhere on the release path."""

    def compose(self, transport, *, runs, remote):
        """A fresh production composition over the shared external state."""
        store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority = rd.GithubAnchorDigestAuthority(transport=transport)
        zip_bytes = lane_zip()
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = CountingLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: remote.get(name),
            npm_fetch=lambda p, v: remote.get(f"npm:{p}@{v}"),
            runs=runs,
            waiter=lambda: None,
        )
        return store, authority, lane

    def frozen_fixture(self, store, authority):
        graph = aw_graph()
        state = rd.FixtureState(
            changed_components={"aw": True},
            versions={"aw": "1.34.3"},
            published_versions={"aw": "1.34.2"},
        )
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1"
        )
        plan_artifact_id = f"plan:s1:{frozen_id}"
        rd._put_content_addressed(
            store, authority, plan_artifact_id, frozen_bytes, frozen_id
        )
        frozen = rd.load_frozen_plan(
            store.get(plan_artifact_id), expected_id=frozen_id
        )
        return graph, plan, frozen

    def test_anchor_run_crash_resume_continuation_and_receipt(self) -> None:
        transport = FakeAnchorTransport()
        remote: dict = {}

        # Round 1: publish fails after external staging.
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote=remote
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        fresh_authority = rd.GithubAnchorDigestAuthority(transport=transport)
        kinds = {i.split(":")[0] for i in fresh_authority.recorded_ids()}
        self.assertIn("plan", kinds)
        self.assertIn("staged-manifest", kinds)

        # Round 2: reconstructed process resumes - zero restage, exact
        # continuation inputs, sealed receipt reloadable externally.
        runs = FakeAwRuns()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )

        def fill_remote(inputs):
            remote.update(remote_state())
        original = runs.dispatch
        runs.dispatch = lambda inputs: (original(inputs), fill_remote(inputs))[0]

        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        entries = rd.resume_plan(
            plan2, graph2,
            lanes=lane2, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(lane2.stage_calls, 0,
                         "resume must never restage")
        self.assertEqual(len(runs.dispatched), 1)
        dispatched = runs.dispatched[0]
        self.assertEqual(dispatched["mode"], "publish-continuation")
        self.assertEqual(dispatched["source_sha"], "a" * 40)
        self.assertEqual(dispatched["stage_run_id"], "30977506589")
        self.assertEqual(dispatched["stage_artifact_id"], "8918869285")
        self.assertEqual(entries["aw"].phase, "verified")
        self.assertEqual(entries["aw"].lane_ref["aw_source_sha"], "a" * 40)

        # The sealed receipt reloads through yet another fresh composition.
        store3, authority3, _ = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        receipt_ids = [
            i for i in authority3.recorded_ids() if i.startswith("receipt:")
        ]
        self.assertEqual(len(receipt_ids), 1)
        receipt = rd.load_sealed_receipt(
            store3.get(receipt_ids[0]),
            expected_digest=authority3.expected_digest(receipt_ids[0]),
        )
        ok, why = rd.receipt_matches_run(receipt, plan2, graph2, source_sha="s1")
        self.assertTrue(ok, why)
        self.assertEqual(receipt.entries["aw"].lane_ref["artifact"],
                         "gh-artifact:awebai/aw:30977506589:8918869285")
        published_transitions = [
            json.loads(store3.get(i))
            for i in authority3.recorded_ids()
            if i.startswith("transition:") and ":published:" in i
        ]
        self.assertTrue(published_transitions)
        for record in published_transitions:
            self.assertEqual(
                record["entry"]["lane_ref"]["aw_source_sha"], "a" * 40
            )
            self.assertTrue(record["entry"]["digest_set"])

    def test_resume_adopts_exact_remote_state_without_continuation(self) -> None:
        transport = FakeAnchorTransport()
        remote = remote_state()  # everything already published, exact bytes
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        runs = FakeAwRuns()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        entries = rd.resume_plan(
            plan2, graph2,
            lanes=lane2, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(runs.dispatched, [],
                         "exact remote state adopts; no continuation")
        self.assertEqual(lane2.stage_calls, 0)
        self.assertEqual(entries["aw"].phase, "verified")

    def test_resume_refuses_a_tampered_published_transition(self) -> None:
        """A transition claiming publication must match the anchored staged
        manifest entry exactly; an authentic-but-wrong record refuses."""
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        manifest_id = next(
            i for i in authority.recorded_ids()
            if i.startswith("staged-manifest:")
        )
        forged = json.dumps({
            "frozen_plan_id": frozen.frozen_id,
            "staged_manifest_id": manifest_id,
            "sequence": 99,
            "component": "aw",
            "kind": "published",
            "entry": {
                "version": "1.34.3",
                "digest": "0" * 64,
                "phase": "published",
                "pointer_state": None,
                "delivery_proof": None,
                "lane_ref": None,
                "digest_set": {"forged": "0" * 64},
            },
        }, sort_keys=True).encode()
        forged_digest = sha256(forged)
        forged_id = (
            f"transition:{frozen.frozen_id}:099:published:aw:{forged_digest}"
        )
        rd._put_content_addressed(store, authority, forged_id, forged, forged_digest)
        runs = FakeAwRuns()
        remote = remote_state()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )
        self.assertIn("transition", str(caught.exception))

    def test_resume_refuses_exact_entry_with_wrong_manifest_identity(self) -> None:
        """A transition whose ENTRY fields are exact but whose
        staged-manifest identity is wrong must refuse: prefix filtering is
        not semantic validation of the body."""
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        manifest_id = next(
            i for i in authority.recorded_ids()
            if i.startswith("staged-manifest:")
        )
        manifest = json.loads(store.get(manifest_id))
        exact = dict(manifest["entries"]["aw"])
        forged = json.dumps({
            "frozen_plan_id": frozen.frozen_id,
            "staged_manifest_id": "staged-manifest:FORGED:" + "0" * 64,
            "sequence": 98,
            "component": "aw",
            "kind": "published",
            "entry": {
                "version": exact["version"],
                "digest": exact["digest"],
                "phase": "published",
                "pointer_state": exact.get("pointer_state"),
                "delivery_proof": None,
                "lane_ref": exact.get("lane_ref"),
                "digest_set": exact.get("digest_set"),
            },
        }, sort_keys=True).encode()
        forged_digest = sha256(forged)
        forged_id = (
            f"transition:{frozen.frozen_id}:098:published:aw:{forged_digest}"
        )
        rd._put_content_addressed(store, authority, forged_id, forged, forged_digest)
        remote = remote_state()
        store2, authority2, lane2 = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )
        self.assertIn("manifest", str(caught.exception))

    def test_resume_refuses_mismatched_remote_state(self) -> None:
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        remote = remote_state()
        remote["checksums.txt"] = b"TAMPERED"
        store2, authority2, lane2 = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError):
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )


class MakeReleaseSurfaceTests(unittest.TestCase):
    def test_release_run_threads_stage_artifact_to_the_cli(self) -> None:
        """The repository's release target must pass every structured
        --stage-artifact value through to the Python CLI; a dry run proves
        the exact value reaches it."""
        import subprocess as sp

        value = ("component=aw,ref=gh-artifact:awebai/aw:1:2,"
                 "source=" + "a" * 40 + ",digest=sha256:" + "b" * 64)
        result = sp.run(
            ["make", "-n", "release-run",
             f"STAGE_ARTIFACT={value}",
             "PLAN_ID=p", "PLAN_ARTIFACT_ID=pa"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'--stage-artifact "{value}"', result.stdout)

    def test_duplicate_component_references_refuse(self) -> None:
        good = ("component=aw,ref=gh-artifact:awebai/aw:1:2,"
                "source=" + "a" * 40 + ",digest=sha256:" + "b" * 64)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.parse_stage_artifact_arguments([good, good])
        self.assertIn("aw", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
