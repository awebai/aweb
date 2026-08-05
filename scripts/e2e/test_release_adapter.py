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
                 owning_run=None, digest=None):
        self.repo = repo
        self.run_id = run_id
        self.artifact_id = artifact_id
        self.zip_bytes = zip_bytes
        self.expired = expired
        self.conclusion = conclusion
        self.head_repo = head_repo or repo
        self.owning_run = owning_run if owning_run is not None else run_id
        self.digest = digest or f"sha256:{sha256(zip_bytes)}"
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
                "path": ".github/workflows/aw-release.yml",
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
        self.assertIsInstance(providers.store, rd.GithubArtifactStore)
        self.assertIsInstance(providers.authority, rd.GithubArtifactDigestAuthority)


def lane_zip(*, mode="stage-only", source_sha="a" * 40, version="1.34.3",
             tamper_payload=False, drop_payload=False, extra_payload=False,
             break_canonical=False) -> bytes:
    payloads = {
        "dist/aw_1.34.3_linux_amd64.tar.gz": b"archive-bytes",
        "dist/checksums.txt": b"checksums",
        "npm/awebai-aw-1.34.3.tgz": b"tgz-bytes",
    }
    files = {name: sha256(data) for name, data in payloads.items()}
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
        for name, data in payloads.items():
            if drop_payload and name.endswith(".tgz"):
                continue
            if tamper_payload and name.endswith(".tar.gz"):
                data = b"tampered"
            z.writestr(name, data)
        if extra_payload:
            z.writestr("dist/uninvited.bin", b"extra")
    return buffer.getvalue()


class LaneStagedArtifactTests(unittest.TestCase):
    def test_coherent_stage_only_artifact_validates(self) -> None:
        manifest = rd.validate_lane_staged_artifact(
            lane_zip(), expected_source_sha="a" * 40, expected_version="1.34.3",
        )
        self.assertEqual(manifest["mode"], "stage-only")
        self.assertEqual(len(manifest["files"]), 3)

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


if __name__ == "__main__":
    unittest.main(verbosity=1)
