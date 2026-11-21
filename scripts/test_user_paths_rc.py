"""Admission controls for released-client RC receipts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths_rc import (
    CASES,
    compatibility,
    production_baseline,
    server_inputs,
    verify_published_server,
    verify_server_image,
)


def runtime(version="1.2.3", digest="a", source="b"):
    return {
        "version": version,
        "image": "ghcr.io/awebai/aweb-server@sha256:" + digest * 64,
        "source_sha": source * 40,
    }


def observations():
    return {
        name: {"status": "PASSED", "visible": {"presented": True}} for name in CASES
    }


class RCEvidenceTests(unittest.TestCase):
    def test_manifest_binds_an_exact_rc_image_and_baseline_wheel(self):
        baseline = {
            "version": "1.2.3",
            "source_sha": "b" * 40,
            "wheel_sha256": "sha256:" + "a" * 64,
        }
        valid = {"baseline": baseline, "rc": runtime("1.2.4rc1", "c", "d")}
        self.assertEqual(server_inputs(valid), valid)
        for invalid in (
            {**valid, "rc": runtime("1.2.4", "c", "d")},
            {**valid, "baseline": runtime()},
            {**valid, "rc": {**valid["rc"], "image": "aweb:latest"}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                server_inputs(invalid)

    def test_tag_commit_and_published_registry_digest_both_must_match(self):
        artifact = runtime("1.2.4rc1", "c", "d")
        digest = "sha256:" + "c" * 64
        source = {"source_sha": "d" * 40}
        verify_published_server(artifact, source, digest)
        with self.assertRaisesRegex(ValueError, "published server tag"):
            verify_published_server(artifact, {"source_sha": "b" * 40}, digest)
        with self.assertRaisesRegex(ValueError, "image digest"):
            verify_published_server(artifact, source, "sha256:" + "b" * 64)

    def test_baseline_must_match_production_wheel_version_and_digest(self):
        digest = "sha256:" + "a" * 64
        baseline = {"version": "1.2.3", "wheel_sha256": digest}
        readback = {
            "service": "production",
            "deployment_id": "deployment",
            "deployed_image": "registry.test/app@" + digest,
            "deployed_source_sha": "b" * 40,
            "observed_at": "2026-11-21T06:25:40Z",
            "package_lock": {"commit": "b" * 40, "path": "uv.lock", "blob": "f" * 40},
            "production_aweb_version": "1.2.3",
            "packages": {
                "aweb": {
                    "version": "1.2.3",
                    "sha256": digest,
                    "url": "https://files.pythonhosted.org/packages/aa/bb/aweb-1.2.3-py3-none-any.whl",
                },
                "aweb-naapp": {
                    "version": "0.5.1",
                    "sha256": digest,
                    "url": "https://files.pythonhosted.org/packages/aa/bb/aweb_naapp-0.5.1-py3-none-any.whl",
                },
                "awid-service": {
                    "version": "1.0.1",
                    "sha256": digest,
                    "url": "https://files.pythonhosted.org/packages/aa/bb/awid_service-1.0.1-py3-none-any.whl",
                },
            },
        }
        self.assertEqual(production_baseline(baseline, readback), readback)
        without_naapp = {
            name: pin
            for name, pin in readback["packages"].items()
            if name != "aweb-naapp"
        }
        with self.assertRaisesRegex(ValueError, "aweb-naapp"):
            production_baseline(baseline, {**readback, "packages": without_naapp})
        for wrong in (
            {**baseline, "version": "1.2.2"},
            {**baseline, "wheel_sha256": "sha256:" + "d" * 64},
        ):
            with self.assertRaisesRegex(ValueError, "differs from the deployed"):
                production_baseline(wrong, readback)
        with self.assertRaisesRegex(ValueError, "deployment"):
            production_baseline(baseline, {**readback, "deployment_id": None})
        with self.assertRaisesRegex(ValueError, "deployed source commit"):
            production_baseline(baseline, {**readback, "deployed_source_sha": "c" * 40})
        with self.assertRaisesRegex(ValueError, "differs from the deployed"):
            production_baseline(
                baseline, {**readback, "production_aweb_version": "1.2.2"}
            )

    def test_changes_and_missing_results_remain_visible_and_red(self):
        baseline, candidate = observations(), observations()
        self.assertEqual(compatibility(baseline, candidate)["status"], "PASSED")
        candidate["channel/mail"]["visible"]["presented"] = False
        del candidate["oats/retire"]
        result = compatibility(baseline, candidate)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(set(result["changes"]), {"channel/mail", "oats/retire"})
        self.assertIn("oats/retire", result["missing"]["rc"])
        self.assertEqual(
            result["changes"]["channel/mail"]["rc"]["visible"], {"presented": False}
        )

    def test_equal_failures_do_not_pass(self):
        evidence = observations()
        evidence["aw/chat"]["status"] = "FAILED"
        result = compatibility(evidence, evidence)
        self.assertEqual(result["changes"], {})
        self.assertEqual(result["status"], "FAILED")

    def test_a_pass_without_public_evidence_does_not_qualify(self):
        evidence = observations()
        evidence["aw/chat"]["visible"] = {}
        self.assertEqual(compatibility(evidence, evidence)["status"], "FAILED")

    def test_exact_digest_labels_and_local_image_must_agree(self):
        artifact = runtime()
        labels = {
            "org.opencontainers.image.version": artifact["version"],
            "org.opencontainers.image.revision": artifact["source_sha"],
        }
        inspection = {
            "Config": {"Labels": labels},
            "RepoDigests": [artifact["image"]],
            "Id": "fixture",
        }
        self.assertEqual(
            verify_server_image(artifact, inspection)["local_image_id"], "fixture"
        )
        for wrong in (
            {**inspection, "RepoDigests": []},
            {
                **inspection,
                "Config": {
                    "Labels": {**labels, "org.opencontainers.image.version": "other"}
                },
            },
            {
                **inspection,
                "Config": {
                    "Labels": {**labels, "org.opencontainers.image.revision": "other"}
                },
            },
        ):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                verify_server_image(artifact, wrong)
