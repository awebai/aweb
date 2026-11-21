"""Admission controls for released-client RC receipts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "e2e"))
from user_paths_rc import CASES, compatibility, server_inputs, verify_server_image


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
    def test_manifest_requires_two_distinct_immutable_server_artifacts(self):
        valid = {"baseline": runtime(), "rc": runtime("1.2.4rc1", "c", "d")}
        self.assertEqual(server_inputs(valid), valid)
        for invalid in (
            {"baseline": runtime(), "rc": runtime("1.2.4", "c", "d")},
            {"baseline": runtime(), "rc": runtime("1.2.4rc1")},
            {"baseline": runtime(), "rc": {**valid["rc"], "image": "aweb:latest"}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                server_inputs(invalid)

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
