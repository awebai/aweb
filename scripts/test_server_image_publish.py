#!/usr/bin/env python3
"""Server tag dispatch and exact OCI publication contracts (no registry writes)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import test_shipping
from test_shipping import PUBLISH, ROOT, command


class ServerDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary, self.root = test_shipping.TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        command(self.root, "git", "tag", "server-v1.2.3")
        self.sha = command(self.root, "git", "rev-parse", "HEAD")

    def test_default_server_tag_publishes_both_from_the_tagged_tree(self):
        calls = []

        def record(kind):
            def publish(checkout, prefix, version, *sha):
                self.assertNotEqual(checkout, self.root)
                self.assertEqual(command(checkout, "git", "rev-parse", "HEAD"), self.sha)
                calls.append((kind, prefix, version, sha))
            return publish

        with patch.object(PUBLISH, "publish_pypi", record("pypi")), patch.object(PUBLISH, "publish_oci", record("oci")):
            PUBLISH.publish(self.root, "server-v1.2.3")
        self.assertEqual(calls, [("pypi", "server-v", "1.2.3", ()), ("oci", "server-v", "1.2.3", (self.sha,))])
        self.assertEqual(len(command(self.root, "git", "worktree", "list").splitlines()), 1)

    def test_workflow_selectors_only_run_their_credential_lane(self):
        for selected in ("pypi", "oci"):
            with self.subTest(selected=selected), patch.object(PUBLISH, "publish_pypi") as pypi, patch.object(PUBLISH, "publish_oci") as oci:
                PUBLISH.publish(self.root, "server-v1.2.3", only=selected)
                self.assertEqual(pypi.call_count, int(selected == "pypi"))
                self.assertEqual(oci.call_count, int(selected == "oci"))

    def test_identity_failure_still_precedes_either_publication(self):
        command(self.root, "git", "tag", "server-v1.2.4")
        with patch.object(PUBLISH, "publish_pypi") as pypi, patch.object(PUBLISH, "publish_oci") as oci:
            with self.assertRaisesRegex(PUBLISH.PublishRefusal, "does not match"):
                PUBLISH.publish(self.root, "server-v1.2.4", only="oci")
            pypi.assert_not_called()
            oci.assert_not_called()

    def test_other_python_lane_stays_python_only_and_rejects_oci(self):
        command(self.root, "git", "tag", "awid-service-v2.3.4")
        with patch.object(PUBLISH, "publish_pypi") as pypi, patch.object(PUBLISH, "publish_oci") as oci:
            PUBLISH.publish(self.root, "awid-service-v2.3.4")
            pypi.assert_called_once()
            oci.assert_not_called()
            with self.assertRaisesRegex(PUBLISH.PublishRefusal, "oci"):
                PUBLISH.publish(self.root, "awid-service-v2.3.4", only="oci")

    def test_tag_workflows_select_both_server_artifacts(self):
        for workflow, lane in (("pypi-release.yml", "pypi"), ("service-image-release.yml", "oci")):
            source = (ROOT / ".github/workflows" / workflow).read_text()
            self.assertIn('"server-v*"', source)
            self.assertIn(f'python3 scripts/publish_release.py --only {lane} "${{GITHUB_REF_NAME}}"', source)


class ServerOciTests(unittest.TestCase):
    def exercise(self, *, existing=False, conflict=False, fail_readback=False):
        raw = b'{"schemaVersion":2}\n'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        calls = []

        def run(root, *args, **kwargs):
            calls.append(args)
            if "inspect-staged" in args:
                Path(args[args.index("--out") + 1]).write_text(json.dumps({"index": digest}))
            if args[:2] == ("skopeo", "list-tags"):
                return json.dumps({"Tags": ["1.2.3", "latest"] if existing else []})
            if "verify-published" in args and fail_readback:
                raise PUBLISH.PublishRefusal("published digest mismatch")
            return ""

        observed = subprocess.CompletedProcess([], 0, b"different" if conflict else raw, b"")
        with patch.dict(os.environ, GHCR_USERNAME="fixture", GHCR_TOKEN="fixture-token"), patch.object(PUBLISH.shutil, "which", return_value="skopeo"), patch.object(PUBLISH, "run", run), patch.object(PUBLISH.subprocess, "run", return_value=observed), redirect_stdout(io.StringIO()) as output:
            PUBLISH.publish_oci(ROOT, "server-v", "1.2.3", "a" * 40)
        return calls, output.getvalue(), digest

    def test_server_builds_both_platforms_and_uses_exact_helper_and_readback(self):
        calls, output, digest = self.exercise()
        build = calls[0]
        self.assertEqual(build[:3], ("docker", "buildx", "build"))
        self.assertEqual(build[build.index("--file") + 1], "server/Dockerfile")
        self.assertEqual(build[build.index("--platform") + 1], "linux/amd64,linux/arm64")
        self.assertEqual(build[-1], ".")
        for flag in ("--provenance=false", "--sbom=false", "org.opencontainers.image.version=1.2.3", "org.opencontainers.image.revision=" + "a" * 40):
            self.assertIn(flag, build)
        self.assertEqual(calls[1][:3], ("bash", "scripts/oci-exact-publish.sh", "inspect-staged"))
        copies = [args for args in calls if args[:2] == ("skopeo", "copy")]
        self.assertEqual([args[-1] for args in copies], ["docker://ghcr.io/awebai/aweb-server:1.2.3", "docker://ghcr.io/awebai/aweb-server:latest"])
        self.assertTrue(all("--all" in args for args in copies))
        self.assertEqual(calls[-1][:3], ("bash", "scripts/oci-exact-publish.sh", "verify-published"))
        self.assertEqual(calls[-1][-1], "ghcr.io/awebai/aweb-server")
        self.assertEqual(json.loads(output.split("release-index=")[1]), {"digest": digest, "source_sha": "a" * 40, "version": "1.2.3"})

    def test_identical_published_index_is_adopted_and_read_back(self):
        calls, _, _ = self.exercise(existing=True)
        self.assertFalse(any(args[:2] == ("skopeo", "copy") for args in calls))
        self.assertIn("verify-published", calls[-1])

    def test_conflicting_immutable_version_refuses(self):
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "immutable ghcr.io/awebai/aweb-server:1.2.3"):
            self.exercise(existing=True, conflict=True)

    def test_readback_failure_is_not_success(self):
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "published digest mismatch"):
            self.exercise(fail_readback=True)


if __name__ == "__main__":
    unittest.main()
