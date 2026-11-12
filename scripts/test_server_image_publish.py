#!/usr/bin/env python3
"""Server tag dispatch and exact OCI publication contracts (no registry writes)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import tomllib
import unittest
import uuid
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

    def test_cli_selector_reaches_the_image_lane(self):
        prior = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.object(PUBLISH, "publish_pypi") as pypi, patch.object(PUBLISH, "publish_oci") as oci:
                self.assertEqual(PUBLISH.main(["--only", "oci", "server-v1.2.3"]), 0)
                pypi.assert_not_called()
                oci.assert_called_once()
        finally:
            os.chdir(prior)

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
    def exercise(self, *, existing=False, conflict=False, fail_readback=False, version="1.2.3"):
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
            PUBLISH.publish_oci(ROOT, "server-v", version, "a" * 40)
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

    def test_rc_publishes_and_reads_back_only_its_immutable_version(self):
        calls, _, _ = self.exercise(version="1.2.3rc1")
        copies = [args for args in calls if args[:2] == ("skopeo", "copy")]
        self.assertEqual([args[-1] for args in copies], ["docker://ghcr.io/awebai/aweb-server:1.2.3rc1"])
        self.assertIn("--version-only", calls[-1])

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


class NativeArchiveHandoffTests(unittest.TestCase):
    """Control the host/transfer edges; real builds remain the opt-in qualification."""
    def exercise(self, machine, environment):
        calls = []
        copied = []
        sha = "a" * 40
        version = tomllib.loads((ROOT / "server/pyproject.toml").read_text())["project"]["version"]

        def build(root, prefix, version, source, archive):
            calls.append(("build",))
            archive.write_bytes(b"unchanged archive bytes")

        def run(root, *args, **kwargs):
            calls.append(args)
            if args[:2] == ("docker", "info"):
                return json.dumps({"Architecture": machine, "OSType": "linux"})
            if "inspect-staged" in args:
                Path(args[args.index("--out") + 1]).write_text(json.dumps({
                    "index": "sha256:" + "b" * 64,
                    "platforms": {"linux/amd64": {}, "linux/arm64": {}}}))
            if "--override-arch" in args:
                copied.append(args[args.index("--override-arch") + 1])
            if args[:3] == ("docker", "image", "inspect"):
                return json.dumps([{"Architecture": copied[-1], "Config": {"Labels": {
                    "org.opencontainers.image.revision": sha}}}])
            if args[:2] == ("docker", "run"):
                self.assertEqual(kwargs["timeout"], 120)
                if args[-1] == "--help":
                    return "Usage: aweb serve"
                return json.dumps({"version": version, "machine": "x86_64" if copied[-1] == "amd64" else "aarch64", "uid": 1001})
            return ""

        probe = ServerPlatformBuildTests()
        method = unittest.defaultTestLoader.getTestCaseNames(ServerPlatformBuildTests)[0]
        with patch.dict(os.environ, environment), patch.object(PUBLISH, "build_oci_archive", build), patch.object(PUBLISH, "run", run), patch.object(PUBLISH.subprocess, "run"), patch(__name__ + ".command", return_value=sha), redirect_stdout(io.StringIO()) as output:
            getattr(probe, method)()
        return calls, copied, output.getvalue()

    def test_one_archive_transfers_from_native_amd64_to_native_arm64_without_rebuild(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "release.tar"
            calls, copied, output = self.exercise("x86_64", {
                "AWEB_SERVER_IMAGE_ARCHIVE_OUT": str(archive), "AWEB_SERVER_IMAGE_ARCHIVE_IN": ""})
            self.assertEqual(copied, ["amd64"])
            self.assertTrue(archive.is_file(), "exported archive must outlive the x86 probe")
            original = archive.read_bytes()
            self.assertIn(hashlib.sha256(original).hexdigest(), output)
            calls, copied, output = self.exercise("aarch64", {
                "AWEB_SERVER_IMAGE_ARCHIVE_IN": str(archive), "AWEB_SERVER_IMAGE_ARCHIVE_OUT": ""})
            self.assertEqual(copied, ["arm64"])
            self.assertNotIn(("build",), calls)
            self.assertEqual(archive.read_bytes(), original)
            self.assertIn(hashlib.sha256(original).hexdigest(), output)
            self.assertTrue(any("inspect-staged" in call for call in calls))

    def test_missing_transferred_archive_refuses_instead_of_rebuilding(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(AssertionError, "input archive"):
                self.exercise("aarch64", {"AWEB_SERVER_IMAGE_ARCHIVE_IN": str(Path(directory) / "missing.tar"),
                                          "AWEB_SERVER_IMAGE_ARCHIVE_OUT": ""})

    def test_unknown_native_architecture_refuses(self):
        with self.assertRaisesRegex(AssertionError, "native architecture"):
            self.exercise("ppc64le", {"AWEB_SERVER_IMAGE_ARCHIVE_IN": "", "AWEB_SERVER_IMAGE_ARCHIVE_OUT": ""})


@unittest.skipUnless(os.environ.get("AWEB_TEST_SERVER_IMAGE_BUILD") == "1", "requires Docker, skopeo and native platform runtime")
class ServerPlatformBuildTests(unittest.TestCase):
    def test_release_archive_and_native_server_cli(self):
        version = tomllib.loads((ROOT / "server/pyproject.toml").read_text())["project"]["version"]
        sha = command(ROOT, "git", "rev-parse", "HEAD")
        daemon = json.loads(PUBLISH.run(ROOT, "docker", "info", "--format", "{{json .}}"))
        native = {"x86_64": ("amd64", "x86_64"), "amd64": ("amd64", "x86_64"),
                  "aarch64": ("arm64", "aarch64"), "arm64": ("arm64", "aarch64")}
        self.assertEqual(daemon["OSType"], "linux")
        self.assertIn(daemon["Architecture"], native, "unsupported native architecture")
        architecture, machine = native[daemon["Architecture"]]
        archive_in = os.environ.get("AWEB_SERVER_IMAGE_ARCHIVE_IN", "")
        archive_out = os.environ.get("AWEB_SERVER_IMAGE_ARCHIVE_OUT", "")
        self.assertFalse(archive_in and archive_out, "select archive input OR output")
        run_id = "server-image-test-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix=run_id) as temporary:
            archive = Path(archive_in or archive_out or str(Path(temporary) / "server.oci.tar")).resolve()
            identities = Path(temporary) / "identities.json"
            if archive_in:
                self.assertTrue(archive.is_file(), "input archive must exist; never rebuild a transferred artifact")
            else:
                self.assertFalse(archive.exists(), "output archive already exists; do not overwrite release bytes")
                # The publication path uses this exact builder, not a second recipe.
                PUBLISH.build_oci_archive(ROOT, "server-v", version, sha, archive)
            PUBLISH.run(ROOT, "bash", "scripts/oci-exact-publish.sh", "inspect-staged",
                        "--archive", str(archive), "--version", version,
                        "--source-sha", sha, "--out", str(identities))
            identity = json.loads(identities.read_text())
            self.assertEqual(set(identity["platforms"]), {"linux/amd64", "linux/arm64"})
            print("server image staged identity=" + json.dumps(identity, sort_keys=True), flush=True)
            with archive.open("rb") as stream:
                archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            print("server image archive receipt=" + json.dumps({
                "sha256": archive_hash, "bytes": archive.stat().st_size,
                "index": identity["index"], "source_sha": sha, "version": version,
                "native_platform": "linux/" + architecture}, sort_keys=True), flush=True)
            with self.subTest(platform=architecture):
                image = run_id + ":" + architecture
                container = run_id + "-" + architecture
                loaded = False
                try:
                    PUBLISH.run(ROOT, "skopeo", "--override-os", "linux", "--override-arch", architecture,
                                "copy", "oci-archive:" + str(archive), "docker-daemon:" + image, timeout=600)
                    loaded = True
                    observed = json.loads(PUBLISH.run(ROOT, "docker", "image", "inspect", image))[0]
                    self.assertEqual(observed["Architecture"], architecture)
                    self.assertEqual(observed["Config"]["Labels"]["org.opencontainers.image.revision"], sha)
                    probe = ("import importlib.metadata as m, json, os, platform; "
                             "import aweb.cli, awid, aweb_naapp; "
                             "print(json.dumps(dict(version=m.version('aweb'), machine=platform.machine(), uid=os.getuid())))")
                    result = json.loads(PUBLISH.run(ROOT, "docker", "run", "--rm", "--name", container,
                                                   "--platform", "linux/" + architecture, image,
                                                   "python", "-c", probe, timeout=120))
                    self.assertEqual(result, {"version": version, "machine": machine, "uid": 1001})
                    help_text = PUBLISH.run(ROOT, "docker", "run", "--rm", "--name", container,
                                           "--platform", "linux/" + architecture, image, "aweb", "serve", "--help", timeout=120)
                    self.assertIn("Usage", help_text)
                    print(f"server image linux/{architecture} PASS: {result}", flush=True)
                finally:
                    # Remove only this probe's resources, including a timed-out container.
                    subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=60, check=False)
                    if loaded:
                        PUBLISH.run(ROOT, "docker", "image", "rm", "-f", image, timeout=60)


if __name__ == "__main__":
    unittest.main()
