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
            def publish(checkout, prefix, version, *sha, **options):
                self.assertNotEqual(checkout, self.root)
                self.assertEqual(
                    command(checkout, "git", "rev-parse", "HEAD"), self.sha
                )
                calls.append((kind, prefix, version, sha))

            return publish

        def publish_pypi(root, tag, sha, assets):
            calls.append(("pypi", tag, sha, assets))

        with (
            patch.object(PUBLISH, "publish_pypi", publish_pypi),
            patch.object(PUBLISH, "publish_oci", record("oci")),
        ):
            PUBLISH.publish(self.root, "server-v1.2.3", assets=Path("assets"))
        self.assertEqual(
            calls,
            [
                ("pypi", "server-v1.2.3", self.sha, Path("assets")),
                ("oci", "server-v", "1.2.3", (self.sha,)),
            ],
        )
        self.assertEqual(
            len(command(self.root, "git", "worktree", "list").splitlines()), 1
        )

    def test_workflow_selectors_only_run_their_credential_lane(self):
        for selected in ("pypi", "oci"):
            with (
                self.subTest(selected=selected),
                patch.object(PUBLISH, "publish_pypi") as pypi,
                patch.object(PUBLISH, "publish_oci") as oci,
            ):
                PUBLISH.publish(
                    self.root, "server-v1.2.3", only=selected, assets=Path("assets")
                )
                self.assertEqual(pypi.call_count, int(selected == "pypi"))
                self.assertEqual(oci.call_count, int(selected == "oci"))

    def test_cli_selector_reaches_the_image_lane(self):
        prior = Path.cwd()
        try:
            os.chdir(self.root)
            with (
                patch.object(PUBLISH, "publish_pypi") as pypi,
                patch.object(PUBLISH, "publish_oci") as oci,
            ):
                self.assertEqual(PUBLISH.main(["--only", "oci", "server-v1.2.3"]), 0)
                pypi.assert_not_called()
                oci.assert_called_once()
        finally:
            os.chdir(prior)

    def test_identity_failure_still_precedes_either_publication(self):
        command(self.root, "git", "tag", "server-v1.2.4")
        with (
            patch.object(PUBLISH, "publish_pypi") as pypi,
            patch.object(PUBLISH, "publish_oci") as oci,
        ):
            with self.assertRaisesRegex(PUBLISH.PublishRefusal, "does not match"):
                PUBLISH.publish(self.root, "server-v1.2.4", only="oci")
            pypi.assert_not_called()
            oci.assert_not_called()

    def test_other_python_lane_stays_python_only_and_rejects_oci(self):
        command(self.root, "git", "tag", "awid-service-v2.3.4")
        with (
            patch.object(PUBLISH, "publish_pypi") as pypi,
            patch.object(PUBLISH, "publish_oci") as oci,
        ):
            PUBLISH.publish(self.root, "awid-service-v2.3.4", assets=Path("assets"))
            pypi.assert_called_once()
            oci.assert_not_called()
            with self.assertRaisesRegex(PUBLISH.PublishRefusal, "oci"):
                PUBLISH.publish(self.root, "awid-service-v2.3.4", only="oci")


IMAGE_WORKFLOW = ROOT / ".github/workflows/service-image-release.yml"


def workflow_step_script(name):
    """The run block of one step of the image workflow, exactly as GitHub runs it."""
    lines = IMAGE_WORKFLOW.read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
    body = []
    for line in lines[run + 1 :]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body) + "\n"


class ImageRecoveryDispatchTests(unittest.TestCase):
    """An existing tag's image can be published again by dispatch, from main's publisher."""

    def test_publication_builds_the_tags_commit_when_the_publisher_is_later(self):
        temporary, root = test_shipping.TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        command(root, "git", "tag", "server-v1.2.3")
        tagged = command(root, "git", "rev-parse", "HEAD")
        (root / "PUBLISHER_FIX").write_text("main moved on after the tag\n")
        command(root, "git", "add", "PUBLISHER_FIX")
        command(root, "git", "commit", "-qm", "publisher fix after the tag")
        later = command(root, "git", "rev-parse", "HEAD")
        self.assertNotEqual(later, tagged)
        built = []

        def publish_oci(
            checkout, prefix, version, sha, recovery=False, first_publication=()
        ):
            built.append(
                (command(checkout, "git", "rev-parse", "HEAD"), prefix, version, sha)
            )

        with (
            patch.object(PUBLISH, "publish_pypi") as pypi,
            patch.object(PUBLISH, "publish_oci", publish_oci),
        ):
            PUBLISH.publish(root, "server-v1.2.3", only="oci")
        pypi.assert_not_called()
        self.assertEqual(built, [(tagged, "server-v", "1.2.3", tagged)])
        self.assertEqual(command(root, "git", "rev-parse", "HEAD"), later)

    def test_workflow_offers_a_tag_input_and_keys_concurrency_to_the_tag(self):
        source = IMAGE_WORKFLOW.read_text()
        self.assertIn("  workflow_dispatch:\n    inputs:\n      tag:\n", source)
        dispatch = source[
            source.index("  workflow_dispatch:") : source.index("permissions:")
        ]
        self.assertIn("required: true", dispatch)
        self.assertIn("type: string", dispatch)
        # A dispatch and the tag's own push run publish the same image: one at a time.
        # A dispatch and the tag's own push run publish the same image: one at a time.
        # Per tag, so a release pushing several image tags at once cancels none of them.
        self.assertIn(
            "group: image-${{ github.event_name == 'workflow_dispatch' && format('refs/tags/{0}', inputs.tag) || github.ref }}",
            source,
        )
        self.assertIn(
            "RELEASE_TAG: ${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}",
            source,
        )
        # The input reaches the shell only through the environment, never as interpolated script text.
        script = workflow_step_script("Publish or adopt the tagged image")
        self.assertNotIn("${{", script)
        # Tags are fetched, so the publisher can resolve the requested one.
        self.assertIn("fetch-depth: 0", source)

    def run_step(self, event, ref, release_tag, first_publication=""):
        temporary, root = test_shipping.TagContractTest.repository(self)
        self.addCleanup(temporary.cleanup)
        command(root, "git", "tag", "server-v1.2.3")
        command(root, "git", "branch", "server-v9.9.9")  # a branch, not a tag
        scratch = tempfile.TemporaryDirectory(prefix="aweb-image-step-")
        self.addCleanup(scratch.cleanup)
        bin_dir = Path(scratch.name) / "bin"
        bin_dir.mkdir()
        calls = Path(scratch.name) / "publisher-calls"
        (bin_dir / "python3").write_text(
            f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> {calls}\n'
        )
        (bin_dir / "python3").chmod(0o755)
        script = workflow_step_script("Publish or adopt the tagged image")
        result = subprocess.run(
            ["bash", "-e", "-c", script],
            cwd=root,
            text=True,
            capture_output=True,
            env={
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "HOME": scratch.name,
                "GITHUB_EVENT_NAME": event,
                "GITHUB_REF": ref,
                "RELEASE_TAG": release_tag,
                "FIRST_PUBLICATION": first_publication,
                "GHCR_USERNAME": "fixture",
                "GHCR_TOKEN": "fixture-token",
            },
        )
        published = calls.read_text().splitlines() if calls.exists() else []
        return result, published

    def test_only_a_dispatch_carries_an_explicit_first_publication(self):
        result, published = self.run_step(
            "workflow_dispatch",
            "refs/heads/main",
            "server-v1.2.3",
            first_publication="ghcr.io/awebai/aweb-server",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            published,
            [
                "scripts/publish_release.py --only oci --recovery "
                "--first-publication ghcr.io/awebai/aweb-server server-v1.2.3"
            ],
        )
        result, published = self.run_step(
            "push",
            "refs/tags/server-v1.2.3",
            "server-v1.2.3",
            first_publication="ghcr.io/awebai/aweb-server",
        )
        self.assertEqual(
            published, ["scripts/publish_release.py --only oci server-v1.2.3"]
        )

    def test_push_and_main_dispatch_run_the_publisher_for_the_tag(self):
        # Only a dispatch is a recovery, which never moves latest.
        for event, ref, expected in (
            ("push", "refs/tags/server-v1.2.3", "--only oci server-v1.2.3"),
            (
                "workflow_dispatch",
                "refs/heads/main",
                "--only oci --recovery server-v1.2.3",
            ),
        ):
            with self.subTest(event=event):
                result, published = self.run_step(event, ref, "server-v1.2.3")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(published, ["scripts/publish_release.py " + expected])

    def test_dispatch_refuses_another_publisher_ref_or_a_name_that_is_not_a_tag(self):
        cases = {
            "branch publisher": (
                "refs/heads/feature",
                "server-v1.2.3",
                "image recovery runs main's publisher; dispatched from refs/heads/feature",
            ),
            "branch named like a tag": (
                "refs/heads/main",
                "server-v9.9.9",
                "no release tag server-v9.9.9",
            ),
            "absent tag": (
                "refs/heads/main",
                "server-v1.2.4",
                "no release tag server-v1.2.4",
            ),
            "empty": ("refs/heads/main", "", "no release tag "),
        }
        for name, (ref, tag, message) in cases.items():
            with self.subTest(case=name):
                result, published = self.run_step("workflow_dispatch", ref, tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(published, [])


# The coordination server image published by a server tag.
SERVER_TAG_REPOSITORIES = ("ghcr.io/awebai/aweb-server",)


def release_indexes(output):
    return [
        json.loads(line.split("=", 1)[1])
        for line in output.splitlines()
        if line.startswith("release-index=")
    ]


class ServerOciTests(unittest.TestCase):
    def exercise(
        self,
        *,
        existing=False,
        conflict=False,
        fail_readback=False,
        version="1.2.3",
        listing=None,
        prefix="server-v",
        recovery=False,
        first_publication=(),
    ):
        raw = b'{"schemaVersion":2}\n'
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        calls = []

        def run(root, *args, **kwargs):
            calls.append(args)
            if "inspect-staged" in args:
                Path(args[args.index("--out") + 1]).write_text(
                    json.dumps({"index": digest})
                )
            if "verify-published" in args and fail_readback:
                raise PUBLISH.PublishRefusal("published digest mismatch")
            return ""

        if listing is None:
            listing = (
                0,
                json.dumps({"Tags": ["1.2.3", "latest"] if existing else []}),
                "",
            )
        observed = subprocess.CompletedProcess(
            [], 0, b"different" if conflict else raw, b""
        )

        def direct(argv, **kwargs):
            calls.append(tuple(argv))
            if tuple(argv[:2]) == ("skopeo", "list-tags"):
                self.assertTrue(kwargs.get("text"))
                answer = (
                    listing[argv[-1].removeprefix("docker://")]
                    if isinstance(listing, dict)
                    else listing
                )
                return subprocess.CompletedProcess(argv, *answer)
            return observed

        with (
            patch.dict(os.environ, GHCR_USERNAME="fixture", GHCR_TOKEN="fixture-token"),
            patch.object(PUBLISH.shutil, "which", return_value="skopeo"),
            patch.object(PUBLISH, "run", run),
            patch.object(PUBLISH.subprocess, "run", direct),
            redirect_stdout(io.StringIO()) as output,
        ):
            PUBLISH.publish_oci(
                ROOT,
                prefix,
                version,
                "a" * 40,
                recovery=recovery,
                first_publication=first_publication,
            )
        return calls, output.getvalue(), digest

    # skopeo's exact answer for ghcr.io/awebai/aweb-server before its first
    # image (Publish service image run 43622390148, server-v1.27.51rc2).
    ABSENT_REPOSITORY = (
        'time="2026-11-14T17:42:02Z" level=fatal '
        'msg="Error listing repository tags: fetching tags list: name unknown"\n'
    )

    def test_first_publication_to_an_absent_repository_has_no_tags(self):
        for version, expected in (
            ("1.27.51rc2", ["1.27.51rc2"]),
            ("1.2.3", ["1.2.3", "latest"]),
        ):
            with self.subTest(version=version):
                calls, output, digest = self.exercise(
                    version=version,
                    listing=(1, "", self.ABSENT_REPOSITORY),
                    first_publication=SERVER_TAG_REPOSITORIES,
                )
                self.assertFalse(
                    any(args[:3] == ("skopeo", "inspect", "--raw") for args in calls)
                )
                copies = [args[-1] for args in calls if args[:2] == ("skopeo", "copy")]
                self.assertEqual(
                    copies,
                    [
                        f"docker://{repository}:{tag}"
                        for repository in SERVER_TAG_REPOSITORIES
                        for tag in expected
                    ],
                )
                self.assertEqual(
                    calls[-1][:3],
                    ("bash", "scripts/oci-exact-publish.sh", "verify-published"),
                )
                self.assertEqual(
                    [index["digest"] for index in release_indexes(output)], [digest]
                )

    def test_name_unknown_without_the_explicit_first_publication_refuses(self):
        # "name unknown" is never taken to mean absent on its own (Antares, aweb-adbc 2).
        with self.assertRaisesRegex(
            PUBLISH.PublishRefusal,
            "name unknown.*--first-publication ghcr.io/awebai/aweb-server",
        ):
            self.exercise(listing=(1, "", self.ABSENT_REPOSITORY))

    def test_only_the_named_repository_may_be_new(self):
        repository = SERVER_TAG_REPOSITORIES[0]
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "publishes no"):
            self.exercise(
                version="1.2.3rc1",
                listing=(1, "", self.ABSENT_REPOSITORY),
                first_publication=("ghcr.io/awebai/unrelated",),
            )
        calls, _, _ = self.exercise(
            version="1.2.3rc1",
            listing=(1, "", self.ABSENT_REPOSITORY),
            first_publication=(repository,),
        )
        copies = [args[-1] for args in calls if args[:2] == ("skopeo", "copy")]
        self.assertEqual(copies, [f"docker://{repository}:1.2.3rc1"])

    def test_a_named_repository_that_lists_tags_is_not_a_first_publication(self):
        with self.assertRaisesRegex(
            PUBLISH.PublishRefusal,
            "not a first publication: ghcr.io/awebai/aweb-server",
        ):
            self.exercise(
                existing=True, first_publication=("ghcr.io/awebai/aweb-server",)
            )

    def test_a_first_publication_outside_the_tags_images_refuses_before_any_build(self):
        calls = []
        with patch.object(
            PUBLISH, "run", lambda root, *args, **kwargs: calls.append(args) or ""
        ):
            with (
                patch.dict(
                    os.environ, GHCR_USERNAME="fixture", GHCR_TOKEN="fixture-token"
                ),
                patch.object(PUBLISH.shutil, "which", return_value="skopeo"),
            ):
                with self.assertRaisesRegex(
                    PUBLISH.PublishRefusal, "server-v publishes no ghcr.io/awebai/awid"
                ):
                    PUBLISH.publish_oci(
                        ROOT,
                        "server-v",
                        "1.2.3",
                        "a" * 40,
                        first_publication=("ghcr.io/awebai/awid",),
                    )
        self.assertEqual(calls, [])

    def test_every_other_listing_failure_refuses_before_any_copy(self):
        failures = {
            "unauthorized": 'time="t" level=fatal msg="Error listing repository tags: fetching tags list: unauthorized: authentication required"\n',
            "denied": 'time="t" level=fatal msg="Error listing repository tags: fetching tags list: denied"\n',
            "name unknown with other detail": 'time="t" level=fatal msg="Error listing repository tags: fetching tags list: name unknown: repository name not known to registry"\n',
            "name unknown at another step": 'time="t" level=fatal msg="Error listing repository tags: pinging container registry: name unknown"\n',
            "transport": 'time="t" level=fatal msg="Error listing repository tags: fetching tags list: Get \\"https://ghcr.io/v2/\\": dial tcp: i/o timeout"\n',
            "absent answer plus more output": self.ABSENT_REPOSITORY
            + 'time="t" level=warning msg="extra"\n',
            "empty": "",
        }
        for name, stderr in failures.items():
            with self.subTest(failure=name):
                with self.assertRaisesRegex(
                    PUBLISH.PublishRefusal,
                    "skopeo list-tags docker://ghcr.io/awebai/aweb-server failed",
                ):
                    self.exercise(listing=(1, "", stderr))
        # The absent-repository text on success output is a malformed listing, not "no tags".
        with self.assertRaisesRegex(PUBLISH.PublishRefusal, "malformed tag listing"):
            self.exercise(
                listing=(0, json.dumps({"Error": self.ABSENT_REPOSITORY}), "")
            )

    def test_server_builds_both_platforms_and_uses_exact_helper_and_readback(self):
        calls, output, digest = self.exercise()
        build = calls[0]
        self.assertEqual(build[:3], ("docker", "buildx", "build"))
        self.assertEqual(build[build.index("--file") + 1], "server/Dockerfile")
        self.assertEqual(
            build[build.index("--platform") + 1], "linux/amd64,linux/arm64"
        )
        self.assertEqual(build[-1], ".")
        for flag in (
            "--provenance=false",
            "--sbom=false",
            "org.opencontainers.image.version=1.2.3",
            "org.opencontainers.image.revision=" + "a" * 40,
        ):
            self.assertIn(flag, build)
        self.assertNotIn(
            "--build-arg", build
        )  # the coordination server alone, no extra
        self.assertEqual(
            calls[1][:3], ("bash", "scripts/oci-exact-publish.sh", "inspect-staged")
        )
        copies = [args for args in calls if args[:2] == ("skopeo", "copy")]
        self.assertEqual(
            [args[-1] for args in copies][:2],
            [
                "docker://ghcr.io/awebai/aweb-server:1.2.3",
                "docker://ghcr.io/awebai/aweb-server:latest",
            ],
        )
        self.assertTrue(all("--all" in args for args in copies))
        verifies = [
            args
            for args in calls
            if args[:3] == ("bash", "scripts/oci-exact-publish.sh", "verify-published")
        ]
        self.assertEqual(verifies[0][-1], "ghcr.io/awebai/aweb-server")
        self.assertEqual(
            release_indexes(output)[0],
            {
                "repository": "ghcr.io/awebai/aweb-server",
                "digest": digest,
                "source_sha": "a" * 40,
                "version": "1.2.3",
            },
        )

    def test_the_image_is_staged_before_any_registry_access(self):
        calls, _, _ = self.exercise()
        staged = [i for i, args in enumerate(calls) if "inspect-staged" in args]
        registry = [i for i, args in enumerate(calls) if args[:1] == ("skopeo",)]
        self.assertEqual(len(staged), 1)
        self.assertLess(max(staged), min(registry))

    def test_a_failed_server_build_publishes_nothing(self):
        calls = []

        def run(root, *args, **kwargs):
            calls.append(args)
            if args[:3] == ("docker", "buildx", "build"):
                raise PUBLISH.PublishRefusal("build failed")
            if "inspect-staged" in args:
                Path(args[args.index("--out") + 1]).write_text(
                    json.dumps({"index": "sha256:" + "c" * 64})
                )
            return ""

        def direct(argv, **kwargs):
            calls.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, json.dumps({"Tags": []}), "")

        with (
            patch.dict(os.environ, GHCR_USERNAME="fixture", GHCR_TOKEN="fixture-token"),
            patch.object(PUBLISH.shutil, "which", return_value="skopeo"),
            patch.object(PUBLISH, "run", run),
            patch.object(PUBLISH.subprocess, "run", direct),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(PUBLISH.PublishRefusal, "build failed"):
                PUBLISH.publish_oci(ROOT, "server-v", "1.2.3", "a" * 40)
        self.assertEqual(
            len([args for args in calls if args[:3] == ("docker", "buildx", "build")]),
            1,
        )
        self.assertFalse(
            [args for args in calls if args[:1] == ("skopeo",)],
            "no login, listing or copy after a failed build",
        )

    def test_each_image_tag_names_its_image(self):
        self.assertEqual(PUBLISH.oci_images("awid-v"), ("ghcr.io/awebai/awid",))
        self.assertEqual(
            PUBLISH.oci_images("server-v"), ("ghcr.io/awebai/aweb-server",)
        )

    def test_rc_publishes_and_reads_back_only_its_immutable_version(self):
        calls, _, _ = self.exercise(version="1.2.3rc1")
        copies = [args for args in calls if args[:2] == ("skopeo", "copy")]
        self.assertEqual(
            [args[-1] for args in copies],
            ["docker://ghcr.io/awebai/aweb-server:1.2.3rc1"],
        )
        self.assertIn("--version-only", calls[-1])
        verifies = [
            args
            for args in calls
            if args[:3] == ("bash", "scripts/oci-exact-publish.sh", "verify-published")
        ]
        self.assertTrue(all("--version-only" in args for args in verifies))

    def published_tags_and_readback(self, **kwargs):
        calls, _, _ = self.exercise(**kwargs)
        copies = [args[-1] for args in calls if args[:2] == ("skopeo", "copy")]
        verifies = [
            args
            for args in calls
            if args[:3] == ("bash", "scripts/oci-exact-publish.sh", "verify-published")
        ]
        return copies, verifies

    def test_an_rc_on_any_image_lane_never_moves_latest(self):
        for prefix, version, repositories in (
            ("server-v", "1.2.3rc1", SERVER_TAG_REPOSITORIES),
            ("awid-v", "0.5.40rc2", ("ghcr.io/awebai/awid",)),
        ):
            with self.subTest(prefix=prefix):
                copies, verifies = self.published_tags_and_readback(
                    prefix=prefix, version=version
                )
                self.assertEqual(
                    copies,
                    [f"docker://{repository}:{version}" for repository in repositories],
                )
                self.assertTrue(
                    verifies and all("--version-only" in args for args in verifies)
                )

    def test_a_recovery_never_moves_latest(self):
        for version in ("1.2.3", "1.2.3rc1"):
            with self.subTest(version=version):
                calls, output, _ = self.exercise(version=version, recovery=True)
                copies = [args[-1] for args in calls if args[:2] == ("skopeo", "copy")]
                self.assertEqual(
                    copies,
                    [
                        f"docker://{repository}:{version}"
                        for repository in SERVER_TAG_REPOSITORIES
                    ],
                )
                verifies = [
                    args
                    for args in calls
                    if args[:3]
                    == ("bash", "scripts/oci-exact-publish.sh", "verify-published")
                ]
                self.assertEqual(len(verifies), 1)
                self.assertTrue(all("--version-only" in args for args in verifies))
                self.assertEqual(output.count("latest unchanged (recovery)"), 1)

    def test_a_final_from_its_own_tag_moves_version_and_latest(self):
        copies, verifies = self.published_tags_and_readback(
            prefix="awid-v", version="0.5.40"
        )
        self.assertEqual(
            copies,
            [
                "docker://ghcr.io/awebai/awid:0.5.40",
                "docker://ghcr.io/awebai/awid:latest",
            ],
        )
        self.assertTrue(all("--version-only" not in args for args in verifies))

    def test_identical_published_index_is_adopted_and_read_back(self):
        calls, _, _ = self.exercise(existing=True)
        self.assertFalse(any(args[:2] == ("skopeo", "copy") for args in calls))
        self.assertIn("verify-published", calls[-1])

    def test_conflicting_immutable_version_refuses(self):
        with self.assertRaisesRegex(
            PUBLISH.PublishRefusal, "immutable ghcr.io/awebai/aweb-server:1.2.3"
        ):
            self.exercise(existing=True, conflict=True)

    def test_readback_failure_is_not_success(self):
        with self.assertRaisesRegex(
            PUBLISH.PublishRefusal, "published digest mismatch"
        ):
            self.exercise(fail_readback=True)


@unittest.skipUnless(
    os.environ.get("AWEB_TEST_SERVER_IMAGE_BUILD") == "1",
    "requires Docker, skopeo and native platform runtime",
)
class ServerPlatformBuildTests(unittest.TestCase):
    def test_release_archive_and_native_server_cli(self):
        self.qualify("AWEB_SERVER_IMAGE_ARCHIVE", "server image")

    def qualify(self, archive_variable, name):
        version = tomllib.loads((ROOT / "server/pyproject.toml").read_text())[
            "project"
        ]["version"]
        sha = command(ROOT, "git", "rev-parse", "HEAD")
        daemon = json.loads(
            PUBLISH.run(ROOT, "docker", "info", "--format", "{{json .}}")
        )
        native = {
            "x86_64": ("amd64", "x86_64"),
            "amd64": ("amd64", "x86_64"),
            "aarch64": ("arm64", "aarch64"),
            "arm64": ("arm64", "aarch64"),
        }
        self.assertEqual(daemon["OSType"], "linux")
        self.assertIn(daemon["Architecture"], native, "unsupported native architecture")
        architecture, machine = native[daemon["Architecture"]]
        archive_in = os.environ.get(archive_variable + "_IN", "")
        archive_out = os.environ.get(archive_variable + "_OUT", "")
        self.assertFalse(archive_in and archive_out, "select archive input OR output")
        run_id = "server-image-test-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix=run_id) as temporary:
            archive = Path(
                archive_in or archive_out or str(Path(temporary) / "server.oci.tar")
            ).resolve()
            identities = Path(temporary) / "identities.json"
            if archive_in:
                self.assertTrue(
                    archive.is_file(),
                    "input archive must exist; never rebuild a transferred artifact",
                )
            else:
                self.assertFalse(
                    archive.exists(),
                    "output archive already exists; do not overwrite release bytes",
                )
                # The publication path uses this exact builder, not a second recipe.
                PUBLISH.build_oci_archive(ROOT, "server-v", version, sha, archive)
            PUBLISH.run(
                ROOT,
                "bash",
                "scripts/oci-exact-publish.sh",
                "inspect-staged",
                "--archive",
                str(archive),
                "--version",
                version,
                "--source-sha",
                sha,
                "--out",
                str(identities),
            )
            identity = json.loads(identities.read_text())
            self.assertEqual(set(identity["platforms"]), {"linux/amd64", "linux/arm64"})
            print(
                name + " staged identity=" + json.dumps(identity, sort_keys=True),
                flush=True,
            )
            with archive.open("rb") as stream:
                archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            print(
                name
                + " archive receipt="
                + json.dumps(
                    {
                        "sha256": archive_hash,
                        "bytes": archive.stat().st_size,
                        "index": identity["index"],
                        "source_sha": sha,
                        "version": version,
                        "native_platform": "linux/" + architecture,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            with self.subTest(platform=architecture):
                image = run_id + ":" + architecture
                container = run_id + "-" + architecture
                loaded = False
                try:
                    PUBLISH.run(
                        ROOT,
                        "skopeo",
                        "--override-os",
                        "linux",
                        "--override-arch",
                        architecture,
                        "copy",
                        "oci-archive:" + str(archive),
                        "docker-daemon:" + image,
                        timeout=600,
                    )
                    loaded = True
                    observed = json.loads(
                        PUBLISH.run(ROOT, "docker", "image", "inspect", image)
                    )[0]
                    self.assertEqual(observed["Architecture"], architecture)
                    self.assertEqual(
                        observed["Config"]["Labels"][
                            "org.opencontainers.image.revision"
                        ],
                        sha,
                    )
                    probe = (
                        "import importlib.metadata as m, json, os, platform; "
                        "import aweb.cli, awid, aweb_naapp; "
                        "print(json.dumps(dict(version=m.version('aweb'), machine=platform.machine(), uid=os.getuid())))"
                    )
                    result = json.loads(
                        PUBLISH.run(
                            ROOT,
                            "docker",
                            "run",
                            "--rm",
                            "--name",
                            container,
                            "--platform",
                            "linux/" + architecture,
                            image,
                            "python",
                            "-c",
                            probe,
                            timeout=120,
                        )
                    )
                    self.assertEqual(
                        result, {"version": version, "machine": machine, "uid": 1001}
                    )
                    help_text = PUBLISH.run(
                        ROOT,
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        container,
                        "--platform",
                        "linux/" + architecture,
                        image,
                        "aweb",
                        "serve",
                        "--help",
                        timeout=120,
                    )
                    self.assertIn("Usage", help_text)
                    print(f"{name} linux/{architecture} PASS: {result}", flush=True)
                finally:
                    # Remove only this probe's resources, including a timed-out container.
                    subprocess.run(
                        ["docker", "rm", "-f", container],
                        capture_output=True,
                        timeout=60,
                        check=False,
                    )
                    if loaded:
                        PUBLISH.run(
                            ROOT, "docker", "image", "rm", "-f", image, timeout=60
                        )


class RecoveryArgumentTests(unittest.TestCase):
    def test_cli_recovery_reaches_the_image_publisher(self):
        with patch.object(PUBLISH, "publish") as publish:
            self.assertEqual(
                PUBLISH.main(["--only", "oci", "--recovery", "server-v1.2.3"]), 0
            )
            publish.assert_called_once()
            self.assertTrue(publish.call_args.kwargs["recovery"])
            publish.reset_mock()
            self.assertEqual(PUBLISH.main(["--only", "oci", "server-v1.2.3"]), 0)
            self.assertFalse(publish.call_args.kwargs["recovery"])


class FirstPublicationArgumentTests(unittest.TestCase):
    def test_cli_first_publication_reaches_the_image_publisher(self):
        with patch.object(PUBLISH, "publish") as publish:
            self.assertEqual(
                PUBLISH.main(
                    [
                        "--only",
                        "oci",
                        "--first-publication",
                        "ghcr.io/awebai/aweb-server",
                        "server-v1.2.3",
                    ]
                ),
                0,
            )
            self.assertEqual(
                publish.call_args.kwargs["first_publication"],
                ["ghcr.io/awebai/aweb-server"],
            )
            self.assertEqual(PUBLISH.main(["--only", "oci", "server-v1.2.3"]), 0)
            self.assertEqual(publish.call_args.kwargs["first_publication"], [])


if __name__ == "__main__":
    unittest.main()
