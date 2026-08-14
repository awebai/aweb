"""Thin release-branch publication contracts and fixture-only rehearsal.

The complete suite runs before the release branch moves. These workflows may
only rebuild the accepted commit, inspect it, publish/adopt exact registry
state, and cheaply verify what the public registry serves. The tests below are
static where GitHub wiring is the behavior and use local fixtures for registry
and git-output decisions; they never dispatch a workflow or contact a public
registry.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PYPI_PRIMITIVE = REPO_ROOT / "scripts" / "pypi-exact-publish.sh"
OCI_PRIMITIVE = REPO_ROOT / "scripts" / "oci-exact-publish.sh"
PYPI = (WORKFLOWS / "pypi-release.yml").read_text(encoding="utf-8")
AWID_IMAGE = (WORKFLOWS / "awid-image-release.yml").read_text(encoding="utf-8")


def run(
    *args: str,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=cwd, text=True, capture_output=True, check=check, env=env
    )


def job_block(workflow: str, job: str) -> str:
    jobs = workflow[workflow.index("\njobs:\n") :]
    header = f"\n  {job}:\n"
    start = jobs.index(header)
    body_start = start + len(header)
    match = re.search(r"(?m)^  [a-zA-Z0-9_-]+:\n", jobs[body_start:])
    end = len(jobs) if match is None else body_start + match.start()
    return jobs[start:end]


def shell_function(workflow: str, name: str) -> str:
    lines = workflow.splitlines()
    start = lines.index(f"          {name}() {{")
    for end in range(start + 1, len(lines)):
        if lines[end] == "          }":
            return "\n".join(line[10:] for line in lines[start : end + 1]) + "\n"
    raise ValueError(f"unterminated shell function {name}")


def make_dist(dist: Path, package: str, version: str) -> None:
    normalized = package.replace("-", "_")
    dist.mkdir(parents=True)
    sdist = dist / f"{normalized}-{version}.tar.gz"
    body = f"Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n".encode()
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo(f"{normalized}-{version}/PKG-INFO")
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    wheel = dist / f"{normalized}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"{normalized}-{version}.dist-info/METADATA", body
        )


def pypi_observation(dist: Path) -> dict[str, object]:
    return {
        "urls": [
            {
                "filename": path.name,
                "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
            }
            for path in sorted(dist.iterdir())
        ]
    }


class ThinReleaseWorkflowContractTests(unittest.TestCase):
    def assert_release_trigger_only(self, workflow: str) -> None:
        triggers = workflow[workflow.index("\non:\n") : workflow.index("\njobs:\n")]
        self.assertIn("push:", triggers)
        self.assertRegex(triggers, r"branches:\s*\[release\]")
        for forbidden in ("workflow_dispatch", "tags:", "main", "pull_request", "schedule"):
            self.assertNotIn(forbidden, triggers)

    def assert_exact_release_identity(self, workflow: str) -> None:
        self.assertIn("SOURCE_SHA: ${{ github.sha }}", workflow)
        self.assertIn('git ls-remote origin refs/heads/release', workflow)
        self.assertIn("+refs/heads/main:refs/remotes/origin/main", workflow)
        self.assertIn("+refs/heads/release:refs/remotes/origin/release", workflow)
        self.assertIn('[[ "$release_tip" == "$SOURCE_SHA" ]]', workflow)
        self.assertIn('git merge-base --is-ancestor "$SOURCE_SHA" origin/main', workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        for forbidden in ("inputs.version", "inputs.source_sha", "SOURCE_SHA: ${{ inputs"):
            self.assertNotIn(forbidden, workflow)

    def assert_thin(self, workflow: str) -> None:
        for forbidden in (
            "pytest",
            "postgres:16",
            "make release-",
            "make test",
            "upload-artifact",
            "download-artifact",
            "stage-only",
            "publish-continuation",
            "stage_run_id",
            "provenance inputs",
        ):
            self.assertNotIn(forbidden, workflow)

    def assert_pypi_contract(self, workflow: str) -> None:
        awid = job_block(workflow, "awid_service")
        server = job_block(workflow, "aweb")
        self.assertIn("needs: awid_service", server)
        self.assertLess(workflow.index("  awid_service:\n"), workflow.index("  aweb:\n"))
        self.assertIn("awid/pyproject.toml", awid)
        self.assertIn("server/pyproject.toml", server)
        self.assertIn("Public AWID floor", server)
        # The floor predicate and the served observation are the extracted
        # shared implementations, invoked unconditionally with status
        # propagation - no inline tomllib/curl reimplementation, and no
        # suppression on either call line (the guard-present-refusal-
        # discarded class).
        floor_call = (
            'bash scripts/check-release-floor.sh --pyproject '
            'server/pyproject.toml --package awid-service --expected '
            '"$AWID_VERSION"'
        )
        observe_call = (
            'python3 scripts/observe_public_target.py '
            '"pypi:awid-service" "$AWID_VERSION"'
        )
        self.assertIn(floor_call, server)
        self.assertIn(observe_call, server)
        for call in (floor_call, observe_call):
            for line in server.splitlines():
                if call in line:
                    self.assertNotIn("|| true", line)
                    self.assertNotIn("2>/dev/null", line)
        floor_step = server[
            server.index("Public AWID floor") : server.index(
                "Build, publish or adopt, verify, and tag aweb"
            )
        ]
        for reimplementation in ("tomllib", "curl"):
            self.assertNotIn(reimplementation, floor_step)
        self.assertIn("https://pypi.org/pypi/", workflow)
        self.assertIn("--index-url https://pypi.org/simple", workflow)
        for job, package, tag, import_name in (
            (awid, "awid-service", "awid-service-v", "import awid"),
            (server, "aweb", "server-v", "import aweb"),
        ):
            with self.subTest(package=package):
                # The runner's uv is a production input like every other:
                # it must be pinned to an exact version, never latest.
                self.assertEqual(job.count("astral-sh/setup-uv@"), 1)
                self.assertIn(
                    '- uses: astral-sh/setup-uv@v7\n'
                    '        with:\n'
                    '          version: "',
                    job,
                )
                self.assertEqual(job.count("uv build --sdist --wheel"), 1)
                # uv build stamps a .gitignore into the out-dir it creates;
                # inspect-staged refuses any extra file, so the workflow must
                # drop the stamp between build and inspection.
                self.assertIn('rm -f "$dist/.gitignore"', job)
                self.assertLess(
                    job.index("uv build --sdist --wheel"),
                    job.index('rm -f "$dist/.gitignore"'),
                )
                self.assertLess(
                    job.index('rm -f "$dist/.gitignore"'),
                    job.index("pypi-exact-publish.sh inspect-staged"),
                )
                self.assertIn("npm-exact-publish.sh validate-inputs", job)
                self.assertIn("pypi-exact-publish.sh inspect-staged", job)
                self.assertIn("pypi-exact-publish.sh plan-publish", job)
                self.assertIn("pypi-exact-publish.sh verify-published", job)
                self.assertIn("--only-binary=:all:", job)
                self.assertIn("--no-cache", job)
                self.assertIn(import_name, job)
                self.assertIn(tag, job)
                self.assertIn("require_tag_compatible", job)
                self.assertIn("publish_tag", job)
                verification = job.index("verify-published")
                tag_output = job.index('publish_tag "$tag"')
                self.assertLess(verification, tag_output)
                self.assertLess(verification, job.rindex("require_release_sha"))
                self.assertLess(job.rindex("require_release_sha"), tag_output)
                self.assertGreaterEqual(job.count("require_release_sha"), 3)
        self.assertIn("UV_PUBLISH_TOKEN", workflow)

    def assert_oci_contract(self, workflow: str) -> None:
        job = job_block(workflow, "publish_image")
        self.assertIn("awid/pyproject.toml", job)
        self.assertEqual(job.count("docker buildx build"), 1)
        self.assertIn("--platform linux/amd64,linux/arm64", job)
        self.assertIn("--file awid/Dockerfile.release", job)
        dockerfile = (REPO_ROOT / "awid" / "Dockerfile.release").read_text(
            encoding="utf-8"
        )
        self.assertIn("COPY server/src ./server/src", dockerfile)
        self.assertIn('org.opencontainers.image.version=${VERSION}', job)
        self.assertIn('org.opencontainers.image.revision=${SOURCE_SHA}', job)
        self.assertIn('type=oci,dest=', job)
        self.assertIn("npm-exact-publish.sh validate-inputs", job)
        self.assertIn("oci-exact-publish.sh inspect-staged", job)
        self.assertIn("oci-exact-publish.sh decide-tag", job)
        self.assertIn("oci-exact-publish.sh verify-published", job)
        self.assertIn('for image_tag in "$VERSION" latest', job)
        self.assertIn("skopeo copy --all", job)
        self.assertIn("docker://ghcr.io/awebai/awid", job)
        self.assertIn("STAGED INDEX DIGEST", job)
        self.assertIn("awid-v", job)
        self.assertIn("require_tag_compatible", job)
        self.assertIn("publish_tag", job)
        verification = job.index("verify-published")
        tag_output = job.index('publish_tag "$tag"')
        self.assertLess(verification, tag_output)
        self.assertLess(verification, job.rindex("require_release_sha"))
        self.assertLess(job.rindex("require_release_sha"), tag_output)
        self.assertGreaterEqual(job.count("require_release_sha"), 3)

    def test_workflows_are_release_branch_only_and_exact_sha_bound(self) -> None:
        for workflow in (PYPI, AWID_IMAGE):
            self.assert_release_trigger_only(workflow)
            self.assert_exact_release_identity(workflow)
            self.assert_thin(workflow)

    def test_pypi_is_awid_before_aweb_with_exact_public_verification(self) -> None:
        self.assert_pypi_contract(PYPI)

    def test_awid_image_is_two_platform_same_commit_and_digest_verified(self) -> None:
        self.assert_oci_contract(AWID_IMAGE)

    def test_contract_mutations_fail_for_each_requested_wiring_boundary(self) -> None:
        mutations = (
            (
                "wrong branch",
                PYPI,
                self.assert_release_trigger_only,
                PYPI.replace("branches: [release]", "branches: [main]", 1),
                "Regex didn't match",
            ),
            (
                "tag trigger",
                PYPI,
                self.assert_release_trigger_only,
                PYPI.replace(
                    "branches: [release]",
                    "branches: [release]\n    tags: ['v*']",
                    1,
                ),
                "tags:",
            ),
            (
                "wrong SHA comparison",
                PYPI,
                self.assert_exact_release_identity,
                PYPI.replace(
                    '[[ "$release_tip" == "$SOURCE_SHA" ]]',
                    '[[ "$release_tip" != "$SOURCE_SHA" ]]',
                ),
                '[[ "$release_tip" == "$SOURCE_SHA" ]]',
            ),
            (
                "caller-supplied version",
                PYPI,
                self.assert_exact_release_identity,
                PYPI + "\n# inputs.version\n",
                "inputs.version",
            ),
            (
                "suite reintroduction",
                PYPI,
                self.assert_thin,
                PYPI + "\n# pytest\n",
                "pytest",
            ),
            (
                "aweb races AWID",
                PYPI,
                self.assert_pypi_contract,
                PYPI.replace("needs: awid_service", "", 1),
                "needs: awid_service",
            ),
            (
                "single-platform image",
                AWID_IMAGE,
                self.assert_oci_contract,
                AWID_IMAGE.replace("linux/amd64,linux/arm64", "linux/amd64", 1),
                "--platform linux/amd64,linux/arm64",
            ),
            (
                "wrong image version label",
                AWID_IMAGE,
                self.assert_oci_contract,
                AWID_IMAGE.replace(
                    "org.opencontainers.image.version=${VERSION}",
                    "org.opencontainers.image.version=unknown",
                    1,
                ),
                "org.opencontainers.image.version=${VERSION}",
            ),
            (
                "wrong image revision label",
                AWID_IMAGE,
                self.assert_oci_contract,
                AWID_IMAGE.replace(
                    "org.opencontainers.image.revision=${SOURCE_SHA}",
                    "org.opencontainers.image.revision=unknown",
                    1,
                ),
                "org.opencontainers.image.revision=${SOURCE_SHA}",
            ),
            (
                "digest verification removed",
                AWID_IMAGE,
                self.assert_oci_contract,
                AWID_IMAGE.replace(
                    "oci-exact-publish.sh verify-published", "echo unverified", 1
                ),
                "oci-exact-publish.sh verify-published",
            ),
        )
        for name, original, assertion, mutation, expected_reason in mutations:
            with self.subTest(mutation=name):
                self.assertNotEqual(original, mutation, f"{name} mutation was a no-op")
                with self.assertRaises((AssertionError, ValueError)) as caught:
                    assertion(mutation)
                actual_reason = str(caught.exception)
                self.assertIn(
                    expected_reason,
                    actual_reason,
                    f"{name} failed for an unrelated assertion: {actual_reason}",
                )
                if os.environ.get("RELEASE_CONTRACT_MUTATION_REPORT") == "1":
                    concise_reason = actual_reason.split(" in ", 1)[0].replace("\n", " ")
                    print(f"MUTATION RED: {name}: {concise_reason[:240]}")

    def test_fixture_registry_and_temp_remote_rehearse_order_retry_and_conflict(self) -> None:
        """No public writes: real exact-state primitives plus a temporary bare git remote."""

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fakebin = root / "network-must-not-run"
            fakebin.mkdir()
            network_attempt = root / "network-attempted"
            for command in ("curl", "skopeo", "gh", "aws", "docker"):
                path = fakebin / command
                path.write_text(
                    "#!/usr/bin/env bash\n"
                    f"printf '%s\\n' {command} >> {network_attempt}\n"
                    "exit 97\n",
                    encoding="utf-8",
                )
                path.chmod(0o755)
            fixture_env = os.environ.copy()
            fixture_env["PATH"] = f"{fakebin}:{fixture_env['PATH']}"
            control = run("curl", "https://pypi.org", check=False, env=fixture_env)
            self.assertEqual(control.returncode, 97)
            self.assertEqual(network_attempt.read_text(encoding="utf-8"), "curl\n")
            network_attempt.unlink()

            events: list[str] = []
            observations: dict[str, Path] = {}
            for package in ("awid-service", "aweb"):
                dist = root / package / "dist"
                make_dist(dist, package, "1.2.3")
                inspected = run(
                    "bash", str(PYPI_PRIMITIVE), "inspect-staged",
                    "--dist", str(dist), "--package", package, "--version", "1.2.3",
                    env=fixture_env,
                )
                self.assertEqual(inspected.stdout.count("STAGED:"), 2)
                planned = run(
                    "bash", str(PYPI_PRIMITIVE), "plan-publish",
                    "--dist", str(dist), "--package", package, "--version", "1.2.3",
                    "--observed-status", "404", env=fixture_env,
                )
                self.assertEqual(len(planned.stdout.splitlines()), 2)
                events.append(f"publish:{package}")
                observed = root / package / "observed.json"
                observed.write_text(json.dumps(pypi_observation(dist)), encoding="utf-8")
                observations[package] = observed
                run(
                    "bash", str(PYPI_PRIMITIVE), "verify-published",
                    "--dist", str(dist), "--package", package, "--version", "1.2.3",
                    "--observed-json", str(observed), env=fixture_env,
                )
            self.assertEqual(events, ["publish:awid-service", "publish:aweb"])

            # Retry adopts both exact two-file sets and plans no upload.
            for package in ("awid-service", "aweb"):
                adopted = run(
                    "bash", str(PYPI_PRIMITIVE), "plan-publish",
                    "--dist", str(root / package / "dist"), "--package", package,
                    "--version", "1.2.3", "--observed-status", "200",
                    "--observed-json", str(observations[package]), env=fixture_env,
                )
                self.assertEqual(adopted.stdout, "")

            outage = run(
                "bash", str(PYPI_PRIMITIVE), "plan-publish",
                "--dist", str(root / "aweb" / "dist"), "--package", "aweb",
                "--version", "1.2.3", "--observed-status", "503", check=False,
                env=fixture_env,
            )
            self.assertNotEqual(outage.returncode, 0)
            self.assertIn("unavailability", outage.stderr)

            conflict_doc = json.loads(observations["aweb"].read_text())
            conflict_doc["urls"][0]["digests"]["sha256"] = "0" * 64
            conflict = root / "conflict.json"
            conflict.write_text(json.dumps(conflict_doc), encoding="utf-8")
            mismatch = run(
                "bash", str(PYPI_PRIMITIVE), "plan-publish",
                "--dist", str(root / "aweb" / "dist"), "--package", "aweb",
                "--version", "1.2.3", "--observed-status", "200",
                "--observed-json", str(conflict), check=False, env=fixture_env,
            )
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("permanent", mismatch.stderr)

            staged = "sha256:" + "1" * 64
            adopted = run(
                "bash", str(OCI_PRIMITIVE), "decide-tag", "--tag-kind", "version",
                "--staged", staged, "--listing-status", "ok", "--present", "yes",
                "--remote-digest", staged, env=fixture_env,
            )
            self.assertEqual(adopted.stdout.strip(), "ADOPT")
            image_conflict = run(
                "bash", str(OCI_PRIMITIVE), "decide-tag", "--tag-kind", "version",
                "--staged", staged, "--listing-status", "ok", "--present", "yes",
                "--remote-digest", "sha256:" + "2" * 64, check=False,
                env=fixture_env,
            )
            self.assertNotEqual(image_conflict.returncode, 0)

            remote = root / "remote.git"
            checkout = root / "checkout"
            run("git", "init", "--bare", str(remote))
            run("git", "init", str(checkout))
            run("git", "config", "user.email", "fixture@example.invalid", cwd=checkout)
            run("git", "config", "user.name", "fixture", cwd=checkout)
            (checkout / "source").write_text("accepted\n", encoding="utf-8")
            run("git", "add", "source", cwd=checkout)
            run("git", "commit", "-m", "accepted", cwd=checkout)
            source_sha = run("git", "rev-parse", "HEAD", cwd=checkout).stdout.strip()
            run("git", "remote", "add", "origin", str(remote), cwd=checkout)
            run("git", "push", "origin", "HEAD:main", "HEAD:release", cwd=checkout)

            # Execute the workflow's actual tag functions against the bare
            # remote, rather than rehearsing a test-side rendering of them.
            pypi_job = job_block(PYPI, "awid_service")
            image_job = job_block(AWID_IMAGE, "publish_image")
            names = ("remote_tag_sha", "require_tag_compatible", "publish_tag")
            pypi_functions = "".join(shell_function(pypi_job, name) for name in names)
            image_functions = "".join(shell_function(image_job, name) for name in names)
            self.assertEqual(pypi_functions, image_functions)
            functions = root / "publication-tag-functions.sh"
            functions.write_text(
                "fail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n"
                + pypi_functions,
                encoding="utf-8",
            )
            tag_env = fixture_env | {"SOURCE_SHA": source_sha}
            first = run(
                "bash", "-c",
                'source "$1"; require_tag_compatible awid-service-v1.2.3; '
                "publish_tag awid-service-v1.2.3",
                "fixture", str(functions), cwd=checkout, env=tag_env,
            )
            self.assertIn("created tag", first.stdout)
            retry = run(
                "bash", "-c", 'source "$1"; publish_tag awid-service-v1.2.3',
                "fixture", str(functions), cwd=checkout, env=tag_env,
            )
            self.assertIn("adopted existing tag", retry.stdout)
            observed_tag = run(
                "git", "ls-remote", "origin", "refs/tags/awid-service-v1.2.3", cwd=checkout
            ).stdout.split()[0]
            self.assertEqual(observed_tag, source_sha)

            (checkout / "source").write_text("other\n", encoding="utf-8")
            run("git", "commit", "-am", "other", cwd=checkout)
            other_sha = run("git", "rev-parse", "HEAD", cwd=checkout).stdout.strip()
            run("git", "tag", "server-v1.2.3", other_sha, cwd=checkout)
            run("git", "push", "origin", "refs/tags/server-v1.2.3", cwd=checkout)
            conflicting_tag = run(
                "git", "ls-remote", "origin", "refs/tags/server-v1.2.3", cwd=checkout
            ).stdout.split()[0]
            self.assertNotEqual(conflicting_tag, source_sha)
            refused = run(
                "bash", "-c", 'source "$1"; require_tag_compatible server-v1.2.3',
                "fixture", str(functions), cwd=checkout, env=tag_env, check=False,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("not", refused.stderr)
            self.assertIn(source_sha, refused.stderr)
            self.assertFalse(
                network_attempt.exists(),
                "fixture rehearsal invoked a real registry/GitHub/provider command",
            )

    def test_dead_hosted_gate_and_component_paths_are_deleted(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        for dead in (
            "release-server-gate", "release-awid-pypi-gate", "release-awid-image-gate",
            "release-server-check", "release-server-tag", "release-server-push",
            "release-awid-check", "release-awid-tag", "release-awid-push",
            "release-awid-pypi-tag", "release-awid-pypi-push", "awid-release.yml",
        ):
            self.assertNotIn(dead, makefile)

        suite_map = (REPO_ROOT / "release-gate" / "suite-map.tsv").read_text(
            encoding="utf-8"
        )
        for mapped_row in (
            "python-locks\tcontract\ttest-python-locks\n",
            "server-unit\tunit\ttest-server\n",
            "awid-unit\tunit\ttest-awid\n",
            "server-package\tartifact\t_release-artifact-server\n",
            "awid-package\tartifact\t_release-artifact-awid-package\n",
            "awid-image\tartifact\t_release-artifact-awid-image\n",
        ):
            self.assertIn(mapped_row, suite_map)


if __name__ == "__main__":
    unittest.main()
