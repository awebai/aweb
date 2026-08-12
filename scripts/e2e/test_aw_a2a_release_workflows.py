"""Contracts for thin aw and A2A release-branch publication."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AW = (ROOT / ".github/workflows/aw-release.yml").read_text()
A2A = (ROOT / ".github/workflows/a2a-gateway-release.yml").read_text()
PUBLISHER_PATHS = tuple(ROOT / ".github/workflows" / name for name in (
    "pypi-release.yml", "awid-image-release.yml", "npm-release.yml", "aw-release.yml", "a2a-gateway-release.yml"))
MAKE = (ROOT / "Makefile").read_text()
SUITES = (ROOT / "release-gate/suite-map.tsv").read_text()


def marked_block(text: str, begin: str, end: str) -> str:
    lines = text.splitlines()
    first = next(i for i, line in enumerate(lines) if begin in line) + 1
    last = next(i for i, line in enumerate(lines[first:], first) if end in line)
    return "\n".join(line[10:] for line in lines[first:last]) + "\n"


def make_oci_archive(path: Path) -> str:
    blobs: dict[str, bytes] = {}
    def add(data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest(); blobs[digest] = data; return digest
    entries = []
    for arch in ("amd64", "arm64"):
        config = add(json.dumps({"architecture": arch, "os": "linux", "config": {"Labels": {
            "org.opencontainers.image.version": "0.5.14", "org.opencontainers.image.revision": "a" * 40}}}).encode())
        layer = add(("layer-" + arch).encode())
        manifest = add(json.dumps({"schemaVersion": 2, "config": {"digest": config},
            "layers": [{"digest": layer}]}).encode())
        entries.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest,
                        "platform": {"os": "linux", "architecture": arch}})
    index_bytes = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                              "manifests": entries}).encode(); index = add(index_bytes)
    top = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json",
                      "digest": index, "size": len(index_bytes)}]}).encode()
    with tarfile.open(path, "w") as archive:
        def put(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name); info.size = len(data); archive.addfile(info, io.BytesIO(data))
        put("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'); put("index.json", top)
        for digest, data in blobs.items(): put("blobs/sha256/" + digest.split(":")[1], data)
    return index


def check_bounded_awid_observations(text: str) -> None:
    observations: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.search(r"\bskopeo (login|list-tags|inspect)\b", stripped)
        if match:
            observations.append((match.group(1), stripped))
    operations = {operation for operation, _line in observations}
    if operations != {"login", "list-tags", "inspect"} or any(
        "timeout 30 skopeo" not in line for _operation, line in observations
    ):
        raise AssertionError(f"bounded AWID observations violated: {observations!r}")


def check_single_loaded_gateway_build(text: str) -> None:
    builds = [line.strip() for line in text.splitlines() if re.match(r"^docker build(?:\s|$)", line.strip())]
    if len(builds) != 1 or "--load" not in builds[0]:
        raise AssertionError(f"single locally loaded gateway build violated: {builds!r}")


def shell_function(text: str, name: str) -> str:
    lines = text.splitlines()
    first = lines.index(f"          {name}() {{")
    last = next(i for i in range(first + 1, len(lines)) if lines[i] == "          }")
    return "\n".join(line[10:] for line in lines[first:last + 1]) + "\n"


class AwA2AReleaseWorkflowTests(unittest.TestCase):
    def assert_release_only(self, text: str) -> None:
        trigger = text[text.index("\non:\n"):text.index("\njobs:\n")]
        self.assertRegex(trigger, r"branches:\s*\[release\]")
        for dead in ("tags:", "main", "workflow_dispatch", "pull_request"):
            self.assertNotIn(dead, trigger)
        self.assertIn("SOURCE_SHA: ${{ github.sha }}", text)
        self.assertRegex(text, r"timeout-minutes: (15|45)")
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("refs/heads/release", text)
        self.assertIn('[[ "$release_tip" == "$SOURCE_SHA" ]]', text)
        self.assertIn('git merge-base --is-ancestor "$SOURCE_SHA" origin/main', text)

    def assert_aw(self, text: str) -> None:
        self.assert_release_only(text)
        for literal in (
            "awebai/aw", "cli/go", "aw-v${VERSION}", "v${VERSION}",
            '"aw"', '"aweb-a2a-gw"', '"@awebai/aw"',
            '"@awebai/aw-darwin-arm64"', '"@awebai/aw-darwin-x64"',
            '"@awebai/aw-linux-arm64"', '"@awebai/aw-linux-x64"',
            '"@awebai/aw-windows-arm64"', '"@awebai/aw-windows-x64"',
            "AW_EXTERNAL_SYNC_BEGIN", "AW_EXTERNAL_SYNC_END",
            "AW_PUBLIC_VERIFY_BEGIN", "AW_PUBLIC_VERIFY_END",
        ):
            self.assertIn(literal, text)
        self.assertIn("scripts/cli-release-version.sh next", text)
        self.assertIn("check-aw-commit-repo-stamp.sh", text)
        self.assertIn("check-cli-go-tidy", text)
        self.assertIn("preserve external .github", text)
        self.assertIn("exact synced non-.github tree", text)
        self.assertIn("HEAD:main", text)
        self.assertIn("git clone --branch main", text)
        self.assertIn("github.com/awebai/aw.git", text)
        self.assertIn("timeout 30", text)
        self.assertLess(text.index("AW_PUBLIC_PREFLIGHT_END"), text.index("AW_EXTERNAL_SYNC_BEGIN"))
        self.assertLess(text.index("AW_PUBLIC_VERIFY_BEGIN"), text.index('publish_tag "aw-v${VERSION}"'))
        for dead in ("GITHUB_REF_NAME#aw-v", "git push origin main\n"):
            self.assertNotIn(dead, text)

    def assert_a2a(self, text: str) -> None:
        self.assert_release_only(text)
        for literal in (
            "server/pyproject.toml", "ghcr.io/awebai/a2a-gateway",
            "linux/amd64,linux/arm64", "oci-exact-publish.sh inspect-staged",
            "oci-exact-publish.sh decide-tag", "oci-exact-publish.sh verify-published",
            'for image_tag in "$VERSION" latest', "STAGED INDEX DIGEST",
            "a2a-gw-v${VERSION}",
        ):
            self.assertIn(literal, text)
        self.assertIn('org.opencontainers.image.version=${VERSION}', text)
        self.assertGreaterEqual(text.count("timeout 30 skopeo"), 3)
        self.assertIn('org.opencontainers.image.revision=${SOURCE_SHA}', text)
        self.assertLess(text.index("verify-published"), text.index('publish_tag "$tag"'))
        self.assertNotIn("GITHUB_REF_NAME#a2a-gw-v", text)

    def test_five_workflows_parse_and_six_definitions_eight_executions_are_bounded(self) -> None:
        code = 'import json,sys,yaml; print(json.dumps({p:{n:j.get("timeout-minutes") for n,j in yaml.safe_load(open(p))["jobs"].items()} for p in sys.argv[1:]}))'
        def parse(paths: tuple[Path, ...], check: bool = True) -> subprocess.CompletedProcess[str]:
            return subprocess.run(["uv", "run", "--project", "server", "--frozen", "python", "-c", code,
                                  *(str(path) for path in paths)], cwd=ROOT, text=True, capture_output=True,
                                  timeout=45, check=check)
        def assert_bounds(result: subprocess.CompletedProcess[str]) -> None:
            observed = json.loads(result.stdout)
            jobs = {(Path(path).name, job): timeout for path, values in observed.items() for job, timeout in values.items()}
            expected = {("pypi-release.yml", "awid_service"), ("pypi-release.yml", "aweb"),
                        ("awid-image-release.yml", "publish_image"), ("npm-release.yml", "publish"),
                        ("aw-release.yml", "sync-to-aw"), ("a2a-gateway-release.yml", "publish")}
            self.assertEqual(set(jobs), expected); self.assertEqual(len(jobs), 6)
            self.assertEqual(sum(3 if item == ("npm-release.yml", "publish") else 1 for item in jobs), 8)
            self.assertTrue(all(isinstance(value, int) and 0 < value <= 45 for value in jobs.values()), "positive ceiling missing")
        assert_bounds(parse(PUBLISHER_PATHS))
        with tempfile.TemporaryDirectory() as raw:
            paths = tuple(Path(raw) / path.name for path in PUBLISHER_PATHS)
            for source, target in zip(PUBLISHER_PATHS, paths): target.write_bytes(source.read_bytes())
            aw = next(path for path in paths if path.name == "aw-release.yml")
            aw.write_text(aw.read_text().replace("    timeout-minutes: 15\n", "", 1))
            with self.assertRaisesRegex(AssertionError, "positive ceiling missing"): assert_bounds(parse(paths))
            aw.write_text("jobs:\n  broken: [\n")
            malformed = parse(paths, check=False)
            self.assertNotEqual(malformed.returncode, 0); self.assertIn("ParserError", malformed.stderr)
        awid = (ROOT / ".github/workflows/awid-image-release.yml").read_text()
        check_bounded_awid_observations(awid)
        check_bounded_awid_observations(awid + "\n          timeout 30 skopeo inspect --raw fixture\n")
        unbounded_awid = awid.replace("timeout 30 skopeo", "skopeo", 1)
        with self.assertRaisesRegex(AssertionError, "bounded AWID observations violated"):
            check_bounded_awid_observations(unbounded_awid)

    def test_release_only_exact_sha_and_literal_artifacts(self) -> None:
        self.assert_aw(AW)
        self.assert_a2a(A2A)

    def test_contract_mutations_are_cause_bound(self) -> None:
        reordered_a2a = A2A.replace("oci-exact-publish.sh verify-published", "echo verification-moved", 1).replace(
            'publish_tag "$tag"', 'publish_tag "$tag"\n          bash scripts/oci-exact-publish.sh verify-published', 1)
        mutations = (
            ("tag trigger", AW, self.assert_aw, AW.replace("branches: [release]", "tags: ['aw-v*']", 1), "branches"),
            ("aw job timeout", AW, self.assert_aw, AW.replace("timeout-minutes: 15", "timeout-minutes: 0"), "timeout-minutes: (15|45)"),
            ("wrong external repo", AW, self.assert_aw, AW.replace("github.com/awebai/aw.git", "github.com/other/aw.git"), "github.com/awebai/aw.git"),
            ("wrong external tree", AW, self.assert_aw, AW.replace("cli/go", "cli/other"), "cli/go"),
            ("wrong external ref", AW, self.assert_aw, AW.replace("HEAD:main", "HEAD:other"), "HEAD:main"),
            ("stale aw version", AW, self.assert_aw, AW.replace("scripts/cli-release-version.sh next", "echo 1.2.3"), "scripts/cli-release-version.sh next"),
            ("missing binary", AW, self.assert_aw, AW.replace('"aweb-a2a-gw"', '"other"'), '"aweb-a2a-gw"'),
            ("missing platform package", AW, self.assert_aw, AW.replace('"@awebai/aw-windows-x64"', '"@awebai/aw-other"'), '"@awebai/aw-windows-x64"'),
            ("nonexistent win32 package", AW, self.assert_aw, AW.replace('"@awebai/aw-windows-x64"', '"@awebai/aw-win32-x64"'), '"@awebai/aw-windows-x64"'),
            ("unverified workflow", AW, self.assert_aw, AW.replace("AW_EXTERNAL_SYNC_BEGIN", "AW_UNVERIFIED", 1), "AW_EXTERNAL_SYNC_BEGIN"),
            ("a2a job timeout", A2A, self.assert_a2a, A2A.replace("timeout-minutes: 45", "timeout-minutes: 0"), "timeout-minutes: (15|45)"),
            ("a2a/server inequality", A2A, self.assert_a2a, A2A.replace("server/pyproject.toml", "awid/pyproject.toml"), "server/pyproject.toml"),
            ("single platform", A2A, self.assert_a2a, A2A.replace("linux/amd64,linux/arm64", "linux/amd64", 1), "linux/amd64,linux/arm64"),
            ("digest verification", A2A, self.assert_a2a, A2A.replace("oci-exact-publish.sh verify-published", "echo unverified", 1), "verify-published"),
            ("verification reordered after tag", A2A, self.assert_a2a, reordered_a2a, "not less than"),
        )
        for name, original, assertion, mutation, reason in mutations:
            with self.subTest(name=name):
                self.assertNotEqual(original, mutation)
                with self.assertRaises((AssertionError, ValueError)) as caught:
                    assertion(mutation)
                actual = str(caught.exception)
                self.assertIn(reason, actual)
                if os.environ.get("AW_A2A_MUTATION_REPORT") == "1":
                    print(f"MUTATION RED: {name}: {actual.splitlines()[0][:200]}")

    def test_exact_version_selection_derives_once_then_adopts_same_sha(self) -> None:
        block = marked_block(AW, "AW_VERSION_SELECT_BEGIN", "AW_VERSION_SELECT_END")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); remote = root / "origin.git"; checkout = root / "checkout"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.name", "fixture"], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.email", "fixture@example.invalid"], check=True)
            (checkout / "scripts").mkdir(); tool = checkout / "scripts/cli-release-version.sh"
            tool.write_text("#!/usr/bin/env bash\necho called >> \"$DERIVE_LOG\"\necho 1.2.3\n"); tool.chmod(0o755)
            (checkout / "source").write_text("accepted\n")
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "accepted"], check=True)
            sha = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
            subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", str(remote)], check=True)
            subprocess.run(["git", "-C", str(checkout), "push", "-q", "origin", "HEAD:main"], check=True)
            script = root / "select.sh"; script.write_text(block)
            output = root / "output"; derive = root / "derived"
            env = os.environ | {"SOURCE_SHA": sha, "GITHUB_OUTPUT": str(output), "DERIVE_LOG": str(derive)}
            first = subprocess.run(["bash", str(script)], cwd=checkout, env=env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(output.read_text(), "version=1.2.3\n")
            self.assertEqual(derive.read_text(), "called\n")
            output.unlink(); derive.unlink()
            subprocess.run(["git", "-C", str(checkout), "tag", "aw-v1.2.3", sha], check=True)
            subprocess.run(["git", "-C", str(checkout), "push", "-q", "origin", "refs/tags/aw-v1.2.3"], check=True)
            retry = subprocess.run(["bash", str(script)], cwd=checkout, env=env, text=True, capture_output=True)
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(output.read_text(), "version=1.2.3\n")
            self.assertFalse(derive.exists(), "same-SHA retry derived a second version")
            subprocess.run(["git", "-C", str(checkout), "tag", "aw-v1.2.4", sha], check=True)
            subprocess.run(["git", "-C", str(checkout), "push", "-q", "origin", "refs/tags/aw-v1.2.4"], check=True)
            conflict = subprocess.run(["bash", str(script)], cwd=checkout, env=env, text=True, capture_output=True)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("multiple aw release tags", conflict.stderr)

    def test_exact_output_tag_functions_create_adopt_and_refuse_conflict_locally(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); remote = root / "origin.git"; checkout = root / "checkout"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.name", "fixture"], check=True)
            subprocess.run(["git", "-C", str(checkout), "config", "user.email", "fixture@example.invalid"], check=True)
            (checkout / "source").write_text("accepted\n")
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "accepted"], check=True)
            source_sha = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True,
                                        capture_output=True, check=True).stdout.strip()
            subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", str(remote)], check=True)
            subprocess.run(["git", "-C", str(checkout), "push", "-q", "origin", "HEAD:main"], check=True)
            for workflow, tag in ((AW, "aw-v1.2.3"), (A2A, "a2a-gw-v1.2.3")):
                functions = "fail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n"
                functions += shell_function(workflow, "remote_tag_sha")
                functions += shell_function(workflow, "publish_tag")
                path = root / (tag + ".sh"); path.write_text(functions)
                command = f'source "{path}"; publish_tag "{tag}"'
                env = os.environ | {"SOURCE_SHA": source_sha}
                first = subprocess.run(["bash", "-c", command], cwd=checkout, env=env,
                                       text=True, capture_output=True)
                self.assertEqual(first.returncode, 0, first.stderr)
                retry = subprocess.run(["bash", "-c", command], cwd=checkout, env=env,
                                       text=True, capture_output=True)
                self.assertEqual(retry.returncode, 0, retry.stderr)
                observed = subprocess.run(["git", "ls-remote", str(remote), f"refs/tags/{tag}"],
                                          text=True, capture_output=True, check=True).stdout.split()[0]
                self.assertEqual(observed, source_sha)
            (checkout / "source").write_text("other\n")
            subprocess.run(["git", "-C", str(checkout), "commit", "-qam", "other"], check=True)
            other = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True,
                                   capture_output=True, check=True).stdout.strip()
            subprocess.run(["git", "-C", str(checkout), "tag", "conflict-v1", other], check=True)
            subprocess.run(["git", "-C", str(checkout), "push", "-q", "origin", "refs/tags/conflict-v1"], check=True)
            functions = root / "aw-v1.2.3.sh"
            refused = subprocess.run(["bash", "-c", f'source "{functions}"; publish_tag conflict-v1'],
                                     cwd=checkout, env=os.environ | {"SOURCE_SHA": source_sha},
                                     text=True, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(other, refused.stderr)

    def test_exact_external_sync_block_uses_local_repo_and_adopts_only_exact_state(self) -> None:
        block = marked_block(AW, "AW_EXTERNAL_SYNC_BEGIN", "AW_EXTERNAL_SYNC_END")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            (source / "cli/go").mkdir(parents=True)
            (source / "cli/go/source.txt").write_text("accepted\n")
            remote = root / "aw.git"
            seed = root / "seed"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            subprocess.run(["git", "init", "-q", str(seed)], check=True)
            subprocess.run(["git", "-C", str(seed), "config", "user.name", "fixture"], check=True)
            subprocess.run(["git", "-C", str(seed), "config", "user.email", "fixture@example.invalid"], check=True)
            workflow = seed / ".github/workflows/release.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("on: {push: {tags: ['v*']}}\nsteps:\n  - run: echo main\n  - uses: goreleaser/goreleaser-action@v6\n  - name: npm\n    run: ./npm/publish.sh\n")
            (seed / ".goreleaser.yaml").write_text("builds:\n  - id: aw\n  - id: aweb-a2a-gw\n")
            publisher = seed / "npm/publish.sh"
            publisher.parent.mkdir()
            publisher.write_text(
                "for pkg_dir in aw aw-linux-x64 aw-linux-arm64 aw-darwin-x64 aw-darwin-arm64 aw-windows-x64 aw-windows-arm64; do :; done\n"
                "for pkg_dir in aw-linux-x64 aw-linux-arm64 aw-darwin-x64 aw-darwin-arm64 aw-windows-x64 aw-windows-arm64; do :; done\n"
                "read -r npm_dir ext aw_binary gw_binary\n"
                "npm publish --access public\n"
                "cd \"$SCRIPT_DIR/aw\"\n"
                "npm publish --access public\n"
            )
            shutil.copy2(seed / ".goreleaser.yaml", source / "cli/go/.goreleaser.yaml")
            (source / "cli/go/npm").mkdir()
            shutil.copy2(publisher, source / "cli/go/npm/publish.sh")
            (seed / "old.txt").write_text("old\n")
            subprocess.run(["git", "-C", str(seed), "add", "."], check=True)
            subprocess.run(["git", "-C", str(seed), "commit", "-qm", "seed"], check=True)
            subprocess.run(["git", "-C", str(seed), "remote", "add", "origin", str(remote)], check=True)
            subprocess.run(["git", "-C", str(seed), "push", "-q", "origin", "HEAD:main"], check=True)
            workflow_bytes = workflow.read_bytes()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "fixture"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "fixture@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "source"], check=True)
            source_sha = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                        text=True, capture_output=True, check=True).stdout.strip()

            fakebin = root / "bin"; fakebin.mkdir()
            real_git = shutil.which("git")
            self.assertIsNotNone(real_git)
            fake_git = fakebin / "git"
            fake_git.write_text(
                "#!/usr/bin/env bash\nset -e\n"
                "if [[ ${GIT_FIXTURE_MODE:-ok} == outage && $1 == clone ]]; then exit 71; fi\n"
                "if [[ ${GIT_FIXTURE_MODE:-ok} == race && $* == *HEAD:main* && ! -e $RACE_FLAG ]]; then touch \"$RACE_FLAG\"; tmp=${RACE_FLAG}.repo; \"$REAL_GIT\" clone -q --branch main \"$AW_REMOTE\" \"$tmp\"; \"$REAL_GIT\" -C \"$tmp\" config user.name race; \"$REAL_GIT\" -C \"$tmp\" config user.email race@example.invalid; \"$REAL_GIT\" -C \"$tmp\" commit --allow-empty -qm race; \"$REAL_GIT\" -C \"$tmp\" push -q origin HEAD:main; exit 1; fi\n"
                "if [[ $1 == clone ]]; then dest=${@: -1}; exec \"$REAL_GIT\" clone --branch main \"$AW_REMOTE\" \"$dest\"; fi\n"
                "if [[ $1 == -C && $3 == remote && $4 == get-url ]]; then echo https://github.com/awebai/aw.git; exit 0; fi\n"
                "exec \"$REAL_GIT\" \"$@\"\n"
            )
            fake_git.chmod(0o755)
            script = root / "sync.sh"
            script.write_text("set -euo pipefail\nPUBLIC_STATE=${PUBLIC_STATE:-absent}\nfail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n" + block)
            env = os.environ | {
                "PATH": f"{fakebin}:{os.environ['PATH']}", "REAL_GIT": real_git,
                "AW_REMOTE": str(remote), "GITHUB_WORKSPACE": str(source),
                "HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": "",
                "RUNNER_TEMP": str(root / "runner"), "VERSION": "1.2.3",
                "AW_REPO_TOKEN": "fixture", "SOURCE_SHA": source_sha, "RACE_FLAG": str(root / "race.flag"),
            }
            (root / "runner").mkdir()
            def execute(**changes: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(["bash", str(script)], text=True, capture_output=True,
                                      env=env | changes)
            first = execute()
            self.assertEqual(first.returncode, 0, first.stderr)
            retry = execute(PUBLIC_STATE="complete")
            self.assertEqual(retry.returncode, 0, retry.stderr)
            partial_retry = execute(PUBLIC_STATE="partial")
            self.assertEqual(partial_retry.returncode, 0, partial_retry.stderr)
            initial_main = subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"], text=True, capture_output=True, check=True).stdout.split()[0]
            initial_tag = subprocess.run(["git", "ls-remote", str(remote), "refs/tags/v1.2.3"], text=True, capture_output=True, check=True).stdout.split()[0]
            self.assertEqual(initial_tag, initial_main)
            race = execute(VERSION="1.2.4", GIT_FIXTURE_MODE="race")
            self.assertEqual(race.returncode, 0, race.stderr)
            race_main = subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"], text=True, capture_output=True, check=True).stdout.split()[0]
            race_tag = subprocess.run(["git", "ls-remote", str(remote), "refs/tags/v1.2.4"], text=True, capture_output=True, check=True).stdout.split()[0]
            self.assertEqual(race_tag, race_main)
            observed = root / "observed"
            subprocess.run(["git", "clone", "-q", str(remote), str(observed)], check=True)
            subprocess.run(["git", "-C", str(observed), "checkout", "-q", "main"], check=True)
            self.assertEqual((observed / ".github/workflows/release.yml").read_bytes(), workflow_bytes)
            self.assertEqual((observed / "source.txt").read_text(), "accepted\n")
            self.assertFalse((observed / "old.txt").exists())
            main = race_main

            goreleaser = source / "cli/go/.goreleaser.yaml"
            exact_goreleaser = goreleaser.read_text()
            goreleaser.write_text(exact_goreleaser + "  - id: extra\n")
            subprocess.run(["git", "-C", str(source), "commit", "-qam", "extra incoming build"], check=True)
            extra_sha = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
            extra = execute(SOURCE_SHA=extra_sha)
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("incoming aw workflow binary set", extra.stderr)
            self.assertEqual(subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"], text=True,
                                            capture_output=True, check=True).stdout.split()[0], main)
            goreleaser.write_text(exact_goreleaser)
            subprocess.run(["git", "-C", str(source), "commit", "-qam", "restore incoming build set"], check=True)
            source_publisher = source / "cli/go/npm/publish.sh"
            exact_publisher = source_publisher.read_text()
            source_publisher.write_text(exact_publisher.replace("aw-windows-arm64; do", "aw-windows-arm64 aw-extra; do", 1))
            subprocess.run(["git", "-C", str(source), "commit", "-qam", "extra incoming package"], check=True)
            extra_package_sha = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
            extra_package = execute(SOURCE_SHA=extra_package_sha)
            self.assertNotEqual(extra_package.returncode, 0)
            self.assertIn("incoming aw package set", extra_package.stderr)
            source_publisher.write_text(exact_publisher)
            subprocess.run(["git", "-C", str(source), "commit", "-qam", "restore incoming package set"], check=True)
            (source / "cli/go/source.txt").write_text("conflict\n")
            subprocess.run(["git", "-C", str(source), "commit", "-qam", "conflicting source"], check=True)
            conflicting_source_sha = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                                    text=True, capture_output=True, check=True).stdout.strip()
            conflict = execute(SOURCE_SHA=conflicting_source_sha)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("external tag v1.2.3 conflicts", conflict.stderr)
            main_after = subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"],
                                        text=True, capture_output=True, check=True).stdout.split()[0]
            self.assertEqual(main_after, main, "tag conflict mutated external main")
            outage = execute(GIT_FIXTURE_MODE="outage")
            self.assertNotEqual(outage.returncode, 0)
            self.assertIn("external aw read failed", outage.stderr)
            self.assertEqual(subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"],
                                            text=True, capture_output=True, check=True).stdout.split()[0], main)

            bad = root / "bad-workflow"
            subprocess.run(["git", "clone", "-q", str(remote), str(bad)], check=True)
            subprocess.run(["git", "-C", str(bad), "checkout", "-q", "main"], check=True)
            subprocess.run(["git", "-C", str(bad), "config", "user.name", "fixture"], check=True)
            subprocess.run(["git", "-C", str(bad), "config", "user.email", "fixture@example.invalid"], check=True)
            bad_workflow = bad / ".github/workflows/release.yml"
            bad_workflow.write_text(workflow_bytes.decode() + "  - uses: goreleaser/goreleaser-action@v6\n")
            subprocess.run(["git", "-C", str(bad), "commit", "-qam", "extra workflow output fixture"], check=True)
            subprocess.run(["git", "-C", str(bad), "push", "-q", "origin", "HEAD:main"], check=True)
            extra_output = execute()
            self.assertNotEqual(extra_output.returncode, 0)
            self.assertIn("missing or extra Release/npm publication steps", extra_output.stderr)
            trigger_cases = ("    branches: [main]\n", "  workflow_dispatch:\n", "  pull_request:\n",
                             "  schedule:\n    - cron: '0 0 * * *'\n", "  workflow_call:\n")
            for index, forbidden_trigger in enumerate(trigger_cases):
                trigger = "on:\n  push:\n    tags: ['v*']\n" + forbidden_trigger
                bad_workflow.write_text(workflow_bytes.decode().replace("on: {push: {tags: ['v*']}}", trigger))
                subprocess.run(["git", "-C", str(bad), "commit", "-qam", f"bad trigger fixture {index}"], check=True)
                subprocess.run(["git", "-C", str(bad), "push", "-q", "origin", "HEAD:main"], check=True)
                bad_trigger = execute()
                self.assertNotEqual(bad_trigger.returncode, 0)
                self.assertIn("publishing trigger is not tag-only", bad_trigger.stderr)
            bad_workflow.write_text("on: {push: {tags: ['v*']}}\n  uses: goreleaser/goreleaser-action@v6\n")
            subprocess.run(["git", "-C", str(bad), "commit", "-qam", "missing workflow output fixture"], check=True)
            subprocess.run(["git", "-C", str(bad), "push", "-q", "origin", "HEAD:main"], check=True)
            bad_main = subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"],
                                      text=True, capture_output=True, check=True).stdout.split()[0]
            unverified = execute()
            self.assertNotEqual(unverified.returncode, 0)
            self.assertIn("workflow contract missing: npm/publish.sh", unverified.stderr)
            self.assertEqual(subprocess.run(["git", "ls-remote", str(remote), "refs/heads/main"],
                                            text=True, capture_output=True, check=True).stdout.split()[0], bad_main)

    def test_exact_public_verification_block_is_bounded_and_fail_closed(self) -> None:
        block = marked_block(AW, "AW_PUBLIC_VERIFY_BEGIN", "AW_PUBLIC_VERIFY_END")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fakebin = root / "bin"
            fakebin.mkdir()
            tag_log = root / "tags"
            assets = [
                f"aw_1.2.3_{platform}.{ext}"
                for platform, ext in (
                    ("linux_amd64", "tar.gz"), ("linux_arm64", "tar.gz"),
                    ("darwin_amd64", "tar.gz"), ("darwin_arm64", "tar.gz"),
                    ("windows_amd64", "zip"), ("windows_arm64", "zip"),
                )
            ] + ["checksums.txt"]
            release_json = root / "release.json"
            release_json.write_text(json.dumps({"tag_name": "v1.2.3", "assets": [{"name": name} for name in assets]}))
            (fakebin / "gh").write_text(
                "#!/usr/bin/env bash\n"
                "case ${GH_MODE:-ok} in\n"
                " ok) cat \"$RELEASE_JSON\";;\n"
                " missing) echo 'HTTP 404' >&2; exit 1;;\n"
                " auth) echo 'HTTP 401' >&2; exit 1;;\n"
                " malformed) printf '{';;\n"
                "esac\n"
            )
            (fakebin / "npm").write_text(
                "#!/usr/bin/env bash\n"
                "target=$2\n"
                "if [[ ${NPM_MODE:-ok} == auth ]]; then echo E401 >&2; exit 1; fi\n"
                "if [[ ${NPM_MODE:-ok} == missing ]]; then echo E404 >&2; exit 1; fi\n"
                "if [[ -n ${NPM_MISSING:-} && $target == ${NPM_MISSING}@* ]]; then echo E404 >&2; exit 1; fi\n"
                "if [[ ${NPM_MODE:-ok} == mismatch ]]; then echo '\"9.9.9\"'; else echo '\"1.2.3\"'; fi\n"
            )
            for path in fakebin.iterdir():
                path.chmod(0o755)
            preflight = root / "preflight.sh"
            preflight.write_text(
                "set -euo pipefail\nfail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n"
                + marked_block(AW, "AW_PUBLIC_PREFLIGHT_BEGIN", "AW_PUBLIC_PREFLIGHT_END")
                + "printf 'STATE=%s\\n' \"$PUBLIC_STATE\"\n"
            )
            script = root / "verify.sh"
            script.write_text(
                "set -euo pipefail\n"
                "fail() { printf 'REFUSE: %s\\n' \"$1\" >&2; exit 1; }\n"
                "require_release_sha() { :; }\n"
                "publish_tag() { printf '%s\\n' \"$1\" >> \"$TAG_LOG\"; }\n"
                + marked_block(AW, "AW_PUBLIC_PREFLIGHT_BEGIN", "AW_PUBLIC_PREFLIGHT_END")
                + block
            )
            base = os.environ | {
                "PATH": f"{fakebin}:{os.environ['PATH']}", "VERSION": "1.2.3",
                "AW_PUBLIC_TIMEOUT_SECONDS": "0", "RELEASE_JSON": str(release_json),
                "HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": "",
                "TAG_LOG": str(tag_log),
            }
            def execute_path(path: Path, **changes: str) -> subprocess.CompletedProcess[str]:
                tag_log.unlink(missing_ok=True)
                return subprocess.run(["bash", str(path)], text=True, capture_output=True,
                                      env=base | changes)
            def execute(**changes: str) -> subprocess.CompletedProcess[str]:
                return execute_path(script, **changes)
            absent = execute_path(preflight, GH_MODE="missing", NPM_MODE="missing")
            self.assertEqual(absent.returncode, 0, absent.stderr)
            self.assertIn("STATE=absent", absent.stdout)
            complete = execute_path(preflight)
            self.assertEqual(complete.returncode, 0, complete.stderr)
            self.assertIn("STATE=complete", complete.stdout)
            partial = execute_path(preflight, NPM_MISSING="@awebai/aw-windows-x64")
            self.assertEqual(partial.returncode, 0, partial.stderr)
            self.assertIn("STATE=partial", partial.stdout)
            outage_preflight = execute_path(preflight, GH_MODE="auth")
            self.assertNotEqual(outage_preflight.returncode, 0)
            self.assertIn("preflight Release observation failed", outage_preflight.stderr)
            exact_document = json.loads(release_json.read_text())
            conflict_document = json.loads(release_json.read_text())
            conflict_document["assets"].append({"name": "unexpected.zip"})
            release_json.write_text(json.dumps(conflict_document))
            conflict_preflight = execute_path(preflight)
            self.assertNotEqual(conflict_preflight.returncode, 0)
            self.assertIn("preflight Release output conflicts", conflict_preflight.stderr)
            release_json.write_text(json.dumps(exact_document))
            green = execute()
            self.assertEqual(green.returncode, 0, green.stderr)
            self.assertEqual(tag_log.read_text(), "aw-v1.2.3\n")
            cases = (
                ({"GH_MODE": "missing"}, "did not propagate"),
                ({"GH_MODE": "auth"}, "Release observation failed"),
                ({"GH_MODE": "malformed"}, "malformed"),
                ({"NPM_MISSING": "@awebai/aw-windows-x64"}, "did not propagate"),
                ({"NPM_MODE": "auth"}, "package @awebai/aw observation failed"),
                ({"NPM_MODE": "mismatch"}, "conflicts with version"),
            )
            for env, reason in cases:
                with self.subTest(env=env):
                    result = execute(**env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(reason, result.stderr)
                    self.assertFalse(tag_log.exists(), "refusal reached output tag")
            document = json.loads(release_json.read_text())
            document["assets"].append({"name": "unexpected.zip"})
            release_json.write_text(json.dumps(document))
            extra = execute()
            self.assertNotEqual(extra.returncode, 0)
            self.assertIn("preflight Release output conflicts", extra.stderr)
            self.assertFalse(tag_log.exists(), "extra Release output reached tag")

    def test_exact_a2a_registry_block_executes_real_primitive_with_fake_registry(self) -> None:
        block = marked_block(A2A, "A2A_REGISTRY_BEGIN", "A2A_REGISTRY_END").replace("${{ github.actor }}", "fixture")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); staging = root / "stage"; staging.mkdir()
            archive = staging / "a2a-gateway-oci.tar"
            staged = make_oci_archive(archive)
            with tarfile.open(archive) as tf:
                exact_raw = tf.extractfile("blobs/sha256/" + staged.split(":")[1]).read()
            raw_path = root / "raw"; raw_path.write_bytes(exact_raw)
            other = root / "other"; other.write_bytes(b"conflict")
            fakebin = root / "bin"; fakebin.mkdir(); events = root / "events"; tags = root / "tags"
            skopeo = fakebin / "skopeo"
            skopeo.write_text(
                "#!/usr/bin/env bash\n"
                "case $1 in login) exit 0;; list-tags) [[ $MODE == list-outage ]] && exit 71; [[ $MODE == present || $MODE == inspect-outage || $MODE == conflict ]] && echo '{\"Tags\":[\"0.5.14\",\"latest\"]}' || echo '{\"Tags\":[]}';; inspect) echo INSPECT >> \"$EVENTS\"; [[ $MODE == inspect-outage || -e $VERIFY_FAIL ]] && exit 72; [[ $MODE == conflict ]] && cat \"$OTHER\" || cat \"$RAW\";; copy) echo COPY >> \"$EVENTS\"; if [[ $MODE == copy-fail ]]; then exit 73; fi; exit 0;; esac\n"
            ); skopeo.chmod(0o755)
            script = root / "registry.sh"
            script.write_text(
                "set -euo pipefail\nfail(){ echo \"REFUSE: $1\" >&2; exit 1; }\nrequire_release_sha(){ :; }\npublish_tag(){ echo TAG >> \"$EVENTS\"; echo \"$1\" >> \"$TAGS\"; }\n" + block)
            base = os.environ | {
                "PATH": f"{fakebin}:{os.environ['PATH']}", "VERSION": "0.5.14", "SOURCE_SHA": "a" * 40,
                "GHCR_TOKEN": "fixture", "staging": str(staging), "staged": staged, "tag": "a2a-gw-v0.5.14",
                "RAW": str(raw_path), "OTHER": str(other), "EVENTS": str(events), "TAGS": str(tags),
                "GITHUB_STEP_SUMMARY": str(root / "summary"), "VERIFY_FAIL": str(root / "verify-fail"), "OCI_VERIFY_DEADLINE": "1",
                "OCI_VERIFY_ATTEMPTS": "1", "OCI_VERIFY_BACKOFF": "0", "OCI_VERIFY_REQUEST_TIMEOUT": "1",
            }
            def execute(mode: str) -> subprocess.CompletedProcess[str]:
                events.unlink(missing_ok=True); tags.unlink(missing_ok=True)
                verify_fail = Path(base["VERIFY_FAIL"]); verify_fail.unlink(missing_ok=True)
                if mode == "verify-fail": verify_fail.touch()
                return subprocess.run(["bash", str(script)], cwd=ROOT, env=base | {"MODE": mode}, text=True, capture_output=True)
            absent = execute("absent")
            self.assertEqual(absent.returncode, 0, absent.stderr + absent.stdout)
            self.assertEqual(events.read_text().splitlines(), ["COPY", "COPY", "INSPECT", "INSPECT", "TAG"])
            self.assertEqual(tags.read_text(), "a2a-gw-v0.5.14\n")
            present = execute("present")
            self.assertEqual(present.returncode, 0, present.stderr)
            self.assertEqual(events.read_text().splitlines(), ["INSPECT", "INSPECT", "INSPECT", "INSPECT", "TAG"])
            self.assertEqual(tags.read_text(), "a2a-gw-v0.5.14\n")
            for mode, reason in (("list-outage", "listing unavailable"), ("inspect-outage", "digest unavailable"),
                                 ("conflict", "never rewritten"), ("copy-fail", "GHCR copy failed"), ("verify-fail", "unavailable")):
                result = execute(mode)
                self.assertNotEqual(result.returncode, 0, f"{mode}: {result.stderr} events={events.read_text() if events.exists() else 'none'}")
                if reason: self.assertIn(reason, result.stderr)
                if mode == "verify-fail": self.assertEqual(events.read_text().splitlines(), ["COPY", "COPY", "INSPECT"])
                self.assertFalse(tags.exists(), f"{mode} reached output tag")

    def test_old_make_publication_targets_deleted_and_checks_mapped(self) -> None:
        for target in (
            "release-cli-version-check", "release-cli-tag", "release-cli-push",
            "release-a2a-gateway-check", "release-a2a-gateway-tag", "release-a2a-gateway-push",
        ):
            self.assertNotRegex(MAKE, rf"(?m)^{re.escape(target)}:")
        for row in ("cli-vcs-release-matrix", "cli-unit", "aw-binary", "a2a-copy-contract", "a2a-image"):
            self.assertRegex(SUITES, rf"(?m)^{row}\t")
        self.assertIn(
            "a2a-gateway-e2e\tjourney\ttest-a2a-gateway-e2e\n",
            SUITES,
        )
        self.assertNotRegex(SUITES, r"(?m)^a2a-unit\t|\ttest-a2a\trun\t")
        journey = (ROOT / "scripts/e2e-a2a-gateway-docker.sh").read_text()
        check = '"$GATEWAY_IMAGE" /aweb-a2a-gw -config /config/gateway.yaml -workspace-dir /workspace -check'
        self.assertIn(check, journey)
        self.assertLess(journey.index(check), journey.index("docker run -d --rm"))
        self.assertIn("down -v --rmi local", journey)
        self.assertIn('docker image rm "$GATEWAY_IMAGE"', journey)
        check_single_loaded_gateway_build(journey)
        without_load = journey.replace("docker build --load", "docker build", 1)
        with self.assertRaisesRegex(AssertionError, "single locally loaded gateway build violated"):
            check_single_loaded_gateway_build(without_load)
        self.assertIn("AWEB_DOCKER_BIND_ROOT", journey)
        self.assertIn("AWEB_DOCKER_PUBLISHED_HOST", journey)
        self.assertIn("127.0.0.1|localhost) DOCKER_PUBLISH_BIND=127.0.0.1", journey)
        self.assertIn("aweb-docker.test) DOCKER_PUBLISH_BIND=0.0.0.0", journey)
        self.assertIn('-p "$DOCKER_PUBLISH_BIND:$GATEWAY_PORT:8080"', journey)
        entrypoint = (ROOT / "scripts/release-local-gate.sh").read_text()
        for port in ("AWEB_A2A_E2E_PORT", "AWID_A2A_E2E_PORT", "AWEB_A2A_E2E_REDIS", "AWEB_A2A_E2E_PG", "A2A_GW_E2E_PORT"):
            self.assertIn(f'-e {port}=', entrypoint)


if __name__ == "__main__":
    unittest.main()
