#!/usr/bin/env python3
"""One-command, crash-resumable release of aweb and AC.

There is no release card and no human checkpoint.  A pair of annotated git tags
binds the exact source commits and desired versions after the aweb gate passes.
Every rerun either completes that intent from observed external state or fails
closed on a conflict.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
INTENT_PREFIX = "release-intent-"
DONE_PREFIX = "release-done-"
MARKETPLACE_REPOSITORY = "git@github.com:awebai/claude-plugins.git"
AW_PACKAGES = (
    "@awebai/aw",
    "@awebai/aw-linux-x64",
    "@awebai/aw-linux-arm64",
    "@awebai/aw-darwin-x64",
    "@awebai/aw-darwin-arm64",
    "@awebai/aw-windows-x64",
    "@awebai/aw-windows-arm64",
)


class Refusal(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Artifact:
    key: str
    tag_prefix: str
    manifest: str | None
    content_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...] = ()


ARTIFACTS = (
    Artifact(
        "aweb-server",
        "server-v",
        "server/pyproject.toml",
        ("server/",),
        ("server/uv.lock",),
    ),
    Artifact(
        "awid-service",
        "awid-service-v",
        "awid/pyproject.toml",
        ("awid/",),
        ("awid/uv.lock",),
    ),
    Artifact(
        "awid-image",
        "awid-v",
        "awid/pyproject.toml",
        ("awid/", "server/"),
        ("awid/uv.lock", "server/uv.lock"),
    ),
    Artifact("aw-cli", "aw-v", None, ("cli/go/",)),
    Artifact(
        "channel-plugin",
        "channel-v",
        "channel/package.json",
        ("channel/", "channel-core/"),
        ("channel/package-lock.json", "channel/test/", "channel-core/test/"),
    ),
    Artifact(
        "pi-extension",
        "pi-v",
        "pi-extension/package.json",
        ("pi-extension/", "channel-core/", "skills/"),
        ("pi-extension/package-lock.json", "pi-extension/test/", "channel-core/test/"),
    ),
    Artifact(
        "skills",
        "skills-v",
        "packages/claude-skills/package.json",
        ("packages/claude-skills/", "packages/claude-ai-skills/", "skills/"),
    ),
    Artifact(
        "a2a-gateway-image",
        "a2a-gw-v",
        "server/pyproject.toml",
        ("cli/go/", "server/pyproject.toml"),
        (),
    ),
)
AC_ARTIFACT = Artifact(
    "ac-image",
    "v",
    "backend/pyproject.toml",
    ("backend/", "frontend/", "Dockerfile.release"),
)


@dataclasses.dataclass(frozen=True)
class Intent:
    aweb_sha: str
    ac_base_sha: str
    versions: dict[str, str]
    publish: tuple[str, ...]

    @property
    def identifier(self) -> str:
        return f"{self.aweb_sha[:12]}-{self.ac_base_sha[:12]}"

    @property
    def tag(self) -> str:
        return INTENT_PREFIX + self.identifier

    @property
    def done_tag(self) -> str:
        return DONE_PREFIX + self.identifier

    def document(self) -> str:
        return json.dumps(
            {
                "schema": 1,
                "aweb_sha": self.aweb_sha,
                "ac_base_sha": self.ac_base_sha,
                "versions": dict(sorted(self.versions.items())),
                "publish": list(self.publish),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def parse(cls, raw: str) -> "Intent":
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise Refusal(f"release intent is malformed: {exc}") from exc
        if (
            not isinstance(value, dict)
            or set(value)
            != {"schema", "aweb_sha", "ac_base_sha", "versions", "publish"}
            or value["schema"] != 1
        ):
            raise Refusal("release intent has an unsupported shape")
        for field in ("aweb_sha", "ac_base_sha"):
            if not isinstance(value[field], str) or not re.fullmatch(
                r"[0-9a-f]{40}", value[field]
            ):
                raise Refusal(f"release intent {field} is invalid")
        versions = value["versions"]
        expected = {artifact.key for artifact in ARTIFACTS} | {"ac-image"}
        if not isinstance(versions, dict) or set(versions) != expected:
            raise Refusal(
                f"release intent version domain differs: expected {sorted(expected)}"
            )
        if any(
            not isinstance(v, str) or not SEMVER.fullmatch(v) for v in versions.values()
        ):
            raise Refusal("release intent contains a malformed version")
        publish = value["publish"]
        artifact_keys = expected
        if (
            not isinstance(publish, list)
            or any(not isinstance(key, str) for key in publish)
            or set(publish) - artifact_keys
            or publish != sorted(set(publish))
        ):
            raise Refusal("release intent publish set is invalid")
        return cls(value["aweb_sha"], value["ac_base_sha"], versions, tuple(publish))


def run(
    argv: Sequence[str], *, cwd: Path, timeout: float = 1800, capture: bool = True
) -> str:
    result = subprocess.run(
        list(argv), cwd=cwd, text=True, capture_output=capture, timeout=timeout
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        raise Refusal(f"{' '.join(argv)} failed in {cwd}: {detail}")
    return result.stdout.strip() if capture else ""


def git(repo: Path, *args: str, timeout: float = 180) -> str:
    return run(("git", *args), cwd=repo, timeout=timeout)


def fetch(repo: Path) -> None:
    git(
        repo,
        "fetch",
        "--prune",
        "origin",
        "+refs/heads/*:refs/remotes/origin/*",
        "+refs/tags/*:refs/tags/*",
    )


def require_clean(repo: Path) -> None:
    if git(repo, "status", "--porcelain"):
        raise Refusal(f"{repo} is dirty; release only observes reviewed commits")


def require_main_tip(repo: Path) -> None:
    head = git(repo, "rev-parse", "HEAD")
    main = git(repo, "rev-parse", "origin/main")
    if head != main:
        raise Refusal(f"{repo} must be checked out at origin/main ({main}), not {head}")


def version_tuple(value: str) -> tuple[int, int, int]:
    if not SEMVER.fullmatch(value):
        raise Refusal(f"version {value!r} is not MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def next_patch(value: str) -> str:
    major, minor, patch = version_tuple(value)
    return f"{major}.{minor}.{patch + 1}"


def manifest_version(repo: Path, sha: str, path: str) -> str:
    raw = git(repo, "show", f"{sha}:{path}")
    if path.endswith(".toml"):
        value = tomllib.loads(raw)["project"]["version"]
    else:
        value = json.loads(raw)["version"]
    if not isinstance(value, str) or not SEMVER.fullmatch(value):
        raise Refusal(f"{path} at {sha} has invalid version {value!r}")
    return value


def version_tags(
    repo: Path, prefix: str
) -> list[tuple[tuple[int, int, int], str, str]]:
    found = []
    for tag in git(repo, "tag", "--list", f"{prefix}*").splitlines():
        version = tag[len(prefix) :]
        if SEMVER.fullmatch(version):
            found.append((version_tuple(version), version, tag))
    return sorted(found)


def latest_release(repo: Path, artifact: Artifact) -> tuple[str, str] | None:
    tags = version_tags(repo, artifact.tag_prefix)
    return (tags[-1][1], tags[-1][2]) if tags else None


def content_changed(
    repo: Path, sha: str, artifact: Artifact, anchor: str | None
) -> bool:
    if anchor is None:
        return True
    pathspec = list(artifact.content_paths) + [
        f":(exclude){path}" for path in artifact.excluded_paths
    ]
    result = subprocess.run(
        ["git", "diff", "--quiet", anchor, sha, "--", *pathspec], cwd=repo
    )
    if result.returncode not in (0, 1):
        raise Refusal(f"cannot compare {artifact.key} content at {anchor}..{sha}")
    return result.returncode == 1


def choose_version(repo: Path, sha: str, artifact: Artifact) -> tuple[str, bool]:
    previous = latest_release(repo, artifact)
    old_version, anchor = previous if previous else ("0.0.0", None)
    changed = content_changed(repo, sha, artifact, anchor)
    if artifact.manifest is None:
        return (next_patch(old_version) if changed else old_version), changed
    wanted = manifest_version(repo, sha, artifact.manifest)
    if previous is None:
        return wanted, True
    if changed and version_tuple(wanted) <= version_tuple(old_version):
        raise Refusal(
            f"{artifact.key} content changed but {artifact.manifest} is {wanted}; "
            f"the next compatible version is {next_patch(old_version)}"
        )
    if not changed and wanted != old_version:
        raise Refusal(
            f"{artifact.key} content is unchanged but its manifest says {wanted}, "
            f"not released {old_version}"
        )
    return wanted, changed


def read_url(url: str) -> dict:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "aweb-release/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.loads(response.read())
            if not isinstance(value, dict):
                raise Refusal(f"registry returned non-object JSON for {url}")
            return value
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError(url) from exc
        raise Refusal(f"registry unavailable for {url}: HTTP {exc.code}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(
            f"registry evidence unavailable or malformed for {url}: {exc}"
        ) from exc


def pypi_present(package: str, version: str) -> bool:
    try:
        data = read_url(f"https://pypi.org/pypi/{package}/{version}/json")
    except FileNotFoundError:
        return False
    return (
        data.get("info", {}).get("name", "").lower().replace("_", "-")
        == package.lower().replace("_", "-")
        and data.get("info", {}).get("version") == version
    )


def npm_present(package: str, version: str) -> bool:
    quoted = urllib.parse.quote(package, safe="")
    try:
        data = read_url(f"https://registry.npmjs.org/{quoted}/{version}")
    except FileNotFoundError:
        return False
    return data.get("name") == package and data.get("version") == version


def command_present(root: Path, *argv: str) -> bool:
    result = subprocess.run(
        argv, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60
    )
    return result.returncode == 0


def missing_aweb_workflows(versions: dict[str, str], root: Path) -> set[str]:
    """Return the publisher workflows needed to repair absent desired outputs."""
    missing: set[str] = set()
    if not pypi_present("aweb", versions["aweb-server"]) or not pypi_present(
        "awid-service", versions["awid-service"]
    ):
        missing.add("pypi-release.yml")
    if (
        not npm_present("@awebai/claude-channel", versions["channel-plugin"])
        or not npm_present("@awebai/pi", versions["pi-extension"])
        or not npm_present("@awebai/claude-skills", versions["skills"])
        or not command_present(
            root,
            "gh",
            "release",
            "view",
            f"skills-v{versions['skills']}",
            "--repo",
            "awebai/aweb",
        )
    ):
        missing.add("npm-release.yml")
    if any(
        not npm_present(package, versions["aw-cli"]) for package in AW_PACKAGES
    ) or not command_present(
        root, "gh", "release", "view", f"v{versions['aw-cli']}", "--repo", "awebai/aw"
    ):
        missing.add("aw-release.yml")
    if not command_present(
        root,
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        f"ghcr.io/awebai/awid:{versions['awid-image']}",
    ):
        missing.add("awid-image-release.yml")
    if not command_present(
        root,
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        f"ghcr.io/awebai/a2a-gateway:{versions['a2a-gateway-image']}",
    ):
        missing.add("a2a-gateway-release.yml")
    return missing


def public_aweb_complete(versions: dict[str, str], root: Path) -> bool:
    return not missing_aweb_workflows(versions, root)


def compute_intent(aweb: Path, ac: Path) -> tuple[Intent, set[str]]:
    aweb_sha = git(aweb, "rev-parse", "origin/main")
    ac_sha = git(ac, "rev-parse", "origin/main")
    versions: dict[str, str] = {}
    moving: set[str] = set()
    for artifact in ARTIFACTS:
        version, changed = choose_version(aweb, aweb_sha, artifact)
        versions[artifact.key] = version
        if changed:
            moving.add(artifact.key)
    if versions["a2a-gateway-image"] != versions["aweb-server"]:
        raise Refusal("a2a-gateway-image version must equal aweb-server")
    ac_version, ac_changed = choose_version(ac, ac_sha, AC_ARTIFACT)
    versions["ac-image"] = ac_version
    targets = {
        "aweb": versions["aweb-server"],
        "awid-service": versions["awid-service"],
    }
    check = subprocess.run(
        [
            "python3",
            "scripts/derive_release_floors.py",
            "--ac-root",
            str(ac),
            "--targets",
            json.dumps(targets),
            "--check",
        ],
        cwd=ac,
        text=True,
        capture_output=True,
    )
    if check.returncode:
        previous = latest_release(ac, AC_ARTIFACT)
        if previous is not None and version_tuple(ac_version) <= version_tuple(
            previous[0]
        ):
            raise Refusal(
                "AC must consume new aweb dependencies but backend/pyproject.toml "
                f"is still {ac_version}; bump it above released {previous[0]}"
            )
        ac_changed = True
    if ac_changed:
        moving.add("ac-image")
    return Intent(aweb_sha, ac_sha, versions, tuple(sorted(moving))), moving


def remote_tags(repo: Path, pattern: str) -> set[str]:
    output = git(
        repo, "ls-remote", "--tags", "--refs", "origin", f"refs/tags/{pattern}"
    )
    return {
        line.split("refs/tags/", 1)[1]
        for line in output.splitlines()
        if "refs/tags/" in line
    }


def tag_document(repo: Path, tag: str) -> str:
    return git(repo, "for-each-ref", "--format=%(contents)", f"refs/tags/{tag}").strip()


def push_annotated_tag(repo: Path, tag: str, target: str, document: str) -> None:
    existing = remote_tags(repo, tag)
    if tag in existing:
        fetch(repo)
        if (
            git(repo, "rev-list", "-n", "1", tag) != target
            or tag_document(repo, tag) != document
        ):
            raise Refusal(f"tag {tag} conflicts with the intended release")
        return
    subprocess.run(
        ["git", "tag", "-d", tag],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(
        (
            "git",
            "-c",
            "user.name=aweb release",
            "-c",
            "user.email=release@aweb.ai",
            "tag",
            "-a",
            tag,
            target,
            "-m",
            document,
        ),
        cwd=repo,
    )
    try:
        git(repo, "push", "origin", f"refs/tags/{tag}")
    except Refusal:
        fetch(repo)
        if (
            tag not in remote_tags(repo, tag)
            or git(repo, "rev-list", "-n", "1", tag) != target
            or tag_document(repo, tag) != document
        ):
            raise


def open_intent(aweb: Path, ac: Path) -> Intent | None:
    tags = remote_tags(aweb, f"{INTENT_PREFIX}*") | remote_tags(ac, f"{INTENT_PREFIX}*")
    done = remote_tags(aweb, f"{DONE_PREFIX}*") & remote_tags(ac, f"{DONE_PREFIX}*")
    open_tags = sorted(
        tag for tag in tags if DONE_PREFIX + tag[len(INTENT_PREFIX) :] not in done
    )
    if len(open_tags) > 1:
        raise Refusal(f"multiple unfinished release intents exist: {open_tags}")
    if not open_tags:
        return None
    tag = open_tags[0]
    documents = []
    for repo in (aweb, ac):
        if tag in remote_tags(repo, tag):
            fetch(repo)
            documents.append(tag_document(repo, tag))
    if not documents or len(set(documents)) != 1:
        raise Refusal(f"intent tag {tag} disagrees across repositories")
    intent = Intent.parse(documents[0])
    if intent.tag != tag:
        raise Refusal(f"intent tag {tag} does not match its source commits")
    return intent


def ensure_intent_tags(aweb: Path, ac: Path, intent: Intent) -> None:
    push_annotated_tag(aweb, intent.tag, intent.aweb_sha, intent.document())
    push_annotated_tag(ac, intent.tag, intent.ac_base_sha, intent.document())


def fast_forward(repo: Path, branch: str, target: str) -> None:
    remote = git(repo, "ls-remote", "origin", f"refs/heads/{branch}").split()
    current = remote[0] if remote else ""
    if current == target:
        return
    if (
        current
        and subprocess.run(
            ["git", "merge-base", "--is-ancestor", current, target], cwd=repo
        ).returncode
    ):
        raise Refusal(f"origin/{branch} at {current} cannot fast-forward to {target}")
    git(repo, "push", "origin", f"{target}:refs/heads/{branch}")


def monitor_workflow(
    repo: Path,
    workflow: str,
    sha: str,
    *,
    repository: str = "awebai/aweb",
    timeout: int = 2700,
) -> int:
    deadline = time.monotonic() + timeout
    while True:
        raw = run(
            (
                "gh",
                "run",
                "list",
                "--repo",
                repository,
                "--workflow",
                workflow,
                "--commit",
                sha,
                "--limit",
                "5",
                "--json",
                "databaseId,status,conclusion",
            ),
            cwd=repo,
            timeout=60,
        )
        runs = json.loads(raw or "[]")
        if runs:
            run_id = int(runs[0]["databaseId"])
            conclusion = runs[0].get("conclusion")
            status = runs[0].get("status")
            break
        if time.monotonic() >= deadline:
            raise Refusal(f"workflow {workflow} did not start for {sha}")
        time.sleep(10)
    if conclusion == "success":
        return run_id
    if status == "completed":
        run(
            ("gh", "run", "rerun", str(run_id), "--repo", repository),
            cwd=repo,
            timeout=60,
        )
    run(
        ("gh", "run", "watch", str(run_id), "--repo", repository, "--exit-status"),
        cwd=repo,
        timeout=timeout,
        capture=False,
    )
    return run_id


def expected_aweb_workflows(moving: set[str]) -> set[str]:
    workflows = set()
    if moving & {"aweb-server", "awid-service"}:
        workflows.add("pypi-release.yml")
    if "awid-image" in moving:
        workflows.add("awid-image-release.yml")
    if "aw-cli" in moving:
        workflows.add("aw-release.yml")
    if moving & {"channel-plugin", "pi-extension", "skills"}:
        workflows.add("npm-release.yml")
    if "a2a-gateway-image" in moving:
        workflows.add("a2a-gateway-release.yml")
    return workflows


def reconcile_aweb(aweb: Path, intent: Intent, moving: set[str]) -> None:
    workflows = expected_aweb_workflows(moving)
    if workflows:
        fast_forward(aweb, "release", intent.aweb_sha)
        for workflow in sorted(workflows):
            monitor_workflow(aweb, workflow, intent.aweb_sha)
    if not public_aweb_complete(intent.versions, aweb):
        raise Refusal(
            "the complete desired aweb artifact set is not publicly observable"
        )
    if moving & {"channel-plugin", "skills"}:
        updates = json.dumps(
            {
                "channel": intent.versions["channel-plugin"],
                "skills": intent.versions["skills"],
            },
            sort_keys=True,
        )
        run(
            (
                "python3",
                "scripts/pointer-adapter-marketplace-pointer.py",
                "apply",
                "--component",
                "marketplace-pointer",
                "--expect-repository",
                MARKETPLACE_REPOSITORY,
                "--updates",
                updates,
            ),
            cwd=aweb,
            timeout=300,
        )


def find_derived_ac(ac: Path, intent: Intent) -> str | None:
    version_tag = f"v{intent.versions['ac-image']}"
    if version_tag in remote_tags(ac, version_tag):
        fetch(ac)
        candidate = git(ac, "rev-list", "-n", "1", version_tag)
        if subprocess.run(
            ["git", "merge-base", "--is-ancestor", intent.ac_base_sha, candidate],
            cwd=ac,
        ).returncode:
            raise Refusal(f"{version_tag} is not descended from the intent's AC base")
        return candidate
    log = git(
        ac,
        "log",
        "origin/main",
        "--format=%H",
        "--fixed-strings",
        f"--grep=Release-Intent: {intent.identifier}",
    )
    return log.splitlines()[0] if log else None


def derive_ac(ac: Path, intent: Intent) -> str:
    existing = find_derived_ac(ac, intent)
    if existing:
        return existing
    if git(ac, "rev-parse", "origin/main") != intent.ac_base_sha:
        raise Refusal(
            "AC main moved before dependency derivation; the active intent remains authoritative and requires an engineering rebase"
        )
    targets = json.dumps(
        {
            "aweb": intent.versions["aweb-server"],
            "awid-service": intent.versions["awid-service"],
        },
        sort_keys=True,
    )
    with tempfile.TemporaryDirectory(prefix="aweb-release-ac-") as raw:
        worktree = Path(raw) / "worktree"
        git(ac, "worktree", "add", "--detach", str(worktree), intent.ac_base_sha)
        try:
            run(
                (
                    "python3",
                    "scripts/derive_release_floors.py",
                    "--ac-root",
                    str(worktree),
                    "--targets",
                    targets,
                ),
                cwd=worktree,
                timeout=600,
            )
            changed = {
                line[3:]
                for line in git(worktree, "status", "--porcelain").splitlines()
                if len(line) > 3
            }
            if not changed:
                return intent.ac_base_sha
            allowed = {"backend/pyproject.toml", "backend/uv.lock"}
            if not changed <= allowed:
                raise Refusal(
                    f"AC derivation changed files outside {sorted(allowed)}: {sorted(changed)}"
                )
            git(worktree, "add", *sorted(allowed))
            run(
                (
                    "git",
                    "-c",
                    "user.name=aweb release",
                    "-c",
                    "user.email=release@aweb.ai",
                    "commit",
                    "-m",
                    f"release: consume public aweb dependencies\n\nRelease-Intent: {intent.identifier}",
                ),
                cwd=worktree,
            )
            final = git(worktree, "rev-parse", "HEAD")
            git(worktree, "push", "origin", "HEAD:refs/heads/main")
            return final
        finally:
            git(ac, "worktree", "remove", "--force", str(worktree))


def ensure_ac_content(ac: Path, sha: str, intent: Intent) -> None:
    targets = json.dumps(
        {
            "aweb": intent.versions["aweb-server"],
            "awid-service": intent.versions["awid-service"],
        },
        sort_keys=True,
    )
    with tempfile.TemporaryDirectory(prefix="aweb-release-ac-check-") as raw:
        worktree = Path(raw) / "worktree"
        git(ac, "worktree", "add", "--detach", str(worktree), sha)
        try:
            run(
                (
                    "python3",
                    "scripts/derive_release_floors.py",
                    "--ac-root",
                    str(worktree),
                    "--targets",
                    targets,
                    "--check",
                ),
                cwd=worktree,
            )
        finally:
            git(ac, "worktree", "remove", "--force", str(worktree))


def ac_digest_from_run(ac: Path, run_id: int) -> str:
    log = run(
        ("gh", "run", "view", str(run_id), "--repo", "awebai/ac", "--log"),
        cwd=ac,
        timeout=300,
    )
    matches = re.findall(r"digest=(sha256:[0-9a-f]{64})", log)
    if not matches:
        matches = DIGEST.findall(log)
    if not matches:
        raise Refusal(f"AC workflow {run_id} emitted no immutable digest")
    return matches[-1]


def reconcile_ac(ac: Path, intent: Intent) -> tuple[str, str]:
    final = derive_ac(ac, intent)
    ensure_ac_content(ac, final, intent)
    with tempfile.TemporaryDirectory(prefix="aweb-release-ac-gate-") as raw:
        worktree = Path(raw) / "worktree"
        git(ac, "worktree", "add", "--detach", str(worktree), final)
        try:
            run(
                ("scripts/release-local-gate.sh",),
                cwd=worktree,
                timeout=7200,
                capture=False,
            )
        finally:
            git(ac, "worktree", "remove", "--force", str(worktree))
    source_tag = f"v{intent.versions['ac-image']}"
    push_annotated_tag(
        ac,
        source_tag,
        final,
        json.dumps({"release_intent": intent.identifier}, sort_keys=True),
    )
    fast_forward(ac, "release", final)
    run_id = monitor_workflow(ac, "aweb-cloud-ci-cd.yml", final, repository="awebai/ac")
    return final, ac_digest_from_run(ac, run_id)


def health_sha(url: str) -> str:
    try:
        return str((read_url(url).get("build") or {}).get("git_sha", ""))
    except FileNotFoundError:
        return ""


def deploy(ac: Path, intent: Intent, final: str, digest: str) -> None:
    ensure_ac_content(ac, final, intent)
    health_url = os.environ.get("RELEASE_HEALTH_URL", "https://app.aweb.ai/health")
    verify = (
        "python3",
        "scripts/render_release_client.py",
        "verify-deploy",
        "--digest",
        digest,
        "--health-url",
        health_url,
        "--expect-git-sha",
        final,
    )
    if health_sha(health_url) == final:
        try:
            run(verify, cwd=ac, timeout=1200, capture=False)
        except Refusal:
            print(
                "production serves the commit but standing state is not exact; reconciling"
            )
        else:
            print(f"production already serves exact release {final} at {digest}")
            return
    prod_env = os.environ.get("PROD_ENV_FILE", ".env.production")
    run(
        ("make", "prod-migrate-direct", f"PROD_ENV_FILE={prod_env}"),
        cwd=ac,
        timeout=1800,
        capture=False,
    )
    run(
        ("python3", "scripts/render_release_client.py", "deploy", "--digest", digest),
        cwd=ac,
        timeout=300,
        capture=False,
    )
    run(verify, cwd=ac, timeout=1200, capture=False)


def mark_done(
    aweb: Path, ac: Path, intent: Intent, final: str, digest: str | None
) -> None:
    document = json.dumps(
        {"release_intent": intent.identifier, "ac_sha": final, "digest": digest},
        sort_keys=True,
        separators=(",", ":"),
    )
    push_annotated_tag(aweb, intent.done_tag, intent.aweb_sha, document)
    push_annotated_tag(ac, intent.done_tag, final, document)


def release(aweb: Path, ac: Path) -> None:
    for repo in (aweb, ac):
        require_clean(repo)
        fetch(repo)
    intent = open_intent(aweb, ac)
    if intent is None:
        require_main_tip(aweb)
        require_main_tip(ac)
        intent, moving = compute_intent(aweb, ac)
        missing = missing_aweb_workflows(intent.versions, aweb)
        repairable = expected_aweb_workflows(moving)
        if missing - repairable:
            raise Refusal(
                "desired public outputs are absent but their source is unchanged; "
                f"bump the owning version to repair workflows {sorted(missing - repairable)}"
            )
        if not moving and not missing:
            print("nothing to release")
            return
        run(("scripts/release-gate.sh",), cwd=aweb, timeout=7200, capture=False)
        ensure_intent_tags(aweb, ac, intent)
    else:
        moving = set(intent.publish)
    ensure_intent_tags(aweb, ac, intent)
    print(
        f"reconciling {intent.tag}: aweb={intent.aweb_sha} ac-base={intent.ac_base_sha}"
    )
    reconcile_aweb(aweb, intent, moving)
    final, digest = intent.ac_base_sha, None
    if "ac-image" in moving:
        final, digest = reconcile_ac(ac, intent)
        deploy(ac, intent, final, digest)
    mark_done(aweb, ac, intent, final, digest)
    print(f"release DONE: aweb={intent.aweb_sha} ac={final} digest={digest}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ac-root", type=Path, default=None)
    args = parser.parse_args(argv)
    aweb = Path.cwd().resolve()
    ac = (args.ac_root or Path(os.environ.get("AC_ROOT", aweb.parent / "ac"))).resolve()
    try:
        release(aweb, ac)
    except (
        OSError,
        Refusal,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"release refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
