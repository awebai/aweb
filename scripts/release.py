#!/usr/bin/env python3
"""One-command, crash-resumable release of aweb OSS artifacts.

There is no release card or human checkpoint.  An annotated git tag binds the
exact source commit and desired versions after the clean gate passes.  Every
rerun either completes that intent from observed public state or fails closed
on a conflict.
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


DEFAULT_SKILLS = (
    "aweb-bootstrap",
    "aweb-coordination",
    "aweb-identity",
    "aweb-messaging",
    "aweb-team-membership",
)
DEFAULT_SKILL_PATHS = tuple(f"skills/{name}/" for name in DEFAULT_SKILLS)


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
        ("pi-extension/", "channel-core/", *DEFAULT_SKILL_PATHS),
        (
            "pi-extension/package-lock.json",
            "pi-extension/test/",
            "channel-core/test/",
        ),
    ),
    Artifact(
        "skills",
        "skills-v",
        "packages/claude-skills/package.json",
        (
            "packages/claude-skills/",
            "packages/claude-ai-skills/",
            *DEFAULT_SKILL_PATHS,
        ),
    ),
    Artifact(
        "a2a-gateway-image",
        "a2a-gw-v",
        None,
        ("cli/go/",),
    ),
)


@dataclasses.dataclass(frozen=True)
class Intent:
    aweb_sha: str
    versions: dict[str, str]
    publish: tuple[str, ...]

    @property
    def identifier(self) -> str:
        return self.aweb_sha

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
            or set(value) != {"schema", "aweb_sha", "versions", "publish"}
            or value["schema"] != 1
        ):
            raise Refusal("release intent has an unsupported shape")
        if not isinstance(value["aweb_sha"], str) or not re.fullmatch(
            r"[0-9a-f]{40}", value["aweb_sha"]
        ):
            raise Refusal("release intent aweb_sha is invalid")
        versions = value["versions"]
        expected = {artifact.key for artifact in ARTIFACTS}
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
        return cls(value["aweb_sha"], versions, tuple(publish))


def run(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float = 1800,
    capture: bool = True,
    env: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        list(argv), cwd=cwd, text=True, capture_output=capture, timeout=timeout, env=env
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


def dependency_floor(repo: Path, sha: str, path: str, package: str) -> str:
    project = tomllib.loads(git(repo, "show", f"{sha}:{path}"))["project"]
    prefix = f"{package}>="
    matches = [item for item in project["dependencies"] if item.startswith(prefix)]
    if len(matches) != 1:
        raise Refusal(
            f"{path} at {sha} must declare exactly one literal {package}>= floor"
        )
    floor = matches[0][len(prefix) :]
    if not SEMVER.fullmatch(floor):
        raise Refusal(f"{path} at {sha} has invalid {package} floor {floor!r}")
    return floor


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


def published_package_versions(kind: str, package: str) -> set[str]:
    if kind == "pypi":
        try:
            data = read_url(f"https://pypi.org/pypi/{package}/json")
        except FileNotFoundError:
            return set()
        values = data.get("releases", {})
    elif kind == "npm":
        quoted = urllib.parse.quote(package, safe="")
        try:
            data = read_url(f"https://registry.npmjs.org/{quoted}")
        except FileNotFoundError:
            return set()
        values = data.get("versions", {})
    else:
        raise Refusal(f"unsupported package registry {kind!r}")
    if not isinstance(values, dict):
        raise Refusal(f"{kind} returned malformed version metadata for {package}")
    return {value for value in values if SEMVER.fullmatch(value)}


def npm_latest(package: str) -> str | None:
    quoted = urllib.parse.quote(package, safe="")
    try:
        data = read_url(f"https://registry.npmjs.org/{quoted}")
    except FileNotFoundError:
        return None
    tags = data.get("dist-tags", {})
    latest = tags.get("latest") if isinstance(tags, dict) else None
    if not isinstance(latest, str) or not SEMVER.fullmatch(latest):
        raise Refusal(f"npm returned no valid latest version for {package}")
    return latest


def refuse_higher_public_versions(versions: dict[str, str]) -> None:
    targets = [
        ("aweb-server", "pypi", "aweb"),
        ("awid-service", "pypi", "awid-service"),
        ("channel-plugin", "npm", "@awebai/claude-channel"),
        ("pi-extension", "npm", "@awebai/pi"),
        ("skills", "npm", "@awebai/claude-skills"),
        *(("aw-cli", "npm", package) for package in AW_PACKAGES),
    ]
    for artifact, kind, package in targets:
        expected = versions[artifact]
        published = published_package_versions(kind, package)
        higher = sorted(
            (
                value
                for value in published
                if SEMVER.fullmatch(value)
                and version_tuple(value) > version_tuple(expected)
            ),
            key=version_tuple,
        )
        if higher:
            raise Refusal(
                f"{kind}:{package} serves versions above reviewed {artifact} "
                f"{expected}: {higher}"
            )
        if kind == "npm" and expected in published:
            latest = npm_latest(package)
            if latest is not None and latest != expected:
                raise Refusal(
                    f"npm:{package} latest is {latest}, not reviewed {artifact} "
                    f"{expected}"
                )


def command_present(root: Path, *argv: str, absent_markers: tuple[str, ...]) -> bool:
    result = subprocess.run(argv, cwd=root, text=True, capture_output=True, timeout=60)
    if result.returncode == 0:
        return True
    detail = "\n".join(
        value.strip() for value in (result.stdout, result.stderr) if value.strip()
    )
    if any(marker in detail.lower() for marker in absent_markers):
        return False
    raise Refusal(
        f"cannot observe public target with {' '.join(argv)}: "
        f"{detail or f'exit {result.returncode}'}"
    )


def oci_digest(root: Path, reference: str) -> str | None:
    argv = (
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        reference,
        "--format",
        "{{json .Manifest.Digest}}",
    )
    result = subprocess.run(argv, cwd=root, text=True, capture_output=True, timeout=60)
    if result.returncode:
        detail = "\n".join(
            value.strip() for value in (result.stdout, result.stderr) if value.strip()
        )
        if any(
            marker in detail.lower()
            for marker in ("manifest unknown", ": not found", "no such manifest")
        ):
            return None
        raise Refusal(
            f"cannot observe public target with {' '.join(argv)}: "
            f"{detail or f'exit {result.returncode}'}"
        )
    try:
        digest = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(
            f"OCI registry returned a malformed digest for {reference}"
        ) from exc
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Refusal(f"OCI registry returned an invalid digest for {reference}")
    return digest


def missing_aweb_workflows(versions: dict[str, str], root: Path) -> set[str]:
    """Return the publisher workflows needed to repair absent desired outputs."""
    refuse_higher_public_versions(versions)
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
            absent_markers=("release not found", "could not resolve to a release"),
        )
    ):
        missing.add("npm-release.yml")
    if any(
        not npm_present(package, versions["aw-cli"]) for package in AW_PACKAGES
    ) or not command_present(
        root,
        "gh",
        "release",
        "view",
        f"v{versions['aw-cli']}",
        "--repo",
        "awebai/aw",
        absent_markers=("release not found", "could not resolve to a release"),
    ):
        missing.add("aw-release.yml")
    awid_digest = oci_digest(root, f"ghcr.io/awebai/awid:{versions['awid-image']}")
    if awid_digest is None:
        missing.add("awid-image-release.yml")
    elif awid_digest != oci_digest(root, "ghcr.io/awebai/awid:latest"):
        raise Refusal(
            "ghcr.io/awebai/awid:latest does not resolve to the reviewed version"
        )
    a2a_digest = oci_digest(
        root, f"ghcr.io/awebai/a2a-gateway:{versions['a2a-gateway-image']}"
    )
    if a2a_digest is None:
        missing.add("a2a-gateway-release.yml")
    elif a2a_digest != oci_digest(root, "ghcr.io/awebai/a2a-gateway:latest"):
        raise Refusal(
            "ghcr.io/awebai/a2a-gateway:latest does not resolve to the reviewed version"
        )
    return missing


def public_aweb_complete(versions: dict[str, str], root: Path) -> bool:
    return not missing_aweb_workflows(versions, root)


def compute_intent(aweb: Path) -> tuple[Intent, set[str]]:
    aweb_sha = git(aweb, "rev-parse", "origin/main")
    versions: dict[str, str] = {}
    moving: set[str] = set()
    for artifact in ARTIFACTS:
        version, changed = choose_version(aweb, aweb_sha, artifact)
        versions[artifact.key] = version
        if changed:
            moving.add(artifact.key)
    awid_floor = dependency_floor(
        aweb, aweb_sha, "server/pyproject.toml", "awid-service"
    )
    if awid_floor != versions["awid-service"]:
        raise Refusal(
            "server/pyproject.toml must set awid-service floor to the desired "
            f"release {versions['awid-service']}, not {awid_floor}"
        )
    return Intent(aweb_sha, versions, tuple(sorted(moving))), moving


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


def open_intent(aweb: Path) -> Intent | None:
    tags = remote_tags(aweb, f"{INTENT_PREFIX}*")
    done = remote_tags(aweb, f"{DONE_PREFIX}*")
    open_tags = sorted(
        tag for tag in tags if DONE_PREFIX + tag[len(INTENT_PREFIX) :] not in done
    )
    if len(open_tags) > 1:
        raise Refusal(f"multiple unfinished release intents exist: {open_tags}")
    if not open_tags:
        return None
    tag = open_tags[0]
    fetch(aweb)
    intent = Intent.parse(tag_document(aweb, tag))
    if intent.tag != tag:
        raise Refusal(f"intent tag {tag} does not match its source commits")
    return intent


def ensure_intent_tag(aweb: Path, intent: Intent) -> None:
    push_annotated_tag(aweb, intent.tag, intent.aweb_sha, intent.document())


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


# Inverse of expected_aweb_workflows: the artifact keys each publisher can
# publish. A workflow repairing an absent output may republish unchanged
# siblings it owns, so the gate scope covers every key its workflows touch.
WORKFLOW_ARTIFACTS = {
    "pypi-release.yml": ("aweb-server", "awid-service"),
    "awid-image-release.yml": ("awid-image",),
    "aw-release.yml": ("aw-cli",),
    "npm-release.yml": ("channel-plugin", "pi-extension", "skills"),
    "a2a-gateway-release.yml": ("a2a-gateway-image",),
}


def workflow_artifact_keys(workflows: set[str]) -> set[str]:
    unknown = workflows - set(WORKFLOW_ARTIFACTS)
    if unknown:
        raise Refusal(f"no artifact mapping for workflows {sorted(unknown)}")
    return {key for workflow in workflows for key in WORKFLOW_ARTIFACTS[workflow]}


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


def mark_done(aweb: Path, intent: Intent) -> None:
    document = json.dumps(
        {
            "release_intent": intent.identifier,
            "aweb_sha": intent.aweb_sha,
            "versions": dict(sorted(intent.versions.items())),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    push_annotated_tag(aweb, intent.done_tag, intent.aweb_sha, document)


def reconcile_intent(source: Path, intent: Intent, moving: set[str]) -> None:
    ensure_intent_tag(source, intent)
    print(f"reconciling {intent.tag}: source={intent.aweb_sha}")
    reconcile_aweb(source, intent, moving)
    mark_done(source, intent)


def release(aweb: Path) -> Intent | None:
    require_clean(aweb)
    completed: Intent | None = None
    while True:
        fetch(aweb)
        intent = open_intent(aweb)
        if intent is None:
            require_main_tip(aweb)
            intent, moving = compute_intent(aweb)
            missing = missing_aweb_workflows(intent.versions, aweb)
            repairable = expected_aweb_workflows(moving)
            if missing - repairable:
                raise Refusal(
                    "desired public outputs are absent but their source is unchanged; "
                    f"bump the owning version to repair workflows {sorted(missing - repairable)}"
                )
            if not moving and not missing:
                print("nothing to release")
                return completed
            gate_scope = sorted(moving | workflow_artifact_keys(missing))
            run(
                ("scripts/release-gate.sh",),
                cwd=aweb,
                timeout=7200,
                capture=False,
                env={**os.environ, "RELEASE_GATE_ARTIFACTS": ",".join(gate_scope)},
            )
        else:
            moving = set(intent.publish)
        if git(aweb, "rev-parse", "HEAD") == intent.aweb_sha:
            reconcile_intent(aweb, intent, moving)
        else:
            with tempfile.TemporaryDirectory(prefix="aweb-release-source-") as raw:
                worktree = Path(raw) / "worktree"
                git(aweb, "worktree", "add", "--detach", str(worktree), intent.aweb_sha)
                try:
                    reconcile_intent(worktree, intent, moving)
                finally:
                    git(aweb, "worktree", "remove", "--force", str(worktree))
        print(
            "release DONE: "
            + intent.aweb_sha
            + " "
            + json.dumps(dict(sorted(intent.versions.items())), sort_keys=True)
        )
        completed = intent
        if git(aweb, "rev-parse", "origin/main") == intent.aweb_sha:
            return completed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        release(Path.cwd().resolve())
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
