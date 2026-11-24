#!/usr/bin/env python3
"""Publish one already-tested OSS tag, without release branches or GitHub Actions."""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from release_versions import (
    SEMVER,
    VersionRefusal as PublishRefusal,
    final_version,
    require_runner_values,
    tag_parts,
    valid_version,
)

MANIFESTS = {
    "server-v": "server/pyproject.toml",
    "awid-service-v": "awid/pyproject.toml",
    "aweb-naapp-v": "naapp-lib/pyproject.toml",
    "awid-v": "awid/pyproject.toml",
    "channel-v": "channel/package.json",
    "pi-v": "pi-extension/package.json",
    "skills-v": "packages/claude-skills/package.json",
    "secrets-v": "naapp/secrets/pyproject.toml",
    "logs-v": "naapp/logs/pyproject.toml",
    "aweb-secrets-runner-v": "naapp/secrets/runner/pyproject.toml",
}
# The PyPI package each PyPI lane publishes. The aweb package depends on the
# in-repo awid-service, which must be public first.
PYPI_PACKAGES = {
    "server-v": "aweb",
    "awid-service-v": "awid-service",
}
# One gated release file in an annotated release tag's message, in sha256sum
# format: the lowercase sha256, two spaces, the file's basename.
LOCKED_FILE = re.compile(r"([0-9a-f]{64})  ([^\s/]+)")
NPM_LANES = {
    "channel-v": ("channel", "@awebai/claude-channel", "channel"),
    "pi-v": ("pi-extension", "@awebai/pi", "pi"),
    "skills-v": ("packages/claude-skills", "@awebai/claude-skills", "skills"),
}


def run(
    root: Path,
    *argv: str,
    capture: bool = True,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout: int = 7200,
) -> str:
    # npm's background self-update lookup is not part of publication. Cover
    # direct build commands and nested scripts, regardless of caller config.
    environment = dict(os.environ if env is None else env)
    environment.update(NPM_CONFIG_UPDATE_NOTIFIER="false", npm_config_update_notifier="false")
    completed = subprocess.run(
        argv,
        cwd=root,
        text=True,
        input=input_text,
        capture_output=capture,
        env=environment,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PublishRefusal(f"{' '.join(argv)} failed: {detail}")
    return completed.stdout.strip() if capture else ""


def manifest_version_at(root: Path, source_sha: str, path: str) -> str:
    raw = run(root, "git", "show", f"{source_sha}:{path}", timeout=60)
    if path.endswith(".toml"):
        value = tomllib.loads(raw)["project"]["version"]
    else:
        value = json.loads(raw)["version"]
    if not valid_version(path, value):
        raise PublishRefusal(f"{path} at {source_sha} has invalid version {value!r}")
    return value


def tag_identity(root: Path, tag: str) -> tuple[str, str, str]:
    prefix, version = tag_parts(tag)
    try:
        source_sha = run(root, "git", "rev-parse", f"{tag}^{{commit}}", timeout=60)
    except PublishRefusal as error:
        raise PublishRefusal(f"local candidate tag {tag} is absent") from error
    if prefix in MANIFESTS:
        manifest = MANIFESTS[prefix]
        if manifest_version_at(root, source_sha, manifest) != version:
            raise PublishRefusal(
                f"{tag} does not match {manifest} version {manifest_version_at(root, source_sha, manifest)}"
            )
    if prefix == "aweb-secrets-runner-v":
        require_runner_values(root, source_sha)
    return prefix, version, source_sha


def request_json(url: str) -> tuple[int, dict]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.loads(response.read().decode())
            return response.status, value if isinstance(value, dict) else {}
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, {}
        raise PublishRefusal(f"registry observation failed for {url}: HTTP {error.code}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise PublishRefusal(f"registry observation failed for {url}: {error}") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def locked_files(root: Path, tag: str) -> dict[str, str]:
    """The release files an annotated tag's message locks, as name -> sha256."""
    ref = f"refs/tags/{tag}"
    if run(root, "git", "cat-file", "-t", ref, timeout=60) != "tag":
        raise PublishRefusal(f"{tag} is not an annotated tag; its message must list the release files")
    locked: dict[str, str] = {}
    for line in run(root, "git", "for-each-ref", "--format=%(contents)", ref, timeout=60).splitlines():
        matched = LOCKED_FILE.fullmatch(line)
        if not matched:
            continue
        digest, name = matched.groups()
        if name in locked:
            raise PublishRefusal(f"{tag} lists {name} more than once")
        locked[name] = digest
    if not locked:
        raise PublishRefusal(f"{tag} lists no release files")
    return locked


def verify_release_assets(assets: Path, locked: dict[str, str]) -> None:
    """Refuse unless the assets directory holds exactly the locked files, byte for byte."""
    present = {path.name: path for path in assets.iterdir()}
    missing = sorted(set(locked) - set(present))
    if missing:
        raise PublishRefusal(f"release assets are missing locked files: {', '.join(missing)}")
    extra = sorted(set(present) - set(locked))
    if extra:
        raise PublishRefusal(f"release assets hold files not in the tag message: {', '.join(extra)}")
    for name, digest in sorted(locked.items()):
        path = present[name]
        if not path.is_file() or path.is_symlink():
            raise PublishRefusal(f"release asset {name} is not a regular file")
        actual = sha256(path)
        if actual != digest:
            raise PublishRefusal(f"release asset {name} has sha256 {actual}, the tag locks {digest}")


def publish_pypi(root: Path, tag: str, source_sha: str, assets: Path) -> None:
    """Upload the gated release files the tag locks; never build."""
    prefix, version = tag_parts(tag)
    package = PYPI_PACKAGES[prefix]
    verify_release_assets(assets, locked_files(root, tag))
    exact = ("bash", str(Path(__file__).resolve().parent / "pypi-exact-publish.sh"))
    lane = ("--dist", str(assets), "--package", package, "--version", version)
    run(root, *exact, "inspect-staged", *lane)
    if prefix == "server-v":
        awid_version = manifest_version_at(root, source_sha, MANIFESTS["awid-service-v"])
        deadline = time.monotonic() + 180
        while True:
            status, _ = request_json(
                f"https://pypi.org/pypi/awid-service/{awid_version}/json"
            )
            if status == 200:
                break
            if time.monotonic() >= deadline:
                raise PublishRefusal(
                    f"awid-service {awid_version} is not publicly available before {prefix} publication"
                )
            time.sleep(6)
    status, observed = request_json(f"https://pypi.org/pypi/{package}/{version}/json")
    with tempfile.TemporaryDirectory(prefix="aweb-pypi-") as temporary:
        observed_path = Path(temporary) / "observed.json"
        observed_path.write_text(json.dumps(observed), encoding="utf-8")
        plan = run(
            root, *exact, "plan-publish", *lane,
            "--observed-status", str(status), "--observed-json", str(observed_path),
        )
    files = [assets / name for name in plan.splitlines() if name]
    if files:
        run(root, "uv", "publish", "--trusted-publishing", "always", *(str(path) for path in files), capture=False)
    run(root, *exact, "verify-published", *lane)


def build_npm_lane(root: Path, prefix: str) -> tuple[str, str, str]:
    directory, package, profile = NPM_LANES[prefix]
    if prefix in {"channel-v", "pi-v"}:
        run(root / "channel-core", "npm", "ci", "--no-audit", "--no-fund", capture=False)
        run(root / "channel-core", "npm", "run", "build", capture=False)
    if prefix in {"channel-v", "pi-v"}:
        run(root / directory, "npm", "ci", "--no-audit", "--no-fund", capture=False)
        run(root / directory, "npm", "run", "build", capture=False)
    else:
        run(root / "packages/claude-skills", "npm", "run", "sync-skills", capture=False)
        run(root / "packages/claude-ai-skills", "./build-zips.sh", capture=False)
    return directory, package, profile


def require_pi_aw_floor(root: Path, timeout_seconds: float = 180) -> str:
    manifest = json.loads((root / "pi-extension/package.json").read_text(encoding="utf-8"))
    declared = (manifest.get("dependencies") or {}).get("@awebai/aw")
    matched = re.fullmatch(rf"\^({SEMVER})", declared or "")
    if not matched:
        raise PublishRefusal(
            f"pi-extension must declare one strict @awebai/aw caret floor, got {declared!r}"
        )
    floor = matched.group(1)
    deadline = time.monotonic() + timeout_seconds
    url = f"https://registry.npmjs.org/%40awebai%2Faw/{floor}"
    while True:
        status, _ = request_json(url)
        if status == 200:
            return floor
        if status != 404:
            raise PublishRefusal(f"npm returned unexpected HTTP {status} for @awebai/aw@{floor}")
        if time.monotonic() >= deadline:
            raise PublishRefusal(
                f"@awebai/aw@{floor} is not public before Pi publication"
            )
        time.sleep(6)


@contextmanager
def _npm_publish_staged(root: Path, directory: str, package: str, profile: str, version: str, *, staged_final: bool = False):
    """Publish/adopt once; keep the exact archive alive until readback finishes."""
    token = os.environ.get("NODE_AUTH_TOKEN", "").strip() or os.environ.get("NPM_TOKEN", "").strip()
    if not token:
        raise PublishRefusal("NODE_AUTH_TOKEN or NPM_TOKEN is required")
    environment = {**os.environ, "NODE_AUTH_TOKEN": token, "NPM_TOKEN": token}
    with tempfile.TemporaryDirectory(prefix="aweb-npm-") as temporary:
        staging = Path(temporary)
        run(
            root,
            "bash",
            "scripts/npm-exact-publish.sh",
            "pack-inspect",
            "--dir",
            directory,
            "--version",
            version,
            "--out",
            str(staging),
            "--profile",
            profile,
            "--source-root",
            ".",
        )
        packages = list(staging.glob("*.tgz"))
        if len(packages) != 1:
            raise PublishRefusal("npm staging did not contain exactly one package")
        archive = packages[0]
        status, observed = request_json(
            f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='')}/{version}"
        )
        action = "publish"
        if status == 200:
            tarball = (observed.get("dist") or {}).get("tarball")
            if not isinstance(tarball, str) or not tarball:
                raise PublishRefusal("present npm version has no tarball URL")
            remote = staging / "remote.tgz"
            try:
                with urllib.request.urlopen(tarball, timeout=30) as response:
                    remote.write_bytes(response.read())
            except OSError as error:
                raise PublishRefusal(f"npm tarball observation failed: {error}") from error
            if sha256(remote) != sha256(archive):
                raise PublishRefusal(
                    f"{package}@{version} already exists with different bytes"
                )
            action = "adopt"
        elif status == 404:
            run(
                root,
                "bash",
                "scripts/npm-exact-publish.sh",
                "publish-exact",
                "--tgz",
                str(archive),
                *(["--staged-final"] if staged_final else []),
                capture=False,
                env=environment,
            )
        else:
            raise PublishRefusal(f"npm registry returned unexpected HTTP {status}")
        yield archive, action, environment


def npm_publish_exact(root: Path, directory: str, package: str, profile: str, version: str, *, staged_final: bool = False) -> None:
    with _npm_publish_staged(root, directory, package, profile, version, staged_final=staged_final) as staged:
        archive, action, environment = staged
        run(
            root,
            "bash",
            "scripts/npm-exact-publish.sh",
            "verify-published-bounded",
            "--tgz",
            str(archive),
            "--package",
            package,
            "--version",
            version,
            "--post-action",
            action,
            "--dist-tag",
            "next" if staged_final or "-" in version else "latest",
            env=environment,
        )


def publish_npm(root: Path, prefix: str, version: str) -> None:
    if prefix == "pi-v":
        require_pi_aw_floor(root)
    directory, package, profile = build_npm_lane(root, prefix)
    npm_publish_exact(root, directory, package, profile, version)
    if prefix == "skills-v":
        print("skill ZIPs are staged locally; hosted release assets can be uploaded later")


def write_json_version(path: Path, version: str, git_head: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value["version"] = version
    # npm records no gitHead for a published tarball; the manifest carries it.
    if git_head is not None:
        value["gitHead"] = git_head
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def publish_aw_npm(root: Path, version: str, source_sha: str, *, staged_final: bool = False) -> None:
    packages = {
        "linux/amd64": ("aw-linux-x64", "aw", "aweb-a2a-gw"),
        "linux/arm64": ("aw-linux-arm64", "aw", "aweb-a2a-gw"),
        "darwin/amd64": ("aw-darwin-x64", "aw", "aweb-a2a-gw"),
        "darwin/arm64": ("aw-darwin-arm64", "aw", "aweb-a2a-gw"),
        "windows/amd64": ("aw-windows-x64", "aw.exe", "aweb-a2a-gw.exe"),
        "windows/arm64": ("aw-windows-arm64", "aw.exe", "aweb-a2a-gw.exe"),
    }
    npm_root = root / "cli/go/npm"
    ldflags = (
        f"-s -w -X main.version={version} -X main.commit={source_sha} "
        "-X main.commitRepo=github.com/awebai/aweb -X main.date=1970-01-01T00:00:00Z"
    )
    for platform, (package_dir, aw_name, gateway_name) in packages.items():
        goos, goarch = platform.split("/")
        binary_dir = npm_root / package_dir / "bin"
        binary_dir.mkdir(parents=True, exist_ok=True)
        environment = {**os.environ, "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch}
        run(
            root / "cli/go",
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            ldflags,
            "-o",
            str(binary_dir / aw_name),
            "./cmd/aw",
            env=environment,
            capture=False,
        )
        run(
            root / "cli/go",
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            ldflags,
            "-o",
            str(binary_dir / gateway_name),
            "./cmd/aweb-a2a-gw",
            env=environment,
            capture=False,
        )
        write_json_version(npm_root / package_dir / "package.json", version, source_sha)
    main_manifest = npm_root / "aw/package.json"
    value = json.loads(main_manifest.read_text(encoding="utf-8"))
    value["version"] = version
    value["gitHead"] = source_sha
    value["optionalDependencies"] = {
        name: version for name in sorted(value.get("optionalDependencies", {}))
    }
    main_manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    # Hold all seven once-staged archives through one verifier invocation.
    # Publishing/adopting never becomes a retry action on readback uncertainty.
    with ExitStack() as staging:
        artifacts = []
        for package_dir in [item[0] for item in packages.values()] + ["aw"]:
            package = "@awebai/" + package_dir
            archive, _, environment = staging.enter_context(_npm_publish_staged(
                root, str(Path("cli/go/npm") / package_dir), package, "", version,
                staged_final=staged_final,
            ))
            artifacts.extend(("--artifact", f"{package}={archive}"))
        run(
            root, "python3", str(npm_root / "readback.py"), *artifacts,
            "--version", version,
            "--dist-tag", "next" if staged_final or "-" in version else "latest",
            "--git-head", source_sha,
            "--registry", environment.get("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org"),
            env=environment,
        )
    print("npm CLI packages published; hosted binary release assets can be resumed later")


OCI_REPOSITORIES = {
    "server-v": "ghcr.io/awebai/aweb-server",
    "awid-v": "ghcr.io/awebai/awid",
    "a2a-gw-v": "ghcr.io/awebai/a2a-gateway",
    "secrets-v": "ghcr.io/awebai/secrets",
    "logs-v": "ghcr.io/awebai/logs",
}
def oci_images(prefix: str) -> tuple[str, ...]:
    """The image repositories published by this tag."""
    return (OCI_REPOSITORIES[prefix],)


def build_oci_archive(
    root: Path, prefix: str, version: str, source_sha: str, archive: Path
) -> None:
    """Build the release bytes once; usable by platform qualification without publishing."""
    if prefix == "server-v":
        build = [
            "docker", "buildx", "build", "--file", "server/Dockerfile",
            "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
            "--label", "org.opencontainers.image.title=aweb server",
            "--label", f"org.opencontainers.image.version={version}",
            "--label", f"org.opencontainers.image.revision={source_sha}",
            "--output", f"type=oci,dest={archive}", ".",
        ]
    elif prefix == "awid-v":
        build = [
            "docker", "buildx", "build", "--file", "awid/Dockerfile.release",
            "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
            "--label", "org.opencontainers.image.title=awid",
            "--label", "org.opencontainers.image.description=Thin awid.ai registry service wrapper around aweb",
            "--label", f"org.opencontainers.image.version={version}",
            "--label", f"org.opencontainers.image.revision={source_sha}",
            "--output", f"type=oci,dest={archive}", ".",
        ]
    elif prefix in {"secrets-v", "logs-v"}:
        service = "secrets" if prefix == "secrets-v" else "logs"
        build = [
            "docker", "buildx", "build", "--file", f"naapp/{service}/Dockerfile",
            "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
            "--build-arg", f"SOURCE_COMMIT={source_sha}",
            "--label", f"org.opencontainers.image.title=aweb {service}",
            "--label", f"org.opencontainers.image.version={version}",
            "--label", f"org.opencontainers.image.revision={source_sha}",
            "--output", f"type=oci,dest={archive}", ".",
        ]
    else:
        build = [
            "docker", "buildx", "build", "--file", "cli/go/Dockerfile.a2a-gw",
            "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
            "--build-arg", f"VERSION={version}", "--build-arg", f"RELEASE_TAG=a2a-gw-v{version}",
            "--build-arg", f"COMMIT={source_sha}", "--build-arg", "COMMIT_REPO=github.com/awebai/aweb",
            "--build-arg", "DATE=1970-01-01T00:00:00Z",
            "--label", "org.opencontainers.image.title=aweb A2A Gateway",
            "--label", "org.opencontainers.image.description=Hosted A2A gateway for aweb agents",
            "--label", f"org.opencontainers.image.version={version}",
            "--label", f"org.opencontainers.image.revision={source_sha}",
            "--output", f"type=oci,dest={archive}", "cli/go",
        ]
    run(root, *build, capture=False)


# skopeo's whole answer when GHCR has no repository of that name yet, which is
# the state before an image's first publication.
ABSENT_REPOSITORY = re.compile(
    r'time="[^"]*" level=fatal msg="Error listing repository tags: fetching tags list: name unknown"'
)


def published_tags(root: Path, repository: str, first_publication: bool = False) -> list:
    """The repository's tags. GHCR's "name unknown" means "no tags" only for a
    repository the operator explicitly names as a first publication; the answer
    alone never establishes absence. A named repository that lists tags is not
    a first publication."""
    argv = ("skopeo", "list-tags", f"docker://{repository}")
    completed = subprocess.run(argv, cwd=root, text=True, capture_output=True, timeout=120, check=False)
    if completed.returncode:
        absent = not completed.stdout.strip() and ABSENT_REPOSITORY.fullmatch(completed.stderr.strip())
        if absent and first_publication:
            return []
        if absent:
            raise PublishRefusal(f"{' '.join(argv)}: name unknown; a new repository is published only with "
                                 f"--first-publication {repository}")
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PublishRefusal(f"{' '.join(argv)} failed: {detail}")
    tags = json.loads(completed.stdout).get("Tags")
    if not isinstance(tags, list):
        raise PublishRefusal("GHCR returned a malformed tag listing")
    if first_publication:
        raise PublishRefusal(f"not a first publication: {repository} lists {len(tags)} tags")
    return tags


def moves_latest(version: str, recovery: bool) -> bool:
    """Only a final published by its own tag moves latest.

    An rc publishes its immutable version only. So does a recovery: a
    dispatch that publishes an existing tag's image again, rc or final.
    """
    if recovery:
        print("latest unchanged (recovery)")
        return False
    return final_version(version) is None


def publish_oci(root: Path, prefix: str, version: str, source_sha: str, *, recovery: bool = False,
                first_publication: tuple | list = ()) -> None:
    username = os.environ.get("GHCR_USERNAME", "").strip() or os.environ.get(
        "AC_REGISTRY_USERNAME", ""
    ).strip()
    token = os.environ.get("GHCR_TOKEN", "").strip() or os.environ.get(
        "AC_REGISTRY_TOKEN", ""
    ).strip()
    if not username or not token:
        raise PublishRefusal("GHCR_USERNAME and GHCR_TOKEN are required")
    if not shutil.which("skopeo"):
        raise PublishRefusal("skopeo is required for exact OCI publication")
    repositories = list(oci_images(prefix))
    for repository in first_publication:
        if repository not in repositories:
            raise PublishRefusal(f"{prefix} publishes no {repository}; it publishes {', '.join(repositories)}")
    # One decision for every image of the tag: an rc or a recovery moves no latest.
    version_only = not moves_latest(version, recovery)
    with tempfile.TemporaryDirectory(prefix="aweb-oci-") as temporary:
        # Every image of the tag is built and checked before the registry is
        # touched, so a failed build publishes none of them.
        staged = []
        for position, repository in enumerate(oci_images(prefix)):
            staging = Path(temporary) / str(position)
            staging.mkdir()
            archive = staging / "image.oci.tar"
            identities = staging / "identities.json"
            build_oci_archive(root, prefix, version, source_sha, archive)
            run(
                root, "bash", "scripts/oci-exact-publish.sh", "inspect-staged",
                "--archive", str(archive), "--version", version,
                "--source-sha", source_sha, "--out", str(identities),
            )
            index = json.loads(identities.read_text(encoding="utf-8"))["index"]
            staged.append((repository, archive, index))
        run(
            root, "skopeo", "login", "ghcr.io", "--username", username,
            "--password-stdin", input_text=token + "\n", timeout=120,
        )
        for repository, archive, index in staged:
            publish_staged_image(root, repository, archive, index, version, version_only,
                                 repository in first_publication)
        for repository, archive, index in staged:
            run(
                root, "bash", "scripts/oci-exact-publish.sh", "verify-published",
                "--archive", str(archive), "--version", version,
                "--source-sha", source_sha, "--repository", repository,
                *(["--version-only"] if version_only else []),
            )
            receipt = {"repository": repository, "digest": index, "source_sha": source_sha, "version": version}
            print(f"release-index={json.dumps(receipt, sort_keys=True, separators=(',', ':'))}")


def publish_staged_image(
    root: Path, repository: str, archive: Path, staged: str, version: str, version_only: bool,
    first_publication: bool = False,
) -> None:
    tags = published_tags(root, repository, first_publication)
    for image_tag in ((version,) if version_only else (version, "latest")):
        remote = ""
        if image_tag in tags:
            raw = subprocess.run(
                ["skopeo", "inspect", "--raw", f"docker://{repository}:{image_tag}"],
                cwd=root, capture_output=True, check=False, timeout=120,
            )
            if raw.returncode:
                raise PublishRefusal(f"cannot inspect present OCI tag {image_tag}")
            remote = "sha256:" + hashlib.sha256(raw.stdout).hexdigest()
        if remote == staged:
            continue
        if image_tag != "latest" and remote:
            raise PublishRefusal(
                f"immutable {repository}:{image_tag} is {remote}, staged is {staged}"
            )
        run(
            root, "skopeo", "copy", "--all", f"oci-archive:{archive}",
            f"docker://{repository}:{image_tag}", capture=False,
        )


def publish(root: Path, tag: str, *, only: str | None = None, recovery: bool = False,
            first_publication: tuple | list = (), assets: Path | None = None) -> None:
    prefix, version, source_sha = tag_identity(root, tag)
    publishes_from_source = prefix in OCI_REPOSITORIES or prefix in NPM_LANES or prefix == "aw-v"
    if prefix not in PYPI_PACKAGES and not publishes_from_source:
        raise PublishRefusal(f"{tag} publishes nothing from this repository")
    if only is not None and not (
        (only == "pypi" and prefix in PYPI_PACKAGES)
        or (only == "oci" and prefix in OCI_REPOSITORIES)
    ):
        raise PublishRefusal(f"{tag} does not publish to {only}")
    publishes_pypi = prefix in PYPI_PACKAGES and only != "oci"
    if publishes_pypi and assets is None:
        raise PublishRefusal(f"{tag} publishes to PyPI only its gated release files: pass --assets")
    # The annotated release tag carries the choice across the distribution
    # repository too; an ambient environment override would be lost there.
    staged_final = False
    if prefix == "aw-v":
        channel = run(root, "python3", "cli/go/npm/publication.py", "channel",
                      "--version", version, "--tag", tag, "--repository", str(root))
        staged_final = channel == "next" and "-rc." not in version
    if publishes_pypi:
        publish_pypi(root, tag, source_sha, assets)
    if only == "pypi" or not publishes_from_source:
        return
    with tempfile.TemporaryDirectory(prefix="aweb-publish-") as temporary:
        checkout = Path(temporary) / "source"
        run(root, "git", "worktree", "add", "--detach", str(checkout), source_sha, timeout=120)
        try:
            if prefix in OCI_REPOSITORIES:
                publish_oci(checkout, prefix, version, source_sha, recovery=recovery,
                            first_publication=first_publication)
            elif prefix in NPM_LANES:
                publish_npm(checkout, prefix, version)
            elif prefix == "aw-v":
                publish_aw_npm(checkout, version, source_sha, staged_final=staged_final)
        finally:
            run(root, "git", "worktree", "remove", "--force", str(checkout), timeout=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-tag", action="store_true", help="validate the tag against its manifest versions without publishing")
    parser.add_argument("--only", choices=("pypi", "oci"), help="publish only this artifact lane")
    parser.add_argument("--recovery", action="store_true",
                        help="publish an existing tag's images again; never moves latest")
    parser.add_argument("--first-publication", action="append", default=[], metavar="REPOSITORY",
                        help="an image repository this publication creates; repeat for each")
    parser.add_argument("--assets", type=Path, metavar="DIRECTORY",
                        help="the tag's downloaded release files, which PyPI receives exactly")
    parser.add_argument("tag")
    arguments = parser.parse_args(argv)
    try:
        if arguments.check_tag:
            tag_identity(Path.cwd().resolve(), arguments.tag)
        else:
            publish(Path.cwd().resolve(), arguments.tag, only=arguments.only, recovery=arguments.recovery,
                    first_publication=arguments.first_publication, assets=arguments.assets)
    except (
        PublishRefusal,
        OSError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"publish refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
