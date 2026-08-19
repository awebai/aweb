#!/usr/bin/env python3
"""Publish one already-tested OSS tag, without release branches or GitHub Actions."""

from __future__ import annotations

import argparse
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


SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
TAG_PATTERN = re.compile(
    rf"^(server-v|awid-service-v|awid-v|aw-v|channel-v|pi-v|skills-v|a2a-gw-v)({SEMVER})$"
)
MANIFESTS = {
    "server-v": "server/pyproject.toml",
    "awid-service-v": "awid/pyproject.toml",
    "awid-v": "awid/pyproject.toml",
    "channel-v": "channel/package.json",
    "pi-v": "pi-extension/package.json",
    "skills-v": "packages/claude-skills/package.json",
}
NPM_LANES = {
    "channel-v": ("channel", "@awebai/claude-channel", "channel"),
    "pi-v": ("pi-extension", "@awebai/pi", "pi"),
    "skills-v": ("packages/claude-skills", "@awebai/claude-skills", "skills"),
}


class PublishRefusal(RuntimeError):
    pass


def run(
    root: Path,
    *argv: str,
    capture: bool = True,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    timeout: int = 7200,
) -> str:
    completed = subprocess.run(
        argv,
        cwd=root,
        text=True,
        input=input_text,
        capture_output=capture,
        env=env,
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PublishRefusal(f"{' '.join(argv)} failed: {detail}")
    return completed.stdout.strip() if capture else ""


def manifest_version(root: Path, path: str) -> str:
    if path.endswith(".toml"):
        with (root / path).open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    else:
        value = json.loads((root / path).read_text(encoding="utf-8"))["version"]
    if not isinstance(value, str) or not re.fullmatch(SEMVER, value):
        raise PublishRefusal(f"{path} has invalid version {value!r}")
    return value


def manifest_version_at(root: Path, source_sha: str, path: str) -> str:
    raw = run(root, "git", "show", f"{source_sha}:{path}", timeout=60)
    if path.endswith(".toml"):
        value = tomllib.loads(raw)["project"]["version"]
    else:
        value = json.loads(raw)["version"]
    if not isinstance(value, str) or not re.fullmatch(SEMVER, value):
        raise PublishRefusal(f"{path} at {source_sha} has invalid version {value!r}")
    return value


def tag_identity(root: Path, tag: str) -> tuple[str, str, str]:
    matched = TAG_PATTERN.fullmatch(tag)
    if not matched:
        raise PublishRefusal(f"unsupported release tag {tag!r}")
    prefix, version = matched.group(1), matched.group(2)
    try:
        source_sha = run(root, "git", "rev-parse", f"{tag}^{{commit}}", timeout=60)
    except PublishRefusal as error:
        raise PublishRefusal(f"local candidate tag {tag} is absent") from error
    manifest = MANIFESTS.get(prefix)
    if manifest and manifest_version_at(root, source_sha, manifest) != version:
        raise PublishRefusal(
            f"{tag} does not match {manifest} version {manifest_version_at(root, source_sha, manifest)}"
        )
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


def publish_pypi(root: Path, prefix: str, version: str) -> None:
    package, directory = (
        ("aweb", "server") if prefix == "server-v" else ("awid-service", "awid")
    )
    token = os.environ.get("UV_PUBLISH_TOKEN", "").strip()
    if not token:
        raise PublishRefusal("UV_PUBLISH_TOKEN is required")
    if prefix == "server-v":
        awid_version = manifest_version(root, "awid/pyproject.toml")
        deadline = time.monotonic() + 180
        while True:
            status, _ = request_json(
                f"https://pypi.org/pypi/awid-service/{awid_version}/json"
            )
            if status == 200:
                break
            if time.monotonic() >= deadline:
                raise PublishRefusal(
                    f"awid-service {awid_version} is not publicly available before aweb publication"
                )
            time.sleep(6)
    with tempfile.TemporaryDirectory(prefix="aweb-pypi-") as temporary:
        dist = Path(temporary)
        run(root, "uv", "build", "--sdist", "--wheel", "--out-dir", str(dist), directory)
        (dist / ".gitignore").unlink(missing_ok=True)
        run(
            root,
            "bash",
            "scripts/pypi-exact-publish.sh",
            "inspect-staged",
            "--dist",
            str(dist),
            "--package",
            package,
            "--version",
            version,
        )
        status, observed = request_json(f"https://pypi.org/pypi/{package}/{version}/json")
        observed_path = dist / "observed.json"
        observed_path.write_text(json.dumps(observed), encoding="utf-8")
        plan = run(
            root,
            "bash",
            "scripts/pypi-exact-publish.sh",
            "plan-publish",
            "--dist",
            str(dist),
            "--package",
            package,
            "--version",
            version,
            "--observed-status",
            str(status),
            "--observed-json",
            str(observed_path),
        )
        files = [dist / name for name in plan.splitlines() if name]
        if files:
            run(root, "uv", "publish", *(str(path) for path in files), capture=False)
        run(
            root,
            "bash",
            "scripts/pypi-exact-publish.sh",
            "verify-published",
            "--dist",
            str(dist),
            "--package",
            package,
            "--version",
            version,
        )


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


def npm_publish_exact(root: Path, directory: str, package: str, profile: str, version: str) -> None:
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
                capture=False,
                env=environment,
            )
        else:
            raise PublishRefusal(f"npm registry returned unexpected HTTP {status}")
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
            env=environment,
        )


def publish_npm(root: Path, prefix: str, version: str) -> None:
    if prefix == "pi-v":
        require_pi_aw_floor(root)
    directory, package, profile = build_npm_lane(root, prefix)
    npm_publish_exact(root, directory, package, profile, version)
    if prefix == "skills-v":
        print("skill ZIPs are staged locally; hosted release assets can be uploaded later")


def write_json_version(path: Path, version: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value["version"] = version
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def publish_aw_npm(root: Path, version: str, source_sha: str) -> None:
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
        write_json_version(npm_root / package_dir / "package.json", version)
    main_manifest = npm_root / "aw/package.json"
    value = json.loads(main_manifest.read_text(encoding="utf-8"))
    value["version"] = version
    value["optionalDependencies"] = {
        name: version for name in sorted(value.get("optionalDependencies", {}))
    }
    main_manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    for package_dir in [item[0] for item in packages.values()] + ["aw"]:
        npm_publish_exact(
            root,
            str(Path("cli/go/npm") / package_dir),
            "@awebai/" + package_dir,
            "",
            version,
        )
    print("npm CLI packages published; hosted binary release assets can be resumed later")


def publish_oci(root: Path, prefix: str, version: str, source_sha: str) -> None:
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
    repository = (
        "ghcr.io/awebai/awid" if prefix == "awid-v" else "ghcr.io/awebai/a2a-gateway"
    )
    with tempfile.TemporaryDirectory(prefix="aweb-oci-") as temporary:
        staging = Path(temporary)
        archive = staging / "image.oci.tar"
        identities = staging / "identities.json"
        if prefix == "awid-v":
            build = [
                "docker", "buildx", "build", "--file", "awid/Dockerfile.release",
                "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
                "--label", "org.opencontainers.image.title=awid",
                "--label", "org.opencontainers.image.description=Thin awid.ai registry service wrapper around aweb",
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
        run(
            root, "bash", "scripts/oci-exact-publish.sh", "inspect-staged",
            "--archive", str(archive), "--version", version,
            "--source-sha", source_sha, "--out", str(identities),
        )
        staged = json.loads(identities.read_text(encoding="utf-8"))["index"]
        run(
            root, "skopeo", "login", "ghcr.io", "--username", username,
            "--password-stdin", input_text=token + "\n", timeout=120,
        )
        listing = json.loads(run(root, "skopeo", "list-tags", f"docker://{repository}", timeout=120))
        tags = listing.get("Tags")
        if not isinstance(tags, list):
            raise PublishRefusal("GHCR returned a malformed tag listing")
        for image_tag in (version, "latest"):
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
        run(
            root, "bash", "scripts/oci-exact-publish.sh", "verify-published",
            "--archive", str(archive), "--version", version,
            "--source-sha", source_sha, "--repository", repository,
        )
        print(f"release-index={json.dumps({'digest': staged, 'source_sha': source_sha, 'version': version}, sort_keys=True, separators=(',', ':'))}")


def publish(root: Path, tag: str) -> None:
    prefix, version, source_sha = tag_identity(root, tag)
    with tempfile.TemporaryDirectory(prefix="aweb-publish-") as temporary:
        checkout = Path(temporary) / "source"
        run(root, "git", "worktree", "add", "--detach", str(checkout), source_sha, timeout=120)
        try:
            if prefix in {"server-v", "awid-service-v"}:
                publish_pypi(checkout, prefix, version)
            elif prefix in NPM_LANES:
                publish_npm(checkout, prefix, version)
            elif prefix == "aw-v":
                publish_aw_npm(checkout, version, source_sha)
            else:
                publish_oci(checkout, prefix, version, source_sha)
        finally:
            run(root, "git", "worktree", "remove", "--force", str(checkout), timeout=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    arguments = parser.parse_args(argv)
    try:
        publish(Path.cwd().resolve(), arguments.tag)
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
