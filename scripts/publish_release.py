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
    require_final_promotion,
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
# Each PyPI lane: whether it depends on the in-repo awid-service, which must be
# public first, and the (package, directory) pairs it publishes, in order. A
# lane's packages share the tag's version.
PYPI_LANES = {
    "server-v": (True, (("aweb", "server"),)),
    "awid-service-v": (False, (("awid-service", "awid"),)),
    "aweb-naapp-v": (True, (("aweb-naapp", "naapp-lib"), ("aweb-naapp-testing", "naapp-lib/testing"))),
    "aweb-secrets-runner-v": (False, (
        ("aweb-secrets-values", "naapp/secrets/values"),
        ("aweb-secrets-runner", "naapp/secrets/runner"),
    )),
}
NPM_LANES = {
    "channel-v": ("channel", "@awebai/claude-channel", "channel"),
    "pi-v": ("pi-extension", "@awebai/pi", "pi"),
    "skills-v": ("packages/claude-skills", "@awebai/claude-skills", "skills"),
}

# The aw npm platform packages: Go platform -> (package directory, aw binary,
# gateway binary). The wrapper package "aw" pins all six.
AW_NPM_PLATFORMS = {
    "linux/amd64": ("aw-linux-x64", "aw", "aweb-a2a-gw"),
    "linux/arm64": ("aw-linux-arm64", "aw", "aweb-a2a-gw"),
    "darwin/amd64": ("aw-darwin-x64", "aw", "aweb-a2a-gw"),
    "darwin/arm64": ("aw-darwin-arm64", "aw", "aweb-a2a-gw"),
    "windows/amd64": ("aw-windows-x64", "aw.exe", "aweb-a2a-gw.exe"),
    "windows/arm64": ("aw-windows-arm64", "aw.exe", "aweb-a2a-gw.exe"),
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


def manifest_version(root: Path, path: str) -> str:
    if path.endswith(".toml"):
        with (root / path).open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    else:
        value = json.loads((root / path).read_text(encoding="utf-8"))["version"]
    if not valid_version(path, value):
        raise PublishRefusal(f"{path} has invalid version {value!r}")
    return value


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
    manifests = [MANIFESTS[prefix]] if prefix in MANIFESTS else []
    manifests += [f"{directory}/pyproject.toml" for _, directory in PYPI_LANES.get(prefix, (False, ()))[1]]
    for manifest in dict.fromkeys(manifests):
        if manifest_version_at(root, source_sha, manifest) != version:
            raise PublishRefusal(
                f"{tag} does not match {manifest} version {manifest_version_at(root, source_sha, manifest)}"
            )
    if prefix == "aweb-secrets-runner-v":
        require_runner_values(root, source_sha)
    require_final_promotion(root, tag, source_sha)
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


def publish_pypi(root: Path, prefix: str, version: str, selected: list[dict]) -> None:
    needs_awid, packages = PYPI_LANES[prefix]
    token = os.environ.get("UV_PUBLISH_TOKEN", "").strip()
    if not token:
        raise PublishRefusal("UV_PUBLISH_TOKEN is required")
    if needs_awid:
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
                    f"awid-service {awid_version} is not publicly available before {prefix} publication"
                )
            time.sleep(6)
    for package, directory in packages:
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


def aw_ldflags(version: str, source_sha: str) -> str:
    return (
        f"-s -w -X main.version={version} -X main.commit={source_sha} "
        "-X main.commitRepo=github.com/awebai/aweb -X main.date=1970-01-01T00:00:00Z"
    )


def build_aw_npm(root: Path, version: str, source_sha: str, npm_root: Path | None = None) -> list[str]:
    """Shared build operation; callers own retention and publication separately."""
    packages = AW_NPM_PLATFORMS
    npm_root = npm_root or root / "cli/go/npm"
    ldflags = aw_ldflags(version, source_sha)
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
    return [item[0] for item in packages.values()] + ["aw"]


def publish_aw_npm(root: Path, version: str, source_sha: str, selected: list[dict], *, staged_final: bool = False) -> None:
    package_dirs = build_aw_npm(root, version, source_sha)
    npm_root = root / "cli/go/npm"
    # Hold all seven once-staged archives through one verifier invocation.
    # Publishing/adopting never becomes a retry action on readback uncertainty.
    with ExitStack() as staging:
        artifacts = []
        for package_dir in package_dirs:
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
    repository = {
        "awid-v": "ghcr.io/awebai/awid",
        "a2a-gw-v": "ghcr.io/awebai/a2a-gateway",
        "secrets-v": "ghcr.io/awebai/secrets",
        "logs-v": "ghcr.io/awebai/logs",
    }[prefix]
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


def lane_files(prefix: str) -> dict[str, tuple[str, ...]]:
    """The package names a manifest-gated tag publishes, with the file kinds each needs."""
    if prefix in PYPI_LANES:
        return {name: (".whl", ".tar.gz") for name, _ in PYPI_LANES[prefix][1]}
    if prefix in NPM_LANES:
        return {NPM_LANES[prefix][1]: (".tgz",)}
    if prefix == "aw-v":
        return {f"@awebai/{package_dir}": (".tgz",) for package_dir, _, _ in AW_NPM_PLATFORMS.values()} | {
            "@awebai/aw": (".tgz",)}
    raise PublishRefusal(f"{prefix} is not a manifest-gated lane")


def require_cloud_verdict(cloud_checkout: Path, cloud_tree: str, manifest_sha256: str,
                          expected_aw_released: str) -> None:
    """AC's candidate-oss-verdict must pass for this tree, digest and released aw."""
    # Fetch only Cloud main's remote-tracking ref; the checkout's branches,
    # index and working tree stay as the operator left them.
    run(cloud_checkout, "git", "fetch", "--quiet", "origin", "+refs/heads/main:refs/remotes/origin/main", timeout=300)
    main_tree = run(cloud_checkout, "git", "rev-parse", "refs/remotes/origin/main^{tree}", timeout=60)
    if main_tree != cloud_tree:
        raise PublishRefusal(f"Cloud main tree is {main_tree}, not CLOUD_TREE {cloud_tree}; rerun the Cloud gate")
    completed = subprocess.run(
        ["make", "--no-print-directory", "-C", str(cloud_checkout), "candidate-oss-verdict",
         f"CLOUD_TREE={cloud_tree}", f"OSS_MANIFEST_SHA256={manifest_sha256}",
         f"EXPECTED_AW_RELEASED={expected_aw_released}"],
        text=True, capture_output=True, timeout=600, check=False)
    refusal = f"Cloud verdict does not pass for manifest {manifest_sha256}, tree {cloud_tree}, aw {expected_aw_released}"
    if completed.returncode:
        raise PublishRefusal(f"{refusal}: exit {completed.returncode}: {(completed.stderr or completed.stdout).strip()}")
    try:
        answer = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise PublishRefusal(f"{refusal}: output is not JSON: {error}") from error
    keys = answer.get("keys") if isinstance(answer, dict) else None
    inputs = answer.get("effective_inputs") if isinstance(answer, dict) else None
    if not (answer.get("schema") == 1 and answer.get("passed") is True
            and answer.get("cloud_tree") == cloud_tree and answer.get("oss_manifest_sha256") == manifest_sha256
            and isinstance(keys, list) and keys and isinstance(inputs, dict)
            and all(isinstance(inputs.get(key), dict)
                    and inputs[key].get("oss-manifest-sha256") == manifest_sha256
                    and inputs[key].get("aw-released") == expected_aw_released for key in keys)):
        raise PublishRefusal(f"{refusal}: {completed.stdout.strip()}")


def gated_publish_set(directory: Path, *, prefix: str, version: str, source_sha: str, cloud_checkout: Path,
                      cloud_tree: str, manifest_sha256: str, expected_aw_released: str,
                      npm_latest_aw: str) -> list[dict]:
    """The tag's rows of the gated manifest, after every byte and the Cloud verdict check out.

    npm_latest_aw is @awebai/aw's npm latest as read once before the release's
    first upload: the released client Cloud was gated against.
    """
    from release_artifacts import manifest_path, verify

    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise PublishRefusal(f"OSS_MANIFEST_SHA256 must be 64 lowercase hex characters, not {manifest_sha256!r}")
    if not re.fullmatch(r"[0-9a-f]{40}", cloud_tree):
        raise PublishRefusal(f"CLOUD_TREE must be a 40-character Git tree id, not {cloud_tree!r}")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_aw_released):
        raise PublishRefusal(f"EXPECTED_AW_RELEASED must be a final X.Y.Z version, not {expected_aw_released!r}")
    observed = sha256(manifest_path(directory))
    if observed != manifest_sha256:
        raise PublishRefusal(f"manifest.json sha256 is {observed}, not the requested {manifest_sha256}")
    manifest = verify(directory)
    if manifest.get("schema") != 2:
        raise PublishRefusal(f"artifact manifest schema {manifest.get('schema')!r} is not 2")
    if manifest.get("source_sha") != source_sha:
        raise PublishRefusal(f"artifact manifest source commit {manifest.get('source_sha')} is not the tag's {source_sha}")
    selected = []
    for package, suffixes in lane_files(prefix).items():
        for suffix in suffixes:
            rows = [row for row in manifest["files"] if row["package"] == package and row["path"].endswith(suffix)]
            if len(rows) != 1 or rows[0]["version"] != version:
                raise PublishRefusal(f"artifact manifest needs exactly one {package} {version} {suffix}, found "
                                     f"{[(row['path'], row['version']) for row in rows]}")
            selected.append(dict(rows[0], path=str(directory / rows[0]["path"])))
    if npm_latest_aw != expected_aw_released:
        raise PublishRefusal(f"npm latest @awebai/aw is {npm_latest_aw}, not the expected {expected_aw_released}")
    require_cloud_verdict(cloud_checkout, cloud_tree, manifest_sha256, expected_aw_released)
    return selected


def released_aw() -> str:
    status, tags = request_json("https://registry.npmjs.org/-/package/%40awebai%2Faw/dist-tags")
    if status != 200 or not isinstance(tags.get("latest"), str):
        raise PublishRefusal(f"npm dist-tags for @awebai/aw are unavailable (HTTP {status})")
    return tags["latest"]


def publish(root: Path, tag: str, *, artifacts: Path, cloud_checkout: Path, cloud_tree: str, manifest_sha256: str,
            expected_aw_released: str, dry_run: bool = False) -> None:
    prefix, version, source_sha = tag_identity(root, tag)
    if prefix in PYPI_LANES or prefix in NPM_LANES or prefix == "aw-v":
        selected = gated_publish_set(
            artifacts, prefix=prefix, version=version, source_sha=source_sha, cloud_checkout=cloud_checkout,
            cloud_tree=cloud_tree, manifest_sha256=manifest_sha256, expected_aw_released=expected_aw_released,
            npm_latest_aw=released_aw())
        for row in selected:
            print(f"publish set: {row['package']} {row['version']} sha256={row['sha256']} {row['path']}")
        if dry_run:
            print(f"dry run: {tag} passed the Cloud verdict for manifest {manifest_sha256}; nothing uploaded")
            return
        raise PublishRefusal(f"{tag}: uploading the gated manifest files is not available")
    print(f"{tag} is not manifest-gated: its image is built from the tag, without a Cloud verdict")
    if dry_run:
        print(f"dry run: {tag}; nothing built or uploaded")
        return
    # The annotated release tag carries the choice across the distribution
    # repository too; an ambient environment override would be lost there.
    staged_final = False
    if prefix == "aw-v":
        channel = run(root, "python3", "cli/go/npm/publication.py", "channel",
                      "--version", version, "--tag", tag, "--repository", str(root))
        staged_final = channel == "next" and "-rc." not in version
    with tempfile.TemporaryDirectory(prefix="aweb-publish-") as temporary:
        checkout = Path(temporary) / "source"
        run(root, "git", "worktree", "add", "--detach", str(checkout), source_sha, timeout=120)
        try:
            if prefix in PYPI_LANES:
                publish_pypi(checkout, prefix, version)
            elif prefix in NPM_LANES:
                publish_npm(checkout, prefix, version)
            elif prefix == "aw-v":
                publish_aw_npm(checkout, version, source_sha, staged_final=staged_final)
            else:
                publish_oci(checkout, prefix, version, source_sha)
        finally:
            run(root, "git", "worktree", "remove", "--force", str(checkout), timeout=120)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-tag", action="store_true", help="validate tag/tree identity without publishing")
    parser.add_argument("--artifacts", type=Path, help="the gated candidate artifact directory holding manifest.json")
    parser.add_argument("--cloud-checkout", type=Path, help="Cloud checkout holding candidate-oss-verdict and its ledger")
    parser.add_argument("--cloud-tree", help="Git tree id of current Cloud main the verdict was gated on")
    parser.add_argument("--manifest-sha256", help="sha256 of the exact gated manifest.json bytes")
    parser.add_argument("--expected-aw-released", help="npm latest @awebai/aw Cloud was gated against, X.Y.Z")
    parser.add_argument("--dry-run", action="store_true", help="run every check and print the publish set; upload nothing")
    parser.add_argument("tag")
    arguments = parser.parse_args(argv)
    gate = ("artifacts", "cloud_checkout", "cloud_tree", "manifest_sha256", "expected_aw_released")
    if not arguments.check_tag:
        missing = [f"--{name.replace('_', '-')}" for name in gate if not getattr(arguments, name)]
        if missing:
            parser.error(f"publishing requires {' '.join(missing)}")
    try:
        if arguments.check_tag:
            tag_identity(Path.cwd().resolve(), arguments.tag)
        else:
            publish(Path.cwd().resolve(), arguments.tag, artifacts=arguments.artifacts,
                    cloud_checkout=arguments.cloud_checkout, cloud_tree=arguments.cloud_tree,
                    manifest_sha256=arguments.manifest_sha256,
                    expected_aw_released=arguments.expected_aw_released, dry_run=arguments.dry_run)
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
