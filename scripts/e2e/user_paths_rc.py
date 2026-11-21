"""Immutable inputs and user-visible receipts for the standing lane's RC mode."""

import argparse
from datetime import datetime
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

CLIENTS = ("aw", "channel", "oats")
OPERATIONS = ("join", "mail", "chat", "wake", "retire")
CASES = tuple(f"{client}/{operation}" for client in CLIENTS for operation in OPERATIONS)
ROLES = ("baseline", "rc")
CHANNEL = "@awebai/claude-channel"
NPM = "https://registry.npmjs.org"
KERNEL = "@awebai/oats"
KERNEL_REPO = "https://github.com/oats-project/oats.git"
PROVIDER_REPO = "https://github.com/awebai/oats-aweb.git"
SERVER_REPO = "https://github.com/awebai/aweb.git"
SERVER_REGISTRY = "ghcr.io/awebai/aweb-server"
BASELINE_PACKAGES = {"aweb", "aweb-naapp", "awid-service"}
FINAL_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
SOURCE = r"[0-9a-f]{40}"
DIGEST = r"sha256:[0-9a-f]{64}"


def server_inputs(document):
    if not isinstance(document, dict) or set(document) != set(ROLES):
        raise ValueError("Specify exactly baseline and rc server artifacts.")
    for role, artifact in document.items():
        required = {"version", "source_sha"}
        expected = required | {"image" if role == "rc" else "wheel_sha256"}
        if not isinstance(artifact, dict) or set(artifact) != expected:
            raise ValueError(f"{role}: expected {', '.join(sorted(expected))}.")
        version = FINAL_VERSION + (r"rc[1-9][0-9]*" if role == "rc" else "")
        if not re.fullmatch(version, str(artifact["version"])):
            raise ValueError(f"{role}: expected an exact published server version.")
        if not re.fullmatch(SOURCE, str(artifact["source_sha"])):
            raise ValueError(f"{role}: expected a full source SHA.")
    if not re.fullmatch(
        re.escape(SERVER_REGISTRY) + "@" + DIGEST, str(document["rc"]["image"])
    ):
        raise ValueError("rc: expected a digest-pinned aweb-server image.")
    if not re.fullmatch(DIGEST, str(document["baseline"]["wheel_sha256"])):
        raise ValueError("baseline: expected the deployment's aweb wheel SHA256.")
    return document


def command(*arguments, timeout=30):
    return subprocess.run(
        arguments, capture_output=True, text=True, timeout=timeout, check=True
    ).stdout.strip()


def remote_tag(repository, tag):
    ref = "refs/tags/" + tag
    peeled = ref + "^{}"
    rows = dict(
        line.split("\t")[::-1]
        for line in command("git", "ls-remote", repository, ref, peeled).splitlines()
    )
    commit = rows.get(peeled, rows.get(ref))
    if (
        set(rows) - {ref, peeled}
        or ref not in rows
        or not re.fullmatch(SOURCE, commit or "")
    ):
        raise ValueError(f"Could not verify published tag {tag} from {repository}.")
    return {
        "tag": tag,
        "ref_sha": rows[ref],
        "source_sha": commit,
        "repository": repository,
    }


def verify_published_server(artifact, source, release_digest=None):
    if source["source_sha"] != artifact["source_sha"]:
        raise ValueError("Server source does not match the published server tag.")
    if "image" in artifact and (
        not isinstance(release_digest, str)
        or artifact["image"] != SERVER_REGISTRY + "@" + release_digest
    ):
        raise ValueError("RC image digest does not match the published server version.")


def published_server(artifact, role):
    source = remote_tag(SERVER_REPO, "server-v" + artifact["version"])
    digest = None
    if role == "rc":
        image = SERVER_REGISTRY + ":" + artifact["version"]
        digest = json.loads(
            command(
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                image,
                "--format",
                "{{json .Manifest.Digest}}",
            )
        )
        source.update(release_image=image, release_digest=digest)
    verify_published_server(artifact, source, digest)
    return source


def production_baseline(artifact, readback):
    """Bind the fixture wheel to an independent production deployment readback."""
    names = (
        "service",
        "deployment_id",
        "deployed_image",
        "deployed_source_sha",
        "observed_at",
        "package_lock",
        "production_aweb_version",
        "packages",
    )
    if not isinstance(readback, dict) or any(not readback.get(name) for name in names):
        raise ValueError(
            "Production readback needs the deployment, image, source, observation time and locked wheels."
        )
    if not re.fullmatch(
        r"[^\s@]+@" + DIGEST, readback["deployed_image"]
    ) or not re.fullmatch(SOURCE, readback["deployed_source_sha"]):
        raise ValueError(
            "Production readback must identify an immutable deployment image and source."
        )
    if (
        datetime.fromisoformat(readback["observed_at"].replace("Z", "+00:00")).tzinfo
        is None
    ):
        raise ValueError("Production readback time must have a timezone.")
    lock = readback["package_lock"]
    if (
        not isinstance(lock, dict)
        or set(lock) != {"commit", "path", "blob"}
        or lock["commit"] != readback["deployed_source_sha"]
        or not re.fullmatch(SOURCE, str(lock["blob"]))
        or not lock["path"]
    ):
        raise ValueError(
            "Package lock must identify the deployed source commit and Git blob."
        )
    packages = readback["packages"]
    if not isinstance(packages, dict) or set(packages) != BASELINE_PACKAGES:
        raise ValueError(
            "Production readback must record the aweb, aweb-naapp and awid-service wheels."
        )
    for name, pkg in packages.items():
        version = pkg["version"]
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        if (
            not re.fullmatch(FINAL_VERSION, version)
            or not re.fullmatch(DIGEST, pkg["sha256"])
            or not re.fullmatch(
                r"https://files\.pythonhosted\.org/packages/[0-9a-f/]+/"
                + re.escape(filename),
                pkg["url"],
            )
        ):
            raise ValueError(f"Invalid deployment wheel pin for {name}.")
    if (
        readback["production_aweb_version"],
        packages["aweb"]["version"],
        packages["aweb"]["sha256"],
    ) != (
        artifact["version"],
        artifact["version"],
        artifact["wheel_sha256"],
    ):
        raise ValueError(
            "Baseline wheel differs from the deployed aweb package readback."
        )
    return readback


def stage_production_wheels(destination, packages):
    from fetch_released_aw import download

    destination.mkdir()
    for name, pkg in packages.items():
        data = download(pkg["url"])
        if "sha256:" + hashlib.sha256(data).hexdigest() != pkg["sha256"]:
            raise ValueError(
                f"The deployed {name} wheel SHA256 does not match the readback."
            )
        (destination / pkg["url"].rsplit("/", 1)[1]).write_bytes(data)


def verify_server_image(artifact, inspection):
    labels = inspection["Config"].get("Labels") or {}
    if (
        artifact["image"] not in (inspection.get("RepoDigests") or [])
        or labels.get("org.opencontainers.image.version") != artifact["version"]
        or labels.get("org.opencontainers.image.revision") != artifact["source_sha"]
    ):
        raise ValueError(
            "Local image digest, version or source differs from the declared server."
        )
    return {**artifact, "local_image_id": inspection["Id"]}


def compatibility(baseline, candidate):
    observations = dict(zip(ROLES, (baseline, candidate)))
    missing = {
        role: sorted(set(CASES) - results.keys())
        for role, results in observations.items()
    }
    failures = {
        role: sorted(
            case
            for case, row in results.items()
            if not isinstance(row, dict)
            or row.get("status") != "PASSED"
            or not isinstance(row.get("visible"), dict)
            or not row["visible"]
        )
        for role, results in observations.items()
    }
    changes = {}
    for case in sorted(set(baseline) | set(candidate)):
        if baseline.get(case) != candidate.get(case):
            changes[case] = {"baseline": baseline.get(case), "rc": candidate.get(case)}
    return {
        "status": "FAILED"
        if changes or any(missing.values()) or any(failures.values())
        else "PASSED",
        "missing": missing,
        "failures": failures,
        "changes": changes,
        "observations": observations,
    }


def stage_channel(destination):
    from fetch_released_aw import download, package_json, tar_member, verify_integrity

    # Resolve latest once. Neither stack resolves a mutable tag after this.
    metadata = json.loads(download(f"{NPM}/@awebai%2fclaude-channel/latest"))
    version = metadata["version"]
    if metadata.get("name") != CHANNEL or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("npm latest must name an exact final channel package.")
    dist = metadata["dist"]
    if dist["tarball"] != f"{NPM}/{CHANNEL}/-/claude-channel-{version}.tgz":
        raise ValueError(
            "Channel tarball must match the canonical registry and version."
        )
    archive = download(dist["tarball"])
    verify_integrity(archive, dist["integrity"])
    package_json(archive, CHANNEL, version)
    # The plugin is distributed as a bundled Node entry. Read only the
    # verified executable members through the existing npm archive guard.
    declaration = json.loads(tar_member(archive, "package/.mcp.json"))
    expected = {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/dist/index.js"]}
    if declaration.get("mcpServers") != {"aweb-channel": expected}:
        raise ValueError("Published channel changed its declared MCP entrypoint.")
    destination.mkdir(parents=True)
    (destination / "dist").mkdir()
    for path in ("package.json", ".mcp.json", "dist/index.js"):
        (destination / path).write_bytes(tar_member(archive, "package/" + path))
    (destination / "provenance.json").write_text(
        json.dumps(
            {
                "name": CHANNEL,
                "version": version,
                "gitHead": metadata.get("gitHead"),
                "tarball": dist["tarball"],
                "integrity": dist["integrity"],
                "tarball_sha256": hashlib.sha256(archive).hexdigest(),
                "entry_sha256": hashlib.sha256(
                    (destination / "dist/index.js").read_bytes()
                ).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )


def stage_oats(destination):
    from fetch_released_aw import download, package_json, verify_integrity

    metadata = json.loads(download(f"{NPM}/@awebai%2foats/latest"))
    version = metadata["version"]
    if metadata.get("name") != KERNEL or not re.fullmatch(FINAL_VERSION, version):
        raise ValueError("npm latest must name an exact final OATS package.")
    dist = metadata["dist"]
    if dist["tarball"] != f"{NPM}/{KERNEL}/-/oats-{version}.tgz":
        raise ValueError("OATS tarball must match the canonical registry and version.")
    archive = download(dist["tarball"])
    verify_integrity(archive, dist["integrity"])
    package_json(archive, KERNEL, version)
    source = remote_tag(KERNEL_REPO, "v" + version)
    if metadata.get("gitHead") not in (None, source["source_sha"]):
        raise ValueError("The latest OATS npm artifact disagrees with its release tag.")
    destination.mkdir()
    package = destination / "kernel.tgz"
    package.write_bytes(archive)
    (destination / "package.json").write_text('{"private":true}\n')
    command(
        "npm",
        "install",
        "--prefix",
        str(destination),
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--registry",
        NPM,
        "--cache",
        str(destination / "npm-cache"),
        str(package),
        timeout=90,
    )

    rows = command(
        "git", "ls-remote", "--tags", "--refs", PROVIDER_REPO, "refs/tags/v*"
    )
    versions = [
        row.split("\t", 1)[1].removeprefix("refs/tags/v") for row in rows.splitlines()
    ]
    provider_version = max(
        (v for v in versions if re.fullmatch(FINAL_VERSION, v)),
        key=lambda v: tuple(map(int, v.split("."))),
    )
    provider = remote_tag(PROVIDER_REPO, "v" + provider_version)
    bare = destination / "provider.git"
    command("git", "init", "--bare", str(bare))
    command(
        "git",
        "--git-dir",
        str(bare),
        "fetch",
        "--depth=1",
        PROVIDER_REPO,
        "refs/tags/" + provider["tag"],
    )
    if (
        command("git", "--git-dir", str(bare), "rev-parse", "FETCH_HEAD^{commit}")
        != provider["source_sha"]
    ):
        raise ValueError(
            "The fetched OATS provider tag moved while staging the release."
        )
    capability = "oats-package/capabilities/oats-aweb"
    payload = destination / "provider.tar"
    command(
        "git",
        "--git-dir",
        str(bare),
        "archive",
        "-o",
        str(payload),
        "FETCH_HEAD",
        "oats-package",
    )
    with tarfile.open(payload) as tar:
        tar.extractall(destination, filter="data")
    provider_manifest = json.loads((destination / capability / "oats.json").read_text())
    if provider_manifest["version"] != provider_version:
        raise ValueError("The OATS provider tag and capability version differ.")
    provider.update(
        version=provider_version,
        capability_path=capability,
        archive_sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
    )
    dependencies = json.loads((destination / "package-lock.json").read_text())[
        "packages"
    ]
    if dependencies["node_modules/" + KERNEL]["integrity"] != dist["integrity"]:
        raise ValueError(
            "Installed OATS kernel integrity differs from the frozen package."
        )
    (destination / "provenance.json").write_text(
        json.dumps(
            {
                "kernel": {
                    "name": KERNEL,
                    "version": version,
                    **source,
                    "tarball": dist["tarball"],
                    "integrity": dist["integrity"],
                    "sha256": hashlib.sha256(archive).hexdigest(),
                    "dependencies": dependencies,
                },
                "provider": provider,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--production-readback", required=True, type=Path)
    args = parser.parse_args()
    stage_channel(args.destination / "channel")
    stage_oats(args.destination / "oats")
    readback = json.loads(args.production_readback.read_text())
    stage_production_wheels(
        args.destination / "production-wheels", readback["packages"]
    )
