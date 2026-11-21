"""Immutable inputs and user-visible receipts for the standing lane's RC mode."""

import argparse
import hashlib
import json
import re
from pathlib import Path

CLIENTS = ("aw", "channel", "oats")
OPERATIONS = ("join", "mail", "chat", "wake", "retire")
CASES = tuple(f"{client}/{operation}" for client in CLIENTS for operation in OPERATIONS)
ROLES = ("baseline", "rc")
CHANNEL = "@awebai/claude-channel"
NPM = "https://registry.npmjs.org"


def server_inputs(document):
    if not isinstance(document, dict) or set(document) != set(ROLES):
        raise ValueError("Specify exactly baseline and rc server artifacts.")
    for role, artifact in document.items():
        if not isinstance(artifact, dict) or set(artifact) != {
            "image",
            "version",
            "source_sha",
        }:
            raise ValueError(f"{role}: expected image, version and source_sha.")
        rc_suffix = r"rc[1-9][0-9]*"
        version = r"[0-9]+\.[0-9]+\.[0-9]+" + (
            rc_suffix if role == "rc" else rf"(?:{rc_suffix})?"
        )
        if not re.fullmatch(version, str(artifact["version"])):
            raise ValueError(f"{role}: expected an exact published server version.")
        if not re.fullmatch(
            r"ghcr\.io/awebai/aweb-server@sha256:[0-9a-f]{64}", str(artifact["image"])
        ):
            raise ValueError(f"{role}: expected a digest-pinned aweb-server image.")
        if not re.fullmatch(r"[0-9a-f]{40}", str(artifact["source_sha"])):
            raise ValueError(f"{role}: expected a full source SHA.")
    if document["baseline"]["image"] == document["rc"]["image"]:
        raise ValueError("Baseline and RC must be distinct server artifacts.")
    return document


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("channel_destination", type=Path)
    stage_channel(parser.parse_args().channel_destination)
