"""Prepare the holder-locked service repository for its own offline test target."""

import argparse
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tomllib
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen

REPOSITORY = "https://github.com/awebai/approval-service.git"


class Operation(StrEnum):
    PREPARE = "prepare"
    VERIFY = "verify"


@dataclass(frozen=True)
class ServicePin:
    revision: str
    lock_sha256: str


@dataclass(frozen=True)
class CoreDnsArtifact:
    version: str
    url: str
    sha256: str


def coredns_artifact(*, declaration: object, architecture: str) -> CoreDnsArtifact:
    message = (
        "Invalid CoreDNS declaration; correct the service's pinned artifact metadata."
    )
    if not isinstance(declaration, dict):
        raise ValueError(message)
    version = declaration.get("version")
    platforms = declaration.get("linux")
    if (
        not isinstance(version, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", version)
        or not isinstance(platforms, dict)
    ):
        raise ValueError(message)
    artifact = platforms.get(architecture)
    if not isinstance(artifact, dict):
        raise ValueError(message)
    digest = artifact.get("sha256")
    expected_url = (
        f"https://github.com/coredns/coredns/releases/download/v{version}/"
        f"coredns_{version}_linux_{architecture}.tgz"
    )
    if (
        artifact.get("url") != expected_url
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise ValueError(message)
    return CoreDnsArtifact(version, expected_url, digest)


def selected_service(source: Path) -> ServicePin:
    """The committed holder lock selects the component, never a moving branch."""
    lock_bytes = (source / "key-holder/uv.lock").read_bytes()
    metadata = tomllib.loads((source / "key-holder/pyproject.toml").read_text())
    try:
        declared = metadata["tool"]["uv"]["sources"]["aweb-approval-service"]
        entries = tomllib.loads(lock_bytes.decode())["package"]
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict) for entry in entries
        ):
            raise ValueError(
                "Invalid holder lock packages; regenerate the committed lock."
            )
        packages = [
            package
            for package in entries
            if package.get("name") == "aweb-approval-service"
        ]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "Holder service pin is missing; regenerate the committed lock."
        ) from error
    if len(packages) != 1:
        raise ValueError(
            "Holder must lock one approval service; regenerate its committed lock."
        )
    locked_source = packages[0].get("source")
    if not isinstance(locked_source, dict) or not isinstance(
        locked_source.get("git"), str
    ):
        raise ValueError(
            "Holder service needs an immutable Git pin; regenerate the committed lock."
        )
    location = urlsplit(locked_source["git"])
    revision = location.fragment
    if (
        not re.fullmatch(r"[0-9a-f]{40}", revision)
        or location._replace(query="", fragment="").geturl() != REPOSITORY
        or parse_qs(location.query) != {"rev": [revision]}
        or declared != {"git": REPOSITORY, "rev": revision}
    ):
        raise ValueError(
            "Holder service metadata and lock disagree; regenerate the committed lock."
        )
    return ServicePin(revision, hashlib.sha256(lock_bytes).hexdigest())


def require_checkout(*, destination: Path, pin: ServicePin) -> None:
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=destination, text=True
    ).strip()
    changes = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=destination,
        text=True,
    ).strip()
    if revision != pin.revision or changes:
        raise ValueError(
            "Prepared service source changed; rebuild the isolated test image."
        )


def coredns_bytes(*, archive: bytes, expected_sha256: str) -> bytes:
    if hashlib.sha256(archive).hexdigest() != expected_sha256:
        raise ValueError(
            "CoreDNS archive hash differs from the service pin; check preparation inputs."
        )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        candidates = [
            member for member in bundle.getmembers() if member.name == "coredns"
        ]
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ValueError(
                "CoreDNS archive lacks one regular binary; check the pinned artifact."
            )
        stream = bundle.extractfile(candidates[0])
        if stream is None:
            raise ValueError(
                "CoreDNS binary could not be read; check the pinned artifact."
            )
        with stream:
            return stream.read()


def prepare(*, source: Path, destination: Path) -> None:
    pin = selected_service(source)
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    subprocess.run(
        ["git", "fetch", "--depth=1", REPOSITORY, pin.revision],
        cwd=destination,
        check=True,
    )
    subprocess.run(
        ["git", "checkout", "--detach", "FETCH_HEAD"], cwd=destination, check=True
    )
    require_checkout(destination=destination, pin=pin)
    subprocess.run(["uv", "sync", "--frozen"], cwd=destination, check=True)
    subprocess.run(["go", "mod", "download"], cwd=destination, check=True)
    declaration = json.loads(
        (destination / "integration/coredns-release.json").read_text()
    )
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or architecture is None:
        raise ValueError(
            "Service preparation needs Linux amd64/arm64; use the gate image build."
        )
    artifact = coredns_artifact(declaration=declaration, architecture=architecture)
    with urlopen(artifact.url, timeout=120) as response:
        binary = coredns_bytes(archive=response.read(), expected_sha256=artifact.sha256)
    executable = destination / ".gate-coredns"
    executable.write_bytes(binary)
    executable.chmod(0o755)
    version_output = subprocess.check_output([str(executable), "-version"], text=True)
    if not version_output.startswith(f"CoreDNS-{artifact.version}\n"):
        raise ValueError(
            "CoreDNS version differs from its declaration; correct the prepared binary."
        )
    require_checkout(destination=destination, pin=pin)
    (destination / ".gate-prepared.json").write_text(
        json.dumps(
            {
                "service_revision": pin.revision,
                "holder_lock_sha256": pin.lock_sha256,
                "coredns_sha256": hashlib.sha256(binary).hexdigest(),
            },
            sort_keys=True,
        )
        + "\n"
    )


def verify(*, source: Path, destination: Path) -> None:
    pin = selected_service(source)
    require_checkout(destination=destination, pin=pin)
    receipt = json.loads((destination / ".gate-prepared.json").read_text())
    expected = {
        "service_revision": pin.revision,
        "holder_lock_sha256": pin.lock_sha256,
        "coredns_sha256": hashlib.sha256(
            (destination / ".gate-coredns").read_bytes()
        ).hexdigest(),
    }
    if receipt != expected:
        raise ValueError(
            "Service preparation does not match this holder lock; rebuild the test image."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", type=Operation, choices=list(Operation))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.operation is Operation.PREPARE:
            prepare(source=args.source, destination=args.destination)
        else:
            verify(source=args.source, destination=args.destination)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(
            2,
            f"Service preparation failed: {error}. Check the locked inputs and rebuild the isolated image.\n",
        )


if __name__ == "__main__":
    main()
