"""Offline pinned OCI content, copied into private memory before unpacking.

Mutable tags never select authority. No registry access, extraction or credential
opening occurs here; the existing OCI unpacker consumes the verified snapshot.
"""

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import Refused
from .filesystem import FileGuard
from .oci_platform import require_memory_directory

_DIGEST = r"sha256:[0-9a-f]{64}"
_REFERENCE = rf"[A-Za-z0-9][A-Za-z0-9./:_-]*@({_DIGEST})"
_INDEX = "application/vnd.oci.image.index.v1+json"
_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIGS = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
_LAYERS = (
    {"application/vnd.oci.image.layer.v1.tar" + suffix for suffix in ("", "+gzip", "+zstd")}
    | {
        "application/vnd.oci.image.layer.nondistributable.v1.tar" + suffix
        for suffix in ("", "+gzip", "+zstd")
    }
    | {
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
    }
)
_METADATA_BOUND = 16 * 1024 * 1024


def _require(condition: Any) -> None:
    if not condition:
        raise Refused("oci_image_invalid")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("non-JSON constant")


def _json(raw: bytes) -> dict[str, Any]:
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    _require(isinstance(result, dict))
    return dict(result)


@dataclass(frozen=True)
class StagedImage:
    layout: Path
    source_digest: str
    manifest_digest: str


class ImageStore:
    """An operator-populated OCI layout; host architecture is never wire input."""

    def __init__(self, layout: Path):
        self._layout = layout

    def stage(self, reference: str, workspace: Path) -> StagedImage:
        root = require_memory_directory(workspace)
        name = "image-" + secrets.token_hex(16)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with ExitStack() as handles:
            try:
                parent_fd = os.open(root, flags)
            except OSError:
                raise Refused("oci_state_invalid") from None
            handles.callback(os.close, parent_fd)
            created = False
            try:
                match = re.fullmatch(_REFERENCE, reference)
                _require(match is not None)
                assert match is not None
                source_digest = match[1]
                source = FileGuard().directory(self._layout)
                with FileGuard().open_file(source / "oci-layout") as stream:
                    raw_version = stream.read(_METADATA_BOUND + 1)
                    _require(len(raw_version) <= _METADATA_BOUND)
                    version = _json(raw_version)
                _require(version.get("imageLayoutVersion") == "1.0.0")
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                created = True
                folder_fd = os.open(name, flags, dir_fd=parent_fd)
                handles.callback(os.close, folder_fd)
                os.mkdir("blobs", mode=0o700, dir_fd=folder_fd)
                blobs_fd = os.open("blobs", flags, dir_fd=folder_fd)
                handles.callback(os.close, blobs_fd)
                os.mkdir("sha256", mode=0o700, dir_fd=blobs_fd)
                algorithm_fd = os.open("sha256", flags, dir_fd=blobs_fd)
                handles.callback(os.close, algorithm_fd)
                copier = _Snapshot(source, algorithm_fd)
                manifests = copier.resolve(source_digest)
                selected = {item["digest"]: item for item in manifests}
                _require(len(selected) == 1)
                descriptor = next(iter(selected.values()))
                descriptor["annotations"] = {"org.opencontainers.image.ref.name": "verified"}
                for filename, document in (
                    ("oci-layout", {"imageLayoutVersion": "1.0.0"}),
                    ("index.json", {"schemaVersion": 2, "manifests": [descriptor]}),
                ):
                    fd = os.open(
                        filename,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=folder_fd,
                    )
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(json.dumps(document, separators=(",", ":")).encode())
                return StagedImage(root / name, source_digest, descriptor["digest"])
            except (OSError, Refused, ValueError, TypeError, KeyError, RecursionError):
                # No process or credential exists yet. Never leave a partial
                # verified-looking snapshot for a later attempt to consume.
                try:
                    if created:
                        shutil.rmtree(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    raise Refused("oci_image_cleanup_failed") from None
                raise Refused("oci_image_invalid") from None


class _Snapshot:
    def __init__(self, source: Path, destination_fd: int):
        self.source = source
        self.destination_fd = destination_fd
        self.copied: dict[str, tuple[int, bytes | None]] = {}
        machine = platform.machine().lower()
        architectures = {
            "x86_64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "arm",
            "ppc64le": "ppc64le",
            "s390x": "s390x",
            "riscv64": "riscv64",
        }
        self.architecture = architectures.get(machine, machine)
        self.variants = {""}
        if self.architecture == "arm64":
            self.variants.add("v8")
        elif machine == "armv7l":
            self.variants.add("v7")
        elif self.architecture == "amd64":
            self.variants.add("v1")
        _require(sys.platform == "linux")

    def blob(
        self, digest: Any, size: Any = None, *, metadata: bool = False
    ) -> tuple[int, bytes | None]:
        _require(isinstance(digest, str) and re.fullmatch(_DIGEST, digest))
        _require(size is None or type(size) is int and size >= 0)
        if digest not in self.copied:
            hasher = hashlib.sha256()
            count = 0
            raw = bytearray() if metadata else None
            with FileGuard().open_file(self.source / "blobs" / "sha256" / digest[7:]) as source:
                fd = os.open(
                    digest[7:],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self.destination_fd,
                )
                with os.fdopen(fd, "wb") as target:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        count += len(chunk)
                        _require(size is None or count <= size)
                        if metadata:
                            _require(count <= _METADATA_BOUND)
                            assert raw is not None
                            raw.extend(chunk)
                        hasher.update(chunk)
                        target.write(chunk)
            _require(hasher.hexdigest() == digest[7:])
            self.copied[digest] = (count, bytes(raw) if raw is not None else None)
        count, raw_bytes = self.copied[digest]
        _require(size is None or count == size)
        _require(not metadata or raw_bytes is not None)
        return count, raw_bytes

    def platform_matches(self, value: Any) -> bool:
        if value is None:
            return True
        _require(isinstance(value, dict))
        return (
            value.get("os") == "linux"
            and value.get("architecture") == self.architecture
            and value.get("variant", "") in self.variants
            and not value.get("os.features")
            and not value.get("os.version")
        )

    def resolve(self, digest: str, size: Any = None, depth: int = 0) -> list[dict[str, Any]]:
        _require(depth <= 8)
        count, raw = self.blob(digest, size, metadata=True)
        assert raw is not None
        document = _json(raw)
        _require(type(document.get("schemaVersion")) is int and document["schemaVersion"] == 2)
        media_type = document.get("mediaType")
        if "manifests" in document:
            _require(media_type in (None, _INDEX, _DOCKER_INDEX))
            _require(isinstance(document["manifests"], list) and len(document["manifests"]) <= 4096)
            for descriptor in document["manifests"]:
                _require(isinstance(descriptor, dict))
                if descriptor.get("mediaType") not in (
                    _INDEX,
                    _MANIFEST,
                    _DOCKER_INDEX,
                    _DOCKER_MANIFEST,
                ):
                    continue
                if self.platform_matches(descriptor.get("platform")):
                    _require(type(descriptor.get("size")) is int and descriptor["size"] >= 0)
                    result = self.resolve(descriptor["digest"], descriptor["size"], depth + 1)
                    if result:
                        # OCI's first matching entry is deterministic: this
                        # order is itself covered by the original pinned hash.
                        return result
            return []
        _require(media_type in (None, _MANIFEST, _DOCKER_MANIFEST))
        config = document["config"]
        _require(isinstance(config, dict) and config["mediaType"] in _CONFIGS)
        _require(type(config.get("size")) is int and config["size"] >= 0)
        _, config_raw = self.blob(config["digest"], config["size"], metadata=True)
        assert config_raw is not None
        configuration = _json(config_raw)
        if not self.platform_matches(configuration):
            return []
        layers = document["layers"]
        _require(isinstance(layers, list) and len(layers) <= 4096)
        for layer in layers:
            _require(isinstance(layer, dict) and layer["mediaType"] in _LAYERS)
            _require(type(layer.get("size")) is int and layer["size"] >= 0)
            self.blob(layer["digest"], layer["size"])
        return [{"mediaType": media_type or _MANIFEST, "digest": digest, "size": count}]
