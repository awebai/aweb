"""Publish one seat's exported report to its OneDrive app folder, at most once.

The outbox is untrusted: the manifest and report are bounded, read as leaf
names without following links, and verified before private staging. The
remote folder is the authority on what was published; the ledger in the
publisher's own state is a cache that is rebuilt from the folder when lost.
The retry identity is (seat, job_id, sha256, target) at one destination, and
it is written onto the uploaded item so it survives without the ledger.
"""

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from hashes import quick_xor_hash
from onedrive import (
    Destination,
    NameTaken,
    ProviderDenied,
    ProviderRejected,
    ProviderUnavailable,
    RemoteItem,
)

JOB_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SEAT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256 = re.compile(r"[0-9a-f]{64}")
LEAF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
BINDING = re.compile(
    r"aweb-publish/1 seat=(?P<seat>[a-z0-9-]+) job=(?P<job>[0-9a-f-]{36}) sha256=(?P<sha>[0-9a-f]{64})"
)
MANIFEST_FIELDS = frozenset({"job_id", "file", "size", "sha256", "target"})
MANIFEST_MAX_BYTES = 4096


class Refused(Exception):
    """A refusal the caller must see; `reason` is a stable code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class PublishUncertain(Exception):
    """Nothing is known to be published; reconcile and retry the same job later."""


@dataclass(frozen=True)
class PublishConfig:
    """Operator configuration; the manifest never chooses any of these."""

    seat: str
    state_dir: Path
    max_bytes: int
    extensions: frozenset[str]

    def __post_init__(self):
        if not SEAT.fullmatch(self.seat):
            raise ValueError("seat must be a lowercase slug")
        if self.max_bytes < 1:
            raise ValueError("max_bytes must be positive")


@dataclass(frozen=True)
class Manifest:
    job_id: str
    file: str
    size: int
    sha256: str
    target: str


@dataclass(frozen=True)
class Receipt:
    job_id: str
    outcome: str
    reason: str | None = None
    item_id: str | None = None
    sha256: str | None = None


class Outbox(Protocol):
    """One seat's export queue, read-only to the publisher."""

    def job_ids(self) -> list[str]: ...

    def read(self, name: str, limit: int) -> bytes: ...


class AppFolder(Protocol):
    def destination(self) -> Destination: ...

    def list_items(self) -> list[RemoteItem]: ...

    def upload_new(self, name: str, content: bytes, description: str) -> RemoteItem: ...

    def download(self, item_id: str) -> bytes: ...


class OutboxUnreadable(Exception):
    pass


class OutboxTooLarge(Exception):
    pass


class DirectoryOutbox:
    """An outbox directory read by leaf name, never following links."""

    def __init__(self, path: Path):
        self.path = path

    def job_ids(self) -> list[str]:
        return sorted(
            name.removesuffix(".json")
            for name in os.listdir(self.path)
            if name.endswith(".json") and JOB_ID.fullmatch(name.removesuffix(".json"))
        )

    def read(self, name: str, limit: int) -> bytes:
        if not LEAF_NAME.fullmatch(name):
            raise OutboxUnreadable(name)
        directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                handle = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
            except OSError as error:
                raise OutboxUnreadable(name) from error
        finally:
            os.close(directory)
        try:
            if not stat.S_ISREG(os.fstat(handle).st_mode):
                raise OutboxUnreadable(name)
            chunks = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(handle, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > limit:
                raise OutboxTooLarge(name)
            return content
        finally:
            os.close(handle)


def format_binding(seat: str, job_id: str, sha256: str) -> str:
    return f"aweb-publish/1 seat={seat} job={job_id} sha256={sha256}"


def parse_binding(description: str | None) -> tuple[str, str, str] | None:
    match = BINDING.fullmatch(description or "")
    if match is None:
        return None
    return match["seat"], match["job"], match["sha"]


class Ledger:
    """The publisher's cache of job bindings at one destination."""

    def __init__(self, path: Path, destination: Destination, jobs: dict[str, dict]):
        self.path = path
        self.destination = destination
        self.jobs = jobs

    def save(self) -> None:
        body = {"v": 1, "destination": asdict(self.destination), "jobs": self.jobs}
        _write_private(self.path, json.dumps(body, sort_keys=True, indent=1).encode())


class Publisher:
    def __init__(self, config: PublishConfig, outbox: Outbox, folder: AppFolder):
        self.config = config
        self.outbox = outbox
        self.folder = folder

    def replay(self) -> list[Receipt]:
        """Publish every queued job; already published jobs write nothing.

        An uncertain job is reported as such and left queued for the next
        replay, which reconciles it before any write.
        """
        receipts = []
        for job_id in self.outbox.job_ids():
            try:
                receipts.append(self.publish(job_id))
            except PublishUncertain as error:
                receipts.append(Receipt(job_id, "uncertain", str(error)))
        return receipts

    def publish(self, job_id: str) -> Receipt:
        if not JOB_ID.fullmatch(job_id):
            raise Refused("job_id_invalid")
        try:
            manifest = self._read_manifest(job_id)
            content = self._read_report(manifest)
        except Refused as refusal:
            return self._receipt(Receipt(job_id, "refused", refusal.reason))
        self._stage(manifest, content)
        try:
            return self._publish(manifest, content)
        except ProviderDenied:
            return self._receipt(Receipt(job_id, "refused", "provider_denied"))
        except ProviderRejected:
            return self._receipt(Receipt(job_id, "refused", "provider_rejected"))
        except ProviderUnavailable as error:
            raise PublishUncertain(str(error)) from error

    def _publish(self, manifest: Manifest, content: bytes) -> Receipt:
        ledger = self._ledger(self.folder.destination())
        entry = ledger.jobs.get(manifest.job_id)
        if entry is not None and (entry["seat"], entry["sha256"], entry["target"]) != (
            self.config.seat,
            manifest.sha256,
            manifest.target,
        ):
            return self._refuse(manifest, "job_conflict")
        if entry is None:
            entry = {
                "seat": self.config.seat,
                "sha256": manifest.sha256,
                "target": manifest.target,
                "status": "pending",
                "item_id": None,
            }
            ledger.jobs[manifest.job_id] = entry
            ledger.save()

        content_hash = quick_xor_hash(content)
        decision, item = self._decide(manifest, content_hash, self.folder.list_items())
        if decision == "upload":
            try:
                item = self.folder.upload_new(
                    manifest.target,
                    content,
                    format_binding(self.config.seat, manifest.job_id, manifest.sha256),
                )
            except NameTaken:
                decision, item = self._decide(manifest, content_hash, self.folder.list_items())
                if decision == "upload":
                    raise ProviderUnavailable("name_taken_then_free") from None
            except ProviderUnavailable:
                entry["status"] = "uncertain"
                ledger.save()
                raise
            else:
                if not self._is_this_job(item, manifest, content_hash):
                    entry["status"] = "uncertain"
                    ledger.save()
                    return self._refuse(manifest, "upload_unverified")
                decision = "published"
        if decision in ("published", "done"):
            assert item is not None
            entry["status"] = "done"
            entry["item_id"] = item.id
            ledger.save()
            outcome = "published" if decision == "published" else "already_published"
            return self._receipt(Receipt(manifest.job_id, outcome, None, item.id, manifest.sha256))
        return self._refuse(manifest, decision)

    def _decide(
        self, manifest: Manifest, content_hash: str, items: list[RemoteItem]
    ) -> tuple[str, RemoteItem | None]:
        """Classify the remote folder for this job: done, upload, or a refusal reason."""
        bound = [item for item in items if self._bound_to_job(item, manifest.job_id)]
        if len(bound) > 1:
            return "job_conflict", None
        if bound:
            item = bound[0]
            if self._is_this_job(item, manifest, content_hash):
                return "done", item
            return "job_conflict", None
        taken = [item for item in items if item.name.casefold() == manifest.target.casefold()]
        if not taken:
            return "upload", None
        binding = parse_binding(taken[0].description)
        if (
            binding is not None
            and binding[0] == self.config.seat
            and binding[2] == manifest.sha256
            and taken[0].quick_xor_hash == content_hash
        ):
            return "duplicate", None
        return "target_taken", None

    def _bound_to_job(self, item: RemoteItem, job_id: str) -> bool:
        binding = parse_binding(item.description)
        return binding is not None and binding[:2] == (self.config.seat, job_id)

    def _is_this_job(self, item: RemoteItem, manifest: Manifest, content_hash: str) -> bool:
        return (
            item.description == format_binding(self.config.seat, manifest.job_id, manifest.sha256)
            and item.name.casefold() == manifest.target.casefold()
            and item.size == manifest.size
            and item.quick_xor_hash == content_hash
        )

    def _ledger(self, destination: Destination) -> Ledger:
        path = self.config.state_dir / "ledger.json"
        try:
            body = json.loads(path.read_bytes())
        except FileNotFoundError:
            return self._rebuild_ledger(path, destination)
        recorded = Destination(**body["destination"])
        if recorded != destination:
            raise Refused("destination_changed")
        return Ledger(path, destination, body["jobs"])

    def _rebuild_ledger(self, path: Path, destination: Destination) -> Ledger:
        """Take the remote folder as the truth for this seat's published jobs."""
        jobs = {}
        for item in self.folder.list_items():
            binding = parse_binding(item.description)
            if binding is None or binding[0] != self.config.seat or binding[1] in jobs:
                continue
            jobs[binding[1]] = {
                "seat": binding[0],
                "sha256": binding[2],
                "target": item.name,
                "status": "done",
                "item_id": item.id,
            }
        ledger = Ledger(path, destination, jobs)
        ledger.save()
        return ledger

    def _read_manifest(self, job_id: str) -> Manifest:
        try:
            raw = self.outbox.read(f"{job_id}.json", MANIFEST_MAX_BYTES)
        except OutboxTooLarge:
            raise Refused("manifest_invalid") from None
        except OutboxUnreadable:
            raise Refused("manifest_unreadable") from None
        try:
            body = json.loads(raw)
        except ValueError:
            raise Refused("manifest_invalid") from None
        if not isinstance(body, dict) or set(body) != MANIFEST_FIELDS:
            raise Refused("manifest_invalid")
        file, target, size, sha256 = body["file"], body["target"], body["size"], body["sha256"]
        extension = _extension(file) if isinstance(file, str) else None
        valid = (
            body["job_id"] == job_id
            and extension in self.config.extensions
            and file == f"{job_id}.{extension}"
            and isinstance(target, str)
            and LEAF_NAME.fullmatch(target) is not None
            and _extension(target) == extension
            and type(size) is int
            and size >= 1
            and isinstance(sha256, str)
            and SHA256.fullmatch(sha256) is not None
        )
        if not valid:
            raise Refused("manifest_invalid")
        if size > self.config.max_bytes:
            raise Refused("too_large")
        return Manifest(job_id, file, size, sha256, target)

    def _read_report(self, manifest: Manifest) -> bytes:
        try:
            content = self.outbox.read(manifest.file, self.config.max_bytes)
        except OutboxTooLarge:
            raise Refused("too_large") from None
        except OutboxUnreadable:
            raise Refused("report_unreadable") from None
        if len(content) != manifest.size:
            raise Refused("size_mismatch")
        if hashlib.sha256(content).hexdigest() != manifest.sha256:
            raise Refused("sha256_mismatch")
        return content

    def _stage(self, manifest: Manifest, content: bytes) -> None:
        _write_private(self.config.state_dir / "staging" / manifest.file, content)

    def _refuse(self, manifest: Manifest, reason: str) -> Receipt:
        return self._receipt(Receipt(manifest.job_id, "refused", reason, None, manifest.sha256))

    def _receipt(self, receipt: Receipt) -> Receipt:
        path = self.config.state_dir / "receipts" / f"{receipt.job_id}.json"
        _write_private(path, json.dumps(asdict(receipt), sort_keys=True).encode())
        return receipt


def _extension(name: str) -> str | None:
    stem, dot, extension = name.rpartition(".")
    return extension if dot and stem else None


def _write_private(path: Path, content: bytes) -> None:
    """Write a file only the publisher identity can read, replacing it atomically."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(handle, 0o600)
        written = 0
        while written < len(content):
            written += os.write(handle, content[written:])
        os.fsync(handle)
    finally:
        os.close(handle)
    os.replace(temporary, path)
