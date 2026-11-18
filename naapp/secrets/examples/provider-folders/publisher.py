"""Publish one seat's exported report to its OneDrive app folder, at most once.

The outbox is untrusted: the manifest and report are bounded, read as leaf
names without following links, and verified; the upload sends exactly the
verified bytes held in memory, and no copy of a report is kept. The
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
from enum import StrEnum
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


class Outcome(StrEnum):
    PUBLISHED = "published"
    ALREADY_PUBLISHED = "already_published"
    REFUSED = "refused"
    UNCERTAIN = "uncertain"


class Reason(StrEnum):
    """Stable refusal codes."""

    JOB_ID_INVALID = "job_id_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_UNREADABLE = "manifest_unreadable"
    REPORT_UNREADABLE = "report_unreadable"
    TOO_LARGE = "too_large"
    SIZE_MISMATCH = "size_mismatch"
    SHA256_MISMATCH = "sha256_mismatch"
    JOB_CONFLICT = "job_conflict"
    DUPLICATE = "duplicate"
    TARGET_TAKEN = "target_taken"
    REMOTE_UNVERIFIED = "remote_unverified"
    PROVIDER_DENIED = "provider_denied"
    PROVIDER_REJECTED = "provider_rejected"
    LEDGER_UNREADABLE = "ledger_unreadable"
    DESTINATION_CHANGED = "destination_changed"


class Decision(StrEnum):
    DONE = "done"
    UPLOAD = "upload"
    REFUSE = "refuse"


class JobStatus(StrEnum):
    PENDING = "pending"
    UNCERTAIN = "uncertain"
    DONE = "done"


class Refused(Exception):
    """A refusal the caller must see; `reason` is a stable code."""

    def __init__(self, reason: Reason):
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
    outcome: Outcome
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


class LedgerUnreadable(Exception):
    pass


@dataclass
class LedgerEntry:
    seat: str
    sha256: str
    target: str
    status: JobStatus
    item_id: str | None = None

    @classmethod
    def parse(cls, body: object) -> "LedgerEntry":
        if not isinstance(body, dict) or set(body) != {
            "seat",
            "sha256",
            "target",
            "status",
            "item_id",
        }:
            raise LedgerUnreadable
        seat, sha256, target = body["seat"], body["sha256"], body["target"]
        status, item_id = body["status"], body["item_id"]
        if not (
            isinstance(seat, str)
            and isinstance(sha256, str)
            and isinstance(target, str)
            and status in set(JobStatus)
            and (item_id is None or isinstance(item_id, str))
        ):
            raise LedgerUnreadable
        return cls(seat, sha256, target, JobStatus(status), item_id)


class Ledger:
    """The publisher's cache of job bindings at one destination."""

    VERSION = 1

    def __init__(self, path: Path, destination: Destination, jobs: dict[str, LedgerEntry]):
        self.path = path
        self.destination = destination
        self.jobs = jobs

    @classmethod
    def load(cls, path: Path) -> "Ledger":
        """Read the ledger; FileNotFoundError when there is none, LedgerUnreadable when corrupt."""
        raw = path.read_bytes()
        try:
            body = json.loads(raw)
            if not isinstance(body, dict) or body.get("v") != cls.VERSION:
                raise LedgerUnreadable
            destination = body["destination"]
            if not isinstance(destination, dict) or set(destination) != {"drive_id", "folder_id"}:
                raise LedgerUnreadable
            if not all(isinstance(value, str) for value in destination.values()):
                raise LedgerUnreadable
            jobs = body["jobs"]
            if not isinstance(jobs, dict):
                raise LedgerUnreadable
            entries = {job_id: LedgerEntry.parse(entry) for job_id, entry in jobs.items()}
        except (ValueError, KeyError):
            raise LedgerUnreadable from None
        return cls(path, Destination(**destination), entries)

    def save(self) -> None:
        body = {
            "v": self.VERSION,
            "destination": asdict(self.destination),
            "jobs": {job_id: asdict(entry) for job_id, entry in self.jobs.items()},
        }
        _write_private(self.path, json.dumps(body, sort_keys=True, indent=1).encode())


@dataclass(frozen=True)
class RemoteState:
    """What the folder says about one job: done, free to upload, or refused."""

    decision: Decision
    item: RemoteItem | None = None
    reason: Reason | None = None


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
                receipts.append(Receipt(job_id, Outcome.UNCERTAIN, str(error)))
        return receipts

    def publish(self, job_id: str) -> Receipt:
        """Publish one job from verified in-memory bytes; no copy is kept."""
        if not JOB_ID.fullmatch(job_id):
            raise Refused(Reason.JOB_ID_INVALID)
        try:
            manifest = self._read_manifest(job_id)
            content = self._read_report(manifest)
        except Refused as refusal:
            return self._receipt(Receipt(job_id, Outcome.REFUSED, refusal.reason))
        try:
            return self._publish(manifest, content)
        except ProviderDenied:
            return self._refuse(manifest, Reason.PROVIDER_DENIED)
        except ProviderRejected:
            return self._refuse(manifest, Reason.PROVIDER_REJECTED)
        except ProviderUnavailable as error:
            raise PublishUncertain(str(error)) from error

    def _publish(self, manifest: Manifest, content: bytes) -> Receipt:
        ledger = self._ledger(self.folder.destination())
        entry = ledger.jobs.get(manifest.job_id)
        if entry is not None and (entry.seat, entry.sha256, entry.target) != (
            self.config.seat,
            manifest.sha256,
            manifest.target,
        ):
            return self._refuse(manifest, Reason.JOB_CONFLICT)
        if entry is None:
            entry = LedgerEntry(
                self.config.seat, manifest.sha256, manifest.target, JobStatus.PENDING
            )
            ledger.jobs[manifest.job_id] = entry
            ledger.save()

        content_hash = quick_xor_hash(content)
        state = self._decide(manifest, content_hash, self.folder.list_items())
        published = False
        if state.decision is Decision.UPLOAD:
            try:
                state, published = self._upload(manifest, content, content_hash)
            except ProviderUnavailable:
                entry.status = JobStatus.UNCERTAIN
                ledger.save()
                raise
        if state.decision is Decision.DONE:
            assert state.item is not None
            entry.status = JobStatus.DONE
            entry.item_id = state.item.id
            ledger.save()
            outcome = Outcome.PUBLISHED if published else Outcome.ALREADY_PUBLISHED
            return self._receipt(
                Receipt(manifest.job_id, outcome, None, state.item.id, manifest.sha256)
            )
        assert state.reason is not None
        if state.reason is Reason.REMOTE_UNVERIFIED:
            entry.status = JobStatus.UNCERTAIN
            ledger.save()
        return self._refuse(manifest, state.reason)

    def _upload(
        self, manifest: Manifest, content: bytes, content_hash: str
    ) -> tuple[RemoteState, bool]:
        """Create the item; when the name was taken first, classify the folder again.

        Returns the resulting state and whether this call created the item.
        """
        try:
            item = self.folder.upload_new(
                manifest.target,
                content,
                format_binding(self.config.seat, manifest.job_id, manifest.sha256),
            )
        except NameTaken:
            state = self._decide(manifest, content_hash, self.folder.list_items())
            if state.decision is Decision.UPLOAD:
                raise ProviderUnavailable("name_taken_then_free") from None
            return state, False
        if not self._is_this_job(item, manifest, content_hash):
            return RemoteState(Decision.REFUSE, None, Reason.REMOTE_UNVERIFIED), False
        return RemoteState(Decision.DONE, item), True

    def _decide(
        self, manifest: Manifest, content_hash: str, items: list[RemoteItem]
    ) -> RemoteState:
        """Classify the remote folder for this job."""
        bound = [item for item in items if self._bound_to_job(item, manifest.job_id)]
        if len(bound) > 1:
            return RemoteState(Decision.REFUSE, None, Reason.JOB_CONFLICT)
        if bound:
            item = bound[0]
            if not self._same_binding(item, manifest):
                return RemoteState(Decision.REFUSE, None, Reason.JOB_CONFLICT)
            if self._is_this_job(item, manifest, content_hash):
                return RemoteState(Decision.DONE, item)
            return RemoteState(Decision.REFUSE, None, Reason.REMOTE_UNVERIFIED)
        taken = [item for item in items if item.name.casefold() == manifest.target.casefold()]
        if not taken:
            return RemoteState(Decision.UPLOAD)
        binding = parse_binding(taken[0].description)
        if (
            binding is not None
            and binding[0] == self.config.seat
            and binding[2] == manifest.sha256
            and taken[0].quick_xor_hash == content_hash
        ):
            return RemoteState(Decision.REFUSE, None, Reason.DUPLICATE)
        return RemoteState(Decision.REFUSE, None, Reason.TARGET_TAKEN)

    def _bound_to_job(self, item: RemoteItem, job_id: str) -> bool:
        binding = parse_binding(item.description)
        return binding is not None and binding[:2] == (self.config.seat, job_id)

    def _same_binding(self, item: RemoteItem, manifest: Manifest) -> bool:
        """The item carries this job's binding and target, whatever its bytes."""
        return (
            item.description == format_binding(self.config.seat, manifest.job_id, manifest.sha256)
            and item.name.casefold() == manifest.target.casefold()
        )

    def _is_this_job(self, item: RemoteItem, manifest: Manifest, content_hash: str) -> bool:
        return (
            self._same_binding(item, manifest)
            and item.size == manifest.size
            and item.quick_xor_hash == content_hash
        )

    def _ledger(self, destination: Destination) -> Ledger:
        path = self.config.state_dir / "ledger.json"
        try:
            ledger = Ledger.load(path)
        except FileNotFoundError:
            return self._rebuild_ledger(path, destination)
        except LedgerUnreadable:
            raise Refused(Reason.LEDGER_UNREADABLE) from None
        if ledger.destination != destination:
            raise Refused(Reason.DESTINATION_CHANGED)
        return ledger

    def _rebuild_ledger(self, path: Path, destination: Destination) -> Ledger:
        """Take the remote folder as the truth for this seat's published jobs."""
        jobs: dict[str, LedgerEntry] = {}
        for item in self.folder.list_items():
            binding = parse_binding(item.description)
            if binding is None or binding[0] != self.config.seat or binding[1] in jobs:
                continue
            jobs[binding[1]] = LedgerEntry(
                binding[0], binding[2], item.name, JobStatus.DONE, item.id
            )
        ledger = Ledger(path, destination, jobs)
        ledger.save()
        return ledger

    def _read_manifest(self, job_id: str) -> Manifest:
        try:
            raw = self.outbox.read(f"{job_id}.json", MANIFEST_MAX_BYTES)
        except OutboxTooLarge:
            raise Refused(Reason.MANIFEST_INVALID) from None
        except OutboxUnreadable:
            raise Refused(Reason.MANIFEST_UNREADABLE) from None
        try:
            body = json.loads(raw)
        except ValueError:
            raise Refused(Reason.MANIFEST_INVALID) from None
        if not isinstance(body, dict) or set(body) != MANIFEST_FIELDS:
            raise Refused(Reason.MANIFEST_INVALID)
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
            raise Refused(Reason.MANIFEST_INVALID)
        if size > self.config.max_bytes:
            raise Refused(Reason.TOO_LARGE)
        return Manifest(job_id, file, size, sha256, target)

    def _read_report(self, manifest: Manifest) -> bytes:
        try:
            content = self.outbox.read(manifest.file, self.config.max_bytes)
        except OutboxTooLarge:
            raise Refused(Reason.TOO_LARGE) from None
        except OutboxUnreadable:
            raise Refused(Reason.REPORT_UNREADABLE) from None
        if len(content) != manifest.size:
            raise Refused(Reason.SIZE_MISMATCH)
        if hashlib.sha256(content).hexdigest() != manifest.sha256:
            raise Refused(Reason.SHA256_MISMATCH)
        return content

    def _refuse(self, manifest: Manifest, reason: Reason) -> Receipt:
        return self._receipt(
            Receipt(manifest.job_id, Outcome.REFUSED, reason, None, manifest.sha256)
        )

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
