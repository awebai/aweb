"""Durable archival of sealed release evidence beyond Actions retention.

The archive branch is a DURABLE BYTE STORE, never an authority: a mutable
git ref plus a manifest fetched from that same ref cannot authorize
itself. Trust comes from a canonical index entry recorded through a
separately reviewed authority (the main-branch index); this module emits
that entry and never pushes main.

Operator contract - the two-step authorization boundary:

  step 1 (this module, reviewed code): ``release-archive`` copies ONLY
  already-sealed exact bytes into the archive branch and PRINTS the
  canonical index entry. Recording that entry on main is a separately
  reviewed landing; the module has no main-push path.

  step 2 (restore): ``release-restore`` trusts only the reviewed index -
  production restore verifies the entry against an independent index
  authority (the operator supplies the index obtained from a reviewed
  main checkout), addresses the exact recorded archive commit plus
  digests, never consults the live archive head, and re-runs semantic
  validation after byte checks. Development/untrusted transport classes
  (local filesystem, unindexed copies) refuse production restore.

Every real archival or restore run against the production repository is
separately authorized; this module makes those runs execute
already-reviewed code only.

Archive-write invariants: the fetched archive head must equal or descend
from the previously recorded head (compare-and-swap, non-force);
logical-ID rebinding, conflicting manifests for an existing digest,
duplicate logical IDs, malformed or non-canonical manifests, and stray
tree content all refuse; archiving the identical logical-id/digest pair
again is idempotent and returns the original holding commit.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from release_driver import ReceiptError

INDEX_ENTRY_SCHEMA = "aweb.release-archive-index-entry.v1"
MANIFEST_SCHEMA = "aweb.release-archive-manifest.v1"
PRODUCTION_TRUST_CLASSES = ("durable-byte-store",)
MAX_IDENTITY_LENGTH = 200

_ENTRY_FIELDS = (
    "schema", "logical_id", "kind", "source", "source_digest",
    "body_sha256", "manifest_sha256", "archive_commit",
)
_MANIFEST_FIELDS = (
    "schema", "logical_id", "kind", "source", "source_digest",
    "body_sha256",
)
KIND_SOURCE_FIELDS = {
    "anchor-artifact": ("repo", "run_id", "artifact_id", "anchor"),
    "workflow-artifact": ("repo", "run_id", "artifact_id"),
}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_NUMERIC_ID = re.compile(r"[0-9]+")
_ANCHOR = re.compile(r"anchor--[0-9a-f]{64}--[0-9a-f]{64}")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,62}")
PRODUCTION_REMOTES = (
    "https://github.com/awebai/aweb.git",
    "git@github.com:awebai/aweb.git",
    # The transport this repository actually pushes with.
    "ssh://git@ssh.github.com:443/awebai/aweb.git",
)
PRODUCTION_BRANCH = "release-receipts"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def encode_index_entry(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _bounded_identity(value, label: str) -> str:
    if (
        not isinstance(value, str) or not value
        or len(value) > MAX_IDENTITY_LENGTH
    ):
        raise ReceiptError(
            f"{label} must be a nonempty string of at most "
            f"{MAX_IDENTITY_LENGTH} characters"
        )
    return value


def _validate_source(source, kind: str) -> dict:
    required = KIND_SOURCE_FIELDS.get(kind)
    if required is None:
        raise ReceiptError(
            f"unsupported archive kind {kind!r}; known kinds: "
            f"{sorted(KIND_SOURCE_FIELDS)}"
        )
    if not isinstance(source, dict) or set(source) != set(required):
        raise ReceiptError(
            f"archive source for kind {kind!r} must carry exactly the "
            f"fields {sorted(required)}"
        )
    grammar = {
        "repo": _REPO, "run_id": _NUMERIC_ID, "artifact_id": _NUMERIC_ID,
        "anchor": _ANCHOR,
    }
    for field in required:
        value = _bounded_identity(source[field], f"source {field}")
        pattern = grammar.get(field)
        if pattern is not None and not pattern.fullmatch(value):
            raise ReceiptError(
                f"source {field} {value!r} does not match its required "
                "format"
            )
    return dict(source)


def _fetch_ref_for_source(source: dict) -> str:
    """The artifact reference is DERIVED from the recorded source identity,
    never supplied independently, so the archive cannot fetch artifact A
    while recording artifact B."""
    return (
        f"gh-artifact:{source['repo']}:{source['run_id']}:"
        f"{source['artifact_id']}"
    )


def _validate_entry(entry) -> dict:
    if not isinstance(entry, dict) or set(entry) != set(_ENTRY_FIELDS):
        present = set(entry) if isinstance(entry, dict) else set()
        raise ReceiptError(
            "archive index entry is malformed; missing "
            f"{sorted(set(_ENTRY_FIELDS) - present)}, extra "
            f"{sorted(present - set(_ENTRY_FIELDS))}"
        )
    if entry["schema"] != INDEX_ENTRY_SCHEMA:
        raise ReceiptError("archive index entry has an unsupported schema")
    _bounded_identity(entry["logical_id"], "index entry logical_id")
    _validate_source(entry["source"], _bounded_identity(entry["kind"], "kind"))
    for field in ("source_digest", "body_sha256", "manifest_sha256"):
        if not isinstance(entry[field], str) or not _HEX64.fullmatch(entry[field]):
            raise ReceiptError(
                f"archive index entry {field} is not a 64-hex digest"
            )
    if (
        not isinstance(entry["archive_commit"], str)
        or not _GIT_SHA.fullmatch(entry["archive_commit"])
    ):
        raise ReceiptError(
            "archive index entry archive_commit is not an exact 40-hex "
            "commit identity"
        )
    return entry


def _parse_manifest(manifest_bytes: bytes, digest: str) -> dict:
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReceiptError(
            f"archive manifest for {digest} is not valid canonical JSON"
        ) from exc
    if not isinstance(manifest, dict) or set(manifest) != set(_MANIFEST_FIELDS):
        raise ReceiptError(
            f"archive manifest for {digest} does not carry exactly the "
            f"fields {sorted(_MANIFEST_FIELDS)}"
        )
    if manifest_bytes != _canonical(manifest):
        raise ReceiptError(
            f"archive manifest for {digest} is not canonical bytes"
        )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ReceiptError(
            f"archive manifest for {digest} has an unsupported schema"
        )
    _bounded_identity(manifest["logical_id"], "manifest logical_id")
    _validate_source(manifest["source"], _bounded_identity(
        manifest["kind"], "manifest kind"))
    if not isinstance(manifest["source_digest"], str) or not _HEX64.fullmatch(
        manifest["source_digest"]
    ):
        raise ReceiptError(
            f"archive manifest for {digest} has a malformed source_digest"
        )
    if not isinstance(manifest["body_sha256"], str) or not _HEX64.fullmatch(
        manifest["body_sha256"]
    ):
        raise ReceiptError(
            f"archive manifest for {digest} has a malformed body_sha256"
        )
    if manifest["body_sha256"] != digest:
        raise ReceiptError(
            f"archive manifest for {digest} conflicts with its own "
            "content address"
        )
    return manifest


def _existing_manifests(
    tree: dict[str, bytes], allowed_paths: tuple[str, ...] = (),
) -> dict[str, dict]:
    """Map body digest -> manifest for every archived pair; refuse strays."""
    manifests: dict[str, dict] = {}
    bodies: set[str] = set()
    for path in tree:
        if path in allowed_paths:
            continue
        parts = path.split("/")
        if (
            len(parts) != 3 or parts[0] != "receipts"
            or not _HEX64.fullmatch(parts[1])
            or parts[2] not in ("body.zip", "manifest.json")
        ):
            raise ReceiptError(f"archive holds an unexpected path: {path}")
        digest = parts[1]
        if parts[2] == "body.zip":
            bodies.add(digest)
        else:
            manifests[digest] = _parse_manifest(tree[path], digest)
    stray_bodies = bodies - set(manifests)
    stray_manifests = set(manifests) - bodies
    if stray_bodies or stray_manifests:
        raise ReceiptError(
            "archive holds unexpected unpaired content: stray bodies "
            f"{sorted(stray_bodies)}, stray manifests {sorted(stray_manifests)}"
        )
    for digest in bodies:
        body = tree[f"receipts/{digest}/body.zip"]
        if _sha256(body) != digest:
            raise ReceiptError(
                f"archived body under receipts/{digest} does not hash to its "
                "content-address directory"
            )
    by_logical: dict[str, str] = {}
    for digest, manifest in manifests.items():
        logical = manifest["logical_id"]
        if logical in by_logical:
            raise ReceiptError(
                f"archive holds duplicate logical id {logical!r} under "
                f"digests {by_logical[logical]} and {digest}"
            )
        by_logical[logical] = digest
    return manifests


def archive_sealed(
    *, logical_id: str, kind: str, source: dict,
    store, authority, transport, recorded_head: str | None,
    artifact_ref: str | None = None,
    allowed_paths: tuple[str, ...] = (),
) -> dict:
    _bounded_identity(logical_id, "logical id")
    source = _validate_source(source, _bounded_identity(kind, "kind"))
    derived_ref = _fetch_ref_for_source(source)
    if artifact_ref is not None and artifact_ref != derived_ref:
        raise ReceiptError(
            f"artifact_ref {artifact_ref!r} does not equal the reference "
            f"derived from the recorded source identity {derived_ref!r}; the "
            "archive may not fetch one artifact while recording another"
        )
    artifact_ref = derived_ref
    expected = authority.expected_digest(artifact_ref)
    body = store.get(artifact_ref)
    body_sha = _sha256(body)
    if body_sha != expected:
        raise ReceiptError(
            f"source bytes hash {body_sha} does not equal the authority "
            f"digest {expected}; only sealed exact bytes are archived"
        )

    head = transport.fetch_head()
    if recorded_head is None:
        if head is not None:
            raise ReceiptError(
                "archive already has history but no recorded head was "
                "supplied; prior content is not recorded through the "
                "reviewed index"
            )
    else:
        if head is None:
            raise ReceiptError(
                "archive head is absent but a recorded head exists; the "
                "archive ref does not descend from recorded history"
            )
        if head != recorded_head and not transport.is_ancestor(recorded_head, head):
            raise ReceiptError(
                "archive head does not descend from the recorded head; "
                "refusing non-fast-forward history"
            )

    tree = transport.read_tree(head) if head is not None else {}
    manifests = _existing_manifests(tree, allowed_paths)
    for digest, manifest in manifests.items():
        if manifest["logical_id"] == logical_id and digest != body_sha:
            raise ReceiptError(
                f"logical id {logical_id!r} is already archived with digest "
                f"{digest}; refusing rebinding to {body_sha}"
            )
    manifest_doc = {
        "schema": MANIFEST_SCHEMA,
        "logical_id": logical_id,
        "kind": kind,
        "source": source,
        "source_digest": expected,
        "body_sha256": body_sha,
    }
    existing = manifests.get(body_sha)
    if existing is not None:
        if existing != manifest_doc:
            raise ReceiptError(
                f"digest {body_sha} is already archived under a conflicting "
                "manifest; refusing ambiguity"
            )
        archive_commit = _commit_holding(transport, head, body_sha)
    else:
        manifest_bytes = _canonical(manifest_doc)
        files = {
            f"receipts/{body_sha}/body.zip": body,
            f"receipts/{body_sha}/manifest.json": manifest_bytes,
        }
        archive_commit = transport.append(
            head, files, f"archive {logical_id} {body_sha}"
        )
    return _validate_entry({
        "schema": INDEX_ENTRY_SCHEMA,
        "logical_id": logical_id,
        "kind": kind,
        "source": source,
        "source_digest": expected,
        "body_sha256": body_sha,
        "manifest_sha256": _sha256(_canonical(manifest_doc)),
        "archive_commit": archive_commit,
    })


def _commit_holding(transport, head: str, body_sha: str) -> str:
    """The earliest commit whose tree already holds the archived pair,
    found through the transport's required parent/history API."""
    path = f"receipts/{body_sha}/body.zip"
    cursor: str | None = head
    holder = head
    while cursor is not None:
        tree = transport.read_tree(cursor)
        if path not in tree:
            break
        holder = cursor
        cursor = transport.parent_of(cursor)
    return holder


def restore_archived(
    *, entry: dict | None, transport, production: bool, validate,
    index_authority=None, logical_id: str | None = None,
) -> bytes:
    if production:
        if transport.trust_class not in PRODUCTION_TRUST_CLASSES:
            raise ReceiptError(
                f"transport class {transport.trust_class!r} is a development/"
                "untrusted byte source; production restore refuses it"
            )
        if validate is None:
            raise ReceiptError(
                "production restore requires the semantic validator; byte "
                "digests alone do not prove receipt semantics"
            )
        if index_authority is None:
            raise ReceiptError(
                "production restore requires the reviewed index authority; "
                "a caller-supplied entry alone does not prove it was "
                "recorded on main"
            )
        wanted = logical_id if logical_id is not None else (
            entry.get("logical_id") if isinstance(entry, dict) else None
        )
        if not isinstance(wanted, str) or not wanted:
            raise ReceiptError(
                "production restore requires the logical id to look up in "
                "the reviewed index"
            )
        try:
            recorded = index_authority.lookup(wanted)
        except ReceiptError:
            raise
        except Exception as exc:
            raise ReceiptError(
                f"reviewed index authority is unavailable: {exc}"
            ) from exc
        if recorded is None:
            raise ReceiptError(
                f"logical id {wanted!r} is not recorded in the reviewed "
                "index; the archive copy is untrusted"
            )
        recorded = _validate_entry(recorded)
        if entry is not None and entry != recorded:
            raise ReceiptError(
                "caller-supplied entry does not equal the reviewed index "
                "record; refusing mismatch"
            )
        entry = recorded
    entry = _validate_entry(entry)
    tree = transport.read_tree(entry["archive_commit"])
    body_path = f"receipts/{entry['body_sha256']}/body.zip"
    manifest_path = f"receipts/{entry['body_sha256']}/manifest.json"
    body = tree.get(body_path)
    manifest_bytes = tree.get(manifest_path)
    if body is None or manifest_bytes is None:
        raise ReceiptError(
            f"archive commit {entry['archive_commit']} does not exist or "
            "does not hold the recorded body/manifest pair"
        )
    if _sha256(body) != entry["body_sha256"]:
        raise ReceiptError(
            "archived body digest does not equal the recorded index entry "
            "digest"
        )
    if _sha256(manifest_bytes) != entry["manifest_sha256"]:
        raise ReceiptError(
            "archived manifest digest does not equal the recorded index "
            "entry digest"
        )
    manifest = _parse_manifest(manifest_bytes, entry["body_sha256"])
    for field in ("logical_id", "kind", "source", "source_digest",
                  "body_sha256"):
        if manifest[field] != entry[field]:
            raise ReceiptError(
                f"archived manifest {field} does not equal the recorded "
                "index entry"
            )
    if validate is not None:
        validate(body, manifest)
    return body


class IndexFileAuthority:
    """Reviewed-index authority backed by a file from a reviewed main
    checkout. The operator supplies the path; this class never reads the
    archive branch."""

    def __init__(self, path: Path):
        self._path = Path(path)

    def lookup(self, logical_id: str) -> dict | None:
        if not self._path.exists():
            raise ReceiptError(
                f"reviewed index file {self._path} does not exist"
            )
        try:
            document = json.loads(self._path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReceiptError(
                f"reviewed index file {self._path} is malformed"
            ) from exc
        entries = document.get("entries") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ReceiptError(
                f"reviewed index file {self._path} has no entries list"
            )
        matches = [
            e for e in entries
            if isinstance(e, dict) and e.get("logical_id") == logical_id
        ]
        if len(matches) > 1:
            raise ReceiptError(
                f"reviewed index records logical id {logical_id!r} more "
                "than once; refusing ambiguity"
            )
        return matches[0] if matches else None


class ReviewedMainIndexAuthority:
    """The production reviewed-index authority.

    Trust does not come from a caller-supplied file: it comes from the index
    at an EXACT reviewed commit that is proven to belong to the canonical
    remote main ancestry. The authority fetches the canonical main tip from
    the exact production remote, refuses a reviewed commit that main does not
    contain, reads the committed index blob at that commit, and enforces the
    index's own schema and canonical bytes before returning a record."""

    INDEX_PATH = "release/receipt-index.json"
    INDEX_SCHEMA = "aweb.release-archive-index.v1"

    def __init__(self, *, remote: str, reviewed_commit: str,
                 main_ref: str = "refs/heads/main", git=None):
        if remote not in PRODUCTION_REMOTES:
            raise ReceiptError(
                f"reviewed-index remote {remote!r} is not the canonical "
                "production remote"
            )
        if not _GIT_SHA.fullmatch(reviewed_commit or ""):
            raise ReceiptError(
                "reviewed-index commit must be an exact 40-hex id"
            )
        self._remote = remote
        self._reviewed_commit = reviewed_commit
        self._main_ref = main_ref
        self._git = git or _GitReader(remote)

    def _entries(self) -> list[dict]:
        main_tip = self._git.ls_remote(self._main_ref)
        if main_tip is None:
            raise ReceiptError(
                f"canonical main ref {self._main_ref} is absent on the "
                "production remote"
            )
        if not self._git.is_ancestor(self._reviewed_commit, main_tip):
            raise ReceiptError(
                f"reviewed index commit {self._reviewed_commit} is not an "
                "ancestor of canonical remote main; it is not reviewed-and-"
                "landed history"
            )
        blob = self._git.file_at(self._reviewed_commit, self.INDEX_PATH)
        if blob is None:
            raise ReceiptError(
                f"reviewed commit {self._reviewed_commit} carries no "
                f"{self.INDEX_PATH}"
            )
        try:
            document = json.loads(blob.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReceiptError("reviewed index blob is malformed") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "entries"}
            or document.get("schema") != self.INDEX_SCHEMA
            or not isinstance(document.get("entries"), list)
        ):
            raise ReceiptError(
                "reviewed index has the wrong top-level schema or keys"
            )
        if blob != _canonical(document):
            raise ReceiptError("reviewed index blob is not canonical bytes")
        entries = [_validate_entry(entry) for entry in document["entries"]]
        seen: set[str] = set()
        for entry in entries:
            logical = entry["logical_id"]
            if logical in seen:
                raise ReceiptError(
                    f"reviewed index records logical id {logical!r} more than "
                    "once; refusing ambiguity"
                )
            seen.add(logical)
        return entries

    def lookup(self, logical_id: str) -> dict | None:
        matches = [
            e for e in self._entries()
            if isinstance(e, dict) and e.get("logical_id") == logical_id
        ]
        if len(matches) > 1:
            raise ReceiptError(
                f"reviewed index records logical id {logical_id!r} more than "
                "once; refusing ambiguity"
            )
        return matches[0] if matches else None


class _GitReader:
    """Minimal read-only git accessor for the reviewed-index authority,
    isolated in a temporary bare clone with the sanitized environment. It
    only fetches from and reads the exact production remote."""

    def __init__(self, remote: str):
        self._remote = remote
        self._root = Path(tempfile.mkdtemp(prefix="aweb-receipt-index-"))
        self._local = self._root / "reader.git"
        self._run("init", "--bare", str(self._local), cwd=self._root,
                  check=True)

    def _run(self, *args, cwd=None, check=False):
        result = subprocess.run(
            ["git", *args], cwd=str(cwd or self._local),
            capture_output=True, env=GitBranchArchive._sanitized_env())
        if check and result.returncode != 0:
            raise ReceiptError(
                f"reviewed-index git {' '.join(map(str, args[:2]))} failed: "
                + result.stderr.decode(errors="replace")[-500:])
        return result

    def ls_remote(self, ref: str) -> str | None:
        out = self._run("ls-remote", self._remote, ref, check=True).stdout.decode()
        return out.split()[0] if out.strip() else None

    def _fetch(self, sha: str) -> None:
        if not _GIT_SHA.fullmatch(sha):
            raise ReceiptError(f"reviewed-index sha {sha!r} is not 40-hex")
        if self._run("cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
            self._run("fetch", self._remote, sha, check=True)

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        self._fetch(ancestor)
        self._fetch(descendant)
        return self._run(
            "merge-base", "--is-ancestor", ancestor, descendant
        ).returncode == 0

    def file_at(self, commit: str, path: str) -> bytes | None:
        self._fetch(commit)
        result = self._run("cat-file", "blob", f"{commit}:{path}")
        return result.stdout if result.returncode == 0 else None

    def close(self) -> None:
        shutil.rmtree(self._root, ignore_errors=True)
        if self._root.exists():
            raise ReceiptError(
                f"reviewed-index temporary root remains: {self._root}"
            )


class GitBranchArchive:
    """Append-only durable byte store on a dedicated git branch.

    All operations run inside an isolated temporary clone; the ambient
    repository and worktree are never touched. Ref updates are strict
    compare-and-swap (force-with-lease against the exact expected parent,
    never force), so a concurrent or force-moved remote refuses.

    trust_class is durable-byte-store ONLY for the exact production
    awebai/aweb + release-receipts configuration; every other remote/branch
    (a local bare repo, a fork, a different branch) is development, so
    production restore refuses it regardless of caller assertion."""

    @property
    def trust_class(self) -> str:
        if (
            self._remote in PRODUCTION_REMOTES
            and self._branch == PRODUCTION_BRANCH
        ):
            return "durable-byte-store"
        return "local-development"

    _ENV = {
        "GIT_AUTHOR_NAME": "aweb-release-archive",
        "GIT_AUTHOR_EMAIL": "release-archive@aweb.invalid",
        "GIT_COMMITTER_NAME": "aweb-release-archive",
        "GIT_COMMITTER_EMAIL": "release-archive@aweb.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }

    def __init__(self, *, remote: str, branch: str):
        self._remote = _bounded_identity(remote, "archive remote")
        self._branch = _bounded_identity(branch, "archive branch")
        if not _BRANCH.fullmatch(self._branch):
            raise ReceiptError(
                f"archive branch {self._branch!r} is not a strict ref name"
            )
        # A leading "-" would be read as an option by every git subcommand.
        if self._remote.startswith("-"):
            raise ReceiptError("archive remote may not begin with '-'")
        self._root = Path(tempfile.mkdtemp(prefix="aweb-receipt-archive-"))
        self._local = self._root / "local.git"
        self._git("init", "--bare", str(self._local), cwd=self._root)

    @classmethod
    def _sanitized_env(cls):
        import os

        return {**os.environ, **cls._ENV}

    def _git_raw(self, *args, cwd=None, input_bytes=None):
        return subprocess.run(
            ["git", *args], cwd=str(cwd or self._local),
            input=input_bytes, capture_output=True,
            env=self._sanitized_env(),
        )

    def _git(self, *args, cwd=None, input_bytes=None) -> bytes:
        result = self._git_raw(*args, cwd=cwd, input_bytes=input_bytes)
        if result.returncode != 0:
            raise ReceiptError(
                f"archive git {' '.join(map(str, args[:3]))} failed: "
                + result.stderr.decode(errors="replace")[-1000:]
            )
        return result.stdout

    def fetch_head(self) -> str | None:
        out = self._git(
            "ls-remote", self._remote, f"refs/heads/{self._branch}"
        ).decode()
        if not out.strip():
            return None
        sha = out.split()[0]
        self._git("fetch", self._remote,
                  f"+refs/heads/{self._branch}:refs/archive/head")
        return sha

    def _ensure_object(self, sha: str) -> None:
        if not _GIT_SHA.fullmatch(sha):
            raise ReceiptError(f"archive commit {sha!r} is not a 40-hex id")
        if self._git_raw("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0:
            return
        fetch = self._git_raw(
            "fetch", self._remote,
            f"+refs/heads/{self._branch}:refs/archive/head")
        probe = self._git_raw("cat-file", "-e", f"{sha}^{{commit}}")
        if probe.returncode != 0:
            detail = fetch.stderr.decode(errors="replace")[-300:]
            raise ReceiptError(
                f"archive commit {sha} does not exist in the archive "
                f"remote{': ' + detail if detail else ''}"
            )

    def read_tree(self, sha: str) -> dict[str, bytes]:
        self._ensure_object(sha)
        listing = self._git("ls-tree", "-r", "-z", sha)
        tree: dict[str, bytes] = {}
        for record in listing.split(b"\x00"):
            if not record:
                continue
            meta, _, path = record.partition(b"\t")
            mode, obj_type, blob = meta.split()[:3]
            if mode != b"100644" and mode != b"100755":
                raise ReceiptError(
                    f"archive tree entry {path!r} is not a regular file "
                    f"(mode {mode.decode()}); refusing symlink/submodule"
                )
            if obj_type != b"blob":
                raise ReceiptError(
                    f"archive tree entry {path!r} is not a blob"
                )
            tree[path.decode("utf-8", "surrogateescape")] = self._git(
                "cat-file", "blob", blob.decode())
        return tree

    def parent_of(self, sha: str) -> str | None:
        self._ensure_object(sha)
        tokens = self._git("rev-list", "--parents", "-n", "1", sha).split()
        return tokens[1].decode() if len(tokens) > 1 else None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        if not _GIT_SHA.fullmatch(ancestor):
            raise ReceiptError(f"ancestor {ancestor!r} is not a 40-hex id")
        self._ensure_object(descendant)
        self._ensure_object(ancestor)
        return self._git_raw(
            "merge-base", "--is-ancestor", ancestor, descendant
        ).returncode == 0

    def append(self, parent: str | None, files: dict[str, bytes],
               subject: str) -> str:
        work = self._root / "work"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir()
        self._git("init", "--initial-branch", self._branch, str(work),
                  cwd=self._root)
        if parent is not None:
            self._ensure_object(parent)
            self._git("fetch", str(self._local), parent, cwd=work)
            self._git("reset", "--hard", parent, cwd=work)
        for path, data in files.items():
            target = work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self._git("add", "-A", cwd=work)
        self._git("commit", "-m", subject, cwd=work)
        new_sha = self._git("rev-parse", "HEAD", cwd=work).decode().strip()
        lease = f"refs/heads/{self._branch}:{parent or ''}"
        push = self._git_raw(
            "push", "--force-with-lease=" + lease, self._remote,
            f"HEAD:refs/heads/{self._branch}", cwd=work)
        if push.returncode != 0:
            raise ReceiptError(
                "archive append is not fast-forward from the fetched head: "
                + push.stderr.decode(errors="replace")[-500:]
            )
        self._git("fetch", str(work),
                  f"+refs/heads/{self._branch}:refs/archive/head")
        return new_sha

    def close(self) -> None:
        shutil.rmtree(self._root, ignore_errors=True)
        if self._root.exists():
            raise ReceiptError(
                f"archive temporary root remains: {self._root}"
            )


ANCHOR_LOGICAL_CLASSES = ("plan", "staged-manifest", "transition", "receipt")


def semantic_validator(providers=None):
    """Production semantic validator over the REAL sealed formats.

    There is no archive-specific bundle format: ``archive_sealed`` copies
    already-sealed bytes verbatim, so the only things it can validate are the
    formats the release path actually produces.

    An anchor artifact is the release-anchor ZIP {record.json, body}. The
    logical id in record.json names the document class AND carries its
    cross-document bindings, so the inner body is dispatched by that class and
    every binding the id asserts is checked against the document itself:

      plan:<source_sha>:<frozen_id>                     -> load_frozen_plan
      staged-manifest:<frozen_plan_id>:<digest>         -> load_staged_manifest
      transition:<frozen_plan_id>:<seq>:<kind>:<comp>:<digest>
      receipt:<frozen_plan_id>:<digest>                 -> load_sealed_receipt

    A workflow artifact is a lane staging ZIP; its own manifest names the
    package, and the exact reviewed lane validator for that package runs.
    """
    import io
    import zipfile

    import release_driver as rd

    def _members(body: bytes, label: str) -> dict[str, bytes]:
        try:
            with zipfile.ZipFile(io.BytesIO(body)) as archive_zip:
                names = archive_zip.namelist()
                if len(names) != len(set(names)):
                    raise ReceiptError(f"{label} contains duplicate ZIP names")
                return {name: archive_zip.read(name) for name in names}
        except zipfile.BadZipFile as exc:
            raise ReceiptError(f"{label} is not a valid ZIP") from exc

    def _inner_semantics(logical_id: str, inner: bytes, digest: str) -> None:
        klass = logical_id.split(":", 1)[0]
        if klass not in ANCHOR_LOGICAL_CLASSES:
            raise ReceiptError(
                f"archived anchor logical id class {klass!r} is not one of "
                f"{list(ANCHOR_LOGICAL_CLASSES)}"
            )
        if klass == "plan":
            parts = logical_id.split(":")
            if len(parts) != 3:
                raise ReceiptError("plan logical id is malformed")
            frozen_id = parts[2]
            if frozen_id != digest:
                raise ReceiptError(
                    "plan logical id frozen identity does not equal the "
                    "recorded body digest"
                )
            rd.load_frozen_plan(inner, expected_id=frozen_id)
        elif klass == "staged-manifest":
            parts = logical_id.split(":")
            if len(parts) != 3:
                raise ReceiptError("staged-manifest logical id is malformed")
            frozen_plan_id, manifest_digest = parts[1], parts[2]
            if manifest_digest != digest:
                raise ReceiptError(
                    "staged-manifest logical id digest does not equal the "
                    "recorded body digest"
                )
            document = rd.load_staged_manifest(inner, expected_digest=digest)
            if document.get("frozen_plan_id") != frozen_plan_id:
                raise ReceiptError(
                    "archived staged manifest binds frozen plan "
                    f"{document.get('frozen_plan_id')!r}, not the "
                    f"{frozen_plan_id!r} its logical id asserts"
                )
            rd.validate_staged_manifest(document)
        elif klass == "transition":
            parts = logical_id.split(":")
            if len(parts) != 6:
                raise ReceiptError("transition logical id is malformed")
            _, frozen_plan_id, sequence, kind, component, body_digest = parts
            if body_digest != digest:
                raise ReceiptError(
                    "transition logical id digest does not equal the recorded "
                    "body digest"
                )
            try:
                document = json.loads(inner)
            except json.JSONDecodeError as exc:
                raise ReceiptError(
                    "archived transition body is not valid JSON"
                ) from exc
            rd.validate_transition_document(document)
            mismatches = [
                name for name, expected, actual in (
                    ("frozen_plan_id", frozen_plan_id,
                     document["frozen_plan_id"]),
                    ("sequence", sequence, f"{document['sequence']:03d}"),
                    ("kind", kind, document["kind"]),
                    ("component", component, document["component"]),
                ) if expected != actual
            ]
            if mismatches:
                raise ReceiptError(
                    "archived transition document disagrees with the bindings "
                    f"its logical id asserts: {mismatches}"
                )
        else:
            parts = logical_id.split(":")
            if len(parts) != 3:
                raise ReceiptError("receipt logical id is malformed")
            frozen_plan_id, receipt_digest = parts[1], parts[2]
            if receipt_digest != digest:
                raise ReceiptError(
                    "receipt logical id digest does not equal the recorded "
                    "body digest"
                )
            receipt = rd.load_sealed_receipt(inner, expected_digest=digest)
            if getattr(receipt, "frozen_plan_id", None) != frozen_plan_id:
                raise ReceiptError(
                    "archived receipt binds frozen plan "
                    f"{getattr(receipt, 'frozen_plan_id', None)!r}, not the "
                    f"{frozen_plan_id!r} its logical id asserts"
                )

    def _anchor(body: bytes, manifest: dict) -> None:
        members = _members(body, "archived anchor body")
        missing = {"record.json", "body"} - set(members)
        extra = set(members) - {"record.json", "body"}
        if missing or extra:
            raise ReceiptError(
                f"archived anchor bundle members are wrong: missing "
                f"{sorted(missing)}, unexpected {sorted(extra)}"
            )
        try:
            record = json.loads(members["record.json"])
        except json.JSONDecodeError as exc:
            raise ReceiptError("archived anchor record.json is malformed") from exc
        if set(record) != {"logical_id", "digest"}:
            raise ReceiptError(
                "archived anchor record.json does not carry exactly "
                "logical_id and digest"
            )
        inner_digest = _sha256(members["body"])
        if inner_digest != record["digest"]:
            raise ReceiptError(
                f"archived anchor inner body hashes {inner_digest}, not the "
                f"recorded {record['digest']}"
            )
        if record["logical_id"] != manifest["logical_id"]:
            raise ReceiptError(
                "archived anchor record logical id does not equal the "
                "manifest logical id"
            )
        expected_name = rd._anchor_name(record["logical_id"], record["digest"])
        if manifest["source"].get("anchor") != expected_name:
            raise ReceiptError(
                "archived anchor name is not derived from the exact logical "
                f"id and inner digest (expected {expected_name})"
            )
        _inner_semantics(record["logical_id"], members["body"], record["digest"])

    def _workflow(body: bytes, manifest: dict) -> None:
        members = _members(body, "archived workflow-artifact body")
        raw = members.get("manifest.json")
        if raw is None:
            raise ReceiptError(
                "archived workflow artifact carries no lane manifest.json"
            )
        try:
            lane_manifest = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReceiptError("archived lane manifest.json is malformed") from exc
        package = lane_manifest.get("package")
        source_sha = lane_manifest.get("source_sha")
        version = lane_manifest.get("candidate_version")
        if package in ("channel", "pi", "skills"):
            rd.validate_npm_lane_artifact(
                body, expected_source_sha=source_sha,
                expected_version=version, package=package, profile=package,
            )
        elif package in ("server", "awid-pypi"):
            rd.validate_pypi_lane_artifact(
                body, expected_source_sha=source_sha,
                expected_version=version, package=package,
                pypi_name="aweb" if package == "server" else "awid-service",
            )
        elif package == "awid-image":
            rd.validate_image_lane_artifact(
                body, expected_source_sha=source_sha,
                expected_version=version,
            )
        elif package is None:
            rd.validate_lane_staged_artifact(
                body, expected_source_sha=source_sha,
                expected_version=version,
            )
        else:
            raise ReceiptError(
                f"archived lane artifact names unknown package {package!r}"
            )

    def validate(body: bytes, manifest: dict) -> None:
        kind = manifest.get("kind")
        if kind == "anchor-artifact":
            _anchor(body, manifest)
        elif kind == "workflow-artifact":
            _workflow(body, manifest)
        else:
            raise ReceiptError(
                f"no semantic validator is defined for archive kind {kind!r}"
            )

    return validate


def validate_transition_set(documents: list) -> None:
    """An archived transition SET must be the complete ordered sequence for one
    frozen plan: sequences strictly increasing from 1 with no gaps, no repeats,
    and one frozen plan throughout."""
    import release_driver as rd

    if not documents:
        raise ReceiptError("transition set is empty")
    plans = {d.get("frozen_plan_id") for d in documents}
    if len(plans) != 1:
        raise ReceiptError(
            f"transition set spans multiple frozen plans: {sorted(plans)}"
        )
    for document in documents:
        rd.validate_transition_document(document)
    sequences = [d["sequence"] for d in documents]
    if sorted(sequences) != list(range(1, len(sequences) + 1)):
        raise ReceiptError(
            f"transition sequences are not the complete ordered set 1..n: "
            f"{sequences}"
        )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Exclusive create of both the temporary and final paths: a pre-existing
    output OR a squatted .part path (possibly a symlink pointing elsewhere)
    refuses instead of being followed."""
    if path.exists() or path.is_symlink():
        raise ReceiptError(f"refusing to overwrite existing output {path}")
    tmp = path.with_suffix(path.suffix + ".part")
    if tmp.exists() or tmp.is_symlink():
        raise ReceiptError(
            f"refusing to write through pre-existing temporary path {tmp}"
        )
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except BaseException:
        os.unlink(tmp)
        raise
    os.replace(tmp, path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)

    arch = sub.add_parser("release-archive")
    arch.add_argument("--remote", required=True)
    arch.add_argument("--branch", required=True)
    arch.add_argument("--logical-id", required=True)
    arch.add_argument("--kind", required=True)
    arch.add_argument("--artifact-ref", required=True)
    arch.add_argument("--source-repo", required=True)
    arch.add_argument("--run-id", required=True)
    arch.add_argument("--artifact-id", required=True)
    arch.add_argument("--anchor")
    arch.add_argument("--workflow-path", required=True)
    arch.add_argument("--recorded-head")
    arch.add_argument("--entry-out", required=True, type=Path)

    rest = sub.add_parser("release-restore")
    rest.add_argument("--remote", required=True)
    rest.add_argument("--branch", required=True)
    rest.add_argument("--logical-id", required=True)
    rest.add_argument("--reviewed-commit", required=True,
                      help="exact reviewed main commit carrying the index")
    rest.add_argument("--out", required=True, type=Path)

    args = parser.parse_args(argv)
    import release_driver as rd

    transport = GitBranchArchive(remote=args.remote, branch=args.branch)
    reader = None
    try:
        if args.verb == "release-archive":
            source = {"repo": args.source_repo, "run_id": args.run_id,
                      "artifact_id": args.artifact_id}
            if args.anchor is not None:
                source["anchor"] = args.anchor
            entry = archive_sealed(
                logical_id=args.logical_id, kind=args.kind, source=source,
                store=rd.GithubArtifactStore(
                    repo=args.source_repo, workflow_path=args.workflow_path,
                ),
                authority=rd.GithubArtifactDigestAuthority(
                    repo=args.source_repo, workflow_path=args.workflow_path,
                ),
                transport=transport, recorded_head=args.recorded_head,
            )
            # Label the digest of the EXACT bytes written (with the trailing
            # newline), never a different encoding.
            encoded = (encode_index_entry(entry) + "\n").encode()
            _atomic_write_bytes(args.entry_out, encoded)
            print(f"{args.entry_out} sha256:{_sha256(encoded)}")
            print("record this entry through the reviewed main-branch "
                  "index before any restore may call the copy trusted")
            return 0
        authority = ReviewedMainIndexAuthority(
            remote=args.remote, reviewed_commit=args.reviewed_commit)
        reader = authority._git
        body = restore_archived(
            entry=None, transport=transport, production=True,
            validate=semantic_validator(),
            index_authority=authority, logical_id=args.logical_id,
        )
        _atomic_write_bytes(args.out, body)
        print(f"{args.out} sha256:{_sha256(body)}")
        return 0
    finally:
        transport.close()
        if reader is not None:
            reader.close()


if __name__ == "__main__":
    raise SystemExit(main())
