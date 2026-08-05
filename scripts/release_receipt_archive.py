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
    for field in required:
        _bounded_identity(source[field], f"source {field}")
    return dict(source)


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
    _validate_source(manifest["source"], manifest["kind"])
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
    *, logical_id: str, kind: str, artifact_ref: str, source: dict,
    store, authority, transport, recorded_head: str | None,
    allowed_paths: tuple[str, ...] = (),
) -> dict:
    _bounded_identity(logical_id, "logical id")
    source = _validate_source(source, _bounded_identity(kind, "kind"))
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


class GitBranchArchive:
    """Append-only durable byte store on a dedicated git branch.

    All operations run inside an isolated temporary clone; the ambient
    repository and worktree are never touched. Ref updates are strict
    compare-and-swap (force-with-lease against the exact expected parent,
    never force), so a concurrent or force-moved remote refuses."""

    trust_class = "durable-byte-store"

    _ENV = {
        "GIT_AUTHOR_NAME": "aweb-release-archive",
        "GIT_AUTHOR_EMAIL": "release-archive@aweb.invalid",
        "GIT_COMMITTER_NAME": "aweb-release-archive",
        "GIT_COMMITTER_EMAIL": "release-archive@aweb.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }

    def __init__(self, *, remote: str, branch: str):
        self._remote = remote
        self._branch = _bounded_identity(branch, "archive branch")
        self._root = Path(tempfile.mkdtemp(prefix="aweb-receipt-archive-"))
        self._local = self._root / "local.git"
        self._git("init", "--bare", str(self._local), cwd=self._root)

    def _git(self, *args, cwd=None, input_bytes=None) -> bytes:
        import os

        result = subprocess.run(
            ["git", *args], cwd=str(cwd or self._local),
            input=input_bytes, capture_output=True,
            env={**os.environ, **self._ENV},
        )
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
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=str(self._local), capture_output=True,
        )
        if probe.returncode == 0:
            return
        fetch = subprocess.run(
            ["git", "fetch", self._remote,
             f"+refs/heads/{self._branch}:refs/archive/head"],
            cwd=str(self._local), capture_output=True,
        )
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=str(self._local), capture_output=True,
        )
        if probe.returncode != 0:
            detail = fetch.stderr.decode(errors="replace")[-300:]
            raise ReceiptError(
                f"archive commit {sha} does not exist in the archive "
                f"remote{': ' + detail if detail else ''}"
            )

    def read_tree(self, sha: str) -> dict[str, bytes]:
        self._ensure_object(sha)
        listing = self._git("ls-tree", "-r", sha).decode()
        tree: dict[str, bytes] = {}
        for line in listing.splitlines():
            meta, path = line.split("\t", 1)
            blob = meta.split()[2]
            tree[path] = self._git("cat-file", "blob", blob)
        return tree

    def parent_of(self, sha: str) -> str | None:
        self._ensure_object(sha)
        tokens = self._git("rev-list", "--parents", "-n", "1", sha).split()
        return tokens[1].decode() if len(tokens) > 1 else None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        self._ensure_object(descendant)
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=str(self._local), capture_output=True,
        )
        return result.returncode == 0

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
        push = subprocess.run(
            ["git", "push", "--force-with-lease=" + lease, self._remote,
             f"HEAD:refs/heads/{self._branch}"],
            cwd=str(work), capture_output=True,
            env={**__import__("os").environ, **self._ENV},
        )
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
    rest.add_argument("--index-file", required=True, type=Path,
                      help="reviewed index from a reviewed main checkout")
    rest.add_argument("--out", required=True, type=Path)

    args = parser.parse_args(argv)
    import release_driver as rd

    transport = GitBranchArchive(remote=args.remote, branch=args.branch)
    try:
        if args.verb == "release-archive":
            source = {"repo": args.source_repo, "run_id": args.run_id,
                      "artifact_id": args.artifact_id}
            if args.anchor is not None:
                source["anchor"] = args.anchor
            entry = archive_sealed(
                logical_id=args.logical_id, kind=args.kind,
                artifact_ref=args.artifact_ref, source=source,
                store=rd.GithubArtifactStore(
                    repo=args.source_repo, workflow_path=args.workflow_path,
                ),
                authority=rd.GithubArtifactDigestAuthority(
                    repo=args.source_repo, workflow_path=args.workflow_path,
                ),
                transport=transport, recorded_head=args.recorded_head,
            )
            encoded = encode_index_entry(entry)
            args.entry_out.write_text(encoded + "\n")
            print(f"{args.entry_out} sha256:{_sha256(encoded.encode())}")
            print("record this entry through the reviewed main-branch "
                  "index before any restore may call the copy trusted")
            return 0
        body = restore_archived(
            entry=None, transport=transport, production=True,
            validate=lambda body, manifest: None if manifest["kind"]
            in KIND_SOURCE_FIELDS else (_ for _ in ()).throw(
                ReceiptError(f"unknown kind {manifest['kind']!r}")),
            index_authority=IndexFileAuthority(args.index_file),
            logical_id=args.logical_id,
        )
        args.out.write_bytes(body)
        print(f"{args.out} sha256:{_sha256(body)}")
        return 0
    finally:
        transport.close()


if __name__ == "__main__":
    raise SystemExit(main())
