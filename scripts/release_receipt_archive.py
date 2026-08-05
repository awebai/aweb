"""Durable archival of sealed release evidence beyond Actions retention.

The archive branch is a DURABLE BYTE STORE, never an authority: a mutable
git ref plus a manifest fetched from that same ref cannot authorize
itself. Trust comes from a canonical index entry recorded through a
separately reviewed authority (the main-branch index); this module emits
that entry and never pushes main.

Operator contract:

  archive:  copy ONLY already-sealed exact bytes. The source authority's
            digest is fetched first and the fetched bytes must hash to it;
            an expired or absent source refuses (nothing unsealed is ever
            archived). Writes are content-addressed under
            receipts/<body-sha256>/{body.zip,manifest.json} and strictly
            append-only: the fetched archive head must equal or descend
            from the previously recorded head, and existing content must
            be internally consistent (no logical-ID rebinding, no
            conflicting manifest for an existing digest, no stray bodies).
            Archiving the identical logical-id/digest pair again is
            idempotent and returns the original commit.
  entry:    the returned canonical index entry binds the original logical
            ID, source repo/run/artifact/anchor IDs, the source authority
            digest, the archived body digest, the archive manifest digest,
            and the exact archive commit SHA. Record it through the
            reviewed main-branch index before calling the copy trusted.
  restore:  addresses the exact recorded archive commit plus digests from
            the entry - never the live branch head (restore performs no
            head fetch at all). After byte verification the caller's
            semantic validator re-runs the existing frozen plan/manifest/
            transition/receipt validation; production restore refuses a
            missing validator and refuses development/untrusted transport
            classes (local filesystem, unindexed copies).
"""

from __future__ import annotations

import hashlib
import json

from release_driver import ReceiptError

INDEX_ENTRY_SCHEMA = "aweb.release-archive-index-entry.v1"
MANIFEST_SCHEMA = "aweb.release-archive-manifest.v1"
PRODUCTION_TRUST_CLASSES = ("durable-byte-store",)

_ENTRY_FIELDS = (
    "schema", "logical_id", "kind", "source", "source_digest",
    "body_sha256", "manifest_sha256", "archive_commit",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def encode_index_entry(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _existing_manifests(tree: dict[str, bytes]) -> dict[str, dict]:
    """Map body digest -> manifest for every archived pair; refuse strays."""
    manifests: dict[str, dict] = {}
    bodies: set[str] = set()
    for path in tree:
        if not path.startswith("receipts/"):
            continue
        parts = path.split("/")
        if len(parts) != 3 or parts[2] not in ("body.zip", "manifest.json"):
            raise ReceiptError(f"archive holds an unexpected path: {path}")
        digest = parts[1]
        if parts[2] == "body.zip":
            bodies.add(digest)
        else:
            try:
                manifest = json.loads(tree[path])
            except json.JSONDecodeError as exc:
                raise ReceiptError(
                    f"archive manifest at {path} is not valid JSON"
                ) from exc
            manifests[digest] = manifest
    stray_bodies = bodies - set(manifests)
    stray_manifests = set(manifests) - bodies
    if stray_bodies or stray_manifests:
        raise ReceiptError(
            "archive holds unexpected unpaired content: stray bodies "
            f"{sorted(stray_bodies)}, stray manifests {sorted(stray_manifests)}"
        )
    for digest, manifest in manifests.items():
        if manifest.get("body_sha256") != digest:
            raise ReceiptError(
                f"archive manifest for {digest} conflicts with its own "
                "content address"
            )
    return manifests


def archive_sealed(
    *, logical_id: str, kind: str, artifact_ref: str, source: dict,
    store, authority, transport, recorded_head: str | None,
) -> dict:
    if not logical_id or not isinstance(logical_id, str):
        raise ReceiptError("archive requires a nonempty logical id")
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
    manifests = _existing_manifests(tree)
    for digest, manifest in manifests.items():
        if manifest.get("logical_id") == logical_id and digest != body_sha:
            raise ReceiptError(
                f"logical id {logical_id!r} is already archived with digest "
                f"{digest}; refusing rebinding to {body_sha}"
            )
    existing = manifests.get(body_sha)
    manifest_doc = {
        "schema": MANIFEST_SCHEMA,
        "logical_id": logical_id,
        "kind": kind,
        "source": dict(source),
        "source_digest": expected,
        "body_sha256": body_sha,
    }
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
    manifest_bytes = _canonical(manifest_doc)
    return {
        "schema": INDEX_ENTRY_SCHEMA,
        "logical_id": logical_id,
        "kind": kind,
        "source": dict(source),
        "source_digest": expected,
        "body_sha256": body_sha,
        "manifest_sha256": _sha256(manifest_bytes),
        "archive_commit": archive_commit,
    }


def _commit_holding(transport, head: str, body_sha: str) -> str:
    """The earliest commit whose tree already holds the archived pair."""
    path = f"receipts/{body_sha}/body.zip"
    cursor = head
    holder = head
    while cursor is not None:
        tree = transport.read_tree(cursor)
        if path not in tree:
            break
        holder = cursor
        cursor = transport.commits[cursor]["parent"] if hasattr(
            transport, "commits"
        ) else None
    return holder


def restore_archived(
    *, entry: dict, transport, production: bool, validate,
) -> bytes:
    if not isinstance(entry, dict) or any(
        field not in entry for field in _ENTRY_FIELDS
    ):
        missing = [f for f in _ENTRY_FIELDS if f not in (entry or {})]
        raise ReceiptError(
            f"archive index entry is malformed; missing {missing}"
        )
    if entry.get("schema") != INDEX_ENTRY_SCHEMA:
        raise ReceiptError("archive index entry has an unsupported schema")
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
    manifest = json.loads(manifest_bytes)
    for field in ("logical_id", "kind", "source", "source_digest",
                  "body_sha256"):
        if manifest.get(field) != entry.get(field):
            raise ReceiptError(
                f"archived manifest {field} does not equal the recorded "
                "index entry"
            )
    if validate is not None:
        validate(body, manifest)
    return body
