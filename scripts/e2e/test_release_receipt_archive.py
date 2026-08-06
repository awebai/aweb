"""aweb-abbe.9: durable sealed-receipt archival beyond Actions retention.

The archive branch is a DURABLE BYTE STORE, never a self-authorizing
authority: a mutable git ref plus a manifest in the same ref cannot
authorize itself. Restore trusts only a canonical index entry recorded
through a separately reviewed authority, addresses the exact recorded
archive commit, and re-runs semantic validation after byte checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import release_driver as rd  # noqa: E402
import release_receipt_archive as archive  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeStore:
    def __init__(self, artifacts: dict[str, bytes]):
        self.artifacts = dict(artifacts)

    def get(self, ref: str) -> bytes:
        if ref not in self.artifacts:
            raise rd.ReceiptError(f"artifact {ref} is expired or absent")
        return self.artifacts[ref]


class FakeAuthority:
    def __init__(self, digests: dict[str, str], expired: set[str] = ()):
        self.digests = dict(digests)
        self.expired = set(expired)

    def expected_digest(self, ref: str) -> str:
        if ref in self.expired:
            raise rd.ReceiptError(f"artifact {ref} is expired; no authority digest")
        if ref not in self.digests:
            raise rd.ReceiptError(f"no authority digest for {ref}")
        return self.digests[ref]


class FakeArchiveTransport:
    trust_class = "durable-byte-store"

    def __init__(self):
        self.commits: dict[str, dict] = {}
        self.head: str | None = None
        self.fetch_head_calls = 0

    def _tree_at(self, sha: str) -> dict[str, bytes]:
        commit = self.commits.get(sha)
        if commit is None:
            raise rd.ReceiptError(f"archive commit {sha} does not exist")
        tree: dict[str, bytes] = {}
        chain = []
        cursor: str | None = sha
        while cursor is not None:
            chain.append(cursor)
            cursor = self.commits[cursor]["parent"]
        for ancestor in reversed(chain):
            tree.update(self.commits[ancestor]["files"])
        return tree

    def fetch_head(self) -> str | None:
        self.fetch_head_calls += 1
        return self.head

    def read_tree(self, sha: str) -> dict[str, bytes]:
        return self._tree_at(sha)

    def read_tree_entries(self, sha: str):
        return {
            path: ("100644", "blob", data)
            for path, data in self._tree_at(sha).items()
        }

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        cursor: str | None = descendant
        while cursor is not None:
            if cursor == ancestor:
                return True
            cursor = self.commits[cursor]["parent"]
        return False

    def parents_of(self, sha: str) -> tuple[str, ...]:
        commit = self.commits.get(sha)
        if commit is None:
            raise rd.ReceiptError(f"archive commit {sha} does not exist")
        parent = commit["parent"]
        return (parent,) if parent is not None else ()

    def parent_of(self, sha: str) -> str | None:
        parents = self.parents_of(sha)
        return parents[0] if parents else None

    def append(self, parent: str | None, files: dict[str, bytes], subject: str) -> str:
        if parent != self.head:
            raise rd.ReceiptError(
                "archive append is not fast-forward from the fetched head"
            )
        body = json.dumps(sorted(files), sort_keys=True) + subject + str(parent)
        sha = hashlib.sha256(body.encode()).hexdigest()[:40]
        self.commits[sha] = {"parent": parent, "files": dict(files)}
        self.head = sha
        return sha

    def force_move_head(self, sha: str | None) -> None:
        self.head = sha


class FakeLocalTransport(FakeArchiveTransport):
    trust_class = "local-development"


BODY = b"sealed-anchor-zip-bytes"
REF = "gh-artifact:awebai/aweb:41:9001"
SOURCE = {"repo": "awebai/aweb", "run_id": "41", "artifact_id": "9001",
          "anchor": "anchor--" + "a" * 64 + "--" + "b" * 64}
LOGICAL_ONE = f"receipt:{'f' * 64}:{'1' * 64}"
LOGICAL_TWO = f"receipt:{'f' * 64}:{'2' * 64}"


def fresh_env(body: bytes = BODY, ref: str = REF):
    return (
        FakeStore({ref: body}),
        FakeAuthority({ref: sha256(body)}),
        FakeArchiveTransport(),
    )


# These helpers exercise APPEND MECHANICS (compare-and-swap, rebinding, stray
# content, idempotence) with synthetic bodies, so they pass an explicit
# permissive validator. Production keeps the real semantic validator as its
# default - ProductionPathControlTests proves the default refuses a
# semantically invalid artifact before any branch mutation.
def _permissive(body, manifest):
    return None


def do_archive(store, authority, transport, *, logical_id=LOGICAL_ONE,
               ref=REF, recorded_head=None, kind="anchor-artifact",
               source=None, semantic=_permissive):
    src = dict(source) if source is not None else dict(SOURCE)
    if kind == "workflow-artifact":
        src.pop("anchor", None)
    return archive.archive_sealed(
        logical_id=logical_id, kind=kind, source=src,
        store=store, authority=authority,
        transport=transport, recorded_head=recorded_head,
        semantic=semantic,
    )


class ArchiveWriteTests(unittest.TestCase):
    def test_archives_exact_sealed_bytes_and_emits_bound_entry(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        self.assertEqual(entry["schema"], archive.INDEX_ENTRY_SCHEMA)
        self.assertEqual(entry["logical_id"], LOGICAL_ONE)
        self.assertEqual(entry["source"], SOURCE)
        self.assertEqual(entry["source_digest"], sha256(BODY))
        self.assertEqual(entry["body_sha256"], sha256(BODY))
        self.assertEqual(entry["archive_commit"], transport.head)
        tree = transport.read_tree(transport.head)
        body_path = f"receipts/{sha256(BODY)}/body.zip"
        manifest_path = f"receipts/{sha256(BODY)}/manifest.json"
        self.assertEqual(tree[body_path], BODY)
        manifest = json.loads(tree[manifest_path])
        self.assertEqual(manifest["logical_id"], LOGICAL_ONE)
        self.assertEqual(
            entry["manifest_sha256"], sha256(tree[manifest_path])
        )

    def test_source_digest_mismatch_refuses_before_any_write(self):
        store = FakeStore({REF: b"tampered"})
        authority = FakeAuthority({REF: sha256(BODY)})
        transport = FakeArchiveTransport()
        with self.assertRaisesRegex(rd.ReceiptError, "digest"):
            do_archive(store, authority, transport)
        self.assertIsNone(transport.head)

    def test_expired_source_refuses_archive(self):
        store = FakeStore({})
        authority = FakeAuthority({}, expired={REF})
        transport = FakeArchiveTransport()
        with self.assertRaisesRegex(rd.ReceiptError, "expired"):
            do_archive(store, authority, transport)
        self.assertIsNone(transport.head)

    def test_moved_ref_refuses_nondescendant_head(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        stranger = FakeArchiveTransport()
        stranger_sha = stranger.append(None, {"x": b"y"}, "foreign")
        transport.commits[stranger_sha] = {"parent": None, "files": {"x": b"y"}}
        transport.force_move_head(stranger_sha)
        body2 = b"second-sealed-body"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "descend"):
            do_archive(store, authority, transport, source=source2,
                       logical_id=LOGICAL_TWO,
                       recorded_head=entry["archive_commit"])

    def test_unrecorded_prior_content_refuses(self):
        store, authority, transport = fresh_env()
        transport.append(None, {"receipts/stray": b"?"}, "unindexed")
        with self.assertRaisesRegex(rd.ReceiptError, "recorded"):
            do_archive(store, authority, transport, recorded_head=None)

    def test_logical_id_rebinding_refuses(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        body2 = b"different-bytes-same-logical-id"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "rebind"):
            do_archive(store, authority, transport, source=source2,
                       recorded_head=entry["archive_commit"])

    def test_duplicate_exact_archive_is_idempotent_not_ambiguous(self):
        store, authority, transport = fresh_env()
        first = do_archive(store, authority, transport)
        again = do_archive(store, authority, transport,
                           recorded_head=first["archive_commit"])
        self.assertEqual(first["body_sha256"], again["body_sha256"])
        self.assertEqual(first["archive_commit"], again["archive_commit"])

    def test_digest_collision_conflicting_manifest_refuses(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        tree = transport.read_tree(transport.head)
        manifest_path = f"receipts/{sha256(BODY)}/manifest.json"
        broken = json.loads(tree[manifest_path])
        broken["logical_id"] = LOGICAL_TWO
        transport.commits[transport.head]["files"][manifest_path] = (
            json.dumps(broken, sort_keys=True).encode()
        )
        with self.assertRaisesRegex(rd.ReceiptError, "conflict|rebind|canonical|duplicate"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])

    def test_extra_unexpected_body_refuses(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        transport.commits[transport.head]["files"]["receipts/deadbeef/body.zip"] = b"stray"
        body2 = b"second-sealed-body"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "unexpected|stray"):
            do_archive(store, authority, transport, source=source2,
                       logical_id=LOGICAL_TWO,
                       recorded_head=entry["archive_commit"])


class RestoreTests(unittest.TestCase):
    def archived(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        return transport, entry

    def restore(self, transport, entry, *, production=True, validate=None,
                validated=None, index_authority="from-entry"):
        if validate is None:
            def validate(body, manifest):
                if validated is not None:
                    validated.append((body, manifest))
        if index_authority == "from-entry":
            index_authority = FakeIndexAuthority([entry]) if production else None
        return archive.restore_archived(
            entry=entry, transport=transport, production=production,
            validate=validate, index_authority=index_authority,
        )

    def test_restores_exact_bytes_by_recorded_commit_never_head(self):
        transport, entry = self.archived()
        validated: list = []
        transport.force_move_head(None)
        transport.fetch_head_calls = 0
        body = self.restore(transport, entry, validated=validated)
        self.assertEqual(body, BODY)
        self.assertEqual(len(validated), 1)
        self.assertEqual(transport.fetch_head_calls, 0,
                         "restore must never consult the live head")

    def test_restore_survives_source_expiry(self):
        transport, entry = self.archived()
        self.assertEqual(self.restore(transport, entry), BODY)

    def test_missing_commit_or_body_refuses(self):
        transport, entry = self.archived()
        bad = dict(entry, archive_commit="0" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "does not exist"):
            self.restore(transport, bad)

    def test_tampered_body_refuses(self):
        transport, entry = self.archived()
        path = f"receipts/{entry['body_sha256']}/body.zip"
        transport.commits[entry["archive_commit"]]["files"][path] = b"evil"
        with self.assertRaisesRegex(rd.ReceiptError, "digest"):
            self.restore(transport, entry)

    def test_tampered_manifest_refuses(self):
        transport, entry = self.archived()
        path = f"receipts/{entry['body_sha256']}/manifest.json"
        files = transport.commits[entry["archive_commit"]]["files"]
        manifest = json.loads(files[path])
        manifest["logical_id"] = "receipt:evil"
        files[path] = json.dumps(manifest, sort_keys=True).encode()
        with self.assertRaisesRegex(rd.ReceiptError, "digest|manifest"):
            self.restore(transport, entry)

    def test_malformed_entry_refuses(self):
        transport, entry = self.archived()
        for missing in ("archive_commit", "body_sha256", "manifest_sha256",
                        "logical_id"):
            bad = {k: v for k, v in entry.items() if k != missing}
            with self.assertRaisesRegex(rd.ReceiptError,
                                        "index entry|reviewed index"):
                self.restore(transport, bad)

    def test_semantic_validator_runs_after_bytes_and_can_refuse(self):
        transport, entry = self.archived()

        def refuse(body, manifest):
            raise rd.ReceiptError("semantically stale receipt")

        with self.assertRaisesRegex(rd.ReceiptError, "semantically stale"):
            self.restore(transport, entry, validate=refuse)

    def test_production_restore_refuses_development_transport(self):
        store, authority, _ = fresh_env()
        local = FakeLocalTransport()
        entry = do_archive(store, authority, local)
        with self.assertRaisesRegex(rd.ReceiptError, "development|untrusted"):
            self.restore(local, entry, production=True)
        self.assertEqual(self.restore(local, entry, production=False), BODY)

    def test_production_restore_requires_validator(self):
        transport, entry = self.archived()
        with self.assertRaisesRegex(rd.ReceiptError, "semantic"):
            archive.restore_archived(
                entry=entry, transport=transport, production=True,
                validate=None,
            )


class FakeIndexAuthority:
    def __init__(self, entries, unavailable=False):
        self.entries = list(entries)
        self.unavailable = unavailable

    def lookup(self, logical_id):
        if self.unavailable:
            raise RuntimeError("index host unreachable")
        matches = [e for e in self.entries
                   if e.get("logical_id") == logical_id]
        if len(matches) > 1:
            raise rd.ReceiptError("duplicate index records")
        return matches[0] if matches else None


class ReviewedIndexAuthorityTests(unittest.TestCase):
    def archived(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        return transport, entry

    def restore(self, transport, entry, authority, logical_id=None):
        return archive.restore_archived(
            entry=entry, transport=transport, production=True,
            validate=lambda body, manifest: None,
            index_authority=authority, logical_id=logical_id,
        )

    def test_production_restore_requires_index_authority(self):
        transport, entry = self.archived()
        with self.assertRaisesRegex(rd.ReceiptError, "index authority"):
            self.restore(transport, entry, None)

    def test_entry_loads_from_authority_when_not_supplied(self):
        transport, entry = self.archived()
        body = self.restore(
            transport, None, FakeIndexAuthority([entry]),
            logical_id=entry["logical_id"],
        )
        self.assertEqual(body, BODY)

    def test_missing_index_record_refuses(self):
        transport, entry = self.archived()
        with self.assertRaisesRegex(rd.ReceiptError, "not recorded"):
            self.restore(transport, None, FakeIndexAuthority([]),
                         logical_id=entry["logical_id"])

    def test_unavailable_authority_refuses(self):
        transport, entry = self.archived()
        with self.assertRaisesRegex(rd.ReceiptError, "unavailable"):
            self.restore(transport, entry,
                         FakeIndexAuthority([entry], unavailable=True))

    def test_caller_entry_mismatching_index_record_refuses(self):
        transport, entry = self.archived()
        drifted = dict(entry, manifest_sha256="0" * 64)
        with self.assertRaisesRegex(rd.ReceiptError, "mismatch"):
            self.restore(transport, drifted, FakeIndexAuthority([entry]))

    def test_archive_branch_content_never_substitutes_authority(self):
        transport, entry = self.archived()
        forged = dict(entry, logical_id=LOGICAL_TWO)
        files = transport.commits[entry["archive_commit"]]["files"]
        files["index.json"] = json.dumps({"entries": [forged]}).encode()
        with self.assertRaisesRegex(rd.ReceiptError, "not recorded"):
            self.restore(transport, None, FakeIndexAuthority([]),
                         logical_id=LOGICAL_TWO)

    def test_index_file_authority_reads_reviewed_file_only(self):
        import tempfile

        transport, entry = self.archived()
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "index.json"
            index.write_text(json.dumps({"entries": [entry]}))
            body = self.restore(
                transport, None, archive.IndexFileAuthority(index),
                logical_id=entry["logical_id"],
            )
            self.assertEqual(body, BODY)
            with self.assertRaisesRegex(rd.ReceiptError, "not recorded"):
                self.restore(transport, None,
                             archive.IndexFileAuthority(index),
                             logical_id=LOGICAL_TWO)
            missing = Path(tmp) / "absent.json"
            with self.assertRaisesRegex(rd.ReceiptError, "does not exist"):
                self.restore(transport, None,
                             archive.IndexFileAuthority(missing),
                             logical_id=entry["logical_id"])


class StrictSchemaTests(unittest.TestCase):
    def archived(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        return transport, entry

    def test_extra_entry_field_refuses(self):
        transport, entry = self.archived()
        bad = dict(entry, extra="field")
        with self.assertRaisesRegex(rd.ReceiptError, "extra"):
            archive.restore_archived(
                entry=bad, transport=transport, production=False,
                validate=None,
            )

    def test_non_hex_digest_and_short_commit_refuse(self):
        transport, entry = self.archived()
        for field, value, needle in (
            ("body_sha256", "zz" * 32, "64-hex"),
            ("source_digest", "ab" * 31, "64-hex"),
            ("archive_commit", "abc123", "40-hex"),
        ):
            bad = dict(entry, **{field: value})
            with self.assertRaisesRegex(rd.ReceiptError, needle):
                archive.restore_archived(
                    entry=bad, transport=transport, production=False,
                    validate=None,
                )

    def test_wrong_kind_source_fields_refuse(self):
        store, authority, transport = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "exactly the"):
            archive.archive_sealed(
                logical_id="x", kind="workflow-artifact", artifact_ref=REF,
                source=dict(SOURCE), store=store, authority=authority,
                transport=transport, recorded_head=None,
            )
        with self.assertRaisesRegex(rd.ReceiptError, "unsupported archive kind"):
            archive.archive_sealed(
                logical_id="x", kind="mystery", artifact_ref=REF,
                source=dict(SOURCE), store=store, authority=authority,
                transport=transport, recorded_head=None,
            )

    def test_oversized_identity_refuses(self):
        store, authority, transport = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "at most"):
            do_archive(store, authority, transport, logical_id="x" * 201)

    def test_noncanonical_or_malformed_manifest_bytes_refuse(self):
        transport, entry = self.archived()
        files = transport.commits[entry["archive_commit"]]["files"]
        path = f"receipts/{entry['body_sha256']}/manifest.json"
        manifest = json.loads(files[path])
        files[path] = json.dumps(manifest, sort_keys=True, indent=2).encode()
        store, authority, _ = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "canonical"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])
        files[path] = b"\xff not json"
        with self.assertRaisesRegex(rd.ReceiptError, "JSON"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])

    def test_duplicate_logical_ids_in_tree_refuse(self):
        transport, entry = self.archived()
        files = transport.commits[entry["archive_commit"]]["files"]
        other_body = b"other-bytes"
        digest = sha256(other_body)
        manifest = {
            "schema": archive.MANIFEST_SCHEMA,
            "logical_id": entry["logical_id"],
            "kind": entry["kind"],
            "source": dict(SOURCE),
            "source_digest": digest,
            "body_sha256": digest,
        }
        files[f"receipts/{digest}/body.zip"] = other_body
        files[f"receipts/{digest}/manifest.json"] = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode()
        store, authority, _ = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "duplicate logical id"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])

    def test_allowed_metadata_path_is_tolerated_when_named(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        transport.commits[entry["archive_commit"]]["files"]["README.md"] = b"docs"
        with self.assertRaisesRegex(rd.ReceiptError, "unexpected path"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])
        again = archive.archive_sealed(
            logical_id=entry["logical_id"], kind=entry["kind"],
            artifact_ref=REF, source=dict(SOURCE), store=store,
            authority=authority, transport=transport,
            recorded_head=entry["archive_commit"],
            allowed_paths=("README.md",), semantic=_permissive,
        )
        self.assertEqual(again["archive_commit"], entry["archive_commit"])


class GitBranchArchiveTests(unittest.TestCase):
    """The production transport against a LOCAL bare remote; no real
    remote write occurs anywhere in this suite."""

    def setUp(self):
        import subprocess, tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.remote = str(Path(self.tmp.name) / "remote.git")
        subprocess.run(["git", "init", "--bare", self.remote],
                       capture_output=True, check=True)

    def transport(self):
        t = archive.GitBranchArchive(remote=self.remote,
                                     branch="release-receipts")
        self.addCleanup(t.close)
        return t

    def env(self, body=BODY, ref=REF):
        return FakeStore({ref: body}), FakeAuthority({ref: sha256(body)})

    def test_orphan_create_append_idempotence_and_historical_restore(self):
        store, authority = self.env()
        t1 = self.transport()
        first = do_archive(store, authority, t1)
        self.assertTrue(len(first["archive_commit"]) == 40)

        body2 = b"second-sealed-body"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        second = do_archive(store, authority, t1, source=source2,
                            logical_id=LOGICAL_TWO,
                            recorded_head=first["archive_commit"])
        self.assertNotEqual(second["archive_commit"], first["archive_commit"])

        t2 = self.transport()
        again = do_archive(store, authority, t2,
                           recorded_head=second["archive_commit"])
        self.assertEqual(again["archive_commit"], first["archive_commit"],
                         "idempotent re-archive finds the ORIGINAL commit")

        # A local bare remote is a development transport by design, so
        # production restore refuses it; mechanics are exercised with
        # production=False against the exact recorded entry.
        with self.assertRaisesRegex(rd.ReceiptError, "development"):
            archive.restore_archived(
                entry=first, transport=t2, production=True,
                validate=lambda b, m: None,
                index_authority=FakeIndexAuthority([first]),
                logical_id=first["logical_id"])
        body = archive.restore_archived(
            entry=first, transport=t2, production=False,
            validate=lambda b, m: None)
        self.assertEqual(body, BODY)

    def test_concurrent_append_refuses_compare_and_swap(self):
        store, authority = self.env()
        t1 = self.transport()
        first = do_archive(store, authority, t1)
        t2 = self.transport()
        body2 = b"concurrent-two"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        do_archive(store, authority, t2, source=source2,
                   logical_id=LOGICAL_TWO,
                   recorded_head=first["archive_commit"])
        head = t1.fetch_head()
        body3 = b"concurrent-three"
        files = {f"receipts/{sha256(body3)}/body.zip": body3,
                 f"receipts/{sha256(body3)}/manifest.json": b"{}"}
        with self.assertRaisesRegex(rd.ReceiptError, "fast-forward"):
            t1.append(first["archive_commit"], files, "stale parent")

    def test_moved_ref_refuses_on_real_git(self):
        import subprocess

        store, authority = self.env()
        t1 = self.transport()
        first = do_archive(store, authority, t1)
        foreign = str(Path(self.tmp.name) / "foreign")
        subprocess.run(["git", "init", "--initial-branch", "release-receipts",
                        foreign], capture_output=True, check=True)
        env_over = {"GIT_AUTHOR_NAME": "x", "GIT_AUTHOR_EMAIL": "x@x",
                    "GIT_COMMITTER_NAME": "x", "GIT_COMMITTER_EMAIL": "x@x"}
        import os
        (Path(foreign) / "divergent.txt").write_text("divergent")
        subprocess.run(["git", "add", "-A"], cwd=foreign, capture_output=True,
                       check=True, env={**os.environ, **env_over})
        subprocess.run(["git", "commit", "-m", "divergent"], cwd=foreign,
                       capture_output=True, check=True,
                       env={**os.environ, **env_over})
        subprocess.run(["git", "push", "--force", self.remote,
                        "HEAD:refs/heads/release-receipts"], cwd=foreign,
                       capture_output=True, check=True)
        t2 = self.transport()
        body2 = b"post-force"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "descend|does not exist"):
            do_archive(store, authority, t2, source=source2,
                       logical_id=LOGICAL_TWO,
                       recorded_head=first["archive_commit"])

    def test_normal_fast_forward_deletion_cannot_erase_and_rebind(self):
        """A non-force descendant is not enough: every intervening commit
        must preserve the exact prior tree before same-ID archival can append."""
        graph, plan = real_graph_and_plan()
        plan_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="a" * 40)
        logical = f"plan:{'a' * 40}:{frozen_id}"
        first_body, _ = anchor_bundle(logical, plan_bytes)
        first_ref = "gh-artifact:awebai/aweb:41:9001"
        first = archive.archive_sealed(
            logical_id=logical,
            kind="anchor-artifact",
            source=dict(
                SOURCE,
                anchor=rd._anchor_name(logical, sha256(plan_bytes))),
            store=FakeStore({first_ref: first_body}),
            authority=FakeAuthority({first_ref: sha256(first_body)}),
            transport=self.transport(),
            recorded_head=None,
        )

        attacker = Path(self.tmp.name) / "normal-ff-delete"
        subprocess.run(
            [archive.SYSTEM_GIT, "clone", self.remote, str(attacker)],
            capture_output=True, check=True)
        subprocess.run(
            [archive.SYSTEM_GIT, "checkout", "release-receipts"],
            cwd=attacker, capture_output=True, check=True)
        for path in (attacker / "receipts").rglob("*"):
            if path.is_file():
                path.unlink()
        for path in sorted(
            (attacker / "receipts").rglob("*"), reverse=True
        ):
            if path.is_dir():
                path.rmdir()
        (attacker / "receipts").rmdir()
        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "normal-ff-attacker",
            "GIT_AUTHOR_EMAIL": "attacker@example.invalid",
            "GIT_COMMITTER_NAME": "normal-ff-attacker",
            "GIT_COMMITTER_EMAIL": "attacker@example.invalid",
        }
        subprocess.run(
            [archive.SYSTEM_GIT, "add", "-A"], cwd=attacker,
            env=git_env, capture_output=True, check=True)
        subprocess.run(
            [archive.SYSTEM_GIT, "commit", "-m", "delete archived body"],
            cwd=attacker, env=git_env, capture_output=True, check=True)
        deletion_head = subprocess.run(
            [archive.SYSTEM_GIT, "rev-parse", "HEAD"], cwd=attacker,
            capture_output=True, check=True).stdout.decode().strip()
        subprocess.run(
            [archive.SYSTEM_GIT, "push", self.remote,
             "HEAD:refs/heads/release-receipts"],
            cwd=attacker, capture_output=True, check=True)

        # A ZIP may carry ignored trailing bytes while preserving the same
        # exact inner sealed plan and logical ID. This gives a genuinely
        # different outer body that still passes production semantics.
        replacement_body = first_body + b"normal-ff-rebinding-body"
        replacement_ref = "gh-artifact:awebai/aweb:41:9002"
        source = dict(
            SOURCE,
            artifact_id="9002",
            anchor=rd._anchor_name(logical, sha256(plan_bytes)),
        )
        transport = self.transport()
        with self.assertRaisesRegex(
            rd.ReceiptError, "append-only|deleted|superset"
        ):
            archive.archive_sealed(
                logical_id=logical,
                kind="anchor-artifact",
                source=source,
                store=FakeStore({replacement_ref: replacement_body}),
                authority=FakeAuthority({
                    replacement_ref: sha256(replacement_body)}),
                transport=transport,
                recorded_head=first["archive_commit"],
            )

        self.assertEqual(transport.fetch_head(), deletion_head,
                         "refusal must not append after the deleting head")
        original_tree = transport.read_tree(first["archive_commit"])
        original_path = f"receipts/{sha256(first_body)}/body.zip"
        self.assertEqual(original_tree[original_path], first_body,
                         "the exact original body remains addressable")

    def test_history_verifier_requires_linear_exact_supersets(self):
        base = "a" * 40
        child = "b" * 40
        other = "c" * 40
        original = {"receipts/x/body.zip": ("100644", "blob", b"body")}

        class History:
            def __init__(self, parents, trees):
                self.parents = parents
                self.trees = trees

            def parents_of(self, sha):
                return self.parents[sha]

            def read_tree_entries(self, sha):
                return self.trees[sha]

        archive._verify_append_only_history(
            History({child: (base,)}, {
                base: original,
                child: {**original, "receipts/y/body.zip": (
                    "100644", "blob", b"addition")},
            }), base, child)

        attacks = {
            "deletion": {},
            "replacement": {"receipts/x/body.zip": (
                "100644", "blob", b"different")},
            "mode": {"receipts/x/body.zip": ("100755", "blob", b"body")},
            "type": {"receipts/x/body.zip": ("100644", "tree", b"body")},
        }
        for label, changed in attacks.items():
            with self.subTest(label=label):
                with self.assertRaises(rd.ReceiptError):
                    archive._verify_append_only_history(
                        History({child: (base,)}, {
                            base: original, child: changed}), base, child)
        with self.assertRaisesRegex(rd.ReceiptError, "linear|parent"):
            archive._verify_append_only_history(
                History({child: (base, other)}, {
                    base: original, child: original}), base, child)

    def test_close_removes_temporary_root(self):
        t = archive.GitBranchArchive(remote=self.remote,
                                     branch="release-receipts")
        root = t._root
        self.assertTrue(root.exists())
        t.close()
        self.assertFalse(root.exists())


class OperatorCliTests(unittest.TestCase):
    def setUp(self):
        import subprocess, tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.remote = str(Path(self.tmp.name) / "remote.git")
        subprocess.run(["git", "init", "--bare", self.remote],
                       capture_output=True, check=True)

    def test_cli_restore_refuses_nonproduction_remote(self):
        store, authority = FakeStore({REF: BODY}), FakeAuthority(
            {REF: sha256(BODY)})
        transport = archive.GitBranchArchive(
            remote=self.remote, branch="release-receipts")
        self.addCleanup(transport.close)
        entry = do_archive(store, authority, transport)
        out = Path(self.tmp.name) / "restored.zip"
        # The CLI restore builds a ReviewedMainIndexAuthority, which refuses a
        # remote that is not the canonical production remote, so a local bare
        # remote can never satisfy production restore.
        with self.assertRaisesRegex(rd.ReceiptError, "canonical"):
            archive.main([
                "release-restore", "--remote", self.remote,
                "--branch", "release-receipts",
                "--logical-id", entry["logical_id"],
                "--reviewed-commit", "a" * 40, "--out", str(out),
            ])
        self.assertFalse(out.exists())

class IndexEntryTests(unittest.TestCase):
    def test_entry_canonical_json_round_trips(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        encoded = archive.encode_index_entry(entry)
        self.assertEqual(json.loads(encoded), entry)
        self.assertEqual(encoded, archive.encode_index_entry(json.loads(encoded)))


class NackCorrectionControlTests(unittest.TestCase):
    """Controls for alice's five .9 blocking findings."""

    # Finding 1: production authority is not caller-asserted.
    def test_local_remote_is_development_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            import subprocess
            remote = str(Path(tmp) / "r.git")
            subprocess.run(["git", "init", "--bare", remote],
                           capture_output=True, check=True)
            transport = archive.GitBranchArchive(
                remote=remote, branch="release-receipts")
            self.addCleanup(transport.close)
            self.assertEqual(transport.trust_class, "local-development")

    def test_production_config_is_durable_class(self):
        transport = archive.GitBranchArchive(
            remote="https://github.com/awebai/aweb.git",
            branch="release-receipts")
        self.addCleanup(transport.close)
        self.assertEqual(transport.trust_class, "durable-byte-store")

    def test_reviewed_index_refuses_noncanonical_remote(self):
        with self.assertRaisesRegex(rd.ReceiptError, "canonical"):
            archive.ReviewedMainIndexAuthority(
                remote="https://example.invalid/x.git",
                reviewed_commit="a" * 40)

    def test_reviewed_index_refuses_commit_not_in_main(self):
        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40
            def is_ancestor(self, ancestor, descendant):
                return False
            def file_at(self, commit, path):
                return b"{}"
        authority = archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())
        with self.assertRaisesRegex(rd.ReceiptError, "not.*ancestor"):
            authority.lookup(LOGICAL_ONE)

    def test_reviewed_index_reads_entry_at_landed_commit(self):
        _, entry, doc = self._reviewed_fixture()
        got = doc.lookup(entry["logical_id"])
        self.assertEqual(got, entry)

    def _reviewed_fixture(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        index = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": [entry],
        }, sort_keys=True, separators=(",", ":")).encode()

        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40
            def is_ancestor(self, a, d):
                return True
            def file_at(self, commit, path):
                return index if path == archive.ReviewedMainIndexAuthority.INDEX_PATH else None
        doc = archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())
        return transport, entry, doc

    # Finding 2: production restore runs real semantic validators.
    def test_semantic_validator_refuses_bad_anchor_bundle(self):
        validate = archive.semantic_validator()
        manifest = {"kind": "anchor-artifact", "logical_id": LOGICAL_ONE,
                    "source_digest": "a" * 64}
        with self.assertRaisesRegex(rd.ReceiptError, "not a valid ZIP"):
            validate(b"not a zip", manifest)

    def test_semantic_validator_refuses_unknown_kind(self):
        validate = archive.semantic_validator()
        with self.assertRaisesRegex(rd.ReceiptError, "no semantic validator"):
            validate(b"x", {"kind": "mystery"})

    # Finding 3: existing-tree integrity.
    def test_corrupted_existing_body_refuses_at_append(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        path = f"receipts/{entry['body_sha256']}/body.zip"
        transport.commits[entry["archive_commit"]]["files"][path] = b"corrupt"
        body2 = b"second"
        ref2 = "gh-artifact:awebai/aweb:41:9002"
        source2 = dict(SOURCE, artifact_id="9002")
        store.artifacts[ref2] = body2
        authority.digests[ref2] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "content-address"):
            do_archive(store, authority, transport, source=source2,
                       logical_id=LOGICAL_TWO,
                       recorded_head=entry["archive_commit"])

    # Finding 4: source identity cannot be rebound at copy time.
    def test_independent_artifact_ref_that_disagrees_refuses(self):
        store, authority, transport = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "does not equal the reference"):
            archive.archive_sealed(
                logical_id=LOGICAL_ONE, kind="anchor-artifact", source=dict(SOURCE),
                artifact_ref="gh-artifact:awebai/aweb:41:0000",
                store=store, authority=authority, transport=transport,
                recorded_head=None)

    def test_malformed_source_fields_refuse(self):
        store, authority, transport = fresh_env()
        for bad in ({"repo": "no-slash", "run_id": "1", "artifact_id": "2"},
                    dict(SOURCE, run_id="notnumeric"),
                    dict(SOURCE, anchor="anchor--short--short")):
            with self.assertRaises(rd.ReceiptError):
                do_archive(store, authority, transport,
                           kind="anchor-artifact" if "anchor" in bad else "workflow-artifact",
                           source=bad, logical_id="x")

    # Finding 5: git/CLI fail-closed details.
    def test_branch_grammar_and_leading_dash_remote_refuse(self):
        with self.assertRaisesRegex(rd.ReceiptError, "strict ref"):
            archive.GitBranchArchive(remote="https://x/y.git",
                                     branch="bad branch")
        with self.assertRaisesRegex(rd.ReceiptError, "begin with"):
            archive.GitBranchArchive(remote="--upload-pack=evil",
                                     branch="release-receipts")

    def test_cli_output_labels_exact_written_bytes(self):
        # The archive CLI prints the digest of the bytes it wrote INCLUDING the
        # trailing newline; the file digest and the printed digest agree.
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        encoded = (archive.encode_index_entry(entry) + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "entry.json"
            archive._atomic_write_bytes(out, encoded)
            self.assertEqual(sha256(out.read_bytes()), sha256(encoded))
            with self.assertRaisesRegex(rd.ReceiptError, "overwrite"):
                archive._atomic_write_bytes(out, encoded)


def real_graph_and_plan():
    graph = rd.Graph.from_dict({
        "component": {
            "channel": {
                "source_paths": ["channel/"],
                "version_source": {"type": "manifest", "path": "channel/v"},
                "tag_format": "channel-v{version}",
                "verify": {"command": "true"},
            },
        },
        "edge": [],
    })
    state = rd.FixtureState(
        changed_components={"channel": True},
        versions={"channel": "1.7.2"},
        published_versions={"channel": "1.7.1"},
    )
    return graph, rd.compute_plan(graph, state)


def anchor_bundle(logical_id: str, inner: bytes):
    """A REAL release-anchor artifact: {record.json, body} plus the manifest
    archive_sealed would record for it."""
    import io
    import zipfile

    digest = sha256(inner)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("record.json", json.dumps(
            {"logical_id": logical_id, "digest": digest}))
        z.writestr("body", inner)
    outer = buf.getvalue()
    manifest = {
        "schema": archive.MANIFEST_SCHEMA,
        "logical_id": logical_id,
        "kind": "anchor-artifact",
        "source": dict(SOURCE, anchor=rd._anchor_name(logical_id, digest)),
        "source_digest": sha256(outer),
        "body_sha256": sha256(outer),
    }
    return outer, manifest


class RealAnchorSemanticsTests(unittest.TestCase):
    """Positives built from the EXISTING seal paths, not an invented format."""

    def setUp(self):
        self.graph, self.plan = real_graph_and_plan()
        self.plan_bytes, self.frozen_id = rd.freeze_plan(
            self.plan, self.graph, source_sha="a" * 40)
        self.validate = archive.semantic_validator()

    def test_real_frozen_plan_anchor_validates(self):
        body, manifest = anchor_bundle(
            f"plan:{'a' * 40}:{self.frozen_id}", self.plan_bytes)
        self.validate(body, manifest)

    def test_frozen_plan_with_unrelated_body_refuses(self):
        other_bytes, _ = rd.freeze_plan(
            self.plan, self.graph, source_sha="b" * 40)
        body, manifest = anchor_bundle(
            f"plan:{'a' * 40}:{self.frozen_id}", other_bytes)
        with self.assertRaises(rd.ReceiptError):
            self.validate(body, manifest)

    def test_real_sealed_receipt_anchor_validates(self):
        entries = {"channel": rd.ReceiptEntry(
            version="1.7.2", digest="d" * 64, phase="verified")}
        sealed, digest = rd.seal_receipt(
            self.plan, self.graph, source_sha="a" * 40, entries=entries,
            approvals={}, frozen_plan_id=self.frozen_id,
            staged_manifest_id="staged-manifest:" + self.frozen_id + ":" + "e" * 64,
        )
        body, manifest = anchor_bundle(
            f"receipt:{self.frozen_id}:{digest}", sealed)
        self.validate(body, manifest)

    def test_receipt_bound_to_a_different_frozen_plan_refuses(self):
        entries = {"channel": rd.ReceiptEntry(
            version="1.7.2", digest="d" * 64, phase="verified")}
        sealed, digest = rd.seal_receipt(
            self.plan, self.graph, source_sha="a" * 40, entries=entries,
            approvals={}, frozen_plan_id=self.frozen_id,
            staged_manifest_id="staged-manifest:" + self.frozen_id + ":" + "e" * 64,
        )
        body, manifest = anchor_bundle(f"receipt:{'f' * 64}:{digest}", sealed)
        with self.assertRaisesRegex(rd.ReceiptError, "binds frozen plan"):
            self.validate(body, manifest)

    def transition_document(self, **overrides):
        document = {
            "frozen_plan_id": self.frozen_id,
            "staged_manifest_id": f"staged-manifest:{self.frozen_id}:{'e' * 64}",
            "sequence": 1,
            "component": "channel",
            "kind": "published",
            "entry": {
                "version": "1.7.2", "digest": "d" * 64, "phase": "published",
                "pointer_state": None, "delivery_proof": None,
                "lane_ref": None, "digest_set": {"x.tgz": "a" * 64},
            },
        }
        document.update(overrides)
        return document

    def transition_anchor(self, document):
        inner = json.dumps(document, sort_keys=True).encode()
        logical = (
            f"transition:{document['frozen_plan_id']}:"
            f"{document['sequence']:03d}:{document['kind']}:"
            f"{document['component']}:{sha256(inner)}"
        )
        return anchor_bundle(logical, inner)

    def test_real_transition_anchor_validates(self):
        body, manifest = self.transition_anchor(self.transition_document())
        self.validate(body, manifest)

    def test_transition_whose_logical_id_lies_refuses(self):
        document = self.transition_document()
        inner = json.dumps(document, sort_keys=True).encode()
        # logical id claims a different component than the document carries
        logical = (f"transition:{self.frozen_id}:001:published:pi:"
                   f"{sha256(inner)}")
        body, manifest = anchor_bundle(logical, inner)
        with self.assertRaisesRegex(rd.ReceiptError, "disagrees"):
            self.validate(body, manifest)

    def test_transition_with_wrong_sequence_in_id_refuses(self):
        document = self.transition_document(sequence=2)
        inner = json.dumps(document, sort_keys=True).encode()
        logical = (f"transition:{self.frozen_id}:001:published:channel:"
                   f"{sha256(inner)}")
        body, manifest = anchor_bundle(logical, inner)
        with self.assertRaisesRegex(rd.ReceiptError, "disagrees"):
            self.validate(body, manifest)

    def test_unknown_logical_class_refuses(self):
        body, manifest = anchor_bundle("mystery:1:2", b"x")
        with self.assertRaisesRegex(rd.ReceiptError, "logical id class"):
            self.validate(body, manifest)

    def test_anchor_name_not_derived_from_logical_id_refuses(self):
        body, manifest = anchor_bundle(
            f"plan:{'a' * 40}:{self.frozen_id}", self.plan_bytes)
        manifest = dict(manifest, source=dict(
            manifest["source"], anchor=rd._anchor_name("other:id", "0" * 64)))
        with self.assertRaisesRegex(rd.ReceiptError, "anchor name"):
            self.validate(body, manifest)

    def test_inner_body_digest_mismatch_refuses(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("record.json", json.dumps(
                {"logical_id": f"plan:{'a' * 40}:{self.frozen_id}",
                 "digest": sha256(b"other")}))
            z.writestr("body", self.plan_bytes)
        manifest = {
            "schema": archive.MANIFEST_SCHEMA,
            "logical_id": f"plan:{'a' * 40}:{self.frozen_id}",
            "kind": "anchor-artifact",
            "source": dict(SOURCE, anchor=rd._anchor_name(
                f"plan:{'a' * 40}:{self.frozen_id}", sha256(b"other"))),
            "source_digest": "c" * 64, "body_sha256": "c" * 64,
        }
        with self.assertRaisesRegex(rd.ReceiptError, "inner body"):
            self.validate(buf.getvalue(), manifest)


class TransitionSetTests(unittest.TestCase):
    @staticmethod
    def document(sequence, component="channel", plan="f" * 64, kind=None):
        # (component, kind) is the unique identity; a plan legitimately has
        # several transitions for one component across kinds.
        kind = kind or f"kind-{sequence}"
        return {
            "frozen_plan_id": plan,
            "staged_manifest_id": f"staged-manifest:{plan}:{'e' * 64}",
            "sequence": sequence, "component": component, "kind": kind,
            "entry": {
                "version": "1.7.2", "digest": "d" * 64, "phase": "published",
                "pointer_state": None, "delivery_proof": None,
                "lane_ref": None, "digest_set": {},
            },
        }

    def test_complete_ordered_set_validates(self):
        archive.validate_transition_set(
            [self.document(1), self.document(2), self.document(3)])

    def test_reordered_sequence_refuses(self):
        """Reviewer counterexample: [2, 1] contains 1..n but is not archived in
        order. Sorting before comparing would accept it."""
        with self.assertRaisesRegex(rd.ReceiptError, "order archived"):
            archive.validate_transition_set(
                [self.document(2), self.document(1)])

    def test_component_inventory_must_match_the_plan(self):
        # Real kinds: a plan's effect anchor is the published transition, and
        # expected_components now requires one per component.
        docs = [self.document(1, component="channel", kind="published"),
                self.document(2, component="pi", kind="published")]
        archive.validate_transition_set(
            docs, expected_components={"channel", "pi"})
        with self.assertRaisesRegex(rd.ReceiptError, "component inventory"):
            archive.validate_transition_set(
                docs, expected_components={"channel", "pi", "server"})

    def test_entry_mismatch_against_staged_or_receipt_refuses(self):
        docs = [self.document(1, component="channel")]
        good = {"channel": dict(docs[0]["entry"])}
        archive.validate_transition_set(
            docs, staged_entries=good, receipt_entries=good)
        drifted = {"channel": dict(docs[0]["entry"], digest="0" * 64)}
        with self.assertRaisesRegex(rd.ReceiptError, "field for field"):
            archive.validate_transition_set(docs, staged_entries=drifted)
        with self.assertRaisesRegex(rd.ReceiptError, "field for field"):
            archive.validate_transition_set(docs, receipt_entries=drifted)

    def test_duplicate_component_kind_refuses(self):
        with self.assertRaisesRegex(rd.ReceiptError, "repeats a component"):
            archive.validate_transition_set(
                [self.document(1, kind="published"),
                 self.document(2, kind="published")])

    def test_duplicate_sequence_refuses(self):
        with self.assertRaisesRegex(rd.ReceiptError, "ordered set"):
            archive.validate_transition_set(
                [self.document(1), self.document(1)])

    def test_gap_in_sequence_refuses(self):
        with self.assertRaisesRegex(rd.ReceiptError, "ordered set"):
            archive.validate_transition_set(
                [self.document(1), self.document(3)])

    def test_mixed_frozen_plans_refuse(self):
        with self.assertRaisesRegex(rd.ReceiptError, "multiple frozen plans"):
            archive.validate_transition_set(
                [self.document(1), self.document(2, plan="a" * 64)])

    def test_empty_set_refuses(self):
        with self.assertRaisesRegex(rd.ReceiptError, "empty"):
            archive.validate_transition_set([])


class SealTimeTransitionValidationTests(unittest.TestCase):
    def test_sealing_path_validates_the_same_shape(self):
        # anchor_transition validates before sealing, so the sealing and
        # re-validation paths share one definition and cannot drift.
        source = (SCRIPTS / "release_driver.py").read_text()
        sealing = source[source.index("def anchor_transition("):]
        sealing = sealing[:sealing.index("_put_content_addressed")]
        self.assertIn("validate_transition_document(document)", sealing)

    def test_invalid_transition_document_refuses(self):
        bad = {"frozen_plan_id": "f" * 64, "sequence": 1}
        with self.assertRaisesRegex(rd.ReceiptError, "transition document"):
            rd.validate_transition_document(bad)


class ReviewedIndexRoundTwoTests(unittest.TestCase):
    """Alice's .9 round-2 blocker 2: index completeness is enforced, not
    claimed."""

    def authority(self, document_bytes):
        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40
            def is_ancestor(self, a, d):
                return True
            def file_at(self, commit, path):
                return document_bytes
        return archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())

    def valid_entry(self, logical_id=LOGICAL_ONE):
        store, auth, transport = fresh_env()
        return do_archive(store, auth, transport, logical_id=logical_id)

    def canonical_index(self, entries):
        return json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": entries,
        }, sort_keys=True, separators=(",", ":")).encode()

    def test_noncanonical_index_bytes_refuse(self):
        entry = self.valid_entry()
        pretty = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": [entry]}, indent=2).encode()
        with self.assertRaisesRegex(rd.ReceiptError, "canonical"):
            self.authority(pretty).lookup(entry["logical_id"])

    def test_extra_top_level_key_refuses(self):
        entry = self.valid_entry()
        doc = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": [entry], "extra": 1},
            sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaisesRegex(rd.ReceiptError, "schema|keys"):
            self.authority(doc).lookup(entry["logical_id"])

    def test_malformed_unrelated_entry_refuses(self):
        entry = self.valid_entry()
        doc = self.canonical_index([entry, {"logical_id": "junk"}])
        with self.assertRaisesRegex(rd.ReceiptError, "index entry"):
            self.authority(doc).lookup(entry["logical_id"])

    def test_global_duplicate_logical_ids_refuse(self):
        entry = self.valid_entry()
        doc = self.canonical_index([entry, dict(entry)])
        with self.assertRaisesRegex(rd.ReceiptError, "more than once|duplicate"):
            self.authority(doc).lookup(entry["logical_id"])

    def test_valid_canonical_index_returns_entry(self):
        entry = self.valid_entry()
        doc = self.canonical_index([entry])
        self.assertEqual(self.authority(doc).lookup(entry["logical_id"]), entry)

    def test_established_ssh_remote_is_production(self):
        transport = archive.GitBranchArchive(
            remote="ssh://git@ssh.github.com:443/awebai/aweb.git",
            branch="release-receipts")
        self.addCleanup(transport.close)
        self.assertEqual(transport.trust_class, "durable-byte-store")

    def test_atomic_write_refuses_preexisting_part_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x.json"
            part = Path(tmp) / "x.json.part"
            part.write_bytes(b"squatted")
            with self.assertRaisesRegex(rd.ReceiptError, "temporary|exists"):
                archive._atomic_write_bytes(out, b"data")


class ProductionPathControlTests(unittest.TestCase):
    """Alice's .9 round-4 gaps: a helper not reached from production is not a
    control, and a durable branch must not be mutated before semantics are
    validated."""

    # Gap 2: archive write must run the real semantic validator BEFORE append.
    def test_semantically_invalid_artifact_is_not_appended(self):
        body = b"digest-authorized but not a valid anchor bundle"
        ref = "gh-artifact:awebai/aweb:41:9001"
        store = FakeStore({ref: body})
        authority = FakeAuthority({ref: sha256(body)})
        transport = FakeArchiveTransport()
        with self.assertRaises(rd.ReceiptError):
            archive.archive_sealed(
                logical_id="receipt:" + "f" * 64 + ":" + "a" * 64,
                kind="anchor-artifact", source=dict(SOURCE),
                store=store, authority=authority, transport=transport,
                recorded_head=None)
        self.assertIsNone(transport.head,
                          "durable branch must not be mutated on refusal")
        self.assertEqual(transport.commits, {})

    def test_valid_anchor_is_appended(self):
        graph, plan = real_graph_and_plan()
        plan_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="a" * 40)
        logical = f"plan:{'a' * 40}:{frozen_id}"
        body, _ = anchor_bundle(logical, plan_bytes)
        ref = "gh-artifact:awebai/aweb:41:9001"
        store = FakeStore({ref: body})
        authority = FakeAuthority({ref: sha256(body)})
        transport = FakeArchiveTransport()
        entry = archive.archive_sealed(
            logical_id=logical, kind="anchor-artifact",
            source=dict(SOURCE, anchor=rd._anchor_name(
                logical, sha256(plan_bytes))),
            store=store, authority=authority, transport=transport,
            recorded_head=None)
        self.assertIsNotNone(transport.head)
        self.assertEqual(entry["logical_id"], logical)

    # Gap 2 positive: a REAL lane ZIP through production archive dispatch.
    def test_real_lane_zip_archives_and_restores(self):
        import io
        import zipfile

        version = "1.26.36"
        wheel = b"exact staged wheel bytes"
        sdist = b"exact staged sdist bytes"
        names = {
            f"aweb-{version}-py3-none-any.whl": wheel,
            f"aweb-{version}.tar.gz": sdist,
        }
        files = {n: sha256(d) for n, d in names.items()}
        manifest = {
            "mode": "stage-only", "package": "server",
            "tag": f"server-v{version}", "candidate_version": version,
            "source_sha": "c" * 40, "files": files,
            "canonical_set_digest": sha256(
                json.dumps(files, sort_keys=True).encode()),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(manifest))
            for n, d in names.items():
                z.writestr(f"dist/{n}", d)
        lane_zip = buf.getvalue()

        ref = "gh-artifact:awebai/aweb:41:9001"
        store = FakeStore({ref: lane_zip})
        authority = FakeAuthority({ref: sha256(lane_zip)})
        transport = FakeArchiveTransport()
        source = {k: v for k, v in SOURCE.items() if k != "anchor"}
        source["source_sha"] = "c" * 40
        entry = archive.archive_sealed(
            logical_id=f"lane:server:{version}:{'c' * 40}",
            kind="workflow-artifact",
            source=source, store=store, authority=authority,
            transport=transport, recorded_head=None)
        restored = archive.restore_archived(
            entry=entry, transport=transport, production=False,
            validate=archive.semantic_validator())
        self.assertEqual(restored, lane_zip,
                         "a real lane ZIP round-trips through production "
                         "archive and restore dispatch")

    # Gap 1: production restore of a receipt must enforce the complete set.
    # The end-to-end control lives in RoundFiveCounterexampleTests, which
    # drives a real set through the real index authority; asserting the
    # function merely exists proves nothing about whether it is reached.

    def test_lone_out_of_order_transition_refuses_in_set_restore(self):
        docs = [{
            "frozen_plan_id": "f" * 64,
            "staged_manifest_id": f"staged-manifest:{'f' * 64}:{'e' * 64}",
            "sequence": 2, "component": "channel", "kind": "published",
            "entry": {"version": "1.7.2", "digest": "d" * 64,
                      "phase": "published", "pointer_state": None,
                      "delivery_proof": None, "lane_ref": None,
                      "digest_set": {}},
        }]
        with self.assertRaisesRegex(rd.ReceiptError, "ordered set"):
            archive.validate_transition_set(docs)


class RoundFiveCounterexampleTests(unittest.TestCase):
    """Alice's round-5 named counterexamples, built rather than asserted.

    Blocker 2 shipped with its counterexamples; blockers 1, 3 and 4 shipped
    with implementations and no adversarial test. That is the exact shape that
    produced the round-5 sort bug: the code looked right and nothing tried the
    input that breaks it.
    """

    SOURCE_SHA = "a" * 40

    # ---- a complete, real release set -------------------------------------
    def real_release_set(self, *, source_sha=None, entry_digest=None,
                         staged_digest=None, components=("channel",),
                         delivery_obligation=None, receipt_partial=False,
                         receipt_plan_digest=None,
                         transition_kinds=("published",)):
        source_sha = source_sha or self.SOURCE_SHA
        entry_digest = entry_digest or "d" * 64
        staged_digest = staged_digest or entry_digest
        graph_data = {
            "component": {
                component: {
                    "source_paths": [f"{component}/"],
                    "version_source": {
                        "type": "manifest", "path": f"{component}/v"},
                    "tag_format": f"{component}-v{{version}}",
                    "verify": {"command": "true"},
                }
                for component in components
            },
            "edge": [],
        }
        graph = rd.Graph.from_dict(graph_data)
        versions = {
            component: f"1.7.{index + 2}"
            for index, component in enumerate(components)
        }
        plan = rd.compute_plan(graph, rd.FixtureState(
            changed_components={component: True for component in components},
            versions=versions,
            published_versions={
                component: f"1.7.{index + 1}"
                for index, component in enumerate(components)
            },
        ))
        plan_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha=source_sha)
        staged = {
            component: rd.ReceiptEntry(
                version=versions[component],
                digest=staged_digest if component == "channel" else "d" * 64,
                phase="staged",
            )
            for component in components
        }
        manifest_bytes, manifest_digest = rd.seal_staged_manifest(
            plan, frozen_plan_id=frozen_id, source_sha=source_sha,
            entries=staged, graph=graph)
        if delivery_obligation is not None:
            manifest_document = json.loads(manifest_bytes)
            manifest_document["entries"]["channel"][
                "delivery_obligation"] = delivery_obligation
            manifest_bytes = json.dumps(
                manifest_document, sort_keys=True).encode()
            manifest_digest = sha256(manifest_bytes)
        staged_id = f"staged-manifest:{frozen_id}:{manifest_digest}"

        transitions = []
        sequence = 0
        for component in components:
            for kind in transition_kinds:
                sequence += 1
                digest = entry_digest if component == "channel" else "d" * 64
                document = {
                    "frozen_plan_id": frozen_id,
                    "staged_manifest_id": staged_id,
                    "sequence": sequence,
                    "component": component,
                    "kind": kind,
                    "entry": {"version": versions[component],
                              "digest": digest,
                              "phase": "published", "pointer_state": None,
                              "delivery_proof": None, "lane_ref": None,
                              "digest_set": None},
                }
                body = json.dumps(document, sort_keys=True).encode()
                logical = (f"transition:{frozen_id}:{sequence:03d}:{kind}:"
                           f"{component}:{sha256(body)}")
                transitions.append((logical, body))

        receipt_entries = {
            component: rd.ReceiptEntry(
                version=versions[component],
                digest="d" * 64, phase="verified")
            for component in components
        }
        sealed, receipt_digest = rd.seal_receipt(
            plan, graph, source_sha=source_sha, entries=receipt_entries,
            approvals={}, frozen_plan_id=frozen_id,
            staged_manifest_id=staged_id, partial=receipt_partial)
        if receipt_plan_digest is not None:
            outer = json.loads(sealed)
            receipt_document = json.loads(outer["body"])
            receipt_document["plan_digest"] = receipt_plan_digest
            outer["body"] = json.dumps(receipt_document, sort_keys=True)
            outer["seal"] = sha256(outer["body"].encode())
            sealed = json.dumps(outer).encode()
            receipt_digest = sha256(sealed)

        artifacts = [
            (f"plan:{source_sha}:{frozen_id}", plan_bytes),
            (staged_id, manifest_bytes),
            *transitions,
            (f"receipt:{frozen_id}:{receipt_digest}", sealed),
        ]
        return {
            "frozen_plan_id": frozen_id,
            "plan_bytes": plan_bytes,
            "plan": artifacts[0][0],
            "staged_manifest": staged_id,
            "transitions": [logical for logical, _ in transitions],
            "receipt": artifacts[-1][0],
            "artifacts": artifacts,
        }

    def archive_all(self, artifacts):
        """Every artifact through the REAL production archive path, with the
        default semantic validator - not a permissive one."""
        transport = FakeArchiveTransport()
        entries = []
        for index, (logical, inner) in enumerate(artifacts):
            body, _ = anchor_bundle(logical, inner)
            # The artifact ref must be derived from the recorded source
            # identity, so each artifact needs its own source id, not just its
            # own ref.
            artifact_id = str(9000 + index)
            ref = f"gh-artifact:awebai/aweb:41:{artifact_id}"
            entries.append(archive.archive_sealed(
                logical_id=logical, kind="anchor-artifact",
                source=dict(SOURCE, artifact_id=artifact_id,
                            anchor=rd._anchor_name(
                                logical, sha256(inner))),
                store=FakeStore({ref: body}),
                authority=FakeAuthority({ref: sha256(body)}),
                transport=transport, artifact_ref=ref,
                recorded_head=transport.head))
        return transport, entries

    def index_authority(self, entries, release_sets):
        document = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": entries,
            "release_sets": release_sets,
        }, sort_keys=True, separators=(",", ":")).encode()

        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40

            def is_ancestor(self, ancestor, descendant):
                return True

            def file_at(self, commit, path):
                return document

        return archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())

    def inventory(self, released, **overrides):
        base = {
            "frozen_plan_id": released["frozen_plan_id"],
            "plan": released["plan"],
            "staged_manifest": released["staged_manifest"],
            "transitions": list(released["transitions"]),
            "receipt": released["receipt"],
        }
        base.update(overrides)
        return base

    # ---- blocker 1: the production set restore, end to end ----------------
    def test_real_production_set_restore_round_trips(self):
        released = self.real_release_set()
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(
            entries, [self.inventory(released)])

        restored = archive.restore_release_set(
            frozen_plan_id=released["frozen_plan_id"], transport=transport,
            index_authority=authority, production=True)

        self.assertEqual(restored["frozen_plan_id"], released["frozen_plan_id"])
        self.assertEqual([d["sequence"] for d in restored["transitions"]],
                         [1])
        self.assertEqual({d["component"] for d in restored["transitions"]},
                         {"channel"})

    def test_set_restore_refuses_an_inventory_missing_a_transition(self):
        """Completeness is the whole point: dropping the staged transition
        leaves a set whose sequences are [2], not 1..n."""
        released = self.real_release_set()
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(
            released, transitions=[])])

        with self.assertRaisesRegex(rd.ReceiptError, "no transitions"):
            archive.restore_release_set(
                frozen_plan_id=released["frozen_plan_id"], transport=transport,
                index_authority=authority, production=True)

    def test_set_restore_refuses_reordered_inventory(self):
        """The reviewer's [2, 1]: every artifact is present and intact, and the
        SET is still wrong."""
        released = self.real_release_set(components=("channel", "pi"))
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(
            released, transitions=list(reversed(released["transitions"])))])

        with self.assertRaisesRegex(rd.ReceiptError, "order archived"):
            archive.restore_release_set(
                frozen_plan_id=released["frozen_plan_id"], transport=transport,
                index_authority=authority, production=True)

    def test_set_restore_refuses_an_index_with_no_release_sets(self):
        released = self.real_release_set()
        transport, entries = self.archive_all(released["artifacts"])
        document = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": entries,
        }, sort_keys=True, separators=(",", ":")).encode()

        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40

            def is_ancestor(self, a, d):
                return True

            def file_at(self, commit, path):
                return document

        authority = archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())
        with self.assertRaisesRegex(rd.ReceiptError, "release_sets"):
            archive.restore_release_set(
                frozen_plan_id=released["frozen_plan_id"], transport=transport,
                index_authority=authority, production=True)

    def test_set_restore_refuses_a_transition_from_another_plan(self):
        """Substituting a foreign-but-valid transition: it is a real sealed
        document, correctly archived, and it belongs to a different release."""
        released = self.real_release_set()
        other = self.real_release_set(source_sha="b" * 40)
        transport, entries = self.archive_all(
            released["artifacts"] + other["artifacts"])
        authority = self.index_authority(entries, [self.inventory(
            released,
            transitions=[released["transitions"][0], other["transitions"][0]])])

        with self.assertRaisesRegex(rd.ReceiptError, "bind the frozen plan"):
            archive.restore_release_set(
                frozen_plan_id=released["frozen_plan_id"], transport=transport,
                index_authority=authority, production=True)

    # ---- blocker 3: source and lane substitution --------------------------
    def test_plan_id_claiming_a_foreign_source_refuses(self):
        """Source substitution. The body is a REAL frozen plan and its digest
        matches the id, so every byte check passes; only the source claim is
        false."""
        graph, plan = real_graph_and_plan()
        plan_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="b" * 40)
        body, manifest = anchor_bundle(
            f"plan:{'a' * 40}:{frozen_id}", plan_bytes)
        with self.assertRaisesRegex(rd.ReceiptError, "claims source"):
            archive.semantic_validator()(body, manifest)

    def test_plan_id_binding_its_real_source_validates(self):
        """The control for the test above: identical machinery, true claim."""
        graph, plan = real_graph_and_plan()
        plan_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="b" * 40)
        body, manifest = anchor_bundle(
            f"plan:{'b' * 40}:{frozen_id}", plan_bytes)
        archive.semantic_validator()(body, manifest)

    def lane_zip(self, *, package="channel", version="1.7.2",
                 source_sha="c" * 40):
        import io
        import zipfile

        tgz = b"exact staged tarball bytes"
        name = f"{package}-{version}.tgz"
        files = {name: sha256(tgz)}
        lane_manifest = {
            "mode": "stage-only", "package": package,
            "tag": f"{package}-v{version}", "candidate_version": version,
            "source_sha": source_sha, "files": files,
            "canonical_set_digest": sha256(
                json.dumps(files, sort_keys=True).encode()),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(lane_manifest))
            z.writestr(f"dist/{name}", tgz)
        return buf.getvalue()

    def pypi_lane_zip(self, *, version="1.26.36", source_sha="c" * 40):
        import io
        import zipfile

        names = {
            f"aweb-{version}-py3-none-any.whl": b"exact staged wheel " + source_sha.encode(),
            f"aweb-{version}.tar.gz": b"exact staged sdist " + source_sha.encode(),
        }
        files = {n: sha256(d) for n, d in names.items()}
        lane_manifest = {
            "mode": "stage-only", "package": "server",
            "tag": f"server-v{version}", "candidate_version": version,
            "source_sha": source_sha, "files": files,
            "canonical_set_digest": sha256(
                json.dumps(files, sort_keys=True).encode()),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", json.dumps(lane_manifest))
            for n, d in names.items():
                z.writestr(f"dist/{n}", d)
        return buf.getvalue()

    def lane_manifest_for(self, body, logical_id, source_sha="c" * 40,
                          **source_extra):
        source = {k: v for k, v in SOURCE.items() if k != "anchor"}
        source["source_sha"] = source_sha
        source.update(source_extra)
        return {
            "schema": archive.MANIFEST_SCHEMA,
            "logical_id": logical_id,
            "kind": "workflow-artifact",
            "source": source,
            "source_digest": sha256(body),
            "body_sha256": sha256(body),
        }

    def test_lane_id_claiming_a_foreign_package_refuses(self):
        """Lane substitution by package: real channel bytes, labelled pi."""
        body = self.lane_zip(package="channel", version="1.7.2")
        manifest = self.lane_manifest_for(body, "lane:pi:1.7.2:" + "c" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "lane manifest binds"):
            archive.semantic_validator()(body, manifest)

    def test_lane_id_claiming_a_foreign_version_refuses(self):
        """Lane substitution by version: the 1.7.1 bytes relabelled 1.7.2 is
        precisely the swap byte-identity exists to prevent."""
        body = self.lane_zip(package="channel", version="1.7.1")
        manifest = self.lane_manifest_for(body, "lane:channel:1.7.2:" + "c" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "lane manifest binds"):
            archive.semantic_validator()(body, manifest)

    def test_same_package_version_from_two_sources_are_distinct(self):
        """Two VALID stagings of the same package/version from different
        commits. Without the source in the identity either could stand in for
        the other, and both would validate."""
        first = self.pypi_lane_zip(source_sha="c" * 40)
        second = self.pypi_lane_zip(source_sha="e" * 40)
        self.assertNotEqual(first, second, "distinct sources, distinct bytes")
        validate = archive.semantic_validator()
        validate(first, self.lane_manifest_for(
            first, f"lane:server:1.26.36:{'c' * 40}", source_sha="c" * 40))
        validate(second, self.lane_manifest_for(
            second, f"lane:server:1.26.36:{'e' * 40}", source_sha="e" * 40))

    def test_substituting_the_other_source_artifact_refuses(self):
        second = self.pypi_lane_zip(source_sha="e" * 40)
        # The first artifact's identity, the second artifact's bytes.
        manifest = self.lane_manifest_for(
            second, f"lane:server:1.26.36:{'c' * 40}", source_sha="c" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "source"):
            archive.semantic_validator()(second, manifest)

    def test_lane_id_source_alone_wrong_refuses(self):
        """Discriminating for the ID binding: the archive source AGREES with
        the lane manifest, so only the logical id disagrees. The
        archive-source check cannot see this one."""
        body = self.pypi_lane_zip(source_sha="e" * 40)
        manifest = self.lane_manifest_for(
            body, f"lane:server:1.26.36:{'c' * 40}", source_sha="e" * 40)
        with self.assertRaisesRegex(
            rd.ReceiptError, "logical id source"
        ):
            archive.semantic_validator()(body, manifest)

    def test_lane_id_without_a_source_sha_refuses(self):
        body = self.pypi_lane_zip()
        manifest = self.lane_manifest_for(body, "lane:server:1.26.36")
        with self.assertRaisesRegex(rd.ReceiptError, "malformed"):
            archive.semantic_validator()(body, manifest)

    def test_archive_source_claiming_a_foreign_commit_refuses(self):
        body = self.pypi_lane_zip(source_sha="c" * 40)
        manifest = self.lane_manifest_for(
            body, f"lane:server:1.26.36:{'d' * 40}", source_sha="d" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "source"):
            archive.semantic_validator()(body, manifest)

    # ---- blocker 4: the output race ---------------------------------------
    def test_output_commit_refuses_a_target_created_after_the_check(self):
        """The race the os.link commit exists to close: the target does not
        exist when _atomic_write_bytes checks, and does exist by the time it
        commits. Simulated deterministically by creating it from inside the
        write, which is the only way to occupy that window on purpose."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "receipt.json"
            real_fdopen = os.fdopen

            def racing_fdopen(fd, mode, *args, **kwargs):
                handle = real_fdopen(fd, mode, *args, **kwargs)
                if not out.exists():
                    out.write_bytes(b"written by the loser of the race")
                return handle

            with unittest.mock.patch.object(os, "fdopen", racing_fdopen):
                with self.assertRaisesRegex(rd.ReceiptError, "concurrently"):
                    archive._atomic_write_bytes(out, b"our bytes")

            self.assertEqual(out.read_bytes(),
                             b"written by the loser of the race",
                             "the concurrent writer's bytes must survive; a "
                             "replace-based commit would have clobbered them")
            self.assertFalse((Path(tmp) / "receipt.json.part").exists(),
                             "a failed commit must not leave .part bytes")

    def test_output_commit_leaves_no_part_file_on_write_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "receipt.json"

            class Exploding:
                def write(self, data):
                    raise OSError("disk full")

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            with unittest.mock.patch.object(
                os, "fdopen", lambda fd, *a, **k: (
                    os.close(fd), Exploding())[1]
            ):
                with self.assertRaises(OSError):
                    archive._atomic_write_bytes(out, b"our bytes")

            self.assertFalse(out.exists())
            self.assertFalse((Path(tmp) / "receipt.json.part").exists())

    def test_successful_write_commits_exactly_the_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "receipt.json"
            archive._atomic_write_bytes(out, b"our bytes")
            self.assertEqual(out.read_bytes(), b"our bytes")
            self.assertFalse((Path(tmp) / "receipt.json.part").exists())



class GitEnvironmentRedirectTests(unittest.TestCase):
    """Reviewer blocker 4: ambient git configuration could redirect the
    canonical remote to an attacker-controlled repository.

    GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_SYSTEM=/dev/null do NOT stop
    GIT_CONFIG_COUNT/KEY/VALUE: those inject configuration directly, so an
    ambient insteadOf rewrite survived into every git invocation.

    `git ls-remote --get-url` resolves insteadOf and prints the result without
    touching the network, so the redirect is provable deterministically.
    """

    CANONICAL = "ssh://git@ssh.github.com:443/awebai/aweb.git"

    def resolved_url(self, env):
        result = subprocess.run(
            ["git", "ls-remote", "--get-url", self.CANONICAL],
            capture_output=True, env=env)
        return result.stdout.decode().strip()

    def hostile_ambient(self, attacker):
        return {
            **os.environ,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.{attacker}.insteadOf",
            "GIT_CONFIG_VALUE_0": "ssh://git@ssh.github.com:443/",
        }

    def test_ambient_insteadof_redirects_when_unsanitized(self):
        """Positive control: without this the negative proves nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            attacker = f"{tmp}/attacker/"
            resolved = self.resolved_url(self.hostile_ambient(attacker))
            self.assertTrue(
                resolved.startswith(tmp),
                f"the attack must actually work unsanitized, got {resolved!r}")

    def test_sanitized_environment_refuses_the_redirect(self):
        with tempfile.TemporaryDirectory() as tmp:
            attacker = f"{tmp}/attacker/"
            hostile = self.hostile_ambient(attacker)
            saved = {k: os.environ.get(k) for k in (
                "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")}
            try:
                os.environ.update({k: v for k, v in hostile.items()
                                   if k.startswith("GIT_CONFIG_")})
                sanitized = archive.GitBranchArchive._sanitized_env()
                resolved = self.resolved_url(sanitized)
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(
                resolved, self.CANONICAL,
                "the canonical remote must survive an ambient insteadOf")

    def test_sanitized_environment_drops_ambient_git_and_ssh_controls(self):
        hostile = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "url.https://evil.invalid/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/",
            "GIT_SSH": "/tmp/evil-ssh",
            "GIT_SSH_COMMAND": "/tmp/evil-ssh",
            "GIT_PROXY_COMMAND": "/tmp/evil-proxy",
            "GIT_ASKPASS": "/tmp/evil-askpass",
            "GIT_EXTERNAL_DIFF": "/tmp/evil-diff",
            "GIT_DIR": "/tmp/evil-dir",
            "GIT_WORK_TREE": "/tmp/evil-tree",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/evil-objects",
            "GIT_NAMESPACE": "evil",
            "GIT_INDEX_FILE": "/tmp/evil-index",
            "GIT_TEMPLATE_DIR": "/tmp/evil-template",
            "ALL_PROXY": "socks5://evil.invalid:1080",
            "HTTPS_PROXY": "http://evil.invalid:8080",
        }
        saved = {k: os.environ.get(k) for k in hostile}
        try:
            os.environ.update(hostile)
            sanitized = archive.GitBranchArchive._sanitized_env()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        leaked = {
            key: sanitized[key] for key in hostile
            if key in sanitized and sanitized[key] == hostile[key]
        }
        self.assertEqual(
            leaked, {},
            f"ambient git/ssh/proxy controls reached the child: {leaked}")

    def test_sanitized_environment_keeps_only_what_transport_needs(self):
        sanitized = archive.GitBranchArchive._sanitized_env()
        self.assertNotIn("GIT_CONFIG_KEY_0", sanitized)
        self.assertEqual(sanitized.get("GIT_CONFIG_COUNT"), "0")
        self.assertEqual(sanitized.get("GIT_CONFIG_GLOBAL"), "/dev/null")
        self.assertEqual(sanitized.get("GIT_CONFIG_SYSTEM"), "/dev/null")
        self.assertEqual(sanitized.get("GIT_TERMINAL_PROMPT"), "0")
        self.assertEqual(sanitized.get("PATH"), archive.SYSTEM_PATH)
        self.assertTrue(
            sanitized.get("GIT_SSH_COMMAND", "").startswith(
                archive.SYSTEM_SSH + " "),
            "Git must dispatch SSH through the fixed reviewed executable")

    def test_hostile_path_fake_git_cannot_replace_reviewed_git(self):
        """The attack is live: bare `git` resolves to the fake, while both
        production Git surfaces execute the fixed reviewed binary and return
        the real local remote identity without touching the marker."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "fake-git-ran"
            fake = fake_bin / "git"
            fake.write_text(
                "#!/bin/sh\n"
                f"echo invoked >> {marker}\n"
                "printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\t"
                "refs/heads/main\\n'\n")
            fake.chmod(0o755)

            attack = subprocess.run(
                ["git", "--version"], env={"PATH": str(fake_bin)},
                capture_output=True)
            self.assertEqual(attack.returncode, 0)
            self.assertTrue(marker.exists(),
                            "control: hostile PATH must execute the fake git")
            marker.unlink()

            remote = root / "remote.git"
            source = root / "source"
            subprocess.run(
                [archive.SYSTEM_GIT, "init", "--bare", str(remote)],
                capture_output=True, check=True)
            subprocess.run(
                [archive.SYSTEM_GIT, "init", "--initial-branch", "main",
                 str(source)], capture_output=True, check=True)
            (source / "index").write_text("reviewed")
            git_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "reviewed-control",
                "GIT_AUTHOR_EMAIL": "reviewed@example.invalid",
                "GIT_COMMITTER_NAME": "reviewed-control",
                "GIT_COMMITTER_EMAIL": "reviewed@example.invalid",
            }
            subprocess.run(
                [archive.SYSTEM_GIT, "add", "index"], cwd=source,
                env=git_env, capture_output=True, check=True)
            subprocess.run(
                [archive.SYSTEM_GIT, "commit", "-m", "reviewed"], cwd=source,
                env=git_env, capture_output=True, check=True)
            expected = subprocess.run(
                [archive.SYSTEM_GIT, "rev-parse", "HEAD"], cwd=source,
                capture_output=True, check=True).stdout.decode().strip()
            subprocess.run(
                [archive.SYSTEM_GIT, "push", str(remote),
                 "HEAD:refs/heads/main"], cwd=source,
                capture_output=True, check=True)

            saved_path = os.environ.get("PATH")
            os.environ["PATH"] = str(fake_bin)
            reader = None
            transport = None
            try:
                reader = archive._GitReader(str(remote))
                self.assertEqual(reader.ls_remote("refs/heads/main"), expected)
                transport = archive.GitBranchArchive(
                    remote=str(remote), branch="main")
                self.assertEqual(transport.fetch_head(), expected)
            finally:
                if transport is not None:
                    transport.close()
                if reader is not None:
                    reader.close()
                if saved_path is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = saved_path
            self.assertFalse(
                marker.exists(),
                "reviewed-index and archive Git must not execute PATH's fake")

    def test_reviewed_index_reader_uses_the_same_sanitized_environment(self):
        """Both surfaces the reviewer named must be covered, not just one."""
        source = Path(archive.__file__).read_text()
        reader = source.split("class _GitReader")[1].split("class ")[0]
        self.assertIn("_sanitized_env", reader,
                      "the reviewed-index reader must sanitize identically to "
                      "the archive transport")




class UnrelatedReleaseSetTests(unittest.TestCase):
    """Reviewer blocker 3: every release-set record must validate, not only the
    one a caller asks for. A corrupt index that serves one good answer while
    hiding malformed or duplicated neighbours is still a corrupt index."""

    def authority(self, document_bytes):
        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40

            def is_ancestor(self, a, d):
                return True

            def file_at(self, commit, path):
                return document_bytes

        return archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())

    def index(self, sets):
        store, auth, transport = fresh_env()
        entry = do_archive(store, auth, transport)
        return json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": [entry],
            "release_sets": sets,
        }, sort_keys=True, separators=(",", ":")).encode(), entry

    def good_set(self, plan="a" * 64):
        return {
            "frozen_plan_id": plan,
            "plan": f"plan:{'c' * 40}:{plan}",
            "staged_manifest": f"staged-manifest:{plan}:{'e' * 64}",
            "transitions": [
                f"transition:{plan}:001:published:channel:{'d' * 64}"],
            "receipt": f"receipt:{plan}:{'f' * 64}",
        }

    def test_malformed_unrelated_set_refuses(self):
        body, entry = self.index([self.good_set(), {"frozen_plan_id": "b" * 64}])
        with self.assertRaises(rd.ReceiptError):
            self.authority(body).release_set("a" * 64)

    def test_duplicate_unrelated_plan_refuses(self):
        other = self.good_set("b" * 64)
        body, entry = self.index([self.good_set(), other, dict(other)])
        with self.assertRaisesRegex(rd.ReceiptError, "more than once"):
            self.authority(body).release_set("a" * 64)

    def test_unrelated_defect_also_refuses_plain_entry_lookup(self):
        """The index is validated as a whole, so a single-artifact lookup must
        not quietly succeed against a corrupt index either."""
        body, entry = self.index([{"frozen_plan_id": "b" * 64}])
        with self.assertRaises(rd.ReceiptError):
            self.authority(body).lookup(entry["logical_id"])

    def test_complete_shaped_unrelated_arbitrary_logical_ids_refuse(self):
        unrelated = {
            "frozen_plan_id": "b" * 64,
            "plan": "x",
            "staged_manifest": "y",
            "transitions": ["z"],
            "receipt": "q",
        }
        body, entry = self.index([self.good_set(), unrelated])
        with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
            self.authority(body).release_set("a" * 64)

    def test_every_logical_id_must_bind_its_record_frozen_plan(self):
        plan = "b" * 64
        wrong = "c" * 64
        mutations = {
            "plan": f"plan:{'d' * 40}:{wrong}",
            "staged_manifest": f"staged-manifest:{wrong}:{'e' * 64}",
            "transitions": [
                f"transition:{wrong}:001:published:channel:{'d' * 64}"],
            "receipt": f"receipt:{wrong}:{'f' * 64}",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                unrelated = self.good_set(plan)
                unrelated[field] = value
                body, entry = self.index([self.good_set(), unrelated])
                with self.assertRaisesRegex(rd.ReceiptError, "frozen plan"):
                    self.authority(body).lookup(entry["logical_id"])

    def test_release_set_logical_id_grammar_is_exact(self):
        malformed = [
            dict(self.good_set("b" * 64), plan="plan:not-a-sha:" + "b" * 64),
            dict(self.good_set("b" * 64),
                 staged_manifest=f"staged-manifest:{'b' * 64}:short"),
            dict(self.good_set("b" * 64), transitions=[
                f"transition:{'b' * 64}:1:published:channel:{'d' * 64}"]),
            dict(self.good_set("b" * 64), transitions=[
                f"transition:{'b' * 64}:001:unreviewed-control:channel:"
                f"{'d' * 64}"]),
            dict(self.good_set("b" * 64), receipt="receipt:bad"),
        ]
        for record in malformed:
            with self.subTest(record=record):
                body, entry = self.index([self.good_set(), record])
                with self.assertRaises(rd.ReceiptError):
                    self.authority(body).lookup(entry["logical_id"])

    def test_valid_sets_still_resolve(self):
        body, entry = self.index([self.good_set(), self.good_set("b" * 64)])
        resolved = self.authority(body).release_set("a" * 64)
        self.assertEqual(resolved["frozen_plan_id"], "a" * 64)




class GlobalLogicalIdTests(unittest.TestCase):
    """Every archive kind has one closed logical-ID namespace.

    Real lane bytes must not become trusted under an arbitrary index name just
    because their inner lane manifest is valid.
    """

    SOURCE_SHA = "c" * 40
    VALID_LOGICAL = f"lane:server:1.26.36:{SOURCE_SHA}"
    INVALID_LOGICALS = (
        "arbitrary-reviewed-index-name",
        "staged:server:1.26.36",
        f"receipt:{'f' * 64}:{'e' * 64}",
    )

    def lane_zip(self):
        import io
        import zipfile

        version = "1.26.36"
        names = {
            f"aweb-{version}-py3-none-any.whl": b"exact staged wheel",
            f"aweb-{version}.tar.gz": b"exact staged sdist",
        }
        files = {name: sha256(data) for name, data in names.items()}
        lane_manifest = {
            "mode": "stage-only", "package": "server",
            "tag": f"server-v{version}", "candidate_version": version,
            "source_sha": self.SOURCE_SHA, "files": files,
            "canonical_set_digest": sha256(
                json.dumps(files, sort_keys=True).encode()),
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as lane:
            lane.writestr("manifest.json", json.dumps(lane_manifest))
            for name, data in names.items():
                lane.writestr(f"dist/{name}", data)
        return buffer.getvalue()

    def source(self):
        return {
            "repo": "awebai/aweb", "run_id": "41", "artifact_id": "9001",
            "source_sha": self.SOURCE_SHA,
        }

    def manifest(self, body, logical_id):
        return {
            "schema": archive.MANIFEST_SCHEMA,
            "logical_id": logical_id,
            "kind": "workflow-artifact",
            "source": self.source(),
            "source_digest": sha256(body),
            "body_sha256": sha256(body),
        }

    def manual_entry(self, body, logical_id):
        manifest = self.manifest(body, logical_id)
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode()
        transport = FakeArchiveTransport()
        digest = sha256(body)
        commit = transport.append(None, {
            f"receipts/{digest}/body.zip": body,
            f"receipts/{digest}/manifest.json": manifest_bytes,
        }, "manual hostile fixture")
        entry = {
            "schema": archive.INDEX_ENTRY_SCHEMA,
            "logical_id": logical_id,
            "kind": "workflow-artifact",
            "source": self.source(),
            "source_digest": sha256(body),
            "body_sha256": digest,
            "manifest_sha256": sha256(manifest_bytes),
            "archive_commit": commit,
        }
        return transport, entry

    def reviewed_authority(self, entries):
        document = json.dumps({
            "schema": archive.ReviewedMainIndexAuthority.INDEX_SCHEMA,
            "entries": entries,
        }, sort_keys=True, separators=(",", ":")).encode()

        class FakeGit:
            def ls_remote(self, ref):
                return "b" * 40

            def is_ancestor(self, ancestor, descendant):
                return True

            def file_at(self, commit, path):
                return document

        return archive.ReviewedMainIndexAuthority(
            remote="https://github.com/awebai/aweb.git",
            reviewed_commit="a" * 40, git=FakeGit())

    def test_non_lane_and_wrong_class_ids_refuse_before_append(self):
        body = self.lane_zip()
        ref = "gh-artifact:awebai/aweb:41:9001"
        for logical_id in self.INVALID_LOGICALS:
            with self.subTest(logical_id=logical_id):
                transport = FakeArchiveTransport()
                with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
                    archive.archive_sealed(
                        logical_id=logical_id,
                        kind="workflow-artifact",
                        source=self.source(),
                        store=FakeStore({ref: body}),
                        authority=FakeAuthority({ref: sha256(body)}),
                        transport=transport,
                        recorded_head=None,
                    )
                self.assertIsNone(
                    transport.head, "invalid identity must refuse before append")

    def test_non_lane_ids_refuse_during_semantic_restore(self):
        body = self.lane_zip()
        for logical_id in self.INVALID_LOGICALS:
            with self.subTest(logical_id=logical_id):
                transport, entry = self.manual_entry(body, logical_id)
                with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
                    archive.restore_archived(
                        entry=entry, transport=transport, production=False,
                        validate=archive.semantic_validator())

    def test_lane_logical_source_binds_during_global_index_load(self):
        body = self.lane_zip()
        _, entry = self.manual_entry(body, self.VALID_LOGICAL)
        entry = dict(entry, source=dict(entry["source"], source_sha="d" * 40))
        with self.assertRaisesRegex(rd.ReceiptError, "source"):
            self.reviewed_authority([entry]).lookup(self.VALID_LOGICAL)

    def test_non_lane_ids_refuse_global_index_load(self):
        body = self.lane_zip()
        _, valid = self.manual_entry(body, self.VALID_LOGICAL)
        for logical_id in self.INVALID_LOGICALS:
            with self.subTest(logical_id=logical_id):
                _, invalid = self.manual_entry(body, logical_id)
                with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
                    self.reviewed_authority(
                        [valid, invalid]).lookup(self.VALID_LOGICAL)

    def test_malformed_unrelated_supported_class_refuses_global_index(self):
        body = self.lane_zip()
        _, valid = self.manual_entry(body, self.VALID_LOGICAL)
        malformed = []
        for logical_id in (
            "plan:not-a-source:not-a-frozen-id",
            f"staged-manifest:{'f' * 64}:short",
            f"transition:{'f' * 64}:001:verify-red:server:{'e' * 64}",
            f"receipt:{'f' * 64}:short",
        ):
            malformed.append(dict(
                valid,
                logical_id=logical_id,
                kind="anchor-artifact",
                source=dict(SOURCE),
            ))
        authority = self.reviewed_authority([valid, *malformed])
        with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
            authority.lookup(self.VALID_LOGICAL)

    def test_valid_lane_identity_still_archives_and_restores(self):
        body = self.lane_zip()
        ref = "gh-artifact:awebai/aweb:41:9001"
        transport = FakeArchiveTransport()
        entry = archive.archive_sealed(
            logical_id=self.VALID_LOGICAL,
            kind="workflow-artifact", source=self.source(),
            store=FakeStore({ref: body}),
            authority=FakeAuthority({ref: sha256(body)}),
            transport=transport, recorded_head=None)
        self.assertEqual(archive.restore_archived(
            entry=entry, transport=transport, production=False,
            validate=archive.semantic_validator()), body)


class ReleaseSetCrossValidationTests(RoundFiveCounterexampleTests):
    """Reviewer blocker 1: the relationship checks were optional and unreached.

    restore_release_set loaded neither the plan nor the staged manifest for
    cross-validation and passed no expected components or entries, so real
    artifacts with source drift, entry drift, and a trailing transition
    omission all restored cleanly.
    """

    def restore(self, released, transport, authority):
        return archive.restore_release_set(
            frozen_plan_id=released["frozen_plan_id"], transport=transport,
            index_authority=authority, production=True)

    def test_trailing_transition_omission_refuses(self):
        """[1] of [1,2] is SELF-CONSISTENT: it satisfies 1..n for n=1. Only an
        expectation derived from the frozen plan can catch it."""
        released = self.real_release_set(components=("channel", "pi"))
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(
            released, transitions=[released["transitions"][0]])])
        with self.assertRaises(rd.ReceiptError):
            self.restore(released, transport, authority)

    def test_entry_digest_drift_against_staged_refuses(self):
        released = self.real_release_set(entry_digest="1" * 64)
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        with self.assertRaisesRegex(rd.ReceiptError, "field for field"):
            self.restore(released, transport, authority)

    def test_drift_against_staged_alone_refuses(self):
        """Discriminating: transitions and receipt agree with each other, and
        only the STAGED manifest disagrees. The receipt comparison cannot see
        this one."""
        released = self.real_release_set(staged_digest="2" * 64)
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        with self.assertRaisesRegex(rd.ReceiptError, "staged entry"):
            self.restore(released, transport, authority)

    def test_plan_id_source_drift_refuses(self):
        released = self.real_release_set()
        bad_plan = f"plan:{'9' * 40}:{released['frozen_plan_id']}"
        # Defence in depth: the archive-time semantic validator already
        # refuses a plan id whose source disagrees with the frozen plan, so the
        # substitution cannot even reach the durable store. Asserting around
        # both steps records WHERE it dies rather than assuming restore is the
        # only guard.
        with self.assertRaisesRegex(rd.ReceiptError, "claims source"):
            transport, entries = self.archive_all(
                released["artifacts"] + [(bad_plan, released["plan_bytes"])])
            authority = self.index_authority(
                entries, [self.inventory(released, plan=bad_plan)])
            self.restore(released, transport, authority)

    def test_forged_staged_delivery_obligation_refuses(self):
        released = self.real_release_set(
            delivery_obligation="forged-delivery-obligation")
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        with self.assertRaisesRegex(rd.ReceiptError, "delivery obligation"):
            self.restore(released, transport, authority)

    def test_partial_receipt_cannot_be_the_final_receipt(self):
        released = self.real_release_set(receipt_partial=True)
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        with self.assertRaisesRegex(rd.ReceiptError, "partial"):
            self.restore(released, transport, authority)

    def test_final_receipt_plan_digest_must_equal_the_frozen_plan(self):
        released = self.real_release_set(receipt_plan_digest="9" * 64)
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        with self.assertRaisesRegex(rd.ReceiptError, "plan digest"):
            self.restore(released, transport, authority)

    def test_hidden_transition_kind_refuses(self):
        released = self.real_release_set(
            transition_kinds=("published", "unreviewed-control"))
        with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
            self.archive_all(released["artifacts"])

    def test_complete_honest_set_still_restores(self):
        """Control: the same machinery must accept an undrifted set."""
        released = self.real_release_set()
        transport, entries = self.archive_all(released["artifacts"])
        authority = self.index_authority(entries, [self.inventory(released)])
        restored = self.restore(released, transport, authority)
        self.assertEqual([d["sequence"] for d in restored["transitions"]], [1])



class GateTests(unittest.TestCase):
    def test_focused_target_is_part_of_the_release_driver_gate(self):
        makefile = (SCRIPTS.parent / "Makefile").read_text()
        self.assertIn("test-release-receipt-archive:", makefile)
        self.assertIn(
            "test-release-receipt-archive",
            makefile.split("test-release-driver:")[1].split("\n")[0],
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
