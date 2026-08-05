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
import sys
import tempfile
import unittest
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

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        cursor: str | None = descendant
        while cursor is not None:
            if cursor == ancestor:
                return True
            cursor = self.commits[cursor]["parent"]
        return False

    def parent_of(self, sha: str) -> str | None:
        commit = self.commits.get(sha)
        if commit is None:
            raise rd.ReceiptError(f"archive commit {sha} does not exist")
        return commit["parent"]

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


def fresh_env(body: bytes = BODY, ref: str = REF):
    return (
        FakeStore({ref: body}),
        FakeAuthority({ref: sha256(body)}),
        FakeArchiveTransport(),
    )


def do_archive(store, authority, transport, *, logical_id="receipt:plan:1",
               ref=REF, recorded_head=None, kind="anchor-artifact",
               source=None):
    src = dict(source) if source is not None else dict(SOURCE)
    if kind == "workflow-artifact":
        src.pop("anchor", None)
    return archive.archive_sealed(
        logical_id=logical_id, kind=kind, source=src,
        store=store, authority=authority,
        transport=transport, recorded_head=recorded_head,
    )


class ArchiveWriteTests(unittest.TestCase):
    def test_archives_exact_sealed_bytes_and_emits_bound_entry(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        self.assertEqual(entry["schema"], archive.INDEX_ENTRY_SCHEMA)
        self.assertEqual(entry["logical_id"], "receipt:plan:1")
        self.assertEqual(entry["source"], SOURCE)
        self.assertEqual(entry["source_digest"], sha256(BODY))
        self.assertEqual(entry["body_sha256"], sha256(BODY))
        self.assertEqual(entry["archive_commit"], transport.head)
        tree = transport.read_tree(transport.head)
        body_path = f"receipts/{sha256(BODY)}/body.zip"
        manifest_path = f"receipts/{sha256(BODY)}/manifest.json"
        self.assertEqual(tree[body_path], BODY)
        manifest = json.loads(tree[manifest_path])
        self.assertEqual(manifest["logical_id"], "receipt:plan:1")
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
                       logical_id="receipt:plan:2",
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
        broken["logical_id"] = "receipt:other"
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
                       logical_id="receipt:plan:2",
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
        forged = dict(entry, logical_id="receipt:forged")
        files = transport.commits[entry["archive_commit"]]["files"]
        files["index.json"] = json.dumps({"entries": [forged]}).encode()
        with self.assertRaisesRegex(rd.ReceiptError, "not recorded"):
            self.restore(transport, None, FakeIndexAuthority([]),
                         logical_id="receipt:forged")

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
                             logical_id="receipt:absent")
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
            allowed_paths=("README.md",),
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
                            logical_id="receipt:plan:2",
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
                   logical_id="receipt:plan:2",
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
                       logical_id="receipt:plan:2",
                       recorded_head=first["archive_commit"])

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
            authority.lookup("receipt:plan:1")

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
        manifest = {"kind": "anchor-artifact", "logical_id": "x",
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
                       logical_id="receipt:plan:2",
                       recorded_head=entry["archive_commit"])

    # Finding 4: source identity cannot be rebound at copy time.
    def test_independent_artifact_ref_that_disagrees_refuses(self):
        store, authority, transport = fresh_env()
        with self.assertRaisesRegex(rd.ReceiptError, "does not equal the reference"):
            archive.archive_sealed(
                logical_id="x", kind="anchor-artifact", source=dict(SOURCE),
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


class SemanticValidatorRoundTwoTests(unittest.TestCase):
    """Alice's .9 round-2 blocker 1: the validator must accept a REAL valid
    anchor bundle (outer ZIP digest and inner body digest are different
    identities by design) and must truly reproduce a workflow bundle."""

    @staticmethod
    def real_anchor(logical_id="receipt:plan:1", body=b"sealed-inner-body"):
        import io
        import zipfile

        digest = sha256(body)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("record.json", json.dumps(
                {"logical_id": logical_id, "digest": digest}))
            z.writestr("body", body)
        outer = buf.getvalue()
        manifest = {
            "schema": archive.MANIFEST_SCHEMA,
            "logical_id": logical_id,
            "kind": "anchor-artifact",
            "source": dict(SOURCE, anchor=rd._anchor_name(logical_id, digest)),
            "source_digest": sha256(outer),   # OUTER ZIP digest, by design
            "body_sha256": sha256(outer),
        }
        return outer, manifest, digest

    def test_valid_real_anchor_bundle_is_accepted(self):
        outer, manifest, _ = self.real_anchor()
        archive.semantic_validator()(outer, manifest)

    def test_inner_body_digest_mismatch_refuses(self):
        import io
        import zipfile

        body = b"sealed-inner-body"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("record.json", json.dumps(
                {"logical_id": "receipt:plan:1", "digest": sha256(b"other")}))
            z.writestr("body", body)
        outer = buf.getvalue()
        manifest = {
            "schema": archive.MANIFEST_SCHEMA, "logical_id": "receipt:plan:1",
            "kind": "anchor-artifact",
            "source": dict(SOURCE, anchor=rd._anchor_name(
                "receipt:plan:1", sha256(b"other"))),
            "source_digest": sha256(outer), "body_sha256": sha256(outer),
        }
        with self.assertRaisesRegex(rd.ReceiptError, "inner body"):
            archive.semantic_validator()(outer, manifest)

    def test_anchor_name_not_derived_from_logical_id_refuses(self):
        outer, manifest, digest = self.real_anchor()
        manifest = dict(manifest, source=dict(
            manifest["source"], anchor=rd._anchor_name("other:id", digest)))
        with self.assertRaisesRegex(rd.ReceiptError, "anchor name"):
            archive.semantic_validator()(outer, manifest)

    def test_record_logical_id_mismatch_refuses(self):
        outer, manifest, _ = self.real_anchor(logical_id="receipt:plan:1")
        manifest = dict(manifest, logical_id="receipt:other")
        with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
            archive.semantic_validator()(outer, manifest)


class WorkflowBundleValidatorTests(unittest.TestCase):
    """A complete workflow bundle must be reproduced member by member, and
    every member type must actually be validated - including transitions."""

    @staticmethod
    def transition_doc():
        return {
            "frozen_plan_id": "f" * 64,
            "staged_manifest_id": "sha256:" + "e" * 64,
            "sequence": 1,
            "component": "channel",
            "kind": "published",
            "entry": {
                "version": "1.7.2", "digest": "d" * 64, "phase": "published",
                "pointer_state": None, "delivery_proof": None,
                "lane_ref": None, "digest_set": {"x.tgz": "a" * 64},
            },
        }

    def bundle(self, *, members=None, tamper=None, extra=None, drop=None):
        import io
        import zipfile

        transition = json.dumps(self.transition_doc(), sort_keys=True).encode()
        payloads = members or {"transition-001.json": ("transition", transition)}
        record_members = []
        for name, (mtype, data) in payloads.items():
            record_members.append({
                "name": name, "type": mtype,
                "logical_id": f"logical:{name}",
                "digest": sha256(data),
            })
        record = {"schema": archive.BUNDLE_SCHEMA,
                  "logical_id": "receipt:plan:1",
                  "members": record_members}
        if tamper:
            record = tamper(record)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("archive-bundle.json", json.dumps(record))
            for name, (_, data) in payloads.items():
                if drop and name == drop:
                    continue
                z.writestr(name, data)
            if extra:
                z.writestr(extra, b"unexpected")
        manifest = {
            "schema": archive.MANIFEST_SCHEMA, "logical_id": "receipt:plan:1",
            "kind": "workflow-artifact",
            "source": {k: v for k, v in SOURCE.items() if k != "anchor"},
            "source_digest": "c" * 64, "body_sha256": "c" * 64,
        }
        return buf.getvalue(), manifest

    def test_complete_bundle_with_transition_validates(self):
        body, manifest = self.bundle()
        archive.semantic_validator()(body, manifest)

    def test_corrupt_transition_refuses(self):
        bad = dict(self.transition_doc())
        bad.pop("entry")
        data = json.dumps(bad, sort_keys=True).encode()
        body, manifest = self.bundle(
            members={"transition-001.json": ("transition", data)})
        with self.assertRaisesRegex(rd.ReceiptError, "transition document"):
            archive.semantic_validator()(body, manifest)

    def test_missing_declared_member_refuses(self):
        body, manifest = self.bundle(drop="transition-001.json")
        with self.assertRaisesRegex(rd.ReceiptError, "missing"):
            archive.semantic_validator()(body, manifest)

    def test_extra_undeclared_member_refuses(self):
        body, manifest = self.bundle(extra="stowaway.json")
        with self.assertRaisesRegex(rd.ReceiptError, "unexpected"):
            archive.semantic_validator()(body, manifest)

    def test_swapped_member_digest_refuses(self):
        def tamper(record):
            record["members"][0]["digest"] = "b" * 64
            return record
        body, manifest = self.bundle(tamper=tamper)
        with self.assertRaisesRegex(rd.ReceiptError, "hashes"):
            archive.semantic_validator()(body, manifest)

    def test_missing_bundle_record_refuses(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("receipt.json", b"{}")
        manifest = {
            "schema": archive.MANIFEST_SCHEMA, "logical_id": "receipt:plan:1",
            "kind": "workflow-artifact",
            "source": {k: v for k, v in SOURCE.items() if k != "anchor"},
            "source_digest": "c" * 64, "body_sha256": "c" * 64,
        }
        with self.assertRaisesRegex(rd.ReceiptError, "archive-bundle.json"):
            archive.semantic_validator()(buf.getvalue(), manifest)

    def test_bundle_logical_id_must_equal_manifest(self):
        def tamper(record):
            record["logical_id"] = "receipt:other"
            return record
        body, manifest = self.bundle(tamper=tamper)
        with self.assertRaisesRegex(rd.ReceiptError, "logical id"):
            archive.semantic_validator()(body, manifest)


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

    def valid_entry(self, logical_id="receipt:plan:1"):
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
