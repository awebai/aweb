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

    def append(self, parent: str | None, files: dict[str, bytes], subject: str) -> str:
        if parent != self.head:
            raise rd.ReceiptError(
                "archive append is not fast-forward from the fetched head"
            )
        body = json.dumps(sorted(files), sort_keys=True) + subject + str(parent)
        sha = hashlib.sha256(body.encode()).hexdigest()[:16]
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
          "anchor": "anchor--aa--bb"}


def fresh_env(body: bytes = BODY, ref: str = REF):
    return (
        FakeStore({ref: body}),
        FakeAuthority({ref: sha256(body)}),
        FakeArchiveTransport(),
    )


def do_archive(store, authority, transport, *, logical_id="receipt:plan:1",
               ref=REF, recorded_head=None, kind="anchor-artifact"):
    return archive.archive_sealed(
        logical_id=logical_id, kind=kind, artifact_ref=ref,
        source=dict(SOURCE), store=store, authority=authority,
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
        store.artifacts["ref2"] = body2
        authority.digests["ref2"] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "descend"):
            do_archive(store, authority, transport, ref="ref2",
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
        store.artifacts["ref2"] = body2
        authority.digests["ref2"] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "rebind"):
            do_archive(store, authority, transport, ref="ref2",
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
        with self.assertRaisesRegex(rd.ReceiptError, "conflict|rebind"):
            do_archive(store, authority, transport,
                       recorded_head=entry["archive_commit"])

    def test_extra_unexpected_body_refuses(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        transport.commits[transport.head]["files"]["receipts/deadbeef/body.zip"] = b"stray"
        body2 = b"second-sealed-body"
        store.artifacts["ref2"] = body2
        authority.digests["ref2"] = sha256(body2)
        with self.assertRaisesRegex(rd.ReceiptError, "unexpected|stray"):
            do_archive(store, authority, transport, ref="ref2",
                       logical_id="receipt:plan:2",
                       recorded_head=entry["archive_commit"])


class RestoreTests(unittest.TestCase):
    def archived(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        return transport, entry

    def restore(self, transport, entry, *, production=True, validate=None,
                validated=None):
        if validate is None:
            def validate(body, manifest):
                if validated is not None:
                    validated.append((body, manifest))
        return archive.restore_archived(
            entry=entry, transport=transport, production=production,
            validate=validate,
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
        bad = dict(entry, archive_commit="0" * 16)
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
            with self.assertRaisesRegex(rd.ReceiptError, "index entry"):
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


class IndexEntryTests(unittest.TestCase):
    def test_entry_canonical_json_round_trips(self):
        store, authority, transport = fresh_env()
        entry = do_archive(store, authority, transport)
        encoded = archive.encode_index_entry(entry)
        self.assertEqual(json.loads(encoded), entry)
        self.assertEqual(encoded, archive.encode_index_entry(json.loads(encoded)))


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
