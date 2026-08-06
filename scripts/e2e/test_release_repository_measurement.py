#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_driver as rd


class RepositoryMeasurementTests(unittest.TestCase):
    def setUp(self):
        self.edge = rd.RuntimeContractEdge(
            a="server",
            b="server",
            journey="make test-federation-e2e (both request directions)",
            artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
            direction="both",
            supported={"set": "measured:local", "record": {}},
        )
        self.document = {
            "schema": "aweb.runtime-support-measurement.v1",
            "edge": {"a": "server", "b": "server"},
            "journey": self.edge.journey,
            "artifacts": self.edge.artifacts,
            "direction": "both",
            "supported_versions": {"server": ["1.26.35"]},
        }

    def committed_repository(self, document=None):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Test"], check=True
        )
        relative = Path("release/measurements/evidence.json")
        path = root / relative
        path.parent.mkdir(parents=True)
        body = rd.canonical_json_bytes(document or self.document)
        path.write_bytes(body)
        subprocess.run(["git", "-C", str(root), "add", str(relative)], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-qm", "measurement"], check=True
        )
        source_sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return temporary, root, relative.as_posix(), body, source_sha

    def test_reads_digest_bound_bytes_from_exact_source_tree(self):
        temporary, root, relative, body, source_sha = self.committed_repository()
        self.addCleanup(temporary.cleanup)
        (root / relative).write_bytes(b"working-tree-tamper")
        resolver = rd.RepositoryMeasurementAuthority(
            repo_root=root, source_sha=source_sha
        )
        record = {
            "authority": "repository",
            "artifact_id": "support:server-federation:1.26.35",
            "path": relative,
            "digest": hashlib.sha256(body).hexdigest(),
        }
        self.assertEqual(
            resolver.resolve(record, self.edge)["supported_versions"],
            {"server": ["1.26.35"]},
        )

    def test_refuses_escape_missing_file_and_digest_mismatch(self):
        temporary, root, relative, body, source_sha = self.committed_repository()
        self.addCleanup(temporary.cleanup)
        resolver = rd.RepositoryMeasurementAuthority(
            repo_root=root, source_sha=source_sha
        )
        base = {
            "authority": "repository",
            "artifact_id": "support:server-federation:1.26.35",
            "path": relative,
            "digest": hashlib.sha256(body).hexdigest(),
        }
        cases = [
            ({**base, "path": "release/measurements/../secret"}, "safe path"),
            ({**base, "path": "release/measurements/missing.json"}, "exact source"),
            ({**base, "digest": "0" * 64}, "declared digest"),
        ]
        for record, message in cases:
            with self.subTest(record=record), self.assertRaisesRegex(
                rd.ReceiptError, message
            ):
                resolver.resolve(record, self.edge)

    def test_refuses_wrong_repository_measurement_schema(self):
        document = {**self.document, "schema": "aweb.runtime-support-measurement.v0"}
        temporary, root, relative, body, source_sha = self.committed_repository(
            document
        )
        self.addCleanup(temporary.cleanup)
        resolver = rd.RepositoryMeasurementAuthority(
            repo_root=root, source_sha=source_sha
        )
        record = {
            "authority": "repository",
            "artifact_id": "support:server-federation:1.26.35",
            "path": relative,
            "digest": hashlib.sha256(body).hexdigest(),
        }
        with self.assertRaisesRegex(rd.ReceiptError, "schema"):
            resolver.resolve(record, self.edge)

    def test_current_graph_make_release_plan_prints_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ["make", "release-plan", f"STORE_ROOT={tmp}"],
                cwd=rd.REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertNotIn("Traceback", result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["plan_artifact_id"].startswith("plan:"))
            self.assertIsInstance(report["declared_input_problems"], list)


if __name__ == "__main__":
    unittest.main()
