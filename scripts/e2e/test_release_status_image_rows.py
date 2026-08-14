"""Image status rows (aben R5, design section 8).

Per-fact rows for an OCI image: the version tag's index digest, each
required platform's presence in the index, each child's source-revision
label against the expected source SHA (dev2's stamper made
load-bearing), the source tag as its own row, and mutable latest equal
to the version digest. Hermetic local registry.
"""

from __future__ import annotations

import json
import http.server
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_status_builders as rsb  # noqa: E402

EXPECTED_SHA = "e" * 40
AMD = "sha256:" + "a" * 64
ARM = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64
INDEX_DIGEST = "sha256:" + "1" * 64


class _Registry(http.server.BaseHTTPRequestHandler):
    latest_matches = True
    arm_label_wrong = False

    def _index(self):
        return json.dumps(
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {"digest": AMD, "platform": {"architecture": "amd64", "os": "linux"}},
                    {"digest": ARM, "platform": {"architecture": "arm64", "os": "linux"}},
                ],
            }
        ).encode()

    def do_GET(self):  # noqa: N802
        cls = type(self)
        if self.path == "/v2/org/img/manifests/1.0.0":
            body = self._index()
            self.send_response(200)
            self.send_header("Docker-Content-Digest", INDEX_DIGEST)
        elif self.path == "/v2/org/img/manifests/latest":
            body = self._index() if cls.latest_matches else b'{"manifests": []}'
            self.send_response(200)
            self.send_header(
                "Docker-Content-Digest",
                INDEX_DIGEST if cls.latest_matches else "sha256:" + "9" * 64,
            )
        elif self.path in (f"/v2/org/img/manifests/{AMD}", f"/v2/org/img/manifests/{ARM}"):
            body = json.dumps({"config": {"digest": CONFIG}}).encode()
            self.send_response(200)
        elif self.path == f"/v2/org/img/blobs/{CONFIG}":
            wrong = cls.arm_label_wrong and "arm-served" in self.headers.get("X-Test", "")
            body = json.dumps(
                {
                    "config": {
                        "Labels": {
                            "org.opencontainers.image.revision": (
                                "f" * 40 if wrong else EXPECTED_SHA
                            )
                        }
                    }
                }
            ).encode()
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class ImageRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Registry)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Registry.latest_matches = True

    def rows(self):
        return rsb.image_rows(
            "org/img",
            "1.0.0",
            required_platforms=("linux/amd64", "linux/arm64"),
            check_latest=True,
            base=self.base,
            token="",
            timeout=3,
        )

    def test_healthy_image_is_all_present_per_fact(self) -> None:
        rows = self.rows()
        facts = [r.fact for r in rows]
        self.assertTrue(any("index digest" in f for f in facts))
        self.assertTrue(any("linux/amd64" in f for f in facts))
        self.assertTrue(any("linux/arm64" in f for f in facts))
        # No revision-label fact: durable status no longer claims the
        # image was built from a given source (the tag ruling).
        self.assertFalse(any("revision label" in f for f in facts), facts)
        self.assertTrue(any("latest" in f for f in facts))
        self.assertTrue(all(r.present() for r in rows), [r.render() for r in rows])

    def test_missing_platform_is_its_own_absent_row(self) -> None:
        rows = rsb.image_rows(
            "org/img",
            "1.0.0",
            required_platforms=("linux/amd64", "linux/arm64", "linux/s390x"),
            check_latest=False,
            base=self.base,
            token="",
            timeout=3,
        )
        missing = next(r for r in rows if "s390x" in r.fact)
        self.assertEqual(missing.state, "observed-absent")
        amd = next(r for r in rows if "amd64" in r.fact)
        self.assertTrue(amd.present())

    def test_stale_latest_is_conflict_not_present(self) -> None:
        _Registry.latest_matches = False
        rows = self.rows()
        latest = next(r for r in rows if "latest" in r.fact)
        self.assertEqual(latest.state, "conflict-unproven")

    def test_absent_tag_is_absent_rows(self) -> None:
        rows = rsb.image_rows(
            "org/ghost",
            "9.9.9",
            required_platforms=("linux/amd64",),
            check_latest=False,
            base=self.base,
            token="",
            timeout=3,
        )
        self.assertTrue(all(r.state == "observed-absent" for r in rows))


class ImageRowsAfterTheTagRuling(ImageRows):
    """Under Juan's tag ruling, durable status proves two required
    facts - the immutable registry object and the exact source tag -
    and NO LONGER proves the first was built from the second.

    plan-critic's boundary 3 keeps registry artifact verification
    (digest equality, platform completeness, immutable read-back);
    boundary 5 requires status language not to imply the deleted
    cross-check still exists. A revision-label row would imply exactly
    that.
    """

    def rows_for(self, platforms):
        return rsb.image_rows(
            "org/img",
            "1.0.0",
            required_platforms=platforms,
            check_latest=True,
            base=self.base,
            token="",
            timeout=3,
        )

    def test_no_row_claims_a_label_matches_a_source(self) -> None:
        for row in self.rows_for(("linux/amd64", "linux/arm64")):
            with self.subTest(fact=row.fact):
                self.assertNotIn("revision label", row.fact)
                self.assertNotIn("label equals", row.evidence)

    def test_platform_completeness_and_digest_survive(self) -> None:
        rows = {r.fact: r for r in self.rows_for(("linux/amd64", "linux/arm64"))}
        index = [f for f in rows if f.endswith("index digest")]
        self.assertEqual(len(index), 1, sorted(rows))
        self.assertEqual(rows[index[0]].state, "observed-present")
        for platform in ("linux/amd64", "linux/arm64"):
            matching = [f for f in rows if f.endswith(platform)]
            self.assertEqual(len(matching), 1, f"{platform}: {sorted(rows)}")
            self.assertEqual(rows[matching[0]].state, "observed-present")

    def test_a_missing_platform_is_absent_under_the_same_fact_key(self) -> None:
        """The key a PRESENT platform emits and the key an ABSENT one
        emits must be the same, or the fact family is not stable across
        outcomes and the two-way domain check compares different sets.
        The old code emitted "... {platform} revision label" when
        present and "... {platform}" when absent."""

        rows = {r.fact: r for r in self.rows_for(("linux/amd64", "linux/s390x"))}
        served = [f for f in rows if f.endswith("linux/amd64")]
        missing = [f for f in rows if f.endswith("linux/s390x")]
        self.assertEqual(len(served), 1, sorted(rows))
        self.assertEqual(len(missing), 1, sorted(rows))
        self.assertEqual(rows[served[0]].state, "observed-present")
        self.assertEqual(rows[missing[0]].state, "observed-absent")
        self.assertEqual(
            served[0].removesuffix("linux/amd64"),
            missing[0].removesuffix("linux/s390x"),
            "present and absent platforms must share a fact-key shape",
        )


if __name__ == "__main__":
    unittest.main()
