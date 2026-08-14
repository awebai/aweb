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

    def setUp(self):
        _Registry.latest_matches = True

    def rows(self):
        return rsb.image_rows(
            "org/img",
            "1.0.0",
            expected_revision=EXPECTED_SHA,
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
        self.assertTrue(any("revision label" in f for f in facts))
        self.assertTrue(any("latest" in f for f in facts))
        self.assertTrue(all(r.present() for r in rows), [r.render() for r in rows])

    def test_missing_platform_is_its_own_absent_row(self) -> None:
        rows = rsb.image_rows(
            "org/img",
            "1.0.0",
            expected_revision=EXPECTED_SHA,
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
            expected_revision=EXPECTED_SHA,
            required_platforms=("linux/amd64",),
            check_latest=False,
            base=self.base,
            token="",
            timeout=3,
        )
        self.assertTrue(all(r.state == "observed-absent" for r in rows))


if __name__ == "__main__":
    unittest.main()
