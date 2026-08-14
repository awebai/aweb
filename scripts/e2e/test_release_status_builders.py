"""Per-fact row builders (aben R5, design section 8).

One row per independently checkable fact - a present tarball cannot
vouch for an absent sibling. pypi rows enforce the exact filename
contract with registry-reported per-file sha256; npm verifies declared
integrity against freshly fetched bytes; unavailability propagates as
UNAVAILABLE rows, never as absence. Hermetic local registry.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_status as rs  # noqa: E402
import release_status_builders as rsb  # noqa: E402

TARBALL = b"npm-tarball-bytes"
TARBALL_SHA = hashlib.sha512(TARBALL).hexdigest()


class _Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/pypi/aweb/1.27.2/json":
            body = json.dumps(
                {
                    "info": {"version": "1.27.2"},
                    "urls": [
                        {
                            "filename": "aweb-1.27.2.tar.gz",
                            "digests": {"sha256": "a" * 64},
                        },
                        {
                            "filename": "aweb-1.27.2-py3-none-any.whl",
                            "digests": {"sha256": "b" * 64},
                        },
                    ],
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/pypi/extras/1.0.0/json":
            body = json.dumps(
                {
                    "info": {"version": "1.0.0"},
                    "urls": [
                        {"filename": "extras-1.0.0.tar.gz", "digests": {"sha256": "c" * 64}},
                        {"filename": "extras-1.0.0-py3-none-any.whl", "digests": {"sha256": "d" * 64}},
                        {"filename": "stray.txt", "digests": {"sha256": "e" * 64}},
                    ],
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/npm/pkg/1.0.0":
            body = json.dumps(
                {
                    "dist": {
                        "tarball": f"http://127.0.0.1:{self.server.server_address[1]}/npm/pkg/-/pkg-1.0.0.tgz",
                        "integrity": f"sha512-{TARBALL_SHA}",
                    }
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/npm/pkg/-/pkg-1.0.0.tgz":
            body = TARBALL
            self.send_response(200)
        elif self.path == "/npm/liar/1.0.0":
            body = json.dumps(
                {
                    "dist": {
                        "tarball": f"http://127.0.0.1:{self.server.server_address[1]}/npm/pkg/-/pkg-1.0.0.tgz",
                        "integrity": "sha512-" + "0" * 128,
                    }
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/pypi/down/1.0.0/json":
            body = b"{}"
            self.send_response(500)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class Builders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Registry)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_pypi_rows_are_per_fact_and_present_on_the_exact_contract(self) -> None:
        rows = rsb.pypi_rows(
            "aweb", "1.27.2",
            base=f"{self.base}/pypi", timeout=3,
        )
        facts = {row.fact: row for row in rows}
        self.assertGreaterEqual(len(rows), 3)  # sdist, wheel, filename-set
        self.assertTrue(all(r.present() for r in rows), [r.render() for r in rows])
        sdist = next(r for f, r in facts.items() if "tar.gz" in f)
        self.assertIn("a" * 64, sdist.evidence)

    def test_pypi_extra_file_makes_the_set_row_conflict(self) -> None:
        rows = rsb.pypi_rows(
            "extras", "1.0.0",
            base=f"{self.base}/pypi", timeout=3,
        )
        set_row = next(r for r in rows if "filename set" in r.fact)
        self.assertEqual(set_row.state, "conflict-unproven")
        self.assertIn("stray.txt", set_row.evidence)

    def test_pypi_absent_version_is_absent_rows(self) -> None:
        rows = rsb.pypi_rows(
            "ghost", "9.9.9",
            base=f"{self.base}/pypi", timeout=3,
        )
        self.assertTrue(all(r.state == "observed-absent" for r in rows))

    def test_pypi_unavailable_is_unavailable_rows_never_absence(self) -> None:
        rows = rsb.pypi_rows(
            "down", "1.0.0",
            base=f"{self.base}/pypi", timeout=3,
        )
        self.assertTrue(all(r.state == "unavailable" for r in rows))

    def test_npm_integrity_verified_against_fetched_bytes(self) -> None:
        row = rsb.npm_tarball_row(
            "pkg", "1.0.0", base=f"{self.base}/npm", timeout=3
        )
        self.assertTrue(row.present())
        self.assertIn(TARBALL_SHA[:16], row.evidence)

    def test_npm_integrity_mismatch_is_conflict(self) -> None:
        row = rsb.npm_tarball_row(
            "liar", "1.0.0", base=f"{self.base}/npm", timeout=3
        )
        self.assertEqual(row.state, "conflict-unproven")


if __name__ == "__main__":
    unittest.main()
