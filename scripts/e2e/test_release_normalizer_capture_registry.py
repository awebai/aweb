"""Registry-side discovery capture (aben R3, design section 2).

One listing document per version-bearing target; grammar filtering with
occupancy conservatism (yanked still occupies); pagination bounded with
its own named stop distinct from unavailable; unavailability is never
absence. Hermetic local HTTP registry.
"""

from __future__ import annotations

import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_normalizer_capture as cap  # noqa: E402


class _Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/pypi/demo/json":
            body = json.dumps(
                {
                    "releases": {
                        "1.0.0": [{}],
                        "1.2.0": [{"yanked": True}],
                        "not-a-version": [{}],
                    }
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/npm/pkg":
            body = json.dumps(
                {"versions": {"0.1.0": {}, "0.2.0": {"deprecated": "old"}}}
            ).encode()
            self.send_response(200)
        elif self.path.startswith("/v2/org/img/tags/list"):
            # Paginated: page 1 links to page 2; page 2 is terminal.
            if "last=" not in self.path:
                body = json.dumps({"tags": ["1.0.0", "latest"]}).encode()
                self.send_response(200)
                self.send_header(
                    "Link", '</v2/org/img/tags/list?last=latest>; rel="next"'
                )
            else:
                body = json.dumps({"tags": ["1.1.0", "sha-deadbeef"]}).encode()
                self.send_response(200)
        elif self.path.startswith("/v2/org/endless/tags/list"):
            # Every page links onward: must hit the product bound.
            n = int(self.path.split("last=p")[1]) if "last=p" in self.path else 0
            body = json.dumps({"tags": [f"0.0.{n}"]}).encode()
            self.send_response(200)
            self.send_header(
                "Link", f'</v2/org/endless/tags/list?last=p{n+1}>; rel="next"'
            )
        elif self.path == "/pypi/broken/json":
            body = b"{}"
            self.send_response(500)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


class RegistryDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Registry)
        port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_pypi_listing_includes_yanked_and_excludes_non_grammar(self) -> None:
        versions = cap.discover_pypi_versions("demo", base=self.base, timeout=3)
        self.assertEqual(versions, {"1.0.0", "1.2.0"})

    def test_npm_listing_includes_deprecated(self) -> None:
        versions = cap.discover_npm_versions("pkg", base=f"{self.base}/npm", timeout=3)
        self.assertEqual(versions, {"0.1.0", "0.2.0"})

    def test_ghcr_pagination_traverses_to_proven_end(self) -> None:
        versions = cap.discover_ghcr_versions(
            "org/img", base=self.base, timeout=3, token=""
        )
        self.assertEqual(versions, {"1.0.0", "1.1.0"})

    def test_endless_pagination_hits_the_named_bound(self) -> None:
        with self.assertRaises(cap.DiscoveryBoundExceeded):
            cap.discover_ghcr_versions(
                "org/endless", base=self.base, timeout=3, token=""
            )

    def test_unavailable_raises_not_empty(self) -> None:
        # A 500 must never read as an empty history.
        with self.assertRaises(cap.DiscoveryUnavailable):
            cap.discover_pypi_versions("broken", base=self.base, timeout=3)

    def test_absent_package_is_empty_history(self) -> None:
        versions = cap.discover_pypi_versions("ghost", base=self.base, timeout=3)
        self.assertEqual(versions, set())


if __name__ == "__main__":
    unittest.main()
