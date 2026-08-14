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
from unittest import mock
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

    def test_source_commit_tags_are_not_version_candidates(self) -> None:
        # Measured against the live registry: ghcr.io/awebai/ac serves
        # ~90 BARE source-commit tags because its publisher pushes
        # :VERSION and :SHA unprefixed (design section 8). Roughly half
        # begin with a digit, so a digit-led classifier reads them as
        # near-versions and halts the train on 90 counts. These are the
        # real shapes.
        classify = cap._version_namespace_candidates
        served = {
            "0.7.14", "0.7.13", "v0.7.12",      # versions
            "0.3", "0.7",                        # legacy two-component
            "latest", "sha-abc1234",             # non-namespace
            "0006499", "559b5f5", "9fa8e59",     # digit-led short commits
            "abc1234", "6c1bbe5c1f6fbb17318186216c9d00ab8f523fc5",  # hex commits
        }
        kept = classify(served)
        self.assertEqual(kept, {"0.7.14", "0.7.13", "v0.7.12", "0.3", "0.7"})
        # The discrimination that matters, stated both ways: every
        # commit-shaped tag is dropped, and no version-shaped one is.
        for commit in ("0006499", "559b5f5", "9fa8e59", "abc1234",
                       "6c1bbe5c1f6fbb17318186216c9d00ab8f523fc5"):
            self.assertNotIn(commit, kept, commit)
        for version in ("0.7.14", "v0.7.12", "0.3"):
            self.assertIn(version, kept, version)

    def test_oci_line_pointers_are_logged_not_occupancy(self) -> None:
        """plan-critic's ruling, with the five REAL measured tags from
        ghcr.io/awebai/ac. v?MAJOR and v?MAJOR.MINOR with wholly
        numeric components are moving channel pointers: logged, never
        occupancy. Exactly three numeric components occupy. Near-misses
        and four-or-more components still stop by name."""

        oci = cap._oci_namespace_candidates
        served = {
            # the five real line pointers, measured on the live registry
            "0.3", "0.4", "0.5", "0.6", "0.7",
            # one-component and optional-v forms
            "1", "v2", "v0.7",
            # valid three-component occupancy
            "0.7.14", "v0.7.13",
            # named stops: three-component near-miss and four components
            "0.7.15rc1", "1.2.3.4",
            # non-namespace
            "latest", "sha-abc1234", "559b5f5",
        }
        kept = oci(served)
        self.assertEqual(kept, {"0.7.14", "v0.7.13", "0.7.15rc1", "1.2.3.4"})
        for pointer in ("0.3", "0.4", "0.5", "0.6", "0.7", "1", "v2", "v0.7"):
            self.assertNotIn(pointer, kept, pointer)
        # The near-misses survive discovery so the reconciler can stop
        # them BY NAME - dropping them here would silence the stop.
        for stops in ("0.7.15rc1", "1.2.3.4"):
            self.assertIn(stops, kept, stops)

    def test_the_exception_does_not_leak_out_of_oci(self) -> None:
        """The non-OCI control the ruling requires: pypi, npm, GitHub
        releases and source tags do NOT inherit the line-pointer
        exception, so a two-component 0.7 there is still a candidate
        the reconciler will judge."""

        served = {"0.7", "0.7.14"}
        self.assertEqual(cap._version_namespace_candidates(served), served)
        self.assertEqual(cap._oci_namespace_candidates(served), {"0.7.14"})

    def test_a_line_pointer_is_never_dereferenced(self) -> None:
        """The sharpest condition, made structural rather than
        unreached: a line pointer is dropped at discovery, so no code
        path can read its manifest and adopt a channel tag's revision
        label as a release identity. Proven by a spy - read_oci_revision
        is never called with a pointer."""

        import release_normalizer_main as main

        asked: list[str] = []

        def spy_revision(image, version, **kwargs):
            asked.append(version)
            return "a" * 40

        with mock.patch.object(
            cap, "discover_ghcr_versions",
            lambda *a, **k: cap._oci_namespace_candidates(
                {"0.7", "0.3", "0.7.14", "latest"}
            ),
        ), mock.patch.object(cap, "read_oci_revision", spy_revision):
            occupied = main.route_discovery(
                "ghcr.io/awebai/ac",
                timeout=1, ghcr_token="t", gh_token="",
                bases=main.registry_bases(),
            )
        self.assertEqual(set(occupied), {"0.7.14"})
        self.assertEqual(asked, ["0.7.14"], "a line pointer was dereferenced")

    def test_unavailable_raises_not_empty(self) -> None:
        # A 500 must never read as an empty history.
        with self.assertRaises(cap.DiscoveryUnavailable):
            cap.discover_pypi_versions("broken", base=self.base, timeout=3)

    def test_absent_package_is_empty_history(self) -> None:
        versions = cap.discover_pypi_versions("ghost", base=self.base, timeout=3)
        self.assertEqual(versions, set())


if __name__ == "__main__":
    unittest.main()
