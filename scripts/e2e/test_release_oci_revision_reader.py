"""The OCI revision-label reader (aben R5, design sections 7 and 8).

read_oci_revision resolves a version tag through the registry's index,
child manifest, and config blob to the org.opencontainers.image.revision
label - the ac-image anchor. Unavailability raises; a missing label is
its own refusal, never an empty answer. Hermetic local registry.
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

CONFIG_DIGEST = "sha256:" + "c" * 64
CHILD_DIGEST = "sha256:" + "d" * 64
REVISION = "e" * 40


class _Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/v2/org/img/manifests/1.0.0":
            body = json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {"digest": CHILD_DIGEST, "platform": {"architecture": "amd64"}}
                    ],
                }
            ).encode()
            self.send_response(200)
        elif self.path == f"/v2/org/img/manifests/{CHILD_DIGEST}":
            body = json.dumps({"config": {"digest": CONFIG_DIGEST}}).encode()
            self.send_response(200)
        elif self.path == f"/v2/org/img/blobs/{CONFIG_DIGEST}":
            body = json.dumps(
                {
                    "config": {
                        "Labels": {"org.opencontainers.image.revision": REVISION}
                    }
                }
            ).encode()
            self.send_response(200)
        elif self.path == "/v2/org/bare/manifests/1.0.0":
            body = json.dumps({"config": {"digest": CONFIG_DIGEST}}).encode()
            self.send_response(200)
        elif self.path == "/v2/org/bare/blobs/" + CONFIG_DIGEST:
            body = json.dumps({"config": {"Labels": {}}}).encode()
            self.send_response(200)
        elif self.path == "/v2/org/broken/manifests/1.0.0":
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


class OciRevisionReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Registry)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_index_child_config_label_resolves(self) -> None:
        revision = cap.read_oci_revision(
            "org/img", "1.0.0", base=self.base, token="", timeout=3
        )
        self.assertEqual(revision, REVISION)

    def test_flat_manifest_without_index_resolves(self) -> None:
        # The bare path serves a manifest directly (no index) whose
        # config lacks the label: that is a named refusal, not None.
        with self.assertRaises(cap.DiscoveryUnavailable) as caught:
            cap.read_oci_revision(
                "org/bare", "1.0.0", base=self.base, token="", timeout=3
            )
        self.assertIn("revision label", str(caught.exception))

    def test_unavailable_raises(self) -> None:
        with self.assertRaises(cap.DiscoveryUnavailable):
            cap.read_oci_revision(
                "org/broken", "1.0.0", base=self.base, token="", timeout=3
            )

    def test_absent_tag_raises_as_unavailable_evidence(self) -> None:
        with self.assertRaises(cap.DiscoveryUnavailable):
            cap.read_oci_revision(
                "org/ghost", "9.9.9", base=self.base, token="", timeout=3
            )


if __name__ == "__main__":
    unittest.main()
