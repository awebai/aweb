"""Exit-code contract for scripts/observe_public_target.py (aben R2).

Hermetic: a local HTTP server plays the registry; the four exit codes
are each demonstrated, including unavailable-is-not-absence via a
connection-refused base.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = REPO_ROOT / "scripts" / "observe_public_target.py"


class _Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming)
        if self.path == "/pypi/demo/1.2.3/json":
            body = json.dumps({"info": {"version": "1.2.3"}}).encode()
            self.send_response(200)
        elif self.path == "/pypi/demo/9.9.9/json":
            body = b"{}"
            self.send_response(404)
        elif self.path == "/pypi/liar/1.2.3/json":
            body = json.dumps({"info": {"version": "9.9.9"}}).encode()
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # quiet
        return


class ObserveCliContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Registry)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def observe(self, target: str, version: str, port: int | None = None) -> int:
        port = port or self.port
        return subprocess.run(
            [
                sys.executable,
                str(CLI),
                target,
                version,
                "--base",
                f"pypi=http://127.0.0.1:{port}",
                "--timeout",
                "3",
            ],
            capture_output=True,
        ).returncode

    def test_present_is_zero(self) -> None:
        self.assertEqual(self.observe("pypi:demo", "1.2.3"), 0)

    def test_absent_is_one(self) -> None:
        self.assertEqual(self.observe("pypi:demo", "9.9.9"), 1)

    def test_wrong_served_version_is_malformed_three(self) -> None:
        self.assertEqual(self.observe("pypi:liar", "1.2.3"), 3)

    def test_unavailable_is_two_never_absence(self) -> None:
        # A refused connection must be exit 2, not 1: unavailability is
        # never absence. Port 1 refuses on this host.
        self.assertEqual(self.observe("pypi:demo", "1.2.3", port=1), 2)


if __name__ == "__main__":
    unittest.main()
