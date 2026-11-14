"""Real TCP collision control; no registry process, DB or response substitute."""

import errno
import json
from pathlib import Path
import socket
import tempfile
import unittest

from released_registry import old_registry_listener


class ListenerOwnershipTests(unittest.TestCase):
    def test_occupied_port_refuses_before_launch_and_leaves_foreign_socket_usable(self):
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as foreign:
            root = Path(temporary)
            foreign.bind(("127.0.0.1", 0))
            foreign.listen(1)
            foreign.settimeout(2)
            address = foreign.getsockname()
            with self.assertRaises(OSError) as caught:
                with old_registry_listener(
                    # A real missing executable detects any attempt to launch
                    # before owning the port; no process is mocked or started.
                    python=root / "must-not-launch",
                    wheel=root / "not-needed-before-port-ownership.whl",
                    run_root=root / "epoch", port=address[1],
                    database_url="unused", redis_url="unused", schema="old_registry",
                    public_origins=("https://api.awid.ai",),
                ):
                    self.fail("yielded a foreign listener")
            self.assertEqual(caught.exception.errno, errno.EADDRINUSE)
            receipt = json.loads((root / "epoch/process.json").read_text())
            self.assertEqual(receipt["state"], "FAILED")
            self.assertIsNone(receipt["pid"])
            self.assertNotIn("health", receipt)
            self.assertFalse((root / "epoch/package.json").exists())
            self.assertEqual(foreign.getsockname(), address)
            # The original bound socket still accepts real TCP traffic after
            # the helper refuses. No cleanup signal or close touched it.
            with socket.create_connection(address, timeout=2) as client:
                client.sendall(b"still owned by the other epoch")
                connection, _ = foreign.accept()
                with connection:
                    self.assertEqual(connection.recv(128), b"still owned by the other epoch")


if __name__ == "__main__":
    unittest.main()
