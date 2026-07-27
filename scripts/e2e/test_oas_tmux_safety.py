#!/usr/bin/env python3
"""Focused controls for fail-closed proof tmux cleanup."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).with_name("oas_tmux_safety.sh")


class TmuxSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.proof_tmux = self.root / "proof-tmux"
        self.default_tmp = self.root / "default-tmp"
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.state = self.root / "state"
        self.log = self.root / "tmux.log"
        fake = self.fake_bin / "tmux"
        fake.write_text(
            """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$MOCK_LOG"
case "$1" in
  list-panes) exit 1 ;;
  list-sessions)
    if [[ "$SCENARIO" == "unexpected" ]]; then
      printf '%s\\n%s\\n' "$PROOF_TMUX_SESSION" foreign-session
      exit 0
    fi
    if [[ "$SCENARIO" == "kill-failure" && -f "$MOCK_STATE" ]]; then
      exit 1
    fi
    printf '%s\\n' "$PROOF_TMUX_SESSION"
    exit 0
    ;;
  kill-session)
    touch "$MOCK_STATE"
    if [[ "$SCENARIO" == "success" ]]; then rm -f "$MOCK_SOCKET"; exit 0; fi
    exit 1
    ;;
esac
exit 2
""",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.sockets: list[socket.socket] = []

    def tearDown(self) -> None:
        for bound in self.sockets:
            bound.close()
        self.temporary.cleanup()

    def bind_socket(self, base: Path) -> Path:
        path = base / f"tmux-{os.getuid()}" / "default"
        path.parent.mkdir(parents=True)
        bound = socket.socket(socket.AF_UNIX)
        bound.bind(str(path))
        self.sockets.append(bound)
        return path

    def run_function(self, command: str, scenario: str) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "TMUX_GUARD_DIR": str(self.fake_bin),
            "PROOF_TMUX_DIR": str(self.proof_tmux),
            "PROOF_TMUX_SESSION": "expected-proof-session",
            "TMPDIR": str(self.default_tmp),
            "MOCK_LOG": str(self.log),
            "MOCK_STATE": str(self.state),
            "MOCK_SOCKET": str(self.proof_tmux / f"tmux-{os.getuid()}" / "default"),
            "SCENARIO": scenario,
        }
        environment.pop("TMUX", None)
        environment.pop("TMUX_TMPDIR", None)
        return subprocess.run(
            [
                "bash", "-c",
                f"source {HELPER!s}; DEFAULT_TMUX_SOCKET_ROOT=$TMPDIR; {command}",
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_cleanup_rejects_kill_failure_when_existing_socket_probe_is_ambiguous(self) -> None:
        socket_path = self.bind_socket(self.proof_tmux)
        result = self.run_function("remove_proof_tmux_session", "kill-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remains but cannot be queried", result.stderr)
        self.assertTrue(socket_path.exists())

    def test_cleanup_rejects_unexpected_second_session_without_killing_any_session(self) -> None:
        socket_path = self.bind_socket(self.proof_tmux)
        result = self.run_function("remove_proof_tmux_session", "unexpected")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not contain exactly", result.stderr)
        self.assertTrue(socket_path.exists())
        self.assertNotIn("kill-session", self.log.read_text(encoding="utf-8"))

    def test_cleanup_accepts_only_authoritative_socket_disappearance_and_is_idempotent(self) -> None:
        self.bind_socket(self.proof_tmux)
        result = self.run_function("remove_proof_tmux_session", "success")
        self.assertEqual(result.returncode, 0, result.stderr)
        again = self.run_function("remove_proof_tmux_session", "success")
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_default_snapshot_rejects_exit_one_while_socket_exists(self) -> None:
        self.bind_socket(self.default_tmp)
        result = self.run_function(
            f"snapshot_default_tmux_topology {self.root / 'topology.txt'}", "snapshot"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not authoritatively snapshot", result.stderr)

    def test_default_snapshot_accepts_exit_one_only_when_socket_is_absent(self) -> None:
        output = self.root / "topology.txt"
        result = self.run_function(f"snapshot_default_tmux_topology {output}", "snapshot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
