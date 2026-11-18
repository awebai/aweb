"""agent_restart.py's state snapshot, read from a real directory, and the
drift between two snapshots that fails a case (aweb-acwd.25.1).

    python3 -I scripts/e2e/test_agent_restart.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import agent_restart as restart  # noqa: E402

SEAT = "agent-one"


def state(base: Path) -> Path:
    """An agent's state as the container leaves it: private directories,
    sshd's host keys, one seat's key and certificate, the probe, and a log
    the running agent keeps writing."""
    root = base / "state"
    for directory in ("ssh", "home", f"seats/{SEAT}/.aw/team-certs"):
        (root / directory).mkdir(parents=True)
    for directory in (root, *[path for path in root.rglob("*") if path.is_dir()]):
        directory.chmod(0o700)
    files = {
        "ssh/ssh_host_ed25519_key": "host key",
        "ssh/ssh_host_ed25519_key.pub": "host public key",
        f"seats/{SEAT}/.aw/signing.key": "member key",
        f"seats/{SEAT}/.aw/team-certs/lfteam.pem": "certificate",
        f"seats/{SEAT}/{restart.RESTART_PROBE}": "work",
        "home/broker.log": "changes while the agent runs",
    }
    for name, text in files.items():
        (root / name).write_text(text)
        (root / name).chmod(0o600)
    return root


def snapshot(root: Path, uid: int | None = None) -> dict:
    # A new directory may take its parent's group (BSD), not the process's:
    # the state's own group stands for the agents' gid.
    return restart.snapshot(root, os.getuid() if uid is None else uid, root.stat().st_gid, SEAT)


class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.root = state(self.base)

    def test_the_snapshot_digests_the_keys_the_certificate_and_the_probe_and_never_keeps_their_bytes(self):
        taken = snapshot(self.root)
        self.assertEqual(sorted(taken["digests"]), [
            f"seats/{SEAT}/.aw/signing.key", f"seats/{SEAT}/.aw/team-certs/lfteam.pem",
            f"seats/{SEAT}/{restart.RESTART_PROBE}", "ssh/ssh_host_ed25519_key", "ssh/ssh_host_ed25519_key.pub"])
        self.assertEqual(taken["foreign"], [])
        self.assertEqual(taken["modes"]["."], "0o700")
        self.assertEqual(taken["modes"][f"seats/{SEAT}/.aw/signing.key"], "0o600")
        kept = json.dumps(taken)
        self.assertNotIn("member key", kept)
        self.assertNotIn("host key", kept)

    def test_the_evidence_summary_names_the_kept_files_without_a_digest(self):
        taken = snapshot(self.root)
        summary = json.dumps(restart.summary(taken))
        for digest in taken["digests"].values():
            self.assertNotIn(digest, summary)
        self.assertIn(f"seats/{SEAT}/.aw/signing.key", summary)

    def test_an_unchanged_state_has_no_drift_though_the_running_agent_wrote_its_logs(self):
        before = snapshot(self.root)
        (self.root / "home" / "broker.log").write_text("more lines")
        (self.root / "home" / "wake.sock").write_text("")
        (self.root / "home" / "broker.log").unlink()
        self.assertEqual(restart.state_drift(before, snapshot(self.root)), [])

    def test_a_replaced_key_a_lost_probe_a_new_key_and_a_changed_mode_are_each_drift(self):
        before = snapshot(self.root)
        (self.root / "seats" / SEAT / ".aw" / "signing.key").write_text("another member key")
        (self.root / "seats" / SEAT / restart.RESTART_PROBE).unlink()
        (self.root / "ssh" / "ssh_host_rsa_key").write_text("a new host key")
        (self.root / "ssh").chmod(0o755)
        self.assertEqual(restart.state_drift(before, snapshot(self.root)), [
            f"seats/{SEAT}/.aw/signing.key: changed",
            f"seats/{SEAT}/{restart.RESTART_PROBE}: gone",
            "ssh/ssh_host_rsa_key: new",
            "ssh: mode 0o700 -> 0o755",
        ])

    def test_a_new_certificate_is_a_second_onboarding(self):
        before = snapshot(self.root)
        (self.root / "seats" / SEAT / ".aw" / "team-certs" / "other.pem").write_text("another certificate")
        self.assertEqual(restart.state_drift(before, snapshot(self.root)),
                         [f"seats/{SEAT}/.aw/team-certs/other.pem: new"])

    def test_an_entry_another_owner_holds_is_drift(self):
        before = snapshot(self.root)
        # The test cannot chown, so the agents' uid is one nothing holds.
        drift = restart.state_drift(before, snapshot(self.root, uid=os.getuid() + 1))
        self.assertIn(".: not the agents' owner", drift)
        self.assertTrue(all(line.endswith(": not the agents' owner") for line in drift), drift)

    def test_a_snapshot_with_nothing_to_compare_is_drift(self):
        empty = self.base / "empty"
        empty.mkdir(mode=0o700)
        taken = snapshot(empty)
        self.assertEqual(restart.state_drift(taken, taken), ["no key, certificate or probe to compare"])

    def test_the_snapshot_never_follows_a_link_out_of_the_state(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "signing.key").write_text("not the agent's")
        (self.root / "seats" / SEAT / ".aw" / "linked").symlink_to(outside)
        (self.root / "ssh" / "ssh_host_linked_key").symlink_to(outside / "signing.key")
        taken = snapshot(self.root)
        self.assertEqual([path for path in taken["digests"] if "linked" in path], [])
        self.assertIn(f"seats/{SEAT}/.aw/linked", taken["modes"])
        self.assertNotIn(f"seats/{SEAT}/.aw/linked/signing.key", taken["modes"])

    def test_another_seats_key_is_not_this_seats(self):
        other = self.root / "seats" / "agent-two" / ".aw"
        other.mkdir(parents=True)
        (other / "signing.key").write_text("the other seat's key")
        self.assertNotIn("seats/agent-two/.aw/signing.key", snapshot(self.root)["digests"])


if __name__ == "__main__":
    unittest.main()
