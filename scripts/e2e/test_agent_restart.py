"""agent_restart.py's state snapshot, read from a real directory, and the
drift between two snapshots that fails a case (aweb-acwd.25.1).

    python3 -I scripts/e2e/test_agent_restart.py
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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


class RequiredStateTests(unittest.TestCase):
    """What must be in the bound state before any case: the probe the seat
    wrote over SSH (so SSH reached this state), the seat's key and a
    certificate, and sshd's host key."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.root = state(self.base)
        self.probe = hashlib.sha256(b"work").hexdigest()

    def missing(self) -> list[str]:
        return restart.missing(snapshot(self.root), SEAT, self.probe)

    def test_a_complete_state_with_the_probe_ssh_wrote_misses_nothing(self):
        self.assertEqual(self.missing(), [])

    def test_a_probe_other_than_the_one_ssh_wrote_means_ssh_reached_another_state(self):
        (self.root / "seats" / SEAT / restart.RESTART_PROBE).write_text("another state's probe")
        self.assertEqual(self.missing(), [f"seats/{SEAT}/{restart.RESTART_PROBE}: not the probe written over SSH"])

    def test_a_state_with_only_a_host_public_key_misses_the_seat_and_the_probe(self):
        # The reviewer's fixture: one matching SSH public key and nothing else.
        for name in (f"seats/{SEAT}/.aw/signing.key", f"seats/{SEAT}/.aw/team-certs/lfteam.pem",
                     f"seats/{SEAT}/{restart.RESTART_PROBE}", "ssh/ssh_host_ed25519_key"):
            (self.root / name).unlink()
        self.assertEqual(self.missing(), [
            f"seats/{SEAT}/.aw/signing.key: missing", f"seats/{SEAT}/.aw/team-certs/: no certificate",
            f"seats/{SEAT}/{restart.RESTART_PROBE}: missing", "ssh/: no private host key"])

    def test_a_directory_the_walk_cannot_read_stops_the_snapshot(self):
        locked = self.root / "home"
        locked.chmod(0o000)
        try:
            with self.assertRaises(restart.Failed):
                snapshot(self.root)
        finally:
            locked.chmod(0o700)


class Daemon:
    """The local daemon's and Compose's answers to the driver, substituted in
    process and every call recorded: what is tested is what the driver does
    with the answers, and that it mutates nothing it has not verified."""

    def __init__(self, answers: dict[str, tuple[int, str, str]]):
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
        self.calls.append(list(args))
        line = " ".join(args)
        for pattern, (rc, out, err) in self.answers.items():
            if pattern in line:
                return subprocess.CompletedProcess(list(args), rc, out, err)
        raise AssertionError(f"unexpected call: {line}")

    def mutations(self) -> list[str]:
        return [" ".join(call) for call in self.calls
                if any(word in call for word in ("stop", "rm", "up", "restart", "kill"))]


ID = "a" * 64
OTHER = "b" * 64


def listing(*containers: tuple[str, str]) -> str:
    return "".join(json.dumps({"ID": identity, "Names": name, "State": "running"}) + "\n"
                   for identity, name in containers)


class ReplaceTests(unittest.TestCase):
    def agent(self) -> "restart.Agent":
        agent = restart.Agent.__new__(restart.Agent)
        agent.container = "oats-agent-acwd25"
        agent.compose = ["docker", "compose", "-p", "acwd25-lab", "-f", "compose.agent.yaml"]
        return agent

    def remove(self, daemon: Daemon) -> None:
        original = restart.run
        restart.run = daemon
        try:
            restart.remove_verified(self.agent(), ID)
        finally:
            restart.run = original

    def test_a_compose_project_whose_agent_is_another_container_mutates_nothing(self):
        daemon = Daemon({"ps --all --quiet agent": (0, OTHER + "\n", "")})
        with self.assertRaisesRegex(restart.Failed, "is not the container inspected"):
            self.remove(daemon)
        self.assertEqual(daemon.mutations(), [])

    def test_a_failed_or_mixed_compose_answer_mutates_nothing(self):
        for answer in ((1, "", "no such project"), (0, ID + "\n", "WARN something"), (0, "", ""),
                       (0, ID + "\n" + OTHER + "\n", "")):
            daemon = Daemon({"ps --all --quiet agent": answer})
            with self.assertRaises(restart.Failed):
                self.remove(daemon)
            self.assertEqual(daemon.mutations(), [])

    def test_the_verified_container_is_removed_by_its_id_and_its_absence_observed(self):
        daemon = Daemon({"ps --all --quiet agent": (0, ID + "\n", ""), f"stop --time 50 {ID}": (0, ID, ""),
                         f"rm {ID}": (0, ID, ""), "container ls": (0, listing((OTHER, "another")), "")})
        self.remove(daemon)
        self.assertEqual(daemon.mutations(), [f"docker stop --time 50 {ID}", f"docker rm {ID}"])

    def test_a_failed_absence_observation_is_no_evidence_of_removal(self):
        daemon = Daemon({"ps --all --quiet agent": (0, ID + "\n", ""), f"stop --time 50 {ID}": (0, ID, ""),
                         f"rm {ID}": (0, ID, ""), "container ls": (1, "", "Cannot connect to the Docker daemon")})
        with self.assertRaisesRegex(restart.Failed, "absence is not known"):
            self.remove(daemon)

    def test_a_container_still_listed_after_rm_stops_the_replacement(self):
        daemon = Daemon({"ps --all --quiet agent": (0, ID + "\n", ""), f"stop --time 50 {ID}": (0, ID, ""),
                         f"rm {ID}": (0, ID, ""), "container ls": (0, listing((ID, "oats-agent-acwd25")), "")})
        with self.assertRaisesRegex(restart.Failed, "still exists"):
            self.remove(daemon)


if __name__ == "__main__":
    unittest.main()
