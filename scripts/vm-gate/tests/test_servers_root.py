"""A root spec's run when its step replaces the guest's Docker engine and the run times out."""

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from unittest.mock import patch

from vm_gate.errors import Infrastructure
from vm_gate.executor import Executor
from vm_gate.servers import ServersExecutor

SHA = "b" * 40


class EngineGoneTransport:
    """A guest whose Docker engine is gone and whose gate never wrote its exit."""

    def __init__(self):
        self.commands = []
        self.downloaded = False
        data = json.dumps(
            {"steps": [{"name": "ruleset", "exit": None, "verdict": "unrun"}]}
        ).encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("var/log/vm-gate/servers/result.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.archive = stream.getvalue()

    def run(self, command, *, timeout, check):
        self.commands.append(command)
        if (
            "docker" in command
            and "evidence-pack" not in command
            and "tarfile" not in command
        ):
            return SimpleNamespace(
                returncode=1, stdout="", stderr="Cannot connect to the Docker daemon\n"
            )
        if command.startswith("cat /var/log/vm-gate/gate-exit"):
            return SimpleNamespace(returncode=1, stdout="", stderr="No such file\n")
        if command.startswith("sha256sum "):
            return SimpleNamespace(
                returncode=0,
                stdout=hashlib.sha256(self.archive).hexdigest() + "  x\n",
                stderr="",
            )
        if "bash /opt/vm-gate/launch.sh" in command:
            return SimpleNamespace(returncode=124, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def copy(self, source, target, *, timeout, download):
        Path(target).write_bytes(self.archive)
        self.downloaded = True


class RootRunTimeout(unittest.TestCase):
    def executor(self, directory):
        executor = ServersExecutor(
            {"ledger": "/tmp/fixture/ledger", "owner": "fixture"},
            directory,
            {"sha": SHA},
            "python3 servers_run.py",
            None,
            servers={"root": True, "spec_bytes": b"{}", "bundles": {}},
        )
        executor.transport = EngineGoneTransport()
        return executor

    def test_a_timed_out_root_run_is_infrastructure_and_its_evidence_comes_back_without_docker(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            executor = self.executor(Path(tmp))
            with self.assertRaisesRegex(
                Infrastructure, "without its completed exit receipt"
            ):
                executor.execute({}, 30)  # nonliteral-call: gate run, not SQL
            # The runner ran as root, not through runuser.
            [launch] = [
                command
                for command in executor.transport.commands
                if "launch.sh" in command
            ]
            self.assertNotIn("runuser", launch)
            self.assertIn("HOME=/root", launch)
            result = executor.collect({}, 30)
            self.assertTrue(executor.transport.downloaded)
            self.assertEqual(
                result["archive_sha256"],
                hashlib.sha256(executor.transport.archive).hexdigest(),
            )
            # The engine's own reports failed and were only observations.
            self.assertTrue(
                any(
                    "docker ps -a" in command for command in executor.transport.commands
                )
            )
            pack = [
                command
                for command in executor.transport.commands
                if "tarfile" in command
            ]
            self.assertEqual(len(pack), 1)
            self.assertNotIn("docker ", pack[0])
            archived = Path(tmp) / "evidence/var/log/vm-gate/servers/result.json"
            self.assertEqual(
                json.loads(archived.read_text())["steps"][0]["name"], "ruleset"
            )


class RecordingTransport:
    """Every command the executor sends; a completed gate whose exit and receipt agree."""

    def __init__(self, exit_code=0):
        self.commands = []
        self.exit_code = exit_code

    def run(self, command, *, timeout, check):
        self.commands.append(command)
        if command == "cat /var/log/vm-gate/supervisor-receipt.json":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"raw_exit": self.exit_code, "grace_expired": False}),
                stderr="",
            )
        if command == "cat /var/log/vm-gate/gate-exit":
            return SimpleNamespace(
                returncode=0, stdout=f"{self.exit_code}\n", stderr=""
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def copy(self, source, target, *, timeout, download=False):
        pass


class RootLaunchPath(unittest.TestCase):
    def executor(self, directory, root):
        executor = ServersExecutor(
            {"ledger": "/tmp/fixture/ledger", "owner": "fixture"},
            directory,
            {"sha": SHA},
            "python3 servers_run.py",
            None,
            servers={"root": root, "spec_bytes": b"{}", "bundles": {}},
        )
        executor.transport = RecordingTransport()
        executor.deadline = 10**12
        (Path(directory) / "launch.sh").write_text(executor.launch_program())
        return executor

    def prepared(self, root):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        executor = self.executor(Path(tmp.name), root)
        with patch.object(Executor, "prepare", lambda self, server, timeout: None):
            executor.prepare({}, 30)
        return executor, "\n".join(executor.transport.commands)

    def test_a_root_spec_owns_its_launcher_working_directory_and_completion_records(
        self,
    ):
        executor, commands = self.prepared(True)
        digest = hashlib.sha256(
            (executor.directory / "launch.sh").read_bytes()
        ).hexdigest()
        self.assertIn(
            "install -d -m 0700 -o root -g root /opt/vm-gate/root-run", commands
        )
        self.assertIn(
            f"echo {digest}  /opt/vm-gate/launch.sh | sha256sum -c -", commands
        )
        self.assertIn(
            "-m 0700 -o root -g root /opt/vm-gate/sources /opt/vm-gate/runs", commands
        )

    def test_a_gate_user_spec_keeps_its_own_path(self):
        executor, commands = self.prepared(False)
        for root_only in (
            "root-run",
            "chown root:root /opt/vm-gate/launch.sh",
            "chown -R root:root /var/log/vm-gate",
        ):
            self.assertNotIn(root_only, commands)
        self.assertIn(
            "-m 0755 -o gateuser -g gateuser /opt/vm-gate/sources /opt/vm-gate/runs",
            commands,
        )

    def test_a_root_launch_runs_from_its_own_directory_and_reads_the_checkout_as_its_owner(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            rooted = self.executor(Path(tmp), True).launch_program()
            plain = self.executor(Path(tmp), False).launch_program()
        self.assertIn("cd /opt/vm-gate/root-run\n", rooted)
        self.assertIn('test "$(id -u)" = 0\n', rooted)
        self.assertNotIn("host_contract", rooted)
        self.assertIn(
            "runuser -u gateuser -- git -C /opt/vm-gate/source status --porcelain --untracked-files=all"
            " > /var/log/vm-gate/source-after",
            rooted,
        )
        self.assertIn("cd /opt/vm-gate/source\n", plain)
        self.assertIn('test "$(id -u)" = 1000\n', plain)
        self.assertIn(
            "git status --porcelain --untracked-files=all > /var/log/vm-gate/source-after",
            plain,
        )

    def test_a_successful_root_run_keeps_its_exit_through_the_receipt(self):
        for root, cwd, user in (
            (True, "/opt/vm-gate/root-run", "HOME=/root"),
            (False, "/opt/vm-gate/source", "runuser -u gateuser --"),
        ):
            with self.subTest(root=root), tempfile.TemporaryDirectory() as tmp:
                executor = self.executor(Path(tmp), root)
                code = executor.execute({}, 30)  # nonliteral-call: gate run, not SQL
                self.assertEqual(code, 0)
                [launch] = [c for c in executor.transport.commands if "launch.sh" in c]
                self.assertTrue(
                    launch.startswith(f"cd {cwd} && setsid --wait nohup "), launch
                )
                self.assertIn(user, launch)
                self.assertEqual("runuser" in launch, not root)


class PrepareTransport(RecordingTransport):
    """A guest for the whole base prepare: the host contract holds, the UID-0 control refuses."""

    def run(self, command, *, timeout, check):
        if "vm_gate.host_contract" in command and "HOME=/root" in command:
            self.commands.append(command)
            return SimpleNamespace(returncode=78, stdout="", stderr="UID 0 refused\n")
        return super().run(command, timeout=timeout, check=check)

    def prove_mismatch(self, *, timeout):
        return SimpleNamespace(returncode=255, stdout="", stderr="host key mismatch\n")


class RootPathFromTheStart(unittest.TestCase):
    """Through the base prepare itself: a root spec's privileged paths are never the gate user's."""

    def prepared(self, root):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        for name in (
            "source.json",
            "ledger-before.tsv",
            "ledger-logs-before.tar.gz",
            "source.bundle",
        ):
            (directory / name).write_text(name)
        executor = ServersExecutor(
            {
                "ledger": "/var/lib/gate/ledger.tsv",
                "owner": "fixture",
                "manifest": {"observed": {}},
            },
            directory,
            {
                "sha": SHA,
                "bundle": str(directory / "source.bundle"),
                "frozen_main": SHA,
            },
            "python3 servers_run.py",
            None,
            servers={"root": root, "spec_bytes": b"{}", "bundles": {}},
        )
        executor.transport = PrepareTransport()
        (directory / "launch.sh").write_text(executor.launch_program())
        executor.prepare({}, 600)
        return executor.transport.commands

    def test_a_root_spec_never_gives_the_gate_user_its_logs_or_launcher(self):
        commands = self.prepared(True)
        text = "\n".join(commands)
        self.assertIn("install -d -m 0755 -o root -g root /var/log/vm-gate", text)
        self.assertNotIn("-o gateuser -g gateuser /var/log/vm-gate", text)
        launch = [
            c
            for c in commands
            if c.startswith("chown")
            and c.rstrip().endswith("/opt/vm-gate/launch.sh")
            or "/opt/vm-gate/launch.sh &&" in c
            and c.startswith("chown")
        ]
        self.assertTrue(launch, commands)
        self.assertTrue(
            all("root:root" in c and "gateuser" not in c for c in launch), launch
        )
        # The gate user's host contract still runs, after the uploads.
        self.assertTrue(
            any(
                "runuser -u gateuser" in c and "vm_gate.host_contract" in c
                for c in commands
            )
        )
        self.assertIn("sha256sum -c -", text)

    def test_the_gate_user_path_still_gives_it_its_logs_and_launcher(self):
        text = "\n".join(self.prepared(False))
        self.assertIn(
            "install -d -m 0750 -o gateuser -g gateuser /var/log/vm-gate", text
        )
        self.assertIn("chown gateuser:gateuser /opt/vm-gate/launch.sh", text)
        self.assertNotIn("root-run", text)


if __name__ == "__main__":
    unittest.main()
