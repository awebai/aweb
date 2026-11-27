"""A root spec's run when its step replaces the guest's Docker engine and the run times out."""

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vm_gate.errors import Infrastructure
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
                executor.execute({}, 30)
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


if __name__ == "__main__":
    unittest.main()
