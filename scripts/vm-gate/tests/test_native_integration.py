import io
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from test_source import GitFixture
from test_native_profile import profile
from test_native_oci import receipt
from vm_gate.cli import main
from vm_gate.config import load
from vm_gate.config_lease import ConfigLease
from vm_gate.errors import Refused
from vm_gate.executor import Executor
from vm_gate.native_executor import ArchiveExecutor
from vm_gate.native_host import preparation_program


class NativeCLI(GitFixture, unittest.TestCase):
    def factory(self, *args, **kwargs):
        self.calls.append(kwargs)
        raise AssertionError("runtime factory must not be reached")

    def invoke(self, *extra):
        return main(
            [
                "--config",
                str(self.config),
                "run",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
                *extra,
            ],
            factory=self.factory,
            out=io.StringIO(),
        )

    def setUp(self):
        super().setUp()
        self.config = self.root / "operator.json"
        self.calls = []
        uid = patch("os.geteuid", return_value=501)
        uid.start()
        self.addCleanup(uid.stop)
        cfg = {
            "state_root": str(self.root / "state"),
            "ledger": str(self.root / "ledger.tsv"),
            "token_file": str(self.root / "credential"),
            "owner": "seat",
            "location": "fsn1",
        }
        self.profile_path = self.root / "native.json"
        self.profile_path.write_text(json.dumps(profile()))
        cfg.update(
            host_profile="native-arm64-oci-v1", native_profile=str(self.profile_path)
        )
        self.config.write_text(json.dumps(cfg))
        self.archive = self.root / "archive.tar"
        self.archive.write_bytes(b"archive")
        self.receipt = self.root / "native-amd64.json"
        self.receipt.write_text(json.dumps(receipt("linux/amd64")))

    def options(self):
        return [
            "--type",
            "cax21",
            "--timeout",
            "900",
            "--command",
            "make test-server-image-build",
            "--archive-in",
            str(self.archive),
            "--amd64-receipt",
            str(self.receipt),
        ]

    def test_missing_archive_refuses_before_runtime_factory(self):
        self.archive.unlink()
        self.assertEqual(self.invoke(*self.options()), 78)
        self.assertEqual(self.calls, [])

    def test_cax_profile_cannot_run_general_command_or_full_gate(self):
        self.assertEqual(self.invoke("--type", "cax21", "--command", "true"), 78)
        self.assertEqual(self.invoke("--type", "cax21", "--stages", "checks"), 78)
        self.assertEqual(self.calls, [])

    def test_native_profile_freezes_source_without_claiming_snapshot_toolchain(self):
        calls = []

        def factory(**kw):
            calls.append(kw)
            return SimpleNamespace(run=lambda: {"exit": 0})

        status = main(
            [
                "--config",
                str(self.config),
                "run",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
                *self.options(),
            ],
            factory=factory,
            out=io.StringIO(),
        )
        self.assertEqual(status, 0)
        self.assertEqual(calls[0]["source"]["host_profile"], "native-arm64-oci-v1")
        self.assertNotIn("snapshot_id", calls[0]["config"])
        self.assertEqual(calls[0]["config"]["image_id"], 161547270)

    def test_profile_replacement_between_admission_and_allocation_refuses(self):
        cfg = load(self.config, self.repo)
        p = profile()
        p["apt"]["packages"]["docker-ce"]["SHA256"] = "f" * 64
        self.profile_path.write_text(json.dumps(p))
        with self.assertRaises(Refused), ConfigLease(cfg):
            pass


class ArchiveTransport(unittest.TestCase):
    def test_collect_retains_actual_archive_before_lifecycle_can_delete_host(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            evidence = root / "evidence/var/log/vm-gate"
            evidence.mkdir(parents=True)
            identity = receipt("linux/amd64")
            (evidence / "gate-exit").write_text("0")
            (evidence / "gate-output.log").write_text(
                "server image archive receipt="
                + json.dumps(identity)
                + "\nserver image linux/amd64 PASS: "
                + repr({"version": "1.2.3", "machine": "x86_64", "uid": 1001})
                + "\n"
            )
            remote = ArchiveExecutor(
                {"archive_out": True},
                root,
                {"sha": "a" * 40},
                "make test-server-image-build",
                None,
            )
            remote.deadline = time.monotonic() + 30
            copied = []

            def copy(source, target, **kw):
                copied.append((source, kw))
                Path(target).write_bytes(b"archive")

            remote.transport = SimpleNamespace(copy=copy)
            with patch.object(Executor, "collect", return_value={}):
                result = remote.collect({}, 30)
            self.assertEqual(
                Path(result["retained_oci_archive"]).read_bytes(), b"archive"
            )
            self.assertEqual(
                Path(result["retained_oci_archive"]).stat().st_mode & 0o777, 0o600
            )
            self.assertTrue(result["native_oci_receipt"]["native_pass"])
            self.assertEqual(copied[0][0], "/evidence/server.oci.tar")
            self.assertTrue(
                json.loads((root / "archive-retention.json").read_text())[
                    "verified_before_delete"
                ]
            )

    def test_root_uid_refusal_precedes_host_inspection(self):
        from vm_gate.native_host import main as host_main

        with (
            patch("os.getuid", return_value=0),
            patch("vm_gate.native_host.observe") as observe,
        ):
            self.assertEqual(host_main(), 78)
            observe.assert_not_called()

    def test_actual_preparation_shell_has_valid_syntax(self):
        result = subprocess.run(
            ["bash", "-n"],
            input=preparation_program(profile()),
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
