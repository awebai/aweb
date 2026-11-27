import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from vm_gate.runtime import Runtime
from vm_gate.provider import Provider
from test_lifecycle import Backend
from test_source import GitFixture
from test_config import hashes
from vm_gate.source import prepare


class FullBackend(Backend):
    def pricing(self, kind):
        return {
            "server_hourly": ".2",
            "ip_hourly": ".01",
            "currency": "EUR",
            "disk": 240,
        }

    def image_info(self, id):
        return {"status": "available", "architecture": "x86", "disk_size": 240}


class FakeRemote:
    def __init__(self, config, directory, source, command, provider):
        self.config = config
        self.directory = directory
        self.source = source
        self.provider = provider

    def preflight(self):
        pass

    def prepare(self, server, timeout):
        pass

    def execute(self, server, timeout):
        return 7

    def collect(self, server, timeout):
        path = self.directory / "evidence/var/log/vm-gate"
        path.mkdir(parents=True)
        before = (self.directory / "ledger-before.tsv").read_bytes()
        host_logs = Path(self.config["ledger"]).parent / "gate-logs"
        logs = path / "ledger-gate-logs"
        retained = Path("unit-evidence-run")
        entries = {
            "unit": Path("run-unit.log"),
            "unit/test-server": retained / "test-egress/test-server/suite.log",
        }
        rows = []
        for entry, relative in entries.items():
            log = logs / relative
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(f"failure evidence for {entry}")
            rows.append(
                "\t".join(
                    [
                        self.source["tree"] + "-inputs",
                        entry,
                        "failed",
                        self.source["sha"],
                        "",
                        str(host_logs / relative),
                        "seat",
                        "start",
                        "end",
                        "",
                    ]
                )
                + "\n"
            )
        (logs / retained / "summary.tsv").write_text(
            "unit/test-server\tFAILED\ttest-egress/test-server/suite.log\t2s\n"
        )
        (path / "ledger-after.tsv").write_bytes(before + "".join(rows).encode())
        return {
            "stages": [{"stage": "unit", "status": "FAILED", "seconds": 2}],
            "memory": {},
        }


class RuntimeTests(GitFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.directory = self.root / "run"
        self.directory.mkdir()
        self.source = prepare(
            self.repo, self.sha, self.directory, observed=self.observed
        )
        self.config = {
            "state_root": str(self.root / "state"),
            "ledger": str(self.root / "state/ledger.tsv"),
            "cap_eur": "150",
            "seed_eur": "0",
            "owner": "seat",
            "repo": str(self.repo),
            "snapshot_id": 1,
            "manifest": {
                "observed": self.observed,
                "commands": hashes(),
                "dpkg": "pkg=1",
            },
            "config_path": str(self.root / "operator.json"),
        }
        Path(self.config["config_path"]).write_text(json.dumps({"snapshot_id": 1}))
        self.backend = FullBackend()
        self.provider = Provider(self.backend, sleep=lambda _: None)
        self.args = SimpleNamespace(type="ccx33", timeout=60, stages="unit")

    def runtime(self):
        return Runtime(
            config=self.config,
            directory=self.directory,
            source=self.source,
            command="false",
            args=self.args,
            run_id="run",
            provider_factory=lambda _: self.provider,
            executor_factory=FakeRemote,
        )

    def test_failure_rows_and_logs_survive_vm_deletion_and_exit_is_preserved(self):
        runtime = self.runtime()
        with patch.object(runtime, "_key"):
            result = runtime.run()
        self.assertEqual(result["exit"], 7)
        self.assertIsNone(result["infrastructure"])
        ledger = Path(self.config["ledger"])
        rows = [row.split("\t") for row in ledger.read_text().splitlines()]
        self.assertEqual({row[1] for row in rows}, {"unit", "unit/test-server"})
        for row in rows:
            self.assertEqual(row[2], "failed")
            self.assertEqual(Path(row[5]).read_text(), f"failure evidence for {row[1]}")
        summary = ledger.parent / "gate-logs/unit-evidence-run/summary.tsv"
        self.assertEqual(
            summary.read_text(), "unit/test-server\tFAILED\ttest-egress/test-server/suite.log\t2s\n"
        )
        self.assertEqual(self.backend.items, [])

    def test_conflicting_nested_log_blocks_ledger_import(self):
        ledger = Path(self.config["ledger"])
        log = ledger.parent / "gate-logs/unit-evidence-run/test-egress/test-server/suite.log"
        log.parent.mkdir(parents=True)
        log.write_bytes(b"original")
        runtime = self.runtime()
        with patch.object(runtime, "_key"):
            result = runtime.run()
        self.assertEqual(result["exit"], 70)
        self.assertIn("conflicts with retained VM log", result["error"])
        self.assertEqual(log.read_bytes(), b"original")
        self.assertFalse(ledger.exists())

    def test_preallocation_provider_failure_does_not_leave_private_host_key(self):
        runtime = self.runtime()

        def keys():
            for name in ["ssh-key", "ssh-key.pub", "ssh-host-key", "ssh-host-key.pub"]:
                (self.directory / name).write_text("private fixture")

        def fail(config):
            from vm_gate.errors import Infrastructure

            raise Infrastructure("provider unavailable before reservation")

        runtime.provider_factory = fail
        from vm_gate.errors import Infrastructure

        with patch.object(runtime, "_key", side_effect=keys):
            with self.assertRaises(Infrastructure):
                runtime.run()
        self.assertFalse((self.directory / "ssh-host-key").exists())

    def test_reaped_run_forgets_private_host_key_only_after_proven_cleanup(self):
        runtime = self.runtime()
        runtime.store.reserve("expired", 1, now=1, expires=2)
        runtime.store.settle("expired", ".2", now=3)
        runtime.store.update("expired", {"reaped": 3})
        old = Path(self.config["state_root"]) / "runs/expired"
        old.mkdir(parents=True)
        for name in ["ssh-key", "ssh-key.pub", "ssh-host-key", "ssh-host-key.pub"]:
            (old / name).write_text("private fixture")
        (old / "evidence.json").write_text("retained receipt")
        runtime._forget_reaped_keys()
        self.assertEqual([p.name for p in old.iterdir()], ["evidence.json"])

    def test_cap_refusal_remains_refusal_when_no_registry_row_was_created(self):
        self.config["cap_eur"] = ".01"
        runtime = self.runtime()
        with patch.object(runtime, "_key"):
            result = runtime.run()
        self.assertEqual(result["exit"], 78)
        self.assertEqual(result["infrastructure"], "refused")
        self.assertEqual(self.backend.items, [])


if __name__ == "__main__":
    unittest.main()
