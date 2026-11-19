import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from vm_gate.cli import main
from test_source import GitFixture
from test_config import hashes


class CliTests(GitFixture, unittest.TestCase):
    # Reuse only the Git fixture, not its inherited source-admission test cases.
    def setUp(self):
        super().setUp()
        self.config = self.root / "operator.json"
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {"observed": self.observed, "commands": hashes(), "dpkg": "fixture=1"}
            )
        )
        self.config.write_text(
            json.dumps(
                {
                    "state_root": str(self.root / "state"),
                    "ledger": str(self.root / "state/ledger.tsv"),
                    "snapshot_manifest": str(self.manifest),
                    "token_file": str(self.root / "credential"),
                    "owner": "seat",
                    "location": "location",
                    "datacenter": "datacenter",
                    "snapshot_id": 1,
                    "cap_eur": "150",
                    "seed_eur": "0",
                }
            )
        )
        self.calls = []
        self.uid = patch("os.geteuid", return_value=501)
        self.uid.start()
        self.addCleanup(self.uid.stop)

    def factory(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("provider must not be constructed")

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

    def test_dirty_admission_precedes_provider_or_credential_read(self):
        (self.repo / "dirty").write_text("dirty")
        self.assertEqual(self.invoke(), 78)
        self.assertEqual(self.calls, [])

    def test_pin_admission_precedes_provider_or_credential_read(self):
        self.observed["go"] = "wrong"
        self.manifest.write_text(
            json.dumps(
                {"observed": self.observed, "commands": hashes(), "dpkg": "fixture=1"}
            )
        )
        self.assertEqual(self.invoke(), 78)
        self.assertEqual(self.calls, [])

    def test_command_syntax_refuses_before_provider(self):
        self.assertEqual(self.invoke("--command", "if then"), 78)
        self.assertEqual(self.calls, [])

    def test_invalid_stage_is_a_local_refusal(self):
        self.assertEqual(self.invoke("--stages", "unknown"), 78)
        self.assertEqual(self.calls, [])

    def test_valid_source_reaches_factory_and_gate_exit_is_returned(self):
        calls = []

        def factory(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(run=lambda: {"exit": 7, "infrastructure": None})

        status = main(
            [
                "--config",
                str(self.config),
                "run",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
            ],
            factory=factory,
            out=io.StringIO(),
        )
        self.assertEqual(status, 7)
        self.assertEqual(calls[0]["source"]["sha"], self.sha)

    def test_root_operator_is_refused_before_provider(self):
        with patch("os.geteuid", return_value=0):
            self.assertEqual(self.invoke(), 78)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
