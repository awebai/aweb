import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from vm_gate.runtime import Runtime
from vm_gate.provider import Provider
from vm_gate.source import prepare
from test_source import GitFixture, git
from test_config import hashes
from test_runtime import FullBackend


class SnapshotBackend(FullBackend):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.images = {
            1: {
                "id": 1,
                "type": "snapshot",
                "status": "available",
                "architecture": "x86",
                "disk_size": 240,
                "image_size": 2,
            }
        }

    def image_info(self, id):
        return self.images[id]

    def snapshot_pricing(self):
        return {"currency": "EUR", "image": {"price_per_gb_month": {"gross": ".01"}}}

    def create_image(self, server, labels):
        self.images[50] = dict(self.images[1], id=50)
        return {"id": 50, "action": {"status": "success"}}

    def wait(self, *args, **kwargs):
        pass

    def promote_image(self, id, run):
        self.calls.append("promote")

    def delete_base(self, id, new):
        assert (
            json.loads(Path(self.config["config_path"]).read_text())["snapshot_id"]
            == new
        )
        self.calls.append("delete-old")
        del self.images[id]

    def get(self, kind, id):
        return self.images.get(id) if kind == "image" else super().get(kind, id)


class SnapshotRemote:
    fail_restore = False

    def __init__(self, config, directory, source, command, provider):
        self.config = config
        self.directory = Path(directory)
        self.source = source
        self.provider = provider
        self.transport = SimpleNamespace(copy=lambda *a, **kw: None)
        self.verify_host = True

    def preflight(self):
        pass

    def prepare(self, server, timeout):
        if self.directory.name == "restore" and self.fail_restore:
            raise RuntimeError("restored host mismatch")
        receipt = {
            **self.config["manifest"],
            "uid": 1000,
            "sha": self.source["sha"],
            "gotoolchain": "local",
        }
        (self.directory / "host-contract.stdout").write_text(json.dumps(receipt))

    def env(self, root=False):
        return ""

    def run(self, command, name, check=True):
        receipt = {
            **self.config["manifest"],
            "uid": 1000,
            "sha": self.source["sha"],
            "gotoolchain": "local",
            "observed": self.source["requirements"],
            "required": self.source["requirements"],
        }
        return SimpleNamespace(returncode=0, stdout=json.dumps(receipt), stderr="")


class SnapshotOperationsTests(GitFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.directory = self.root / "snapshot-run"
        self.directory.mkdir()
        self.source = prepare(
            self.repo, self.sha, self.directory, observed=self.observed
        )
        self.manifest = {
            "observed": self.observed,
            "commands": hashes(),
            "dpkg": "pkg=1",
        }
        manifest = self.root / "base.json"
        manifest.write_text(json.dumps(self.manifest))
        self.config = {
            "config_path": str(self.root / "operator.json"),
            "state_root": str(self.root / "state"),
            "ledger": str(self.root / "state/ledger.tsv"),
            "cap_eur": "150",
            "seed_eur": "0",
            "owner": "seat",
            "snapshot_id": 1,
            "snapshot_manifest": str(manifest),
            "manifest": self.manifest,
        }
        Path(self.config["config_path"]).write_text(
            json.dumps({"snapshot_id": 1, "snapshot_manifest": str(manifest)})
        )
        self.backend = SnapshotBackend(self.config)
        self.provider = Provider(self.backend, sleep=lambda _: None)
        self.runtime = Runtime(
            config=self.config,
            directory=self.directory,
            source=self.source,
            command=None,
            args=SimpleNamespace(),
            run_id="snapshot",
            provider_factory=lambda cfg: self.provider,
        )

        def key():
            for name in ["ssh-key", "ssh-key.pub"]:
                (self.directory / name).write_text("fixture")

        self.key = patch.object(self.runtime, "_key", side_effect=key)
        self.key.start()
        self.addCleanup(self.key.stop)

    def invoke(self, fail=False):
        SnapshotRemote.fail_restore = fail
        with (
            patch("vm_gate.snapshot_ops.Executor", SnapshotRemote),
            patch("vm_gate.snapshot_ops.resolve", return_value={}),
        ):
            return self.runtime.snapshot()

    def test_complete_snapshot_wiring_verifies_restore_before_replacing_old_base(self):
        result = self.invoke()
        self.assertEqual(result["exit"], 0, result)
        self.assertTrue(result["verified"])
        self.assertTrue(result["old_deleted"])
        self.assertEqual(list(self.backend.images), [50])
        self.assertEqual(self.backend.items, [])
        self.assertEqual(
            json.loads(Path(self.config["config_path"]).read_text())["snapshot_id"], 50
        )
        self.assertEqual(len(result["servers"]), 2)

    def test_restored_host_failure_leaves_config_old_and_new_snapshot_reported(self):
        result = self.invoke(fail=True)
        self.assertEqual(result["exit"], 70)
        self.assertEqual(
            json.loads(Path(self.config["config_path"]).read_text())["snapshot_id"], 1
        )
        self.assertEqual(set(self.backend.images), {1, 50})
        self.assertEqual(result["orphan_snapshots"], [50])
        self.assertEqual(self.backend.items, [])


if __name__ == "__main__":
    unittest.main()
