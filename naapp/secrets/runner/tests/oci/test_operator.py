"""Protected runtime config and real CLI doctor; no execution or service calls."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

import test_lifecycle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.execution import execute
from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.protocol import canonical, public_did
from aweb_secrets_runner.state import Identity, IdentityStore


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class OperatorTests(unittest.IsolatedAsyncioTestCase):
    command = test_lifecycle.LifecycleTests.command
    inputs = test_lifecycle.LifecycleTests.inputs
    credential = test_lifecycle.LifecycleTests.credential
    config = test_lifecycle.LifecycleTests.config

    def setUp(self):
        test_lifecycle.LifecycleTests.setUp(self)

    def configured(self, *, change=None, paths=()):
        config, body = self.config("exit 0")
        path = self.root / "runner.json"
        document = json.loads(path.read_bytes())
        spec = {
            "kind": "runc",
            "images": str(self.runtime.images),
            "workspace": str(self.runtime.workspace),
        }
        for key in ("engine", "unpacker", "supervisor"):
            pin = getattr(self.runtime, key)
            spec[key] = {"path": str(pin.path), "sha256": pin.sha256}
        if change:
            change(spec)
        body["oci"]["read_only_paths"] = list(paths)
        document["jobs"]["fixture"] = {"digest": job_digest(body), "definition": body}
        document["runtime"] = spec
        path.write_bytes(canonical(document))
        return RunnerConfig.load(path), body

    def test_real_runtime_pins_and_tmpfs_preflight_create_no_bundle(self):
        config, body = self.configured()
        self.assertEqual(config.runtime(), self.runtime)
        self.assertEqual(config.doctor(body["runner_ids"][0]), ("fixture",))
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_cli_checks_without_spawning_even_a_pinned_tool_or_printing_private_paths(self):
        marker = self.root / "must-not-exist"
        tool = self.root / "engine"
        tool.write_text("#!/bin/sh\ntouch " + str(marker) + "\nexit 99\n")
        tool.chmod(0o700)
        config, body = self.configured(
            change=lambda spec: spec.update(
                engine={"path": str(tool), "sha256": hashlib.sha256(tool.read_bytes()).hexdigest()}
            )
        )
        state = self.root / "identity"
        identity = Identity(
            origin="https://secrets.example",
            runner_id=body["runner_ids"][0],
            service_kid=public_did(Ed25519PrivateKey.generate().public_key()),
            signing_key=Ed25519PrivateKey.generate(),
            encryption_key=X25519PrivateKey.generate(),
        )
        store = IdentityStore(state)
        with store.registration_lock():
            store.save(identity)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aweb_secrets_runner",
                "doctor",
                "--config",
                str(self.root / "runner.json"),
                "--state-dir",
                str(state),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout), {"runner_id": identity.runner_id, "jobs": ["fixture"]}
        )
        self.assertEqual(result.stderr, b"")
        self.assertFalse(marker.exists())
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertTrue((state / "journal.sqlite3").exists())

        document = json.loads((self.root / "runner.json").read_bytes())
        document["runtime"]["engine"]["sha256"] = "0" * 64
        (self.root / "runner.json").write_bytes(canonical(document))
        refusal = subprocess.run(
            result.args, stdin=subprocess.DEVNULL, capture_output=True, timeout=5
        )
        self.assertEqual(refusal.returncode, 1)
        self.assertEqual(refusal.stdout, b"")
        self.assertEqual(refusal.stderr, b"file_pin_mismatch\n")
        self.assertFalse(marker.exists())

    def test_every_tool_hash_is_checked(self):
        for key in ("engine", "unpacker", "supervisor"):
            with self.subTest(key=key):
                config, body = self.configured(
                    change=lambda spec, key=key: spec[key].update(sha256="0" * 64)
                )
                with self.assertRaisesRegex(Refused, "file_pin_mismatch"):
                    config.doctor(body["runner_ids"][0])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_different_supervisor_refuses_even_when_its_hash_is_valid(self):
        config, body = self.configured(change=lambda spec: spec.update(supervisor=spec["engine"]))
        with self.assertRaisesRegex(Refused, "runner_runtime_unavailable"):
            config.doctor(body["runner_ids"][0])

    def test_disk_workspace_is_not_a_memory_capability(self):
        with tempfile.TemporaryDirectory(dir="/disk") as directory:
            config, body = self.configured(change=lambda spec: spec.update(workspace=directory))
            with self.assertRaisesRegex(Refused, "oci_state_invalid"):
                config.doctor(body["runner_ids"][0])

    def test_public_workspace_and_writable_image_store_refuse(self):
        config, body = self.configured()
        self.workspace.chmod(0o750)
        with self.assertRaisesRegex(Refused, "oci_state_invalid"):
            config.doctor(body["runner_ids"][0])
        self.workspace.chmod(0o700)
        self.layout.chmod(0o777)
        with self.assertRaisesRegex(Refused, "path_permissions"):
            config.doctor(body["runner_ids"][0])
        self.layout.chmod(0o700)

    def test_read_only_mount_cannot_expose_the_private_workspace(self):
        config, body = self.configured(paths=(str(self.workspace),))
        with self.assertRaisesRegex(Refused, "oci_mount_invalid"):
            config.doctor(body["runner_ids"][0])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_changed_operator_settings_are_not_reloaded_implicitly(self):
        config, body = self.configured()
        path = self.root / "runner.json"
        value = json.loads(path.read_bytes())
        value["runtime"]["workspace"] += "-other"
        path.write_bytes(canonical(value))
        with self.assertRaisesRegex(Refused, "config_changed"):
            config.doctor(body["runner_ids"][0])

    async def test_preflight_without_runtime_composition_still_refuses_execution(self):
        config, body = self.configured()
        config.doctor(body["runner_ids"][0])
        with self.assertRaisesRegex(Refused, "runner_runtime_unavailable"):
            await execute(
                config,
                job_id="fixture",
                digest=job_digest(body),
                runner_id=body["runner_ids"][0],
                params={},
                credentials=[self.credential(wrong_dispatch=True)],
                expires_at=time.time() + 300,
            )
        self.assertEqual(list(self.workspace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
