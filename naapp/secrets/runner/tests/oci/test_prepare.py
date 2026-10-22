"""Real public-only OCI preparation, not worker/credential release acceptance."""

import asyncio
import hashlib
import io
import json
import os
import pwd
import shutil
import subprocess
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_runtime

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.job_inputs import JobInputs
from aweb_secrets_runner.oci_prepare import BinaryPin, RuncPreparation


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class PreparationTests(unittest.IsolatedAsyncioTestCase):
    command = test_runtime.RuntimeCapabilityTests.command

    def setUp(self):
        test_runtime.RuntimeCapabilityTests.setUp(self)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        engine, unpacker = Path(shutil.which("runc")), Path(shutil.which("umoci"))
        self.runtime = RuncPreparation(
            BinaryPin(engine, hashlib.sha256(engine.read_bytes()).hexdigest()),
            BinaryPin(unpacker, hashlib.sha256(unpacker.read_bytes()).hexdigest()),
            self.layout,
            self.workspace,
        )

    def inputs(self, *, environment=None, argv=("/bin/env",), paths=()):
        environment = {"HOME": "/pinned-home"} if environment is None else environment
        pin = json.loads((self.layout / "index.json").read_bytes())["manifests"][0]["digest"]
        declared = {
            name: value if value is not None else {"$credential": "db", "field": "password"}
            for name, value in environment.items()
        }
        has_credential = any(value is None for value in environment.values())
        body = {
            "v": 1,
            "job_id": "fixture",
            "runner_ids": ["rnr_" + "a" * 22],
            "kind": "oci",
            "exec": None,
            "oci": {"image": "fixture/image@" + pin, "read_only_paths": list(paths)},
            "argv": list(argv),
            "env": declared,
            "cwd": "/pinned-work",
            "params": {},
            "timeout_s": 5,
            "output": {"max_bytes": 1024, "projection": ["/exit_code"]},
            "credentials": [{"secret_ref": "db", "delivery": "durable", "mint": None}]
            if has_credential
            else [],
            "allow_durable": has_credential,
        }
        # The immutable data object is real. Full RunnerConfig validation and
        # parameter expansion have separate real tests; this is its consumer.
        return JobInputs(json.dumps(body).encode(), b"{}", json.dumps(environment).encode(), argv)

    def run_bundle(self, bundle):
        return subprocess.run(
            [
                str(bundle.engine),
                "--root",
                str(bundle.state),
                "--rootless=true",
                "--log",
                "/dev/null",
                "run",
                "--bundle",
                str(bundle.directory),
                "proof",
            ],
            env={},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            umask=0o077,
        )

    async def test_actual_bundle_uses_exact_known_env_and_removes_implicit_host_binds(self):
        expected = {"HOME": "/pinned-home", "DECLARED": "non-credential-test-value"}
        async with self.runtime.prepare(self.inputs(environment=expected)) as bundle:
            spec = json.loads((bundle.directory / "config.json").read_bytes())
            self.assertFalse(any(mount.get("type") == "bind" for mount in spec["mounts"]))
            self.assertEqual(spec["process"]["args"], ["/bin/env"])
            self.assertEqual(spec["process"]["cwd"], "/pinned-work")
            self.assertEqual((bundle.directory / "config.json").stat().st_mode & 0o777, 0o600)
            result = self.run_bundle(bundle)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                dict(line.split("=", 1) for line in result.stdout.decode().splitlines()), expected
            )
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_credential_slots_remain_unknown_and_are_never_opened_to_test_home(self):
        async with self.runtime.prepare(
            self.inputs(environment={"HOME": "/pinned-home", "PASSWORD": None})
        ) as bundle:
            spec = json.loads((bundle.directory / "config.json").read_bytes())
            self.assertEqual(spec["process"]["env"], ["HOME=/pinned-home"])
            self.assertIsNone(bundle.inputs.environment["PASSWORD"])
        for environment in ({}, {"HOME": ""}, {"HOME": None}):
            with self.assertRaisesRegex(Refused, "oci_environment_unsupported"):
                async with self.runtime.prepare(self.inputs(environment=environment)):
                    self.fail("unsupported environment prepared")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_actual_runner_input_validation_feeds_a_frozen_parameter_to_the_runtime(self):
        from aweb_secrets_runner.jobs import RunnerConfig, job_digest
        from aweb_secrets_runner.protocol import canonical

        body = self.inputs().definition
        body["env"]["HOME"] = {"$param": "home"}
        body["params"] = {"home": {"schema": {"type": "string", "maxLength": 64}, "charset": None}}
        config = self.root / "local.json"
        # Existing different non-root OS account, not a provisioned S19 agent.
        config.write_bytes(
            canonical(
                {
                    "v": 1,
                    "agent_uids": [pwd.getpwnam("nobody").pw_uid],
                    "jobs": {"fixture": {"digest": job_digest(body), "definition": body}},
                }
            )
        )
        params = {"home": "frozen-parameter-home"}
        selected = RunnerConfig.load(config).inputs(
            job_id="fixture",
            digest=job_digest(body),
            runner_id=body["runner_ids"][0],
            params=params,
            credential_refs=(),
        )
        params["home"] = "changed-caller"
        async with self.runtime.prepare(selected) as bundle:
            result = self.run_bundle(bundle)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"HOME=frozen-parameter-home\n")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_declared_readonly_data_is_visible_but_cannot_be_written(self):
        source = self.root / "mount-data"
        source.mkdir(mode=0o700)
        (source / "public").write_bytes(b"public-data")
        for argv, expected in (
            (("/bin/busybox", "cat", str(source / "public")), 0),
            (("/bin/busybox", "touch", str(source / "created")), 1),
        ):
            async with self.runtime.prepare(self.inputs(argv=argv, paths=(str(source),))) as bundle:
                result = self.run_bundle(bundle)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 0:
                    self.assertEqual(result.stdout, b"public-data")
            self.assertFalse((source / "created").exists())
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_runtime_workspace_and_its_ancestors_cannot_be_mounted(self):
        for path in (self.workspace, self.root):
            with self.assertRaisesRegex(Refused, "oci_mount_invalid"):
                async with self.runtime.prepare(self.inputs(paths=(str(path),))):
                    self.fail("runtime state exposed")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_agent_writable_descendant_is_refused_before_unpacking(self):
        source = self.root / "mount-data"
        source.mkdir(mode=0o700)
        (source / "unsafe").write_bytes(b"public")
        (source / "unsafe").chmod(0o666)
        with self.assertRaisesRegex(Refused, "path_permissions"):
            async with self.runtime.prepare(self.inputs(paths=(str(source),))):
                self.fail("unsafe mount prepared")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_binary_pin_mismatch_refuses_before_creating_runtime_state(self):
        runtime = RuncPreparation(
            BinaryPin(self.runtime.engine.path, "0" * 64),
            self.runtime.unpacker,
            self.layout,
            self.workspace,
        )
        with self.assertRaisesRegex(Refused, "file_pin_mismatch"):
            async with runtime.prepare(self.inputs()):
                self.fail("unqualified runtime prepared")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_unmapped_image_user_refuses_without_overriding_the_image_identity(self):
        self.command("umoci", "config", "--image", self.image, "--config.user", "1000:1000")
        with self.assertRaisesRegex(Refused, "runner_runtime_unavailable"):
            async with self.runtime.prepare(self.inputs()):
                self.fail("unmapped user prepared")
        self.assertEqual(list(self.workspace.iterdir()), [])

    async def test_uncertain_runtime_state_is_retained_instead_of_unlinked(self):
        state = None
        with self.assertRaisesRegex(Refused, "oci_cleanup_required"):
            async with self.runtime.prepare(self.inputs()) as bundle:
                state = bundle.state
                (state / "uncertain").write_bytes(b"retain-until-stopped")
        self.assertIsNotNone(state)
        self.assertEqual((state / "uncertain").read_bytes(), b"retain-until-stopped")
        self.assertTrue((state.parent / "bundle/config.json").exists())

    async def test_read_protected_image_directory_does_not_prevent_private_cleanup(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "marker").write_bytes(b"must-survive")
        outside.chmod(0o555)
        self.addCleanup(outside.chmod, 0o700)
        layer = self.root / "closed.tar"
        with tarfile.open(layer, "w") as archive:
            directory = tarfile.TarInfo("closed")
            directory.type, directory.mode = tarfile.DIRTYPE, 0
            archive.addfile(directory)
            file = tarfile.TarInfo("closed/file")
            file.mode, file.size = 0o444, 6
            archive.addfile(file, io.BytesIO(b"public"))
            link = tarfile.TarInfo("closed/outside-link")
            link.type, link.linkname = tarfile.SYMTYPE, str(outside)
            archive.addfile(link)
        self.command("umoci", "raw", "add-layer", "--image", self.image, str(layer))
        try:
            async with self.runtime.prepare(self.inputs()):
                pass
        finally:
            # Preserve fixture teardown when exercising the initially broken
            # cleanup; these are our known real image directories, not links.
            for path in self.workspace.glob("job-*/bundle/rootfs/closed"):
                path.chmod(0o700)
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertEqual((outside / "marker").read_bytes(), b"must-survive")
        self.assertEqual(outside.stat().st_mode & 0o777, 0o555)

    async def test_cancellation_stops_the_owned_external_unpacker_group_before_cleanup(self):
        ready = self.root / "ready.json"
        script = self.root / "slow-unpacker"
        script.write_text(
            "#!/usr/bin/python3\nimport json, os, signal\n"
            "child = os.fork()\n"
            "if child == 0:\n while True: signal.pause()\n"
            f"open({str(ready)!r}, 'w').write(json.dumps([os.getpid(), child]))\n"
            "while True: signal.pause()\n"
        )
        script.chmod(0o700)
        runtime = RuncPreparation(
            self.runtime.engine,
            BinaryPin(script, hashlib.sha256(script.read_bytes()).hexdigest()),
            self.layout,
            self.workspace,
        )

        async def prepare():
            async with runtime.prepare(self.inputs()):
                self.fail("blocking external tool returned")

        task = asyncio.create_task(prepare())
        try:
            async with asyncio.timeout(3):
                while not ready.exists():
                    await asyncio.sleep(0.01)
            pids = json.loads(ready.read_bytes())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            async with asyncio.timeout(3):
                while any(Path(f"/proc/{pid}").exists() for pid in pids):
                    await asyncio.sleep(0.01)
            self.assertEqual(list(self.workspace.iterdir()), [])
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_cancellation_while_spawn_returns_still_reaps_the_real_unpacker(self):
        from aweb_secrets_runner.oci_prepare import _tool

        script = self.root / "waiting-tool"
        script.write_text("#!/usr/bin/python3\nimport signal\nsignal.pause()\n")
        script.chmod(0o700)
        spawned, release = asyncio.Event(), asyncio.Event()
        original = asyncio.create_subprocess_exec
        process = None

        async def delayed_return(*args, **kwargs):
            nonlocal process
            process = await original(*args, **kwargs)
            spawned.set()
            await release.wait()
            return process

        # Gate only the stdlib's return boundary; the process and wait/reaping
        # are real, and no runner primitive is replaced.
        with patch.object(asyncio, "create_subprocess_exec", delayed_return):
            task = asyncio.create_task(_tool(script))
            try:
                async with asyncio.timeout(3):
                    await spawned.wait()
                task.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertIsNotNone(process)
                self.assertIsNotNone(process.returncode)
                self.assertFalse(Path(f"/proc/{process.pid}").exists())
            finally:
                release.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.wait()


if __name__ == "__main__":
    unittest.main()
