"""Lock-driven package preparation controls; no Docker or dependency downloads."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, HERE / "test-egress" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preparation = load("prepare_projects")
images = load("package_image")
runner = load("package_environment")


class ProjectPreparation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.receipt = self.root / "receipt.json"
        for name in ("server", "naapp/folio"):
            project = self.root / name
            project.mkdir(parents=True)
            (project / "pyproject.toml").write_text(
                '[project]\nname="fixture"\nversion="0.0.0"\n'
            )
            (project / "uv.lock").write_text("version=1\n")
        self.commands = []

    def invoke(self, mode, *, fail=None, mutate=False, versions=None):
        def command(args, **kwargs):
            self.commands.append((args, kwargs))
            project = args[args.index("--project") + 1]
            if fail and fail(args):
                return subprocess.CompletedProcess(args, 1, "", "")
            if mutate:
                (Path(project) / "uv.lock").write_text("changed\n")
            return subprocess.CompletedProcess(
                args,
                0,
                (
                    (versions or {}).get(
                        str(Path(project).relative_to(self.root)), "1.63.0"
                    )
                    + "\n"
                )
                if "-c" in args
                else "",
                "",
            )

        with (
            patch.object(preparation.subprocess, "check_output", return_value="a" * 40),
            patch.object(preparation.subprocess, "run", side_effect=command),
            patch.object(preparation.os, "getuid", return_value=1000),
        ):
            preparation.provision(
                self.root, "a" * 40, ["server", "naapp/folio"], mode, self.receipt
            )

    def test_preparation_uses_each_project_lock_and_one_pinned_browser_install(self):
        self.invoke("prepare")
        syncs = [args for args, _ in self.commands if args[:2] == ["uv", "sync"]]
        self.assertEqual(
            [args[-1] for args in syncs],
            [str(self.root / name) for name in ("server", "naapp/folio")],
        )
        installs = [args for args, _ in self.commands if "install" in args]
        self.assertEqual(len(installs), 1)
        self.assertIn("--no-sync", installs[0])
        self.assertEqual(
            installs[0][-4:], ["install", "--with-deps", "--only-shell", "chromium"]
        )
        self.assertTrue(
            all(kwargs["env"]["UV_OFFLINE"] == "0" for _, kwargs in self.commands)
        )
        self.assertEqual(json.loads(self.receipt.read_text())["status"], "PASS")

    def test_distinct_locked_browser_versions_each_use_their_own_project_installer(
        self,
    ):
        self.invoke("prepare", versions={"server": "1.63.0", "naapp/folio": "1.64.0"})
        installers = [args for args, _ in self.commands if "install" in args]
        self.assertEqual(len(installers), 2)
        self.assertEqual(
            [args[args.index("--project") + 1] for args in installers],
            [str(self.root / name) for name in ("server", "naapp/folio")],
        )

    def test_offline_verification_uses_fresh_environments_and_launches_the_browser(
        self,
    ):
        self.invoke("verify")
        syncs = [
            (args, kwargs)
            for args, kwargs in self.commands
            if args[:2] == ["uv", "sync"]
        ]
        self.assertEqual(len(syncs), 2)
        self.assertTrue(all("--offline" in args for args, _ in syncs))
        paths = [Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"]) for _, kwargs in syncs]
        self.assertEqual(len(set(paths)), 2)
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(
            sum("b=p.chromium.launch()" in " ".join(args) for args, _ in self.commands),
            2,
        )
        self.assertTrue(
            all(kwargs["env"]["UV_OFFLINE"] == "1" for _, kwargs in self.commands)
        )

    def test_missing_cached_wheel_refuses_before_browser_or_pass_receipt(self):
        with self.assertRaisesRegex(
            preparation.SetupFailure, r"PACKAGE_OFFLINE_CACHE_MISSING\[server\]"
        ):
            self.invoke("verify", fail=lambda args: args[:2] == ["uv", "sync"])
        self.assertEqual(len(self.commands), 1)
        self.assertFalse(self.receipt.exists())

    def test_missing_browser_refuses_with_project_and_no_pass_receipt(self):
        with self.assertRaisesRegex(
            preparation.SetupFailure, r"PACKAGE_BROWSER_UNAVAILABLE\[server\]"
        ):
            self.invoke(
                "verify", fail=lambda args: "b=p.chromium.launch()" in " ".join(args)
            )
        self.assertFalse(self.receipt.exists())

    def test_source_lock_mutation_refuses(self):
        with self.assertRaisesRegex(preparation.SetupFailure, "PACKAGE_LOCK_CHANGED"):
            self.invoke("prepare", mutate=True)
        self.assertFalse(self.receipt.exists())

    def test_project_escape_and_missing_lock_refuse_without_dependency_effects(self):
        with self.assertRaisesRegex(
            preparation.SetupFailure, "PACKAGE_PROJECT_INVALID"
        ):
            preparation.selected_projects(self.root, ["../outside"])
        (self.root / "server/uv.lock").unlink()
        with self.assertRaisesRegex(preparation.SetupFailure, "PACKAGE_LOCK_MISSING"):
            preparation.selected_projects(self.root, ["server"])


class SourceImagePreparation(unittest.TestCase):
    def test_preparation_trusts_only_selected_checkout_with_different_git_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "selected"
            other = root.parent / "unselected"
            for repo in (root, other):
                (repo / "server").mkdir(parents=True)
                (repo / "server/pyproject.toml").write_text(
                    '[project]\nname="fixture"\nversion="0.0.0"\n'
                )
                (repo / "server/uv.lock").write_text("version=1\n")
                for args in (
                    ["init", "-q"],
                    ["add", "."],
                    [
                        "-c",
                        "user.name=fixture",
                        "-c",
                        "user.email=fixture@example.test",
                        "commit",
                        "-qm",
                        "source",
                    ],
                ):
                    subprocess.run(["git", *args], cwd=repo, check=True)
            sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            real_run = subprocess.run
            child_checks = []

            def invoke(args, **kwargs):
                if args[0] != "uv":
                    return real_run(args, **kwargs)
                allowed = real_run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=root,
                    env=kwargs["env"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                refused = real_run(
                    ["git", "status"],
                    cwd=other,
                    env=kwargs["env"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(allowed.returncode, 0, allowed.stderr)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("dubious ownership", refused.stderr)
                child_checks.append(True)
                return subprocess.CompletedProcess(args, 0, "\n", "")

            with patch.dict(
                os.environ,
                {
                    "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                },
            ):
                baseline = real_run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(baseline.returncode, 0)
                self.assertIn("dubious ownership", baseline.stderr)
                with patch.object(preparation.subprocess, "run", side_effect=invoke):
                    preparation.provision(
                        root, sha, ["server"], "prepare", root.parent / "receipt.json"
                    )
            self.assertTrue(child_checks)

    def test_real_source_bundle_and_recipe_bind_the_selected_locks_and_uid_verification(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            for name, text in {
                "candidate-gate/Dockerfile": "FROM python:3.12\n",
                "scripts/test-egress/Dockerfile": "WORKDIR /src\nCOPY . .\n",
                "naapp/folio/uv.lock": "version=1\n",
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            for args in (
                ["init", "-q"],
                ["add", "."],
                [
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "commit",
                    "-qm",
                    "source",
                ],
            ):
                subprocess.run(["git", *args], cwd=root, check=True)
            evidence = Path(temporary) / "evidence"
            evidence.mkdir()
            real_run = subprocess.run
            builds = []

            def invoke(args, **kwargs):
                if args[:2] == ["docker", "build"]:
                    context = Path(args[-1])
                    self.assertTrue((context / "source.bundle").is_file())
                    builds.append((context / "isolated.Dockerfile").read_text())
                    return subprocess.CompletedProcess(args, 0)
                return real_run(args, **kwargs)

            with patch.object(images.subprocess, "run", side_effect=invoke):
                images.prepare_image(root, evidence, "owned-image", ["naapp/folio"])
            self.assertEqual(len(builds), 1)
            self.assertIn("--project naapp/folio --mode prepare", builds[0])
            self.assertIn("USER 1000:1000\nRUN", builds[0])
            self.assertIn("--mode verify", builds[0])
            self.assertNotIn("1243", builds[0])
            self.assertNotIn("2.41.5", builds[0])
            self.assertTrue((evidence / "package-preparation-tool.sha256").is_file())

    def test_package_runtime_keeps_private_home_and_forwards_only_fixture_environment(
        self,
    ):
        receipt = {
            "status": "PASS",
            "image": "sha256:" + "a" * 64,
            "source": "b" * 40,
            "locks": {},
        }
        with (
            patch.object(runner.Path, "stat") as stat,
            patch.dict(
                os.environ,
                {"TEST_DB_PORT": "1234", "HCLOUD_TOKEN": "private-fixture"},
                clear=True,
            ),
        ):
            stat.return_value.st_gid = 998
            args = runner.runner_args(
                receipt,
                Path("/owned/results"),
                "owned-run",
                ["bash", "-c", "make e2e"],
                True,
            )
        self.assertIn("TEST_DB_PORT", args)
        self.assertNotIn("HCLOUD_TOKEN", args)
        self.assertNotIn("private-fixture", args)
        self.assertIn("1000:1000", args)
        self.assertEqual(args[args.index("--network") + 1], "host")
        self.assertEqual(args[-3:], ["bash", "-c", "make e2e"])
        self.assertIn(receipt["image"], args)

    def test_real_child_exit_and_source_mutation_are_retained_before_container_removal(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            lock = root / "uv.lock"
            lock.write_text("version=1\n")
            for args in (
                ["init", "-q"],
                ["add", "."],
                [
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "commit",
                    "-qm",
                    "source",
                ],
            ):
                subprocess.run(["git", *args], cwd=root, check=True)
            expected = {
                "source": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=root, text=True
                ).strip(),
                "locks": {"uv.lock": hashlib.sha256(lock.read_bytes()).hexdigest()},
            }
            for command, raw, returned in [
                ([sys.executable, "-c", "raise SystemExit(17)"], 17, 17),
                (
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path('uv.lock').write_text('changed')",
                    ],
                    0,
                    78,
                ),
            ]:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        runner.COMMAND_RECEIPT,
                        json.dumps(expected),
                        str(root),
                        *command,
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, returned, result.stderr)
                receipt = json.loads((root / "source-after.json").read_text())
                self.assertEqual(receipt["test_exit"], raw)
                self.assertEqual(receipt["source_unchanged"], returned != 78)

    def test_wrong_source_binding_refuses_before_any_container_or_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            binding = Path(temporary) / "binding.json"
            binding.write_text(json.dumps({"source": "a" * 40}))
            evidence = Path(temporary) / "not-created"
            with self.assertRaisesRegex(
                RuntimeError, "PACKAGE_BINDING_SOURCE_MISMATCH"
            ):
                runner.run(binding, evidence, ["false"], False, "b" * 40)
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
