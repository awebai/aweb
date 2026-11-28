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

    def test_preparation_syncs_each_project_lock_and_installs_no_browser(self):
        # The image installs the locked browser and its system libraries once,
        # as root; preparation runs as UID 1000 and only syncs.
        self.invoke("prepare")
        syncs = [args for args, _ in self.commands if args[:2] == ["uv", "sync"]]
        # Each selected project's lock is synced once, in any order.
        self.assertEqual(
            sorted(args[-1] for args in syncs),
            sorted(str(self.root / name) for name in ("server", "naapp/folio")),
        )
        self.assertEqual([args for args, _ in self.commands if "install" in args], [])
        self.assertTrue(
            all(kwargs["env"]["UV_OFFLINE"] == "0" for _, kwargs in self.commands)
        )
        self.assertEqual(json.loads(self.receipt.read_text())["status"], "PASS")

    def test_offline_verification_uses_fresh_environments_and_launches_the_browser(
        self,
    ):
        self.invoke("verify")
        syncs = [
            (args, kwargs)
            for args, kwargs in self.commands
            if args[:2] == ["uv", "sync"]
        ]
        projects = sorted(str(self.root / name) for name in ("server", "naapp/folio"))
        self.assertEqual(
            sorted(args[args.index("--project") + 1] for args, _ in syncs), projects
        )
        self.assertTrue(all("--offline" in args for args, _ in syncs))
        paths = [Path(kwargs["env"]["UV_PROJECT_ENVIRONMENT"]) for _, kwargs in syncs]
        self.assertEqual(len(set(paths)), len(syncs))
        self.assertTrue(all(not path.exists() for path in paths))
        launches = [
            args[args.index("--project") + 1]
            for args, _ in self.commands
            if preparation.BROWSER_LAUNCH_CHECK in args
        ]
        self.assertEqual(sorted(launches), projects)
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
                "verify", fail=lambda args: preparation.BROWSER_LAUNCH_CHECK in args
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


class GoBuildCache(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.module = self.root / "cli/go"
        self.module.mkdir(parents=True)
        (self.module / "go.mod").write_text("module fixture\n")
        (self.module / "go.sum").write_text("frozen sum\n")
        (self.module / "Makefile").write_text(
            "GOMODCACHE := $(CURDIR)/build-owner-cache\n"
            'GOENV = env GOMODCACHE="$(GOMODCACHE)"\n'
            "build:\n\t@$(GOENV) go build\n"
        )
        tools = self.root / "tools"
        tools.mkdir()
        go = tools / "go"
        go.write_text(
            f"#!{sys.executable}\n"
            "import os,sys\nfrom pathlib import Path\n"
            "cache=Path(os.environ['GOMODCACHE'])\n"
            "if sys.argv[1:]==['env','GOMODCACHE']: print(cache)\n"
            "elif sys.argv[1:]==['mod','download']:\n"
            " if os.environ['GOPROXY']=='off':\n"
            "  if not (cache/'module.zip').exists(): sys.exit(12)\n"
            " else:\n"
            "  cache.mkdir(parents=True,exist_ok=True)\n"
            "  (cache/'module.zip').write_bytes(b'cached module')\n"
            " if os.environ.get('MUTATE_GO_LOCK'): Path('go.sum').write_text('changed')\n"
            "elif sys.argv[1:]==['build']:\n"
            " if not (cache/'module.zip').exists():\n"
            "  print('module lookup disabled by GOPROXY=off',file=sys.stderr); sys.exit(12)\n"
            "else: sys.exit(13)\n"
        )
        go.chmod(0o700)
        self.env = {
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "GOPROXY": "off",
            "GOSUMDB": "off",
        }

    def test_prepares_make_selected_cache_then_verifies_it_offline(self):
        prepared = preparation.go_build_cache(
            root=self.root, mode=preparation.PreparationMode.PREPARE, env=self.env
        )
        verified = preparation.go_build_cache(
            root=self.root, mode=preparation.PreparationMode.VERIFY, env=self.env
        )
        self.assertEqual(prepared, verified)
        self.assertEqual(prepared["cache"], str(self.module / "build-owner-cache"))
        self.assertEqual(prepared["files"], 1)
        self.assertEqual(len(prepared["sha256"]), 64)
        self.assertEqual((self.module / "go.sum").read_text(), "frozen sum\n")

    def test_offline_missing_make_cache_refuses_even_with_another_cache(self):
        other = self.root / "default-cache"
        other.mkdir()
        (other / "module.zip").write_bytes(b"wrong cache")
        with self.assertRaisesRegex(
            preparation.SetupFailure,
            "PACKAGE_GO_OFFLINE_CACHE_MISSING.*Prepare the selected frozen source.*offline phase\\.",
        ):
            preparation.go_build_cache(
                root=self.root, mode=preparation.PreparationMode.VERIFY, env=self.env
            )

    def test_download_cannot_change_go_manifests(self):
        with self.assertRaisesRegex(
            preparation.SetupFailure,
            "PACKAGE_GO_LOCK_CHANGED.*Restore the committed go.mod and go.sum.*again\\.",
        ):
            preparation.go_build_cache(
                root=self.root,
                mode=preparation.PreparationMode.PREPARE,
                env={**self.env, "MUTATE_GO_LOCK": "1"},
            )

    def test_make_selection_and_preparation_refusals_offer_recovery(self):
        cases = (
            (
                "package-go-cache",
                2,
                "",
                "PACKAGE_GO_CACHE_SELECTION_FAILED",
                "Correct the selected source's Make GOENV cache path",
            ),
            (
                "package-go-cache",
                0,
                "relative/cache",
                "PACKAGE_GO_CACHE_PATH_INVALID",
                "Correct Make GOENV to select an absolute module cache",
            ),
            (
                "package-go-download",
                2,
                "",
                "PACKAGE_GO_PREPARATION_FAILED",
                "Prepare the selected frozen source's Make-owned Go cache",
            ),
        )
        native = subprocess.run
        for target, code, output, failure, action in cases:
            with self.subTest(target=target, code=code, output=output):

                def invoke(args, **kwargs):
                    if args[-1] == target:
                        return subprocess.CompletedProcess(args, code, output, "")
                    return native(args, **kwargs)

                with (
                    patch.object(preparation.subprocess, "run", side_effect=invoke),
                    self.assertRaises(preparation.SetupFailure) as caught,
                ):
                    preparation.go_build_cache(
                        root=self.root,
                        mode=preparation.PreparationMode.PREPARE,
                        env=self.env,
                    )
                self.assertIn(failure, str(caught.exception))
                self.assertIn(action, str(caught.exception))
                self.assertTrue(
                    str(caught.exception).endswith("again.")
                    or str(caught.exception).endswith("offline phase.")
                )

    def test_package_receipt_retains_the_go_cache_hash(self):
        project = self.root / "server"
        project.mkdir()
        (project / "pyproject.toml").write_text("[project]\nname='fixture'\n")
        (project / "uv.lock").write_text("version=1\n")
        native = subprocess.run

        def invoke(args, **kwargs):
            if args[0] == "uv":
                return subprocess.CompletedProcess(args, 0, "\n", "")
            return native(args, **kwargs)

        with (
            patch.dict(os.environ, self.env),
            patch.object(preparation.subprocess, "run", side_effect=invoke),
            patch.object(preparation.subprocess, "check_output", return_value="a" * 40),
        ):
            receipt = self.root / "receipt.json"
            preparation.provision(self.root, "a" * 40, ["server"], "prepare", receipt)
        built = native(
            ["make", "-s", "-C", str(self.module), "build"],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(built.returncode, 0, built.stderr)
        value = json.loads(receipt.read_text())
        self.assertEqual(
            value["go_cache"]["cache"], str(self.module / "build-owner-cache")
        )
        self.assertEqual(value["go_cache"]["files"], 1)


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

    def test_real_source_bundle_and_build_inputs(
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
            # Native job inputs are private0400; COPY must override that mode.
            tools = Path(temporary) / "tools"
            tools.mkdir()
            helper = tools / "prepare_projects.py"
            helper.write_bytes((HERE / "test-egress/prepare_projects.py").read_bytes())
            helper.chmod(0o400)

            def invoke(args, **kwargs):
                if args[:2] == ["docker", "build"]:
                    context = Path(args[-1])
                    self.assertTrue((context / "source.bundle").is_file())
                    self.assertEqual(
                        (context / "package-environment.py").stat().st_mode & 0o777,
                        0o400,
                    )
                    builds.append((context / "isolated.Dockerfile").read_text())
                    return subprocess.CompletedProcess(args, 0)
                return real_run(args, **kwargs)

            with (
                patch.object(images.subprocess, "run", side_effect=invoke),
                patch.object(images, "__file__", str(tools / "package_image.py")),
            ):
                images.prepare_image(root, evidence, "owned-image")
            self.assertEqual(len(builds), 1)
            self.assertTrue((evidence / "package-preparation-tool.sha256").is_file())
            # In a gate run the image starts from the gate's image, which is
            # already in the engine, and the engine's own builder builds it.
            builds.clear()
            calls = []

            def recorded(args, **kwargs):
                calls.append((args, kwargs))
                return invoke(args, **kwargs)

            gate_env = dict(
                os.environ,
                BUILDX_BUILDER="run-builder",
                AWEB_CANDIDATE_RESOURCE_LABEL="run-label",
            )
            with (
                patch.object(images.subprocess, "run", side_effect=recorded),
                patch.object(images, "__file__", str(tools / "package_image.py")),
                patch.dict(os.environ, gate_env, clear=True),
            ):
                (evidence / "gate").mkdir()
                images.prepare_image(
                    root, evidence / "gate", "owned-image", base="gate-image:run"
                )
            self.assertTrue(
                builds[0].startswith("FROM gate-image:run\n"), builds[0][:80]
            )
            self.assertNotIn("FROM python:3.12", builds[0])
            args, kwargs = next(c for c in calls if c[0][:2] == ["docker", "build"])
            self.assertNotIn("BUILDX_BUILDER", kwargs["env"])
            self.assertEqual(
                args[args.index("--label") + 1], "aweb.candidate-gate=run-label"
            )


REAL_RUN = subprocess.run


class PackageReceipts(unittest.TestCase):
    """The gate reads back what the image build proved, from the built image."""

    SOURCE = "c" * 40
    HELPER = b"package helper bytes"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        (self.root / "naapp/folio").mkdir(parents=True)
        (self.root / "naapp/folio/uv.lock").write_text("version=1\n")
        for args in (
            ["init", "-q"],
            ["add", "."],
            [
                "-c",
                "user.name=f",
                "-c",
                "user.email=f@example.test",
                "commit",
                "-qm",
                "s",
            ],
        ):
            subprocess.run(["git", *args], cwd=self.root, check=True)
        self.source = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True
        ).strip()
        self.evidence = Path(self.temporary.name) / "evidence"
        self.evidence.mkdir()
        digest = hashlib.sha256(self.HELPER).hexdigest()
        (self.evidence / "package-preparation-tool.sha256").write_text(digest + "\n")
        self.receipts = {
            images.RECEIPTS["helper"]: dict(
                status="PASS",
                uid=1000,
                gid=1000,
                path="/opt/package-environment.py",
                mode="0644",
                bytes=len(self.HELPER),
                sha256=digest,
                parents={
                    "/opt": dict(mode="0755", traversable=True),
                    "/": dict(mode="0755", traversable=True),
                },
            ),
            images.RECEIPTS["prepared"]: dict(
                status="PASS", uid=1000, gid=1000, mode="prepare", source=self.source
            ),
            images.RECEIPTS["verified"]: dict(
                status="PASS", uid=1000, gid=1000, mode="verify", source=self.source
            ),
        }
        self.reads = []

    def docker(self, args, **kwargs):
        if args[0] != "docker":
            return REAL_RUN(args, **kwargs)
        # docker run --rm --network none --user 1000:1000 --entrypoint cat IMAGE PATH
        self.assertEqual(
            args[:9],
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "1000:1000",
                "--entrypoint",
                "cat",
            ],
        )
        self.reads.append(args[-1])
        if args[-1] not in self.receipts:
            return subprocess.CompletedProcess(
                args, 1, "", f"cat: {args[-1]}: No such file\n"
            )
        return subprocess.CompletedProcess(
            args, 0, json.dumps(self.receipts[args[-1]]), ""
        )

    def read(self):
        with patch.object(images.subprocess, "run", side_effect=self.docker):
            images.read_package_receipts(self.root, self.evidence, "owned-image")

    def test_receipts_proving_uid_1000_pass_and_are_kept_as_evidence(self):
        self.read()
        self.assertEqual(self.reads, list(images.RECEIPTS.values()))
        for name in images.RECEIPTS:
            self.assertTrue((self.evidence / f"receipt-{name}.json").is_file())

    def test_every_broken_receipt_is_refused_naming_it(self):
        helper, prepared, verified = (
            images.RECEIPTS[k] for k in ("helper", "prepared", "verified")
        )
        cases = {
            "wrong uid": (verified, "uid", 0),
            "missing gid": (prepared, "gid", None),
            "not passed": (helper, "status", "FAIL"),
            "swapped modes": (prepared, "mode", "verify"),
            "another source": (verified, "source", "d" * 40),
            "another helper": (helper, "sha256", "e" * 64),
            "wrong helper mode": (helper, "mode", "0600"),
        }
        for name, (path, field, value) in cases.items():
            with self.subTest(case=name):
                original = dict(self.receipts[path])
                if value is None:
                    del self.receipts[path][field]
                else:
                    self.receipts[path][field] = value
                with self.assertRaisesRegex(images.PackageReceiptError, field):
                    self.read()
                self.receipts[path] = original
        with self.subTest(case="missing parent"):
            del self.receipts[helper]["parents"]["/opt"]
            with self.assertRaisesRegex(images.PackageReceiptError, "/opt"):
                self.read()

    def test_a_receipt_the_image_lacks_is_refused(self):
        del self.receipts[images.RECEIPTS["verified"]]
        with self.assertRaisesRegex(images.PackageReceiptError, "verified"):
            self.read()

    def test_a_build_with_projects_needs_the_helper_digest(self):
        (self.evidence / "package-preparation-tool.sha256").unlink()
        with self.assertRaisesRegex(images.PackageReceiptError, "digest"):
            self.read()

    def test_a_build_without_projects_reads_nothing(self):
        subprocess.run(
            ["git", "rm", "-q", "naapp/folio/uv.lock"], cwd=self.root, check=True
        )
        self.read()
        self.assertEqual(self.reads, [])


if __name__ == "__main__":
    unittest.main()
