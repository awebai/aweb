"""Exercise real stack file creation; Docker/service startup is not simulated."""

import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class StackInputModes(unittest.TestCase):
    def test_stack_container_inputs_readable_under_private_and_normal_umasks(self):
        for mask in (0o077, 0o022):
            with (
                self.subTest(umask=oct(mask)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                old_environment = dict(os.environ)
                old_path = sys.path.copy()
                old_mask = os.umask(mask)
                try:
                    os.environ["AWEB_DOCKER_BIND_ROOT"] = temporary
                    os.environ["USER_PATHS_EVIDENCE"] = str(
                        Path(temporary) / "evidence"
                    )
                    sys.path.insert(0, str(ROOT / "scripts/e2e"))
                    stack = runpy.run_path(
                        str(ROOT / "scripts/e2e/user_paths_stack.py")
                    )
                    stack["prepare_container_inputs"]()
                    work = stack["WORK"]
                    for path in work.rglob("*"):
                        with self.subTest(input=str(path.relative_to(work))):
                            if path.is_dir():
                                self.assertEqual(
                                    stat.S_IMODE(path.stat().st_mode), 0o755
                                )
                            else:
                                self.assertTrue(path.read_bytes())
                                self.assertEqual(
                                    stat.S_IMODE(path.stat().st_mode), 0o644
                                )
                    self.assertEqual(stat.S_IMODE((work / "dns").stat().st_mode), 0o755)
                    # The bind mount substitutes its source at /zones or /work;
                    # host parents may remain private and are not traversed inside it.
                    self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)
                finally:
                    os.umask(old_mask)
                    os.environ.clear()
                    os.environ.update(old_environment)
                    sys.path[:] = old_path


class SharedFixtureModes(unittest.TestCase):
    def test_public_fixture_tree_is_readable_but_private_neighbor_stays_private(self):
        module = runpy.run_path(str(ROOT / "scripts/e2e/container_fixture_modes.py"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            old_mask = os.umask(0o077)
            try:
                for name in ("e2e", "test-support", "tls"):
                    directory = root / name
                    directory.mkdir()
                    (directory / "input").write_text("public disposable input")
                    (directory / "input").chmod(0o400)
                executable = root / "e2e/run.sh"
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
                private = root / "identity"
                private.mkdir()
                key = private / "key"
                key.write_text("private neighbor")
                (root / "e2e/external").symlink_to(key)
                module["prepare_fixture_permissions"](root=root)
                for name in ("e2e", "test-support", "tls"):
                    self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o755)
                    self.assertEqual(
                        stat.S_IMODE((root / name / "input").stat().st_mode), 0o644
                    )
                self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            finally:
                os.umask(old_mask)

    def test_custody_stack_stages_readable_public_inputs_without_changing_checkout(
        self,
    ):
        old_path = sys.path.copy()
        sys.path.insert(0, str(ROOT / "scripts/e2e"))
        try:
            module = runpy.run_path(str(ROOT / "scripts/e2e/custody_bulk.py"))
        finally:
            sys.path[:] = old_path
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binary = root / "selected-aw"
            binary.write_bytes(b"exact selected binary")
            binary.chmod(0o700)
            work = root / "work"
            work.mkdir(mode=0o700)
            old_mask = os.umask(0o077)
            try:
                module["prepare_container_inputs"](
                    work=work, aw_bin=binary, provision_aw_bin=binary
                )
                for name in (
                    "init.sql",
                    "dns/Corefile",
                    "dns/test.zone",
                    "custody_bulk_client.py",
                    "custody_bulk_relay.py",
                ):
                    self.assertEqual(
                        stat.S_IMODE((work / name).stat().st_mode), 0o644, name
                    )
                self.assertEqual(stat.S_IMODE((work / "dns").stat().st_mode), 0o755)
                for path in (work / "source").rglob("*"):
                    self.assertTrue(
                        path.stat().st_mode & (0o001 if path.is_dir() else 0o004),
                        str(path),
                    )
                self.assertEqual((work / "aw").read_bytes(), binary.read_bytes())
                self.assertEqual(stat.S_IMODE((work / "aw").stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)
            finally:
                os.umask(old_mask)


class ShellInputModes(unittest.TestCase):
    def test_federation_dns_initial_and_replacement_files_ignore_private_umask(self):
        source = (ROOT / "scripts/e2e-oss-federation.sh").read_text()
        initial = source[
            source.index('cat > "$DNS_COREFILE"') : source.index('echo "=== Phase 1:')
        ]
        publisher = source[
            source.index("publish_strict_dns_authority() {") : source.index(
                "assert_strict_dns_authority() {"
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            dns = root / "dns"
            dns.mkdir(mode=0o700)
            environment = dict(
                os.environ,
                DNS_DIR=str(dns),
                DNS_COREFILE=str(dns / "Corefile"),
                DNS_ZONE=str(dns / "test.local.zone"),
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "set -euo pipefail; umask 0077\n"
                    + initial
                    + publisher
                    + "\npublish_strict_dns_authority first second\n",
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in dns.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(dns.stat().st_mode), 0o755)
            self.assertIn("controller=first", (dns / "test.local.zone").read_text())

    def test_candidate_archive_uses_git_modes_under_private_umask(self):
        from fixture_repo import init_fixture_repo

        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        function = source[
            source.index("record_input() {") : source.index("record_input blueprints")
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            repo.mkdir()
            home = root / "empty-home"
            home.mkdir()
            # A gate has no author identity; forbid Git's host-specific inference too.
            git_environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_", "GIT_CONFIG"))
                and key not in ("EMAIL", "GIT_TEMPLATE_DIR")
            }
            git_environment.update(
                HOME=str(home),
                XDG_CONFIG_HOME=str(home),
                GIT_CONFIG_NOSYSTEM="1",
                GIT_CONFIG_GLOBAL=os.devnull,
                GIT_CONFIG_COUNT="1",
                GIT_CONFIG_KEY_0="user.useConfigOnly",
                GIT_CONFIG_VALUE_0="true",
            )
            self.enterContext(patch.dict(os.environ, git_environment, clear=True))
            init_fixture_repo(repo)
            (repo / "public.sql").write_text("SELECT 1;\n")
            (repo / "public.sql").chmod(0o400)
            subprocess.run(
                ["git", "-C", str(repo), "add", "."], check=True, capture_output=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "commit",
                    "-qm",
                    "public fixture",
                ],
                check=True,
                capture_output=True,
            )
            sha = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            work, logs = root / "work", root / "logs"
            work.mkdir(mode=0o700)
            logs.mkdir(mode=0o700)
            environment = dict(
                os.environ,
                work=str(work),
                LOG_DIR=str(logs),
                fixture_input_sha=sha,
                fixture_source=str(repo),
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'set -euo pipefail; umask 0077\nrefuse() { echo "$*" >&2; exit 2; }\n'
                    + function
                    + '\nrecord_input fixture "$fixture_source"\n',
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                stat.S_IMODE((work / "inputs/fixture/public.sql").stat().st_mode), 0o644
            )
            self.assertEqual(
                stat.S_IMODE((work / "inputs/fixture").stat().st_mode), 0o755
            )
            self.assertEqual(stat.S_IMODE((repo / "public.sql").stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
