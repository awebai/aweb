#!/usr/bin/env python3
"""Real checkout permissions at the gate's cross-UID mount boundary, no Docker."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from fixture_repo import init_fixture_repo

ROOT = Path(__file__).resolve().parents[1]


class CandidateInputModesTests(unittest.TestCase):
    def checkout(self, caller_umask):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        # Execute the production materialization/checks, not a second clone recipe.
        fragment = source.split('checkout="$work/aweb"\n', 1)[1].split(
            "\nrecord_input() {", 1
        )[0]
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            repo = private / "source"
            repo.mkdir(mode=0o700)
            init_fixture_repo(repo)
            sql = repo / "scripts/e2e/initdb/10-create-library-db.sql"
            sql.parent.mkdir(parents=True, mode=0o700)
            sql.write_text("CREATE DATABASE library;\n")
            sql.chmod(0o600)
            executable = repo / "probe.sh"
            executable.write_text("#!/bin/sh\nprintf 'tracked executable\\n'\n")
            executable.chmod(0o700)
            (repo / "sql-link").symlink_to(sql.relative_to(repo))

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(repo), *args], text=True
                ).strip()

            git("add", ".")
            git(
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "mounted inputs",
            )
            sha = git("rev-parse", "HEAD")
            # The selected commit differs from clone's default HEAD: checkout
            # must restore the SQL under the same explicit materialization mask.
            git("rm", str(sql.relative_to(repo)))
            git(
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "-qm",
                "different default head",
            )
            main = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", main)
            work = private / "candidate-private"
            work.mkdir(mode=0o700)
            env = dict(
                os.environ,
                ROOT=str(repo),
                work=str(work),
                SOURCE_SHA=sha,
                SYNCHRONIZED_MAIN_SHA=main,
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "set -euo pipefail\numask "
                    + caller_umask
                    + '\ncheckout="$work/aweb"\nrefuse() { echo "$*" >&2; exit 2; }\n'
                    + fragment
                    + '\numask > "$work/caller-mask"\n'
                    + 'printf private > "$work/private-key"\n',
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            checkout = work / "aweb"
            mounted = checkout / sql.relative_to(repo)
            self.assertEqual(mounted.read_bytes(), b"CREATE DATABASE library;\n")
            for path in (
                checkout,
                mounted.parent,
                mounted.parent.parent,
                mounted.parent.parent.parent,
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755, str(path))
            self.assertEqual(stat.S_IMODE(mounted.stat().st_mode), 0o644)
            self.assertEqual(
                stat.S_IMODE((checkout / "probe.sh").stat().st_mode), 0o755
            )
            self.assertTrue((checkout / "sql-link").is_symlink())
            self.assertEqual(
                os.readlink(checkout / "sql-link"), str(sql.relative_to(repo))
            )
            self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(
                (work / "caller-mask").read_text().strip(), caller_umask.zfill(4)
            )
            self.assertEqual(
                stat.S_IMODE((work / "private-key").stat().st_mode),
                0o666 & ~int(caller_umask, 8),
            )
            self.assertEqual(stat.S_IMODE(repo.stat().st_mode), 0o700)
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
                ).strip(),
                sha,
            )
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(checkout), "status", "--porcelain"], text=True
                ),
                "",
            )

    def test_private_caller_retains_privacy_and_mount_inputs_are_readable(self):
        self.checkout("0077")

    def test_ordinary_caller_has_the_same_tracked_input_modes(self):
        self.checkout("0022")


if __name__ == "__main__":
    unittest.main()
