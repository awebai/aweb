"""The memory-backed test PostgreSQL policy, without a Docker daemon.

A docker stand-in on PATH answers the inspection commands, so these controls
prove only how the policy reads answers and what it says; the effective
storage of a real container is proved natively by
scripts/test-egress/test_postgres.py.
"""

import dataclasses
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "isolated_services_policy", ROOT / "scripts/test-egress/docker.py"
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

DATA = "/var/lib/postgresql/data/pgdata"


def docker_stand_in(test, script):
    """Put a docker running script first on PATH for the rest of test."""
    directory = Path(tempfile.mkdtemp())
    docker = directory / "docker"
    docker.write_text("#!/bin/sh\n" + script)
    docker.chmod(0o755)
    saved = dict(os.environ)
    test.addCleanup(os.environ.update, saved)
    os.environ["PATH"] = f"{directory}{os.pathsep}{os.environ['PATH']}"


def storage_answers(*, data_fs="tmpfs", wal_fs="tmpfs", swap="echo 0"):
    """A stand-in answering postgres_storage's inspection of one container."""
    return (
        'case "$*" in\n'
        f'*"SHOW data_directory"*) echo {DATA} ;;\n'
        '*"readlink -f"*) shift $(($# - 1)); echo "$1" ;;\n'
        f'*"%T {DATA}/pg_wal"*) echo {wal_fs} ;;\n'
        f'*"%T {DATA}"*) echo {data_fs} ;;\n'
        f"*memory.swap.max*) {swap} ;;\n"
        "*) echo unexpected docker call: $* >&2; exit 3 ;;\n"
        "esac\n"
    )


class MemoryPostgresOptions(unittest.TestCase):
    def test_options_hold_the_memory_backed_rule(self):
        options = runner.memory_postgres_options(memory="512m")
        docker_options = list(options.docker_options)
        self.assertEqual(docker_options[docker_options.index("--memory") + 1], "512m")
        self.assertEqual(
            docker_options[docker_options.index("--memory-swap") + 1], "512m"
        )
        self.assertIn(
            "/var/lib/postgresql/data:rw,noexec,nosuid,size=1g", docker_options
        )
        self.assertIn("PGDATA=" + DATA, docker_options)
        self.assertEqual(
            options.server_args,
            ("-c", "max_wal_size=128MB", "-c", "min_wal_size=32MB"),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            options.docker_options = ()

    def test_runner_arguments_carry_the_shared_options(self):
        for args, memory in [
            (runner.postgres_args("owned-runner"), "2g"),
            (runner.postgres_args("owned-runner", 5433, True), "1280m"),
        ]:
            options = runner.memory_postgres_options(memory=memory)
            image = args.index("postgres:17")
            for option in options.docker_options:
                self.assertIn(option, args[:image])
            self.assertEqual(
                args[image + 1 : image + 1 + len(options.server_args)],
                list(options.server_args),
            )


class MemoryPostgresRefusals(unittest.TestCase):
    def test_memory_backed_storage_is_accepted(self):
        docker_stand_in(self, storage_answers())
        storage = runner.require_memory_postgres("pg-1")
        self.assertEqual(storage["data"], {"path": DATA, "filesystem": "tmpfs"})
        self.assertEqual(
            storage["wal"], {"path": DATA + "/pg_wal", "filesystem": "tmpfs"}
        )
        self.assertEqual(storage["swap_max"], "0")

    def test_data_off_tmpfs_is_refused_with_what_to_do(self):
        docker_stand_in(self, storage_answers(data_fs="ext2/ext3"))
        with self.assertRaises(RuntimeError) as refused:
            runner.require_memory_postgres("pg-1")
        self.assertEqual(
            str(refused.exception),
            f"Postgres data must be on tmpfs: {{'path': '{DATA}', 'filesystem': "
            "'ext2/ext3'}. Recreate the test PostgreSQL with the "
            "memory_postgres_options settings and rerun.",
        )

    def test_wal_off_tmpfs_is_refused_with_what_to_do(self):
        docker_stand_in(self, storage_answers(wal_fs="overlayfs"))
        with self.assertRaises(RuntimeError) as refused:
            runner.require_memory_postgres("pg-1")
        self.assertEqual(
            str(refused.exception),
            f"Postgres wal must be on tmpfs: {{'path': '{DATA}/pg_wal', "
            "'filesystem': 'overlayfs'}. Recreate the test PostgreSQL with the "
            "memory_postgres_options settings and rerun.",
        )

    def test_swap_that_is_allowed_is_refused_with_what_to_do(self):
        docker_stand_in(self, storage_answers(swap="echo max"))
        with self.assertRaises(RuntimeError) as refused:
            runner.require_memory_postgres("pg-1")
        self.assertEqual(
            str(refused.exception),
            "Postgres swap must be disabled: memory.swap.max=max. Recreate the test "
            "PostgreSQL with equal --memory and --memory-swap from "
            "memory_postgres_options and rerun.",
        )

    def test_unreadable_swap_accounting_fails_with_its_own_error(self):
        docker_stand_in(
            self,
            storage_answers(swap="echo 'No such file or directory' >&2; exit 1"),
        )
        with self.assertRaises(subprocess.CalledProcessError) as failed:
            runner.require_memory_postgres("pg-1")
        self.assertIn("/sys/fs/cgroup/memory.swap.max", failed.exception.cmd)


class PostgresReadiness(unittest.TestCase):
    def test_ready_postgres_is_accepted(self):
        docker_stand_in(self, "exit 0\n")
        runner.wait_for_postgres("pg-1", attempts=1, interval=0)

    def test_postgres_that_never_answers_names_its_logs(self):
        docker_stand_in(self, "exit 2\n")
        with self.assertRaises(RuntimeError) as refused:
            runner.wait_for_postgres("pg-1", attempts=2, interval=0)
        self.assertEqual(
            str(refused.exception),
            "Postgres did not become ready in pg-1. Inspect its startup with docker "
            "logs pg-1, fix what stops it, and rerun.",
        )


if __name__ == "__main__":
    unittest.main()
