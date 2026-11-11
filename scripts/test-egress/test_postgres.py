"""Exercise the isolated runner's actual PostgreSQL launch and storage."""
import unittest

from docker import docker, postgres_args, require_memory_postgres, wait_for_postgres


class PostgresStorage(unittest.TestCase):
    def launch(self, change=None):
        runner = docker('run', '-d', '--network', 'none', 'postgres:17', 'sleep', 'infinity')
        self.addCleanup(docker, 'rm', '-f', '-v', runner)
        args = postgres_args(runner)
        if change:
            change(args)
        postgres = docker(*args)
        self.addCleanup(docker, 'rm', '-f', '-v', postgres)
        wait_for_postgres(postgres)
        return postgres

    def test_effective_data_and_wal_are_memory_backed(self):
        postgres = self.launch()
        storage = require_memory_postgres(postgres)
        self.assertEqual(storage['data']['filesystem'], 'tmpfs', storage)
        self.assertEqual(storage['wal']['filesystem'], 'tmpfs', storage)
        self.assertEqual(storage['swap_max'], '0', storage)
        # Confirm the measured paths belong to a working database, with durable
        # commit settings retained rather than fsync/synchronous_commit disabled.
        result = docker('exec', postgres, 'psql', '-At', '-v', 'ON_ERROR_STOP=1',
                        '-U', 'postgres', '-d', 'postgres', '-c',
                        'CREATE TABLE probe (n int); INSERT INTO probe VALUES (1); '
                        'SELECT n FROM probe; SHOW fsync; SHOW synchronous_commit')
        self.assertTrue(result.endswith('1\non\non'), result)

    def test_data_outside_the_mount_is_refused(self):
        def outside(args):
            index = args.index('PGDATA=/var/lib/postgresql/data/pgdata')
            args[index] = 'PGDATA=/tmp/outside-data'
        with self.assertRaisesRegex(RuntimeError, 'Postgres data must be on tmpfs'):
            require_memory_postgres(self.launch(outside))

    def test_wal_symlink_outside_the_mount_is_refused(self):
        def outside(args):
            index = args.index('postgres:17')
            args[index:index] = ['-e', 'POSTGRES_INITDB_ARGS=--waldir=/tmp/outside-wal']
        with self.assertRaisesRegex(RuntimeError, 'Postgres wal must be on tmpfs'):
            require_memory_postgres(self.launch(outside))

    def test_swappable_tmpfs_is_refused(self):
        def swapping(args):
            args[args.index('--memory-swap') + 1] = '3g'
        with self.assertRaisesRegex(RuntimeError, 'Postgres swap must be disabled'):
            require_memory_postgres(self.launch(swapping))


if __name__ == '__main__':
    unittest.main()
