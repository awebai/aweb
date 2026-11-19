"""Exercise the disposable services the AWID and command-stack fixtures own."""
import subprocess
import unittest

from disposable_services import (
    disposable_postgres_and_redis,
    remove_owned_containers,
    run,
    start_container,
    verify_postgres_on_tmpfs,
    wait_for_postgres,
)


def anonymous_volume(container):
    return run('docker', 'inspect', container, '--format', '{{range .Mounts}}{{.Name}}{{end}}')


def volume_exists(volume):
    return subprocess.run(['docker', 'volume', 'inspect', volume],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


class OwnedContainerRemoval(unittest.TestCase):
    def start(self, *options):
        # redis:7 declares a /data volume, so each container gets an anonymous one.
        container = run('docker', 'run', '-d', *options, 'redis:7')
        volume = anonymous_volume(container)
        self.assertTrue(volume, container)
        self.addCleanup(subprocess.run, ['docker', 'rm', '-f', '-v', container],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(subprocess.run, ['docker', 'volume', 'rm', volume],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return container, volume

    def test_owned_container_volumes_are_removed_and_others_kept(self):
        # The fixture starts its containers with --rm; removing one explicitly
        # still has to remove its anonymous volume.
        owned, owned_volume = self.start('--rm')
        bystander, bystander_volume = self.start()

        remove_owned_containers([owned])

        self.assertFalse(volume_exists(owned_volume), owned_volume)
        self.assertEqual(run('docker', 'inspect', bystander, '--format', '{{.State.Running}}'), 'true')
        self.assertTrue(volume_exists(bystander_volume), bystander_volume)


def container_on_host_port(port):
    """The running container whose published port is 127.0.0.1:port."""
    for line in run('docker', 'ps', '--format', '{{.ID}} {{.Ports}}').splitlines():
        container, _, ports = line.partition(' ')
        if f'127.0.0.1:{port}->' in ports:
            return container
    raise AssertionError(f'no container publishes 127.0.0.1:{port}')


class DisposablePostgresAndRedis(unittest.TestCase):
    def test_services_answer_on_tmpfs_and_are_removed(self):
        with disposable_postgres_and_redis() as services:
            postgres = container_on_host_port(services['PGPORT'])
            redis = container_on_host_port(services['REDIS_URL'].rsplit(':', 1)[1].split('/')[0])
            mounts = run('docker', 'exec', postgres, 'cat', '/proc/mounts')
            self.assertIn(' /var/lib/postgresql/data tmpfs ', mounts)
            self.assertEqual(run('docker', 'exec', postgres, 'psql', '-h', '127.0.0.1', '-U', 'postgres',
                                 '-tAc', 'SELECT 1'), '1')
            self.assertEqual(run('docker', 'exec', redis, 'redis-cli', 'ping'), 'PONG')
        self.assertEqual(run('docker', 'ps', '-aq', '--filter', 'id=' + postgres), '')
        self.assertEqual(run('docker', 'ps', '-aq', '--filter', 'id=' + redis), '')

    def test_postgres_on_the_container_filesystem_is_refused(self):
        owned = []
        self.addCleanup(remove_owned_containers, owned)
        postgres, _ = start_container(owned, 'postgres:17', 5432, '-e', 'POSTGRES_PASSWORD=postgres')
        wait_for_postgres(postgres)
        with self.assertRaisesRegex(RuntimeError, 'is not on tmpfs'):
            verify_postgres_on_tmpfs(postgres)


if __name__ == '__main__':
    unittest.main()
