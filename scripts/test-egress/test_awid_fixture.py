"""Exercise the disposable services the AWID and command-stack fixtures own."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from disposable_services import (
    OWNER_LABEL,
    disposable_postgres_and_redis,
    reap_orphaned_containers,
    remove_owned_containers,
    run,
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
        with disposable_postgres_and_redis(password='fixture-test') as services:
            postgres = container_on_host_port(services['PGPORT'])
            redis = container_on_host_port(services['REDIS_URL'].rsplit(':', 1)[1].split('/')[0])
            mounts = run('docker', 'exec', postgres, 'cat', '/proc/mounts')
            self.assertIn(' /var/lib/postgresql/data tmpfs ', mounts)
            self.assertEqual(run('docker', 'exec', postgres, 'psql', '-h', '127.0.0.1', '-U', 'postgres',
                                 '-tAc', 'SELECT 1'), '1')
            self.assertEqual(run('docker', 'exec', redis, 'redis-cli', 'ping'), 'PONG')
        self.assertEqual(run('docker', 'ps', '-aq', '--filter', 'id=' + postgres), '')
        self.assertEqual(run('docker', 'ps', '-aq', '--filter', 'id=' + redis), '')



class OwnedContainerRemovalFailures(unittest.TestCase):
    """Without a daemon: a docker on PATH that cannot remove one container."""

    def test_one_failed_removal_does_not_skip_the_others(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        calls = directory / 'calls'
        docker = directory / 'docker'
        docker.write_text('#!/bin/sh\necho "$@" >> "$DOCKER_CALLS"\n'
                          'if [ "$4" = stuck ]; then echo "removal of stuck failed" >&2; exit 1; fi\n')
        docker.chmod(0o755)
        saved = dict(os.environ)
        self.addCleanup(os.environ.update, saved)
        os.environ['PATH'] = f"{directory}{os.pathsep}{os.environ['PATH']}"
        os.environ['DOCKER_CALLS'] = str(calls)

        with self.assertRaises(RuntimeError) as refused:
            remove_owned_containers(['first', 'stuck', 'last'])
        self.assertEqual(str(refused.exception),
                         'could not remove owned containers: stuck: removal of stuck failed. '
                         'Inspect the listed owned containers and finish their cleanup before another run.')

        self.assertEqual(calls.read_text().splitlines(),
                         ['rm -f -v last', 'rm -f -v stuck', 'rm -f -v first'])


class OrphanedContainerReaping(unittest.TestCase):
    """Without a daemon: a docker on PATH listing labelled containers."""

    def test_only_containers_whose_launcher_is_gone_are_removed(self):
        finished = subprocess.Popen(['true'])
        finished.wait()
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        calls = directory / 'calls'
        docker = directory / 'docker'
        listing = '\n'.join([
            f'orphan {finished.pid}',
            f'live {os.getpid()}',
            'unreadable not-a-pid',
        ])
        docker.write_text('#!/bin/sh\necho "$@" >> "$DOCKER_CALLS"\n'
                          f'if [ "$1" = ps ]; then printf "%s\\n" "{listing}"; fi\n')
        docker.chmod(0o755)
        saved = dict(os.environ)
        self.addCleanup(os.environ.update, saved)
        os.environ['PATH'] = f"{directory}{os.pathsep}{os.environ['PATH']}"
        os.environ['DOCKER_CALLS'] = str(calls)

        reap_orphaned_containers()

        recorded = calls.read_text().splitlines()
        self.assertIn(f'ps -a --filter label={OWNER_LABEL} --format {{{{.ID}}}} {{{{.Label "{OWNER_LABEL}"}}}}', recorded)
        self.assertEqual([call for call in recorded if call.startswith('rm ')], ['rm -f -v orphan'])


if __name__ == '__main__':
    unittest.main()
