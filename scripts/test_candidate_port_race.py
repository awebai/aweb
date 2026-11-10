#!/usr/bin/env python3
"""Reproduce acwx's allocation race without Docker or a synthetic socket stub.

The incident cause remains unconfirmed: these tests establish the allocator's
reservation gap, not why Docker Desktop dropped the incident's awid traffic.
Run explicitly: python3 scripts/test_candidate_port_race.py -v
"""
import errno
import importlib.util
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import uuid
import unittest

ALLOCATOR = Path(__file__).with_name('candidate-ports.py')


def allocate():
    spec = importlib.util.spec_from_file_location('candidate_ports', ALLOCATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Exercise the default gate allocations; inherited overrides are not part
    # of this reproduction. Only this worker's environment is changed.
    for name in module.PORT_VARIABLES:
        os.environ.pop(name, None)
    ports, _ = module.allocate('race-proof', [])
    return ports


def allocator_worker(connection):
    with connection:
        while connection.recv() == 'allocate':
            connection.send(allocate())


class CandidatePortRaceTests(unittest.TestCase):
    def test_returned_port_is_reserved_until_service_binds(self):
        # A separate allocator process has returned and closed its sockets,
        # just as it does before the gate starts its runner. An unrelated listener wins the
        # check/use gap on a real kernel, without relying on random :0 reuse.
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe()
        worker = context.Process(target=allocator_worker, args=(child,))
        worker.start()
        child.close()
        try:
            parent.send('allocate')
            self.assertTrue(parent.poll(10), 'allocator did not return')
            port = parent.recv()['LIBRARY_E2E_AWID_PORT']
            with socket.socket() as competitor:
                try:
                    competitor.bind(('127.0.0.1', port))
                except OSError as error:
                    self.assertEqual(error.errno, errno.EADDRINUSE)
                    return
                competitor.listen()
                # This is the real consumer's later bind, now refused.
                with socket.socket() as service:
                    with self.assertRaises(OSError) as refused:
                        service.bind(('127.0.0.1', port))
                self.assertEqual(refused.exception.errno, errno.EADDRINUSE)
                self.fail(f'allocator returned unreserved awid port {port}; '
                          'another process can take it before the service binds')
        finally:
            parent.send('stop')
            worker.join(5)
            if worker.is_alive():
                worker.terminate()
                worker.join()
            parent.close()

    @unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_PORTS') == '1',
                         'requires an approved Docker slot')
    def test_journey_port_stays_reserved_until_service_binds(self):
        # Execute the actual incident-path functions, not a model of them.
        source = ALLOCATOR.with_name('e2e-oss-user-journey.sh').read_text()
        functions = source[source.index('allocate_service_ports() {'):
                           source.index('compose() {')]
        project = 'acwx-race-' + uuid.uuid4().hex[:12]
        env = {**os.environ, 'PROJECT': project, 'AWEB_PORT': '',
               'AWID_PORT': '', 'PORT_ALLOCATOR': ''}
        competitor, consumer = project + '-competitor', project + '-consumer'
        try:
            allocation = subprocess.run(
                ['bash', '-seu'], input=functions + '\n'
                'trap release_service_ports EXIT\n'
                'allocate_service_ports\n'
                'release_service_ports\n'
                'printf "%s\\n" "$AWID_PORT"\n',
                env=env, text=True, capture_output=True, timeout=60, check=True)
            port = int(allocation.stdout.strip())
            # The real journey then executes compose up using the returned
            # port. Place a Docker consumer in precisely that scheduling gap.
            command = ['docker', 'run', '-d', '--label', 'aweb.e2e.project=' + project,
                       '--cpus', '.1', '--memory', '32m', '--pids-limit', '16',
                       '-p', f'0.0.0.0:{port}:8010', '--entrypoint', '/bin/sleep']
            winner = subprocess.run(
                [*command, '--name', competitor, 'redis:7-alpine', 'infinity'],
                text=True, capture_output=True, timeout=60)
            if winner.returncode:
                self.fail('competitor could not start; reproduction inconclusive: '
                          + winner.stderr)
            refused = subprocess.run(
                [*command, '--name', consumer, 'redis:7-alpine', 'infinity'],
                text=True, capture_output=True, timeout=60)
            self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
            self.assertRegex(refused.stderr.lower(),
                             'port is already allocated|address already in use|ports are not available')
            self.fail(f'journey returned unreserved awid port {port}; Docker '
                      'competitor took it and the subsequent service bind failed: '
                      + refused.stderr.strip())
        finally:
            # The incident allocator and both probe containers share this
            # run-unique label, including a failed docker-run container.
            owned = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', 'label=aweb.e2e.project=' + project],
                text=True, capture_output=True, timeout=30, check=True).stdout.split()
            if owned:
                subprocess.run(['docker', 'rm', '-fv', *owned],
                               text=True, capture_output=True, timeout=30, check=True)
            remaining = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', 'label=aweb.e2e.project=' + project],
                text=True, capture_output=True, timeout=30, check=True).stdout.strip()
            self.assertEqual(remaining, '', 'race-probe containers survived cleanup')

    def test_two_concurrent_allocators_do_not_return_the_same_port(self):
        # Both workers allocate on each round before either consumer binds.
        # Bounded sampling is diagnostic: absence of a collision is NOT proof
        # of safety; the deterministic reservation-gap test above supplies it.
        context = multiprocessing.get_context('spawn')
        workers, pipes = [], []
        try:
            for _ in range(2):
                parent, child = context.Pipe()
                worker = context.Process(target=allocator_worker, args=(child,))
                worker.start()
                child.close()
                workers.append(worker)
                pipes.append(parent)
            for attempt in range(1, 2001):
                for pipe in pipes:
                    pipe.send('allocate')
                results = []
                for pipe in pipes:
                    self.assertTrue(pipe.poll(10), 'allocator did not return')
                    results.append(pipe.recv())
                overlap = set(results[0].values()) & set(results[1].values())
                if overlap:
                    assignments = [{name: port for name, port in result.items()
                                    if port in overlap} for result in results]
                    self.fail(f'two concurrent gate allocations reused ports '
                              f'on round {attempt}: {assignments}')
            self.skipTest('no random overlap observed in 2000 rounds; '
                          'this does not establish reservation safety')
        finally:
            for pipe in pipes:
                pipe.send('stop')
            for worker in workers:
                worker.join(5)
                if worker.is_alive():
                    worker.terminate()
                    worker.join()
            for pipe in pipes:
                pipe.close()


if __name__ == '__main__':
    unittest.main()
