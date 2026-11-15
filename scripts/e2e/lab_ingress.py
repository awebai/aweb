"""Ephemeral-host ingress fence, retained until exact provider teardown.

No host is adopted/reused. SSH remains reachable; public Docker publications
are usable from the lab's own namespaces, not from outside the host. Every
mutation is intent-journaled before the daemon/kernel call. This is fixture
isolation; registry public-address validation and TLS policy stay unchanged.
"""
import json
import os
import re
import subprocess
import time


class Ingress:
    def __init__(self, root, fixture_id, deadline):
        if not re.fullmatch('adaz-[0-9a-f]{32}', fixture_id):
            raise ValueError('invalid ingress ownership')
        self.root, self.deadline = root, deadline
        self.chain = 'ADAZ_' + fixture_id[5:21]
        self.journal = root / 'ingress.private.jsonl'

    def call(self, argv, *, mutate=False):
        record = {'argv': argv, 'mutation': mutate, 'started_unix_seconds': time.time()}
        if mutate:
            self.append({**record, 'kind': 'intent'})
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('ingress deadline exhausted')
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=min(10, left))
            self.append({**record, 'kind': 'result', 'rc': done.returncode,
                         'stdout': done.stdout, 'stderr': done.stderr})
        except BaseException as error:
            self.append({**record, 'kind': 'uncertain' if mutate else 'unknown', 'error': type(error).__name__})
            raise
        if done.returncode:
            raise RuntimeError('ingress call failed; retained exact journal')
        return done.stdout

    def append(self, record):
        with self.journal.open('a') as stream:
            stream.write(json.dumps(record) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def install(self):
        routes = json.loads(self.call(['ip', '-j', '-4', 'route', 'show', 'default']))
        devices = {route['dev'] for route in routes}
        if len(devices) != 1 or not re.fullmatch('[A-Za-z0-9_.:-]{1,32}', next(iter(devices))):
            raise ValueError('external interface is ambiguous')
        device = next(iter(devices))
        ipv6 = json.loads(self.call(['ip', '-j', '-6', 'address', 'show', 'scope', 'global']))
        if any(link.get('addr_info') for link in ipv6):
            raise ValueError('this profile requires no globally assigned IPv6')
        rules = self.call(['iptables', '-w', '2', '-S'])
        if any(line.split()[:2] == ['-N', self.chain] for line in rules.splitlines()):
            raise ValueError('ingress chain already exists; never adopted')
        if '-N DOCKER-USER' not in rules.splitlines():
            raise ValueError('reviewed Docker iptables ingress hook is unavailable')
        for argv in [
            ['-N', self.chain],
            ['-A', self.chain, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
            ['-A', self.chain, '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'],
            ['-A', self.chain, '-j', 'DROP'],
            ['-I', 'INPUT', '1', '-i', device, '-j', self.chain],
            ['-I', 'DOCKER-USER', '1', '-i', device, '-j', 'DROP'],
        ]:
            # The DOCKER-USER rule is tagged with the owned chain as a comment;
            # no global save/restore or adoption of an existing rule occurs.
            if argv[:2] == ['-I', 'DOCKER-USER']:
                argv = argv[:-2] + ['-m', 'comment', '--comment', self.chain, *argv[-2:]]
            self.call(['iptables', '-w', '2', *argv], mutate=True)
        readback = self.call(['iptables', '-w', '2', '-S'])
        expected = f'-A INPUT -i {device} -j {self.chain}'
        if expected not in readback.splitlines():
            raise RuntimeError('owned INPUT jump readback differs')
        expected_forward = f'-A DOCKER-USER -i {device} -m comment --comment {self.chain} -j DROP'
        if expected_forward not in readback.splitlines():
            raise RuntimeError('owned Docker ingress rule readback differs')
        self.append({'kind': 'installed', 'chain': self.chain, 'external_interface': device,
                     'rules': readback, 'disposition': 'retained until provider teardown'})
        return {'chain': self.chain, 'external_interface': device,
                'disposition': 'retained until exact provider teardown'}
