"""Source-visible lifecycle regressions; no kernel/daemon qualification."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

import default_registry_lab
from lab_ingress import Ingress
from lab_lifecycle import Resources, final_verdict


class RuleCapture(Ingress):
    def __init__(self):
        super().__init__(Path('/unused'), 'adaz-' + 'a' * 32, time.monotonic() + 1)
        self.rules = {'INPUT': [], 'DOCKER-USER': []}

    def append(self, record):
        pass

    def call(self, argv, *, mutate=False):
        if argv[:4] == ['ip', '-j', '-4', 'route']:
            return '[{"dev":"eth0"}]'
        if argv[:4] == ['ip', '-j', '-6', 'address']:
            return '[]'
        if argv[:3] != ['iptables', '-w', '2']:
            raise AssertionError(argv)
        rule = argv[3:]
        if rule == ['-S']:
            return '\n'.join(['-N ' + c for c in self.rules if c != 'INPUT'] +
                ['-A ' + chain + ' ' + ' '.join(r) for chain, rules in self.rules.items() for r in rules])
        if rule[0] == '-N':
            self.rules[rule[1]] = []
        elif rule[0] == '-A':
            self.rules[rule[1]].append(rule[2:])
        elif rule[0] == '-I':
            self.rules[rule[1]].insert(int(rule[2]) - 1, rule[3:])
        else:
            raise AssertionError(rule)
        return ''

    def forward_verdict(self, state, port):
        def chain(name):
            for rule in self.rules[name]:
                if '--ctstate' in rule and state not in rule[rule.index('--ctstate') + 1].split(','):
                    continue
                if '--dport' in rule and str(port) != rule[rule.index('--dport') + 1]:
                    continue
                target = rule[rule.index('-j') + 1]
                if target in ('DROP', 'ACCEPT'):
                    return target
                return chain(target)
            return 'CONTINUE'
        return chain('DOCKER-USER')


class LifecycleRegressions(unittest.TestCase):
    def test_forwarding_permits_outbound_replies_but_not_unsolicited_public_or_ssh_flows(self):
        captured = RuleCapture()
        captured.install()
        self.assertEqual(captured.forward_verdict('ESTABLISHED', 43210), 'ACCEPT')
        self.assertEqual(captured.forward_verdict('RELATED', 43210), 'ACCEPT')
        self.assertEqual(captured.forward_verdict('NEW', 8010), 'DROP')
        self.assertEqual(captured.forward_verdict('NEW', 22), 'DROP')

    def observer(self):
        plan = dict(owner_label={'key': 'aweb.adaz.default', 'value': 'ours'}, compose_projects=[],
            created_unix_seconds=1, published_listener=dict(project='', service='awid', container_name='run-awid',
            host_ip='8.8.8.8', published_port=443))
        observer = Resources(Path('/unused'), plan, time.monotonic() + 1)
        value = dict(Id='a' * 64, Name='/run-awid', Image='image', Created='1970-01-01T00:00:02Z',
            Config={'Labels': {'aweb.adaz.default': 'ours'}}, HostConfig={}, Mounts=[],
            State={'Running': False, 'Status': 'created'}, NetworkSettings={'Ports': {}, 'Networks': {}})
        observer.inventory = mock.Mock(side_effect=lambda kind, selector: ['a' * 64] if kind == 'container' else [])
        observer.all_objects = mock.Mock(return_value=set())
        observer.inspect = mock.Mock(side_effect=lambda *args, **kwargs: copy.deepcopy(value))
        return observer, value

    def test_created_pending_listener_becomes_observed_only_when_running_with_exact_binding(self):
        observer, value = self.observer()
        observer.discover()
        self.assertFalse(observer.listener_seen)
        value['State']['Running'] = True
        value['NetworkSettings']['Ports'] = {'8010/tcp': [{'HostIp': '8.8.8.8', 'HostPort': '443'}]}
        observer.discover()
        self.assertTrue(observer.listener_seen)

    def test_wrong_running_publication_refuses(self):
        observer, value = self.observer()
        value['State']['Running'] = True
        value['NetworkSettings']['Ports'] = {'8010/tcp': [{'HostIp': '8.8.8.8', 'HostPort': '444'}]}
        with self.assertRaisesRegex(RuntimeError, 'binding differs'):
            observer.discover()
        self.assertFalse(observer.listener_seen)

    def test_never_live_listener_cannot_qualify_even_after_clean_resource_removal(self):
        result = {'primary': 'PASS', 'process': {'populated': False, 'verdict': 'CLEAN'},
                  'cleanup': {'plan': {'verdict': 'CLEAN', 'public_listener_seen': False}}}
        quota = {'plan': {'enforcement': {'verdict': 'PASS'}, 'binding_verified_after_body': True}}
        self.assertEqual(final_verdict(result, 1, quota), 'FAIL')
        result['cleanup']['plan']['public_listener_seen'] = True
        self.assertEqual(final_verdict(result, 1, quota), 'PASS')

    def test_plan_is_not_visible_until_complete_json_is_fsynced_and_published(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'resources.plan.json'
            started, release = threading.Event(), threading.Event()
            failures = []
            original_dump = json.dump
            def slow_dump(value, stream, **kwargs):
                text = json.dumps(value, **kwargs)
                stream.write(text[:len(text) // 2])
                stream.flush()
                started.set()
                if not release.wait(2):
                    raise TimeoutError('test reader did not release publisher')
                stream.write(text[len(text) // 2:])
            def publish():
                try:
                    default_registry_lab.publish_plan(path, {'fixture_id': 'real-value', 'payload': list(range(20))})
                except BaseException as error:
                    failures.append(error)
            with mock.patch.object(json, 'dump', slow_dump):
                child = threading.Thread(target=publish)
                child.start()
                try:
                    self.assertTrue(started.wait(2))
                    self.assertFalse(path.exists(), 'a reader can observe the incomplete final-name plan')
                finally:
                    release.set()
                    child.join(timeout=3)
            self.assertFalse(child.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(json.loads(path.read_text())['fixture_id'], 'real-value')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with mock.patch.object(json, 'dump', original_dump), self.assertRaises(FileExistsError):
                default_registry_lab.publish_plan(path, {'fixture_id': 'replacement'})


if __name__ == '__main__':
    unittest.main()
