"""Safety/evidence decisions with synthetic observations, never daemon proof."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest

from lab_lifecycle import Resources
from lab_quota_observer import enforcement, write_private


class EvidenceControls(unittest.TestCase):
    def test_atomic_private_publication_never_replaces_an_existing_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ack.json'
            write_private(path, {'value': 'first'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(path, {'value': 'second'})
            self.assertEqual(json.loads(path.read_text()), {'value': 'first'})
            self.assertEqual(list(path.parent.glob('*.staging')), [])

    def test_owned_volume_second_precision_requires_a_pre_child_inventory(self):
        plan = {'owner_label': {'key': 'owner', 'value': 'ours'}, 'compose_projects': [],
                'created_unix_seconds': 1.75}
        volume = {'Name': 'v', 'CreatedAt': '1970-01-01T00:00:01Z', 'Labels': {'owner': 'ours'}}
        observer = Resources(Path('/unused'), plan, time.monotonic() + 1)
        with self.assertRaises(RuntimeError):
            observer.ownership('volume', volume)
        observer.baseline = {'volume': set()}
        observer.ownership('volume', volume)
        observer.baseline = {'volume': {'v'}}
        with self.assertRaises(RuntimeError):
            observer.ownership('volume', volume)
        observer.baseline = {'volume': set()}
        volume['Labels'] = {'owner': 'foreign'}
        with self.assertRaises(RuntimeError):
            observer.ownership('volume', volume)

    def test_enforcement_needs_shared_actual_peer_and_matching_live_redis_buckets(self):
        requests = [
            {'path': '/v1/namespaces/example.com', 'status': 429,
             'headers': {'X-RateLimit-Limit': '60', 'X-RateLimit-Reset': '120'}},
            {'path': '/v1/did/did:aw:fixture/head', 'status': 200,
             'headers': {'X-RateLimit-Limit': '120', 'X-RateLimit-Reset': '120'}},
        ]
        log = ('INFO: 172.18.0.2:4321 - "GET /v1/namespaces/example.com HTTP/1.1" 429 Too Many Requests\n'
               'INFO: 172.18.0.2:4322 - "GET /v1/did/did:aw:fixture/head HTTP/1.1" 200 OK\n')
        values = [['aweb:rl:namespace_get:172.18.0.2:1', '61', 20],
                  ['aweb:rl:did_head:172.18.0.2:1', '1', 20]]
        self.assertEqual(enforcement({'requests': requests}, values, log)['verdict'], 'PASS')
        with self.assertRaisesRegex(ValueError, 'source'):
            enforcement({'requests': requests}, values, log.replace('172.18.0.2:4322', '172.18.0.3:4322'))
        for changed in (values[:1], copy.deepcopy(values)):
            if len(changed) == 2:
                changed[0][2] = -2
            with self.assertRaises(ValueError):
                enforcement({'requests': requests}, changed, log)
        changed = copy.deepcopy(requests)
        changed[1]['headers']['X-RateLimit-Limit'] = '60'
        with self.assertRaises(ValueError):
            enforcement({'requests': changed}, values, log)


if __name__ == '__main__':
    unittest.main()
