#!/usr/bin/env python3
"""Gate volume ownership controls; real Docker proof is opt-in on a dedicated host."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / 'candidate-gate/bin/docker'


class Commands(unittest.TestCase):
    def test_owned_removal_requests_volumes_but_plain_docker_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'docker'
            fake.write_text('#!' + sys.executable + '\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
            fake.chmod(0o755)
            for command in (['rm', '-f', 'owned'], ['container', 'rm', '-f', 'owned']):
                env = dict(os.environ, AWEB_CANDIDATE_REAL_DOCKER=str(fake))
                env.pop('CANDIDATE_RESOURCE_MANIFEST', None)
                env.pop('AWEB_CANDIDATE_RESOURCE_LABEL', None)
                plain = subprocess.check_output(['bash', str(SHIM), *command], env=env, text=True)
                self.assertEqual(json.loads(plain), command)
                env['AWEB_CANDIDATE_RESOURCE_LABEL'] = 'this-run'
                owned = subprocess.check_output(['bash', str(SHIM), *command], env=env, text=True)
                self.assertIn('--volumes', json.loads(owned))


@unittest.skipUnless(os.environ.get('AWEB_TEST_DOCKER_VOLUMES') == '1', 'dedicated Docker host required')
class RealVolumes(unittest.TestCase):
    def test_early_removal_does_not_orphan_anonymous_volume(self):
        image = os.environ.get('AWEB_VOLUME_TEST_IMAGE', 'python:3.12-slim')
        name = 'aweb-volume-proof-' + uuid.uuid4().hex[:12]
        volume = None
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, AWEB_CANDIDATE_RESOURCE_LABEL=name,
                       CANDIDATE_RESOURCE_MANIFEST=str(Path(tmp) / 'owned.tsv'),
                       AWEB_CANDIDATE_REAL_DOCKER=subprocess.check_output(['which', 'docker'], text=True).strip())
            try:
                subprocess.run(['bash', str(SHIM), 'run', '-d', '--pull=never', '--name', name,
                                '-v', '/anonymous-data', image, 'sleep', '300'], env=env, check=True)
                info = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]
                volume = next(m['Name'] for m in info['Mounts'] if m['Destination'] == '/anonymous-data')
                # Deliberately omit -v: this was the nested cleanup hole.
                subprocess.run(['bash', str(SHIM), 'rm', '-f', name], env=env, check=True)
                self.assertNotEqual(subprocess.run(['docker', 'volume', 'inspect', volume],
                                    capture_output=True).returncode, 0, 'gate orphaned an anonymous volume')
                self.assertIn('volume\t' + volume, Path(env['CANDIDATE_RESOURCE_MANIFEST']).read_text())
            finally:
                subprocess.run(['docker', 'rm', '-fv', name], capture_output=True)
                if volume:
                    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)


if __name__ == '__main__':
    unittest.main()
