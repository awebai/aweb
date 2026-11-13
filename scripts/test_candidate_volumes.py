#!/usr/bin/env python3
"""Gate volume ownership controls; real Docker proof is opt-in on a dedicated host."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / 'candidate-gate/bin/docker'
SPEC = importlib.util.spec_from_file_location('volumes', ROOT / 'scripts/candidate-volumes.py')
VOLUMES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VOLUMES)


class Commands(unittest.TestCase):
    def test_shim_removal_records_mounts_through_real_helper_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'docker'
            calls = root / 'calls.jsonl'
            manifest = root / 'owned.tsv'
            # Exercise the helper with this test's interpreter, including 3.12
            # used by the gate, rather than the host's default python3.
            (root / 'python3').symlink_to(sys.executable)
            fake.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['TEST_DOCKER_CALLS']).open('a') as output:
    output.write(json.dumps(args) + '\\n')
if args[:2] == ['container', 'inspect']:
    print(json.dumps([{'Config': {'Labels': {'aweb.candidate-gate': 'owned'}},
                      'Mounts': [{'Type': 'volume', 'Name': 'volume-' + args[2]}]}]))
elif args[:2] == ['volume', 'inspect']:
    print(json.dumps([{'Name': args[2], 'Labels': {'com.docker.volume.anonymous': ''}}]))
elif args == ['rm', '--volumes', '-f', 'first', 'second']:
    pass
else:
    sys.exit('Unexpected Docker call: ' + repr(args))
''')
            fake.chmod(0o755)
            env = dict(os.environ, AWEB_CANDIDATE_REAL_DOCKER=str(fake),
                       AWEB_CANDIDATE_RESOURCE_LABEL='owned',
                       CANDIDATE_RESOURCE_MANIFEST=str(manifest), TEST_DOCKER_CALLS=str(calls),
                       PATH=str(root) + os.pathsep + os.environ['PATH'])
            for command in (['rm'], ['container', 'rm'], ['container', 'remove']):
                with self.subTest(command=command):
                    manifest.write_text('')
                    calls.write_text('')
                    result = subprocess.run(['bash', str(SHIM), *command, '-f', 'first', 'second'],
                                            env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(manifest.read_text(), 'volume\tvolume-first\nvolume\tvolume-second\n')
                    self.assertEqual([json.loads(line) for line in calls.read_text().splitlines()], [
                        ['container', 'inspect', 'first'], ['volume', 'inspect', 'volume-first'],
                        ['container', 'inspect', 'second'], ['volume', 'inspect', 'volume-second'],
                        ['rm', '--volumes', '-f', 'first', 'second']])

    def test_compose_removal_includes_anonymous_volumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'docker'
            fake.write_text('#!' + sys.executable + '\nimport json,sys\na=sys.argv[1:]\n'
                            'print("service" if "config" in a else json.dumps(a))\n')
            fake.chmod(0o755)
            env = dict(os.environ, AWEB_CANDIDATE_REAL_DOCKER=str(fake),
                       AWEB_CANDIDATE_RESOURCE_LABEL='owned', AWEB_DOCKER_BIND_ROOT=tmp)
            for key in ('CANDIDATE_RESOURCE_MANIFEST', 'CANDIDATE_RUNNER_NAME'):
                env.pop(key, None)
            for operation in ('down', 'rm'):
                output = subprocess.check_output(['bash', str(SHIM), 'compose', '-f', 'unused.yml', operation], env=env, text=True)
                args = json.loads(output)
                self.assertEqual(args[args.index(operation) + 1], '--volumes')

    def test_owned_anonymous_receipts_exclude_preexisting_and_foreign_volumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / 'owned.tsv'
            manifest.write_text('preexisting-volume\tborrowed\n')
            info = {'Config': {'Labels': {'aweb.candidate-gate': 'run'}}, 'Mounts': [
                {'Type': 'volume', 'Name': name} for name in ('anonymous', 'named-foreign', 'borrowed')]}
            def inspect(binary, *args):
                self.assertEqual(args[:2], ('volume', 'inspect'))
                labels = {'com.docker.volume.anonymous': ''} if args[2] == 'anonymous' else {}
                return json.dumps([{'Name': args[2], 'Labels': labels}])
            with patch.object(VOLUMES.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps([info]))), patch.object(VOLUMES, 'docker', side_effect=inspect):
                VOLUMES.remember('docker', 'run', manifest, ['container'])
            self.assertEqual(manifest.read_text(), 'preexisting-volume\tborrowed\nvolume\tanonymous\n')
            # An unrelated container's anonymous volumes are not ours either.
            info['Config']['Labels']['aweb.candidate-gate'] = 'other'
            with patch.object(VOLUMES.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps([info]))), patch.object(VOLUMES, 'docker') as docker:
                VOLUMES.remember('docker', 'run', manifest, ['container'])
                docker.assert_not_called()

    def test_final_verdict_detects_remaining_owned_volume_without_pruning_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / 'owned.tsv'
            for retained in (False, True):
                manifest.write_text('volume\tanonymous\n')
                with patch.object(VOLUMES, 'docker', side_effect=['anonymous\nunrelated', 'anonymous\nunrelated' if retained else 'unrelated']), patch.object(VOLUMES.subprocess, 'run', return_value=subprocess.CompletedProcess([], int(retained))) as remove:
                    if retained:
                        with self.assertRaises(RuntimeError):
                            VOLUMES.remove_recorded('docker', manifest)
                    else:
                        VOLUMES.remove_recorded('docker', manifest)
                    self.assertEqual(remove.call_args.args[0], ['docker', 'volume', 'rm', 'anonymous'])
                    self.assertIn('absence-owned-volumes\t' + ('anonymous' if retained else 'none'), manifest.read_text())

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
            env = dict(os.environ, AWEB_CANDIDATE_RESOURCE_LABEL=os.environ.get('AWEB_CANDIDATE_RESOURCE_LABEL', name),
                       CANDIDATE_RESOURCE_MANIFEST=os.environ.get('CANDIDATE_RESOURCE_MANIFEST', str(Path(tmp) / 'owned.tsv')),
                       AWEB_CANDIDATE_REAL_DOCKER=os.environ.get('AWEB_CANDIDATE_REAL_DOCKER') or shutil.which('docker'))
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
