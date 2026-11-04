"""The early user-path stage must stop the train on a failed real journey."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('user_paths_result', ROOT / 'scripts/e2e/user_paths_result.py')
result_model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(result_model)


class UserPathsAdmission(unittest.TestCase):
    def test_missing_prepared_runtime_fails_without_allocating_or_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bind = root / 'bind'
            bind.mkdir()
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('USER_PATHS_', 'CANDIDATE_GATE_IMAGE'))}
            env.update(USER_PATHS_EVIDENCE=str(root / 'evidence'), AWEB_DOCKER_BIND_ROOT=str(bind))
            result = subprocess.run(['python3', str(ROOT / 'scripts/e2e/user_paths_stack.py')],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('infrastructure prerequisite failed; no pull or retry attempted', result.stderr)
            self.assertEqual(list(bind.iterdir()), [])
            self.assertTrue((root / 'evidence/infrastructure.json').is_file())

    def test_missing_lane_failure_cleanup_budget_and_required_humans_cannot_qualify(self):
        inventory = result_model.qualification({}, 10, [])['required_agent_cases']
        lanes = {lane: {'outcomes': [dict(case=case, status='PASSED') for case in inventory if case.startswith(lane + '/')]}
                 for lane in ['head', 'released']}
        full = result_model.qualification(lanes, 100, [])
        self.assertEqual(full['status'], 'INCOMPLETE')
        self.assertEqual(len(full['required_humans']), 12)
        self.assertEqual(len(full['required_agent_cases']), 66)
        self.assertEqual(result_model.qualification({'head': lanes['head']}, 100, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 600, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 100, ['owned resource remains'])['status'], 'FAILED')
        lanes['released']['outcomes'][0]['status'] = 'FAILED'
        self.assertEqual(result_model.qualification(lanes, 100, [])['status'], 'FAILED')

    def test_failure_is_a_failed_second_stage_and_stops_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make = root / 'make'
            make.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$CALLS"\n[[ "$1" != e2e-user-paths ]] || exit 86\n')
            make.chmod(0o755)
            result = subprocess.run(['bash', str(ROOT / 'scripts/candidate-suite.sh'), 'checks user-paths unit'],
                                    env=dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                                             CALLS=str(root / 'calls'), CANDIDATE_LOG_DIR=str(root)),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
            self.assertNotIn('_candidate-unit-suites', (root / 'calls').read_text())
            summary = (root / 'summary.tsv').read_text()
            self.assertIn('checks\tPASSED', summary)
            self.assertIn('user-paths\tFAILED', summary)



class FrozenGateInput(unittest.TestCase):
    """Real entrypoint, Git clone, reset, suite and ledger; Docker is a boundary stub."""
    def test_snapshot_survives_reset_and_focused_checks_are_reused(self):
        import hashlib
        import json
        import shutil
        import sys
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        metadata = dict(name='@awebai/aw', version='1.36.54', gitHead='a' * 40,
                        dist=dict(tarball='https://example.test/aw.tgz', integrity='sha512-fixture'))
        class Registry(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(metadata).encode())
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Registry)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, commands = root / 'repo', root / 'bin'
                (repo / 'scripts').mkdir(parents=True)
                commands.mkdir()
                for name in ['candidate-docker-gate.sh', 'candidate-suite.sh', 'candidate-cleanup.sh', 'fetch_released_aw.py']:
                    shutil.copy2(ROOT / 'scripts' / name, repo / 'scripts' / name)
                (repo / 'scripts/candidate-host-pressure.py').write_text('import pathlib,sys\nif sys.argv[1]=="capture": pathlib.Path(sys.argv[2]).write_text("{}")\n')
                (repo / 'candidate-gate').mkdir()
                (repo / 'candidate-gate/Dockerfile').write_text('FROM scratch\n')
                (repo / 'naapp/library/test-vectors/blueprints/team').mkdir(parents=True)
                (repo / 'naapp/library/test-vectors/blueprints/team/proof').touch()
                (repo / 'Makefile').write_text(''' .DEFAULT:
\t@true
naapp-e2e-packages:
\t@echo proof/one
e2e-user-paths:
\t@python3 -c 'import os,pathlib,hashlib,json; p=pathlib.Path(os.environ["USER_PATHS_LATEST_METADATA"]); b=p.read_bytes(); pathlib.Path(os.environ["SNAPSHOT_RECEIPT"]).write_text(json.dumps(dict(body=b.decode(),digest=hashlib.sha256(b).hexdigest(),declared=os.environ.get("USER_PATHS_LATEST_SHA256"))))'
'''.lstrip())
                def git(*args):
                    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
                git('init', '-qb', 'main')
                git('config', 'user.name', 'entrypoint test')
                git('config', 'user.email', 'gate@example.test')
                git('add', '.')
                git('commit', '-qm', 'gate entrypoint fixture')
                git('remote', 'add', 'origin', str(repo))
                # Redirect only the registry transport to owned HTTP; run the real
                # freeze implementation. Every other Python command is unchanged.
                (commands / 'python3').write_text(f'''#!{sys.executable}
import importlib.util,os,sys
if len(sys.argv)>2 and sys.argv[1].endswith('/fetch_released_aw.py') and sys.argv[2]=='--freeze-latest':
 from pathlib import Path
 spec=importlib.util.spec_from_file_location('fetch',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
 print(m.freeze_latest(Path(sys.argv[3]),'http://127.0.0.1:{server.server_port}'))
else: os.execv({sys.executable!r},[{sys.executable!r},*sys.argv[1:]])
''')
                (commands / 'uname').write_text('#!/bin/sh\nprintf "Linux\\n"\n')
                (commands / 'df').write_text('#!/bin/sh\nprintf "Filesystem blocks Used Available Capacity Mounted\\nfixture 999999999 0 999999999 0 /\\n"\n')
                (commands / 'docker').write_text(f'''#!{sys.executable}
import os,subprocess,sys
args=sys.argv[1:]
if args[0]=='info': print('/');sys.exit(0)
if args[:2] in [['container','inspect'],['volume','inspect'],['buildx','inspect']]: sys.exit(1)
if args[:2]==['image','inspect']: sys.exit(0 if '--format' in args else 1)
if args[0]=='inspect': print('healthy' if 'Health.Status' in ' '.join(args) else '0');sys.exit(0)
if args[0]=='exec':
 text=' '.join(args);print('pg_catalog|user' if 'pg_settings' in text else 'public' if 'extnamespace' in text else '');sys.exit(0)
if args[0]=='run' and 'scripts/candidate-suite.sh' in args:
 env=dict(os.environ)
 for i,a in enumerate(args):
  if a=='-e': k,v=args[i+1].split('=',1);env[k]=v
 checkout=args[args.index('-w')+1]
 env['PATH']={str(commands)!r}+os.pathsep+env['PATH']
 # The fixture executes the actual stage script at the runner boundary.
 sys.exit(subprocess.run(['bash','scripts/candidate-suite.sh',args[-1]],cwd=checkout,env=env).returncode)
if args[0]=='run': print('1000' if 'stat' in args else 'service');sys.exit(0)
if args[:2] in [['network','create'],['volume','create']]: print('owned');sys.exit(0)
''')
                for path in commands.iterdir():
                    path.chmod(0o755)
                env = {k: v for k,v in os.environ.items() if not k.startswith(('AWEB_', 'CANDIDATE_', 'GATE_', 'LIBRARY_E2E_', 'USER_PATHS_'))}
                env.update(PATH=f'{commands}:{env["PATH"]}', AWEB_GATE_LEDGER=str(root / 'ledger.tsv'),
                           AWEB_GATE_LOG_DIR=str(root / 'logs'), CLI_VERSION='1.36.54', A2A_GATEWAY_VERSION='1.27.6',
                           SNAPSHOT_RECEIPT=str(root / 'snapshot.json'))
                def invoke(stages):
                    settings = dict(env)
                    if stages is not None:
                        settings['AWEB_CANDIDATE_STAGES'] = stages
                    result = subprocess.run(['bash','scripts/candidate-docker-gate.sh'], cwd=repo,
                        env=settings, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    return result.stdout
                try:
                    invoke('checks')
                    invoke(None)
                    ledger = (root / 'ledger.tsv').read_text().splitlines()
                    self.assertEqual(len(ledger), 5, ledger)
                    self.assertEqual(len({row.split('\t')[0] for row in ledger}), 1)
                    receipt = json.loads((root / 'snapshot.json').read_text())
                    expected = (json.dumps(metadata, sort_keys=True) + '\n').encode()
                    digest = hashlib.sha256(expected).hexdigest()
                    self.assertEqual(receipt['body'].encode(), expected)
                    self.assertEqual(receipt['digest'], digest)
                    self.assertEqual(receipt['declared'], digest)
                    tree = git('rev-parse', 'HEAD^{tree}')
                    external = f'CLI_VERSION=1.36.54\nA2A_GATEWAY_VERSION=1.27.6\nRELEASED_AW={digest}\n'
                    self.assertEqual(ledger[0].split('\t')[0], tree+'-'+hashlib.sha256(external.encode()).hexdigest())
                    self.assertIn('no stages run', invoke(None))
                    self.assertEqual(len((root / 'ledger.tsv').read_text().splitlines()), 5)
                    # Changing only the frozen artifact invalidates the key.
                    metadata['version'] = '1.36.55'
                    invoke('checks')
                    changed = (root / 'ledger.tsv').read_text().splitlines()
                    self.assertEqual(len(changed), 6)
                    self.assertNotEqual(changed[-1].split('\t')[0], ledger[0].split('\t')[0])
                    self.assertEqual(server.requests, ['/@awebai%2faw/latest'] * 4)
                finally:
                    shutil.rmtree('/tmp/aweb-candidate-gate-' + git('rev-parse', 'HEAD'), ignore_errors=True)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


class ExactMessageAssertions(unittest.TestCase):
    """Negative controls exercise the matrix's actual three-turn assertion path."""
    def exercise(self, kind, encrypted, mutate=None):
        import copy
        import json
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(paths)
        with tempfile.TemporaryDirectory() as directory:
            lane = paths.Lane.__new__(paths.Lane)
            lane.name, lane.root, lane.results = 'head', Path(directory), []
            lane.actors = {name: dict(address=name+'.test/'+name, events=str(Path(directory)/name)) for name in ['g1','g2']}
            records = []
            mode = 'encrypted_v2' if encrypted else 'legacy_plaintext_v1'
            for turn, (sender, receiver) in enumerate([('g1','g2'), ('g2','g1'), ('g1','g2')]):
                body = f'head/g1->g2/{kind}/{"v2" if encrypted else "plain"}/nonce' + ['', '/reply', '/continuation'][turn]
                mid, cid = 'message-'+str(turn), 'conversation'
                message = dict(body=body, message_id=mid, verification_status='verified',
                               from_address=lane.actors[sender]['address'], content_mode=mode,
                               message_version=2 if encrypted else 1)
                # These are DTO assertion controls, not substitute crypto proof.
                proof = dict(message_id=mid, conversation_id=cid)
                if encrypted:
                    message['encrypted_envelope'] = proof
                else:
                    message['signed_payload'] = json.dumps(proof)
                event = dict(kind=kind, content=body, meta=dict(message_id=mid, conversation_id=cid, verified='true', trust_status='verified'))
                if kind=='mail':
                    message['conversation_id']=cid
                    inbox=dict(messages=[copy.deepcopy(message)])
                    history=dict(messages=[copy.deepcopy(message)])
                    sent=dict(message_id=mid, conversation_id=cid)
                else:
                    event['meta']['session_id']=cid
                    inbox=dict(pending=[dict(last_message=body,last_from_address=lane.actors[sender]['address'], session_id=cid)])
                    history=dict(session_id=cid,messages=[copy.deepcopy(message)])
                    sent=dict(message_id=mid,session_id=cid)
                records.append(dict(event=event,inbox=inbox,history=history,sent=sent))
            if mutate:
                mutate(records)
            current = -1
            def command(actor, *args):
                nonlocal current
                if args[1] in ['send','send-and-wait','reply']:
                    current+=1
                    return records[current]['sent']
                return records[current]['inbox' if args[1] in ['inbox','pending'] else 'history']
            lane.command=command
            lane.delivered=lambda receiver, body: records[current]['event']
            with patch.object(paths.uuid,'uuid4') as random:
                random.return_value.hex='nonce'
                lane.flow('g1','g2',kind,encrypted)
            self.assertEqual(len(lane.results),1)

    def test_exact_three_turn_mail_and_chat_plain_and_v2(self):
        for kind in ['mail','chat']:
            for encrypted in [False,True]:
                with self.subTest(kind=kind, encrypted=encrypted):
                    self.exercise(kind,encrypted)

    def test_each_turn_rejects_message_thread_or_mode_substitution(self):
        for kind in ['mail','chat']:
            changes = [
                ('event id',lambda r:r['event']['meta'].update(message_id='another-message')),
                ('event thread',lambda r:r['event']['meta'].update(conversation_id='another-thread')),
                ('history id',lambda r:r['history']['messages'][0].update(message_id='another-message')),
                ('mode downgrade',lambda r:r['history']['messages'][0].update(content_mode='legacy_plaintext_v1')),
                ('envelope id',lambda r:r['history']['messages'][0]['encrypted_envelope'].update(message_id='another-message')),
                ('envelope thread',lambda r:r['history']['messages'][0]['encrypted_envelope'].update(conversation_id='another-thread')),
            ]
            if kind=='mail':
                changes += [('inbox id',lambda r:r['inbox']['messages'][0].update(message_id='another-message')),
                            ('inbox thread',lambda r:r['inbox']['messages'][0].update(conversation_id='another-thread')),
                            ('history thread',lambda r:r['history']['messages'][0].update(conversation_id='another-thread'))]
            else:
                changes += [('event session',lambda r:r['event']['meta'].update(session_id='another-thread')),
                            ('pending session',lambda r:r['inbox']['pending'][0].update(session_id='another-thread')),
                            ('history session',lambda r:r['history'].update(session_id='another-thread'))]
            for turn in range(3):
                for name,change in changes:
                    with self.subTest(kind=kind,turn=turn,change=name):
                        with self.assertRaises(AssertionError):
                            self.exercise(kind,True,lambda records:change(records[turn]))
            for turn in [1,2]:
                with self.subTest(kind=kind,turn=turn,change='send result thread'):
                    with self.assertRaises(AssertionError):
                        self.exercise(kind,True,lambda records:records[turn]['sent'].update(
                            {('conversation_id' if kind=='mail' else 'session_id'):'another-thread'}))
            for turn in range(3):
                with self.subTest(kind=kind,turn=turn,change='plaintext mode substitution'):
                    with self.assertRaises(AssertionError):
                        self.exercise(kind,False,lambda records:records[turn]['history']['messages'][0].update(content_mode='encrypted_v2'))


if __name__ == '__main__':
    unittest.main()
