"""The early user-path stage must stop the train on a failed real journey."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import importlib.util

from fixture_repo import fixture_env, init_fixture_repo, run_fixture

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('user_paths_result', ROOT / 'scripts/e2e/user_paths_result.py')
result_model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(result_model)


def known_failure(case):
    sender, receiver = case.split('/')[1].split('->')
    message = ('sending message: recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel '
               'and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext')
    return dict(actor=sender, args=['chat', 'send-and-wait', receiver, case+'/'+'a'*32, '--e2ee', '--wait', '0'],
                exit=1, response={'error': {'code': 'error', 'message': message}}, stderr=message+'\n')


class UserPathsAdmission(unittest.TestCase):
    def test_cross_server_controls_expect_current_stored_route_refusal_in_both_lanes(self):
        import sys
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'user_paths_result': result_model}):
            spec.loader.exec_module(paths)
        for name in ['head', 'released']:
            with self.subTest(lane=name):
                lane = paths.Lane.__new__(paths.Lane)
                lane.name, lane.legacy_released_diagnostics = name, name == 'released'
                observed = []
                lane.refused = lambda *args: observed.append(args)
                lane.run_case = lambda case, operation: operation() if '/cross-server/' in case else None
                lane.controls()
                self.assertEqual(observed, [('t1', 'remote', kind, 422, 'local_sender_route_mismatch', 'local_sender_route_mismatch')
                                            for kind in ['mail', 'chat']])

    def test_missing_prepared_runtime_fails_without_allocating_or_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bind = root / 'bind'
            bind.mkdir()
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('USER_PATHS_', 'CANDIDATE_GATE_IMAGE'))}
            env.update(USER_PATHS_EVIDENCE=str(root / 'evidence'), AWEB_DOCKER_BIND_ROOT=str(bind))
            result = run_fixture(['python3', str(ROOT / 'scripts/e2e/user_paths_stack.py')],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('infrastructure prerequisite failed; no pull or retry attempted', result.stderr)
            self.assertEqual(list(bind.iterdir()), [])
            self.assertTrue((root / 'evidence/infrastructure.json').is_file())
            import json
            report = json.loads((root / 'evidence/qualification.json').read_text())
            self.assertEqual(report['status'], 'FAILED')
            self.assertEqual(len(report['required_humans']), 12)
            self.assertEqual(result.stdout.count('NOT COVERED: pending aweb-actu'), 12)
            self.assertIn('incomplete: human paths not covered', result.stdout)

    def test_agent_failures_cleanup_budget_and_visible_human_gap(self):
        inventory = result_model.qualification({}, 10, [])['required_agent_cases']
        lanes = {lane: {'outcomes': [dict(case=case, status='PASSED') for case in inventory if case.startswith(lane + '/')]}
                 for lane in ['head', 'released']}
        lanes['released']['version'] = '1.36.55'
        full = result_model.qualification(lanes, 100, [])
        self.assertEqual(full['status'], 'PASSED')
        self.assertEqual(full['coverage_summary'], 'incomplete: human paths not covered')
        self.assertEqual({row['status'] for row in full['required_humans']}, {'NOT COVERED: pending aweb-actu'})
        self.assertTrue(all(row['case'] not in full['passed_agent_cases'] for row in full['required_humans']))
        self.assertEqual(len(full['required_humans']), 12)
        self.assertEqual(len(full['required_agent_cases']), 66)
        self.assertEqual(len(full['passed_agent_cases']), 66)
        self.assertEqual(full['known_issue_budget'], [])
        self.assertEqual(full['known_issues'], [])
        self.assertEqual(result_model.qualification({'head': lanes['head']}, 100, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 600, [])['status'], 'FAILED')
        self.assertEqual(result_model.qualification(lanes, 100, ['owned resource remains'])['status'], 'FAILED')
        lanes['released']['outcomes'][0]['status'] = 'FAILED'
        self.assertEqual(result_model.qualification(lanes, 100, [])['status'], 'FAILED')

    def test_fixed_released_local_chat_has_no_budget_exception(self):
        self.assertEqual(result_model.KNOWN_RELEASED_ISSUES, [])
        for case in ['released/t1->t2/chat/v2', 'released/t2->t1/chat/v2']:
            with self.subTest(case=case):
                passed = result_model.classify_outcome(dict(case=case, status='PASSED'), '1.36.55')
                self.assertEqual(passed['status'], 'PASSED')
                self.assertNotIn('known_issue', passed)
                # A recurrence is an ordinary failure, including the old exact diagnostic.
                failed = result_model.classify_outcome(
                    dict(case=case, status='FAILED', failure=known_failure(case)), '1.36.55')
                self.assertEqual(failed['status'], 'FAILED')
                self.assertNotIn('known_issue', failed)

    def test_failure_is_a_failed_second_stage_and_stops_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make = root / 'make'
            make.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "$CALLS"\n[[ "$1" != e2e-user-paths ]] || exit 86\n')
            make.chmod(0o755)
            result = run_fixture(['bash', str(ROOT / 'scripts/candidate-suite.sh'), 'checks user-paths unit'],
                                    env=dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                                             CALLS=str(root / 'calls'), CANDIDATE_LOG_DIR=str(root)),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
            self.assertNotIn('_candidate-unit-suites', (root / 'calls').read_text())
            summary = (root / 'summary.tsv').read_text()
            self.assertIn('checks\tPASSED', summary)
            self.assertIn('user-paths\tFAILED', summary)

    def test_passing_stage_summary_still_exposes_incomplete_human_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make = root / 'make'
            make.write_text('#!/bin/bash\nmkdir -p "$CANDIDATE_LOG_DIR/user-paths"\nprintf "%s\\n" "incomplete: human paths not covered" > "$CANDIDATE_LOG_DIR/user-paths/coverage-summary.txt"\n')
            make.chmod(0o755)
            result = run_fixture(['bash', str(ROOT / 'scripts/candidate-suite.sh'), 'user-paths'],
                                    env=dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CANDIDATE_LOG_DIR=str(root)),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = (root / 'summary.tsv').read_text().strip().split('\t')
            self.assertEqual(row[:2], ['user-paths', 'PASSED'])
            self.assertEqual(row[-1], 'incomplete: human paths not covered')



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
                for name in ['candidate-docker-gate.sh', 'candidate-suite.sh', 'candidate-cleanup.sh', 'gate_settings.py', 'gate_budgets.py', 'candidate-ports.py', 'fetch_released_aw.py']:
                    shutil.copy2(ROOT / 'scripts' / name, repo / 'scripts' / name)
                shutil.copy2(ROOT / 'scripts/e2e/user_paths_result.py', repo / 'scripts/user_paths_result.py')
                (repo / 'scripts/coverage_fixture.py').write_text('from user_paths_result import qualification\nr=qualification({},0,[])\nfor h in r["required_humans"]: print(h["case"]+": "+h["status"])\nprint(r["coverage_summary"])\n')
                (repo / 'scripts/candidate-host-pressure.py').write_text('import pathlib,sys\nif sys.argv[1]=="capture": pathlib.Path(sys.argv[2]).write_text("{}")\n')
                (repo / 'candidate-gate').mkdir()
                shutil.copy2(ROOT / 'candidate-gate/unit-settings.json', repo / 'candidate-gate/unit-settings.json')
                (repo / 'candidate-gate/Dockerfile').write_text('FROM scratch\n')
                (repo / 'naapp/library/test-vectors/blueprints/team').mkdir(parents=True)
                (repo / 'naapp/library/test-vectors/blueprints/team/proof').touch()
                (repo / 'Makefile').write_text(''' .DEFAULT:
\t@true
naapp-e2e-packages:
\t@echo proof/one
e2e-user-paths:
\t@python3 -c 'import os,pathlib,hashlib,json; p=pathlib.Path(os.environ["USER_PATHS_LATEST_METADATA"]); b=p.read_bytes(); pathlib.Path(os.environ["SNAPSHOT_RECEIPT"]).write_text(json.dumps(dict(body=b.decode(),digest=hashlib.sha256(b).hexdigest(),declared=os.environ.get("USER_PATHS_LATEST_SHA256"))))'
\t@python3 scripts/coverage_fixture.py
'''.lstrip())
                def git(*args):
                    return run_fixture(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
                init_fixture_repo(repo)
                git('config', 'user.name', 'entrypoint test')
                git('config', 'user.email', 'gate@example.test')
                git('add', '.')
                git('commit', '-qm', 'gate entrypoint fixture')
                git('remote', 'add', 'origin', str(repo))
                blueprints = repo / 'naapp/library/test-vectors/blueprints/team'
                self.assertEqual(subprocess.check_output(
                    ['git', '-C', str(blueprints), 'rev-parse', '--show-toplevel'], text=True, env=fixture_env()).strip(),
                    str(repo.resolve()))
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
                real_id = shutil.which('id')
                (commands / 'id').write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> "$ID_LOOKUP_RECEIPT"
if [ "$*" = -un ]; then
 printf '501\\n'
 printf 'id: cannot find name for user ID 501\\n' >&2
 exit 1
fi
if [ "$*" = -u ]; then
 printf '501\\n'
 exit 0
fi
exec {real_id} "$@"
''')
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
                env = {k: v for k,v in os.environ.items() if not k.startswith(
                    ('AWEB_', 'CANDIDATE_', 'GATE_', 'LIBRARY_E2E_', 'USER_PATHS_'))}
                (root / 'home').mkdir()
                env.pop('OATS_INSTANCE', None)
                env.update(PATH=f'{commands}:{env["PATH"]}', AWEB_GATE_LEDGER=str(root / 'ledger.tsv'),
                           AWEB_GATE_PROFILE='lane', AWEB_GATE_LOG_DIR=str(root / 'logs'), CLI_VERSION='1.36.54', A2A_GATEWAY_VERSION='1.27.6',
                           HOME=str(root / 'home'), SNAPSHOT_RECEIPT=str(root / 'snapshot.json'),
                           ID_LOOKUP_RECEIPT=str(root / 'id-lookups'))
                def invoke(stages):
                    settings = dict(env)
                    if stages is not None:
                        settings['AWEB_CANDIDATE_STAGES'] = stages
                    result = run_fixture(['bash','scripts/candidate-docker-gate.sh'], cwd=repo,
                        env=settings, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    return result.stdout
                def ledger_rows():
                    rows = (root / 'ledger.tsv').read_text().splitlines()
                    self.assertTrue(all(len(row.split('\t')) == 10 for row in rows), rows)
                    self.assertEqual({row.split('\t')[6] for row in rows}, {'501'})
                    return rows
                try:
                    invoke('checks')
                    self.assertEqual(len(ledger_rows()), 1)
                    self.assertEqual((root / 'id-lookups').read_text().splitlines()[:2], ['-un', '-u'])
                    self.assertTrue(list((repo / 'scripts/__pycache__').glob('fetch_released_aw.*.pyc')))
                    self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), '')
                    invoke(None)
                    ledger = ledger_rows()
                    self.assertEqual(len(ledger), 5, ledger)
                    self.assertEqual(len({row.split('\t')[0] for row in ledger}), 1)
                    receipt = json.loads((root / 'snapshot.json').read_text())
                    # The frozen input names its source: a registry gitHead here.
                    expected = (json.dumps(dict(metadata, source='gitHead'), sort_keys=True) + '\n').encode()
                    digest = hashlib.sha256(expected).hexdigest()
                    self.assertEqual(receipt['body'].encode(), expected)
                    self.assertEqual(receipt['digest'], digest)
                    self.assertEqual(receipt['declared'], digest)
                    tree = git('rev-parse', 'HEAD^{tree}')
                    external = f'CLI_VERSION=1.36.54\nA2A_GATEWAY_VERSION=1.27.6\nRELEASED_AW={digest}\nAWEB_GATE_PROFILE=lane\n'
                    self.assertEqual(ledger[0].split('\t')[0], tree+'-'+hashlib.sha256(external.encode()).hexdigest())
                    reused = invoke(None)
                    self.assertIn('no stages run', reused)
                    self.assertEqual(reused.count('NOT COVERED: pending aweb-actu'), 12)
                    self.assertIn('incomplete: human paths not covered', reused)
                    self.assertEqual(len(ledger_rows()), 5)
                    # Changing only the frozen artifact invalidates the key.
                    metadata['version'] = '1.36.55'
                    invoke('checks')
                    changed = ledger_rows()
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
        import sys
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'user_paths_result': result_model}):
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
                    sent=(dict(message_id=mid,session_id=cid) if turn == 0 else
                          dict(message_id=mid,delivered=True,extends_wait_seconds=0))
                records.append(dict(event=event,inbox=inbox,history=history,sent=sent))
            if mutate:
                mutate(records)
            current = -1
            def command(actor, *args, **kwargs):
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

    def test_chat_create_requires_its_own_message_and_session_ids(self):
        for field in ['message_id', 'session_id']:
            with self.subTest(field=field):
                with self.assertRaises(KeyError):
                    self.exercise('chat', False, lambda records: records[0]['sent'].pop(field))

    def test_continuation_checks_any_returned_thread(self):
        for field in ['session_id', 'conversation_id']:
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    self.exercise('chat', False, lambda records: records[1]['sent'].update({field:'wrong-thread'}))

    def test_failed_case_keeps_exact_initial_reply_and_continuation_output(self):
        import io
        import json
        import sys
        from contextlib import redirect_stdout
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'user_paths_result': result_model}):
            spec.loader.exec_module(paths)
        with tempfile.TemporaryDirectory() as directory:
            lane = paths.Lane.__new__(paths.Lane)
            lane.name, lane.version, lane.root = 'head', None, Path(directory)
            lane.binary, lane.environment = '/fixture/aw', {}
            lane.results, lane.failures, lane.outcomes = [], [], []
            lane.actors = {actor: dict(home=Path(directory), address='') for actor in ['g1','g2']}
            outputs = ['{"session_id":"thread","message_id":"first"}\n',
                       '{"message_id":"reply","delivered":true}\n',
                       '{"message_id":"last","delivered":true}\n']
            results = [subprocess.CompletedProcess([], 0, value, 'stderr-'+str(i)) for i,value in enumerate(outputs)]
            def operation():
                for phase in ['initial-send','reply','continuation']:
                    lane.command('g1', 'chat', 'send-and-wait' if phase=='initial-send' else 'send', phase=phase)
                raise AssertionError('post-send assertion')
            with redirect_stdout(io.StringIO()), patch.object(paths.subprocess, 'run', side_effect=results):
                lane.run_case('head/capture', operation)
            captured = json.loads((Path(directory)/'failure-head_capture/commands.json').read_text())
            self.assertEqual([row['stdout'] for row in captured], outputs)
            self.assertEqual([row['stderr'] for row in captured], ['stderr-0','stderr-1','stderr-2'])
            self.assertEqual([row['phase'] for row in captured], ['initial-send','reply','continuation'])
            self.assertEqual([row['exit'] for row in captured], [0,0,0])
            self.assertEqual(lane.outcomes[0]['status'], 'FAILED')

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



class ReleasedKnownIssueBudget(unittest.TestCase):
    def setUp(self):
        # Exercise the unchanged guard using test-only rules, independently of
        # the now-empty production budget. These are not admission exceptions.
        from unittest.mock import patch
        rules = []
        for case in ['released/t1->t2/chat/v2', 'released/t2->t1/chat/v2']:
            failure = known_failure(case)
            rules.append(dict(case=case, task='fixture-issue', minimum_version='1.36.53',
                              maximum_version='1.36.54', actor=failure['actor'],
                              target=failure['args'][2], exit=failure['exit'], code='error',
                              message=failure['response']['error']['message']))
        guard = patch.object(result_model, 'KNOWN_RELEASED_ISSUES', rules)
        guard.start()
        self.addCleanup(guard.stop)

    def test_successful_budgeted_flow_reports_only_failure_after_classification(self):
        import io
        import sys
        from contextlib import redirect_stdout
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'user_paths_result': result_model}):
            spec.loader.exec_module(paths)
        for name, expected in [('released', 'FAILED'), ('head', 'PASSED')]:
            lane = paths.Lane.__new__(paths.Lane)
            lane.name, lane.version = name, '1.36.53'
            lane.results, lane.outcomes, lane.failures = [], [], []
            lane.actors = {actor: dict(address='') for actor in ['t1','t2']}
            sent = iter([dict(message_id='message-'+str(turn), session_id='same-session') for turn in range(3)])
            lane.command = lambda *args, **kwargs: next(sent)
            deliveries = []
            lane.assert_message = lambda *args: deliveries.append(args)
            case = name+'/t1->t2/chat/v2'
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                lane.run_case(case, lambda: lane.flow('t1','t2','chat',True))
            self.assertEqual(len(deliveries), 3)
            self.assertEqual(lane.outcomes[0]['status'], expected)
            if name == 'released':
                self.assertNotIn('PASS '+case, stdout.getvalue())
                self.assertIn('FAIL '+case, stdout.getvalue())
                self.assertEqual(len(lane.failures), 1)
            else:
                self.assertEqual(stdout.getvalue(), 'PASS '+case+'\n')

    def test_real_lane_command_failure_is_classified_without_a_head_exception(self):
        import io
        import json
        import sys
        from contextlib import redirect_stdout
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('user_paths', ROOT / 'scripts/e2e/user_paths.py')
        paths = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'user_paths_result': result_model}):
            spec.loader.exec_module(paths)
        with tempfile.TemporaryDirectory() as directory:
            for name, expected in [('released', 'KNOWN_ISSUE'), ('head', 'FAILED')]:
                lane = paths.Lane.__new__(paths.Lane)
                lane.name, lane.version, lane.binary, lane.environment = name, '1.36.53', '/fixture/aw', {}
                lane.root = Path(directory)
                lane.results, lane.outcomes, lane.failures = [], [], []
                lane.actors = {actor: dict(address='', home=Path(directory)) for actor in ['t1','t2']}
                case = name+'/t1->t2/chat/v2'
                failure = known_failure(case)
                response = subprocess.CompletedProcess([], 1, json.dumps(failure['response'])+'\n', failure['stderr'])
                stdout = io.StringIO()
                with redirect_stdout(stdout), patch.object(paths.subprocess, 'run', return_value=response):
                    lane.run_case(case, lambda: lane.flow('t1','t2','chat',True))
                self.assertEqual(lane.outcomes[0]['status'], expected)
                self.assertEqual(len(lane.failures), 0 if name=='released' else 1)
                if name=='released':
                    self.assertTrue(stdout.getvalue().startswith('KNOWN ISSUE '+case+' fixture-issue observed failure:'))
                    self.assertNotIn('FAIL ', stdout.getvalue())
                    self.assertEqual(lane.outcomes[0]['failure']['response'], failure['response'])
                    unexpected = io.StringIO()
                    with redirect_stdout(unexpected):
                        lane.run_case(case, lambda: None)
                    self.assertEqual(unexpected.getvalue(), 'FAIL '+case+' declared known issue passed unexpectedly or failed differently\n')
                    self.assertEqual(lane.outcomes[-1]['status'], 'FAILED')
                    self.assertEqual(len(lane.failures), 1)
                else:
                    self.assertTrue(stdout.getvalue().startswith('FAIL '+case+' '))
                self.assertNotIn('PASS ', stdout.getvalue())

    def test_exact_measured_failures_only_on_each_released_cell(self):
        self.assertEqual(len(result_model.KNOWN_RELEASED_ISSUES), 2)
        for case in ['released/t1->t2/chat/v2', 'released/t2->t1/chat/v2']:
            for version in ['1.36.53', '1.36.54']:
                row = dict(case=case, status='FAILED', failure=known_failure(case))
                classified = result_model.classify_outcome(row, version)
                self.assertEqual(classified['status'], 'KNOWN_ISSUE')
                self.assertEqual(classified['known_issue']['task'], 'fixture-issue')
                self.assertEqual(classified['observed_status'], 'FAILED')
                # Reclassification at the parent boundary preserves the same verdict.
                self.assertEqual(result_model.classify_outcome(classified, version), classified)

    def test_unexpected_success_wrong_failure_phase_version_or_lane_is_red(self):
        import copy
        case = 'released/t1->t2/chat/v2'
        row = dict(case=case, status='FAILED', failure=known_failure(case))
        variants = [('unexpected pass', dict(case=case,status='PASSED'))]
        for field,value in [('exit',2), ('stderr','different failure'), ('actor','t2'),
                            ('args',['chat','send','--session-id','existing','--e2ee'])]:
            changed=copy.deepcopy(row);changed['failure'][field]=value;variants.append((field,changed))
        for field,value in [('message','different key error'),('code','permission_denied'),('reason','new_reason')]:
            changed=copy.deepcopy(row);changed['failure']['response']['error'][field]=value;variants.append((field,changed))
        for name,changed in variants:
            with self.subTest(change=name):
                self.assertEqual(result_model.classify_outcome(changed,'1.36.53')['status'],'FAILED')
        for version in ['1.36.52','1.36.55','dev','1.36.54-rc.1',None]:
            with self.subTest(version=version):
                self.assertEqual(result_model.classify_outcome(row,version)['status'],'FAILED')
                self.assertEqual(result_model.classify_outcome(dict(case=case,status='PASSED'),version)['status'],'FAILED')
        for other in ['head/t1->t2/chat/v2','released/g1->t1/chat/v2','released/t1->t2/mail/v2']:
            changed=copy.deepcopy(row);changed['case']=other
            self.assertEqual(result_model.classify_outcome(changed,'1.36.53')['status'],'FAILED')


if __name__ == '__main__':
    unittest.main()
