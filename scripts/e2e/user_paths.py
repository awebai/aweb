"""Ordinary CLI user paths, run inside the owned DNS-configured client.

No SQL, credential fabrication, private service calls, or HTTP substitutes.
AW_BIN is the same exact-binary hook used by cli/scripts/e2e.sh.
"""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import time
import uuid
from user_paths_result import classify_outcome, HUMAN_STATUS, COVERAGE_SUMMARY

ROOT = Path('/work')
REGISTRY = 'http://awid:8010'
PAIRS = [('g1', 'g2'), ('g2', 'g1'), ('t1', 't2'), ('t2', 't1'), ('t1', 'g1'), ('g1', 't1')]


class CLICommandError(AssertionError):
    def __init__(self, lane, actor, args, result):
        try:
            response = json.loads(result.stdout)
        except ValueError:
            response = None
        self.failure = dict(actor=actor, args=list(args), exit=result.returncode,
                            response=response, stderr=result.stderr)
        super().__init__(f'{lane}/{actor} aw {args}: {result.returncode}\n{result.stdout}\n{result.stderr}')


def rows(value):
    if isinstance(value, list):
        return value
    return value.get('messages', value.get('history', value.get('pending', [])))


def sent_identity(sent, kind, conversation=None):
    """Use the send result as the expected identity, never the delivered DTO."""
    message_id = sent['message_id']
    thread = sent['conversation_id' if kind == 'mail' else 'session_id']
    assert isinstance(message_id, str) and message_id, sent
    assert isinstance(thread, str) and thread, sent
    assert conversation is None or thread == conversation, ('send result thread', conversation, sent)
    return message_id, thread


class Lane:
    def __init__(self, name, binary):
        self.name, self.binary = name, binary
        self.root = ROOT / name
        self.root.mkdir()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.actors = {}
        self.receivers = []
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith(('AW_', 'AWEB_', 'AWID_', 'OATS_'))}
        self.environment.update(HOME=str(self.home), AW_NO_UPDATE_CHECK='1', AWID_REGISTRY_URL=REGISTRY, NO_COLOR='1', APP_ENV='development', AWEB_FEDERATION_TEST='1')
        self.results = []
        self.failures = []
        self.outcomes = []
        version_output = subprocess.run([self.binary, 'version'], capture_output=True, text=True, check=True, timeout=10).stdout
        match = re.search(r'^aw (\d+)\.(\d+)\.(\d+)\s*$', version_output, re.M)
        self.version = '.'.join(match.groups()) if match else None
        self.legacy_released_diagnostics = self.name == 'released' and match is not None and tuple(map(int, match.groups())) <= (1, 36, 54)
        (self.root / 'version.txt').write_text(version_output)

    def capture_failure(self, case, sender, receiver, kind, encrypted):
        """Retain public bindings, never private identity files, on a failed path."""
        directory = self.root / ('failure-' + case.replace('/', '_').replace('->', '-'))
        directory.mkdir(exist_ok=True)
        commands = [('roster', sender, ['id', 'request', 'GET', 'http://server:8000/v1/agents', '--team-auth', '--raw']),
                    ('sessions', sender, ['id', 'request', 'GET', 'http://server:8000/v1/chat/sessions', '--team-auth', '--raw'])]
        for name in (sender, receiver):
            commands.extend([(name + '-whoami', name, ['whoami']),
                             (name + '-identity', name, ['id', 'show']),
                             (name + '-encryption-key', name, ['id', 'encryption-key', 'show'])])
        for label, actor, args in commands:
            result = self.command(actor, *args, check=False)
            (directory / (label + '.json')).write_text(json.dumps(dict(exit=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2))
        # A separately pinned published client is an author diagnostic only;
        # it never substitutes for npm latest in the standing released lane.
        comparison = os.environ.get('USER_PATHS_COMPARISON_BIN')
        if comparison and kind == 'chat' and encrypted:
            original = self.binary
            try:
                self.binary = comparison
                result = self.command(sender, 'chat', 'send-and-wait', self.actors[receiver]['address'] or receiver,
                                      case + '/published-comparison/' + uuid.uuid4().hex, '--e2ee', '--wait', '0', check=False)
                (directory / 'published-comparison.json').write_text(json.dumps(dict(exit=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2))
            finally:
                self.binary = original

    def run_case(self, case, operation, diagnostic=None):
        started = time.monotonic()
        try:
            operation()
        except Exception as error:
            record = dict(case=case, status='FAILED', error=str(error))
            if isinstance(error, CLICommandError):
                record['failure'] = error.failure
            if diagnostic:
                try:
                    self.capture_failure(case, *diagnostic)
                except Exception as capture_error:
                    record['diagnostic_error'] = str(capture_error)
            # Let real presentation callbacks finish even after an assertion
            # fails, so one red case cannot prevent later cases being attempted.
            for actor in self.actors.values():
                events = actor.get('events')
                if events and events.exists():
                    for line in events.read_text().splitlines():
                        event = json.loads(line)
                        if event.get('type') == 'awakening':
                            Path(str(events) + '.release-' + event['meta']['message_id']).touch()
        else:
            record = dict(case=case, status='PASSED')
        record = classify_outcome(record, self.version)
        if record['status'] == 'FAILED':
            self.failures.append(record)
            print('FAIL', case, record.get('budget_error', record.get('error')), flush=True)
        elif record['status'] == 'KNOWN_ISSUE':
            print('KNOWN ISSUE', case, record['known_issue']['task'], 'observed failure:', record['failure']['response'], flush=True)
        record['seconds'] = round(time.monotonic() - started, 3)
        self.outcomes.append(record)

    def command(self, actor, *args, check=True, wait=True):
        work = self.actors[actor]['home']
        cmd = [self.binary, '--json', *args]
        if not wait:
            return subprocess.Popen(cmd, cwd=work, env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result = subprocess.run(cmd, cwd=work, env=self.environment, capture_output=True, text=True, timeout=25)
        if check and result.returncode:
            raise CLICommandError(self.name, actor, args, result)
        if not check:
            return result
        return json.loads(result.stdout)

    def actor(self, name, domain, server='http://server:8000'):
        path = self.root / name
        path.mkdir()
        self.actors[name] = dict(home=path, domain=domain, server=server)

    def provision(self):
        for name in ['g1', 'g2', 'remote', 'nonresident']:
            self.actor(name, f'{self.name}-{name}.test', 'http://peer:8000' if name == 'remote' else 'http://server:8000')
            domain = self.actors[name]['domain']
            controller = self.command(name, 'id', 'namespace', 'prepare-controller', '--domain', domain, '--registry', REGISTRY)
            zone = ROOT / 'dns/test.zone'
            text = zone.read_text()
            import re
            text = re.sub(r'\((\d+) 1 1 1 1\)', lambda match: f'({int(match[1])+1} 1 1 1 1)', text)
            zone.write_text(text + f'_awid.{domain}. 1 IN TXT "{controller["dns_value"]}"\n')
        # DNS readiness, not a retry of a failed identity creation.
        for name in ['g1', 'g2', 'remote', 'nonresident']:
            actor = self.actors[name]
            deadline = time.monotonic() + 15
            while True:
                checked = self.command(name, 'id', 'namespace', 'check-txt', '--domain', actor['domain'], check=False)
                if checked.returncode == 0:
                    break
                assert time.monotonic() < deadline, checked.stderr
                time.sleep(.1)
            self.command(name, 'id', 'create', '--domain', actor['domain'], '--name', name, '--registry', REGISTRY, '--root-parent')
            actor['address'] = actor['domain'] + '/' + name
            if name == 'nonresident':
                self.command(name, 'id', 'namespace', 'set-delivery-origin', '--namespace', actor['domain'], '--origin', actor['server'])
                continue
            self.command(name, 'id', 'team', 'create', '--namespace', actor['domain'], '--name', 'members', '--registry', REGISTRY)
            invite = self.command(name, 'id', 'team', 'invite', '--namespace', actor['domain'], '--team', 'members', '--member-global')
            self.command(name, 'id', 'team', 'accept-invite', invite['token'], '--name', name, '--global')
            self.command(name, 'init', '--url', actor['server'], '--name', name, '--do-not-touch-agents-md')
            self.command(name, 'id', 'namespace', 'set-delivery-origin', '--namespace', actor['domain'], '--origin', actor['server'])
            actor['address'] = actor['domain'] + '/' + name
        for name in ['t1', 't2']:
            domain = self.actors['g1']['domain']
            self.actor(name, domain)
            invite = self.command('g1', 'id', 'team', 'invite', '--namespace', domain, '--team', 'members')
            self.command(name, 'id', 'team', 'accept-invite', invite['token'], '--name', name)
            self.command(name, 'init', '--url', 'http://server:8000', '--name', name, '--do-not-touch-agents-md')
            self.actors[name]['address'] = ''
        for name in self.actors:
            if name == 'nonresident':
                continue
            self.command(name, 'id', 'encryption-key', 'setup')
            actor = self.actors[name]
            actor['did'] = self.command(name, 'id', 'show')['did_key']
            actor['events'] = self.root / (name + '-events.jsonl')
            log = (self.root / (name + '-channel.log')).open('w')
            proc = subprocess.Popen(['node', '/work/user_paths_receive.mjs', str(actor['home']), str(actor['events']), self.binary],
                                    cwd=actor['home'], env=self.environment, stdout=log, stderr=log)
            self.receivers.append((proc, log))
        for name in self.actors:
            if name == 'nonresident':
                continue
            self.wait_event(name, lambda event: event.get('type') == 'stream' and event.get('state') == 'connected')

    def refused(self, sender, receiver, kind, status, message_text, reason=None):
        body = f'{self.name}/refusal/{reason or status}/' + uuid.uuid4().hex
        target = self.actors[receiver]['address']
        if kind == 'mail':
            args = ['mail', 'send', '--to-address', target, '--subject', reason or str(status), '--body', body]
        else:
            args = ['chat', 'send-and-leave', target, body]
        result = self.command(sender, *args, check=False)
        text = result.stdout + result.stderr
        assert result.returncode != 0, ('expected refusal', args, result.stdout)
        error = json.loads(result.stdout)['error']
        (self.root / f'refusal-{receiver}-{kind}.json').write_text(json.dumps(dict(exit=result.returncode, response=error, stderr=result.stderr), indent=2))
        assert error.get('http_status') == status and message_text in text, (status, message_text, text)
        if reason:
            assert reason in text, (reason, text)
        assert not any(error in text.lower() for error in ['connection refused', 'no such host', 'timeout', 'timed out']), text
        # Independent public read and real channel sink must both have no effect.
        if receiver != 'nonresident':
            read = self.command(receiver, 'mail', 'inbox', '--show-all') if kind == 'mail' else self.command(receiver, 'chat', 'pending')
            assert body not in json.dumps(read), read
            assert body not in self.actors[receiver]['events'].read_text()
        self.results.append(f'{self.name}/refusal/{reason or status}/{kind}')

    def same_team_policy(self):
        self.command('g1', 'inbound-mode', 'team-and-contacts')
        try:
            self.flow('t1', 'g1', 'mail', False)
        finally:
            self.command('g1', 'inbound-mode', 'open')
    def contacts_only(self, kind):
        self.command('g2', 'inbound-mode', 'contacts-only')
        try:
            self.refused('t1', 'g2', kind, 403, 'Recipient only accepts messages from exact active contacts')
        finally:
            self.command('g2', 'inbound-mode', 'open')

    def controls(self):
        self.run_case(self.name + '/same-team/team-and-contacts', self.same_team_policy)
        for kind in ['mail', 'chat']:
            self.run_case(self.name + '/contacts-only/' + kind, lambda: self.contacts_only(kind))
            if self.legacy_released_diagnostics:
                # These released clients refuse during their public target
                # preflight; they do not expose the newer server reason/404.
                self.run_case(self.name + '/nonresident/' + kind, lambda: self.refused('g1', 'nonresident', kind,
                    None, self.actors['nonresident']['address'] + ' is not a member of your team or a registered address. Check the name with `aw workspace status`.'))
            else:
                self.run_case(self.name + '/nonresident/' + kind, lambda: self.refused('g1', 'nonresident', kind,
                    404, 'The recipient is not set up for messaging', 'recipient_identity_not_found'))
            # The peer is a real connected global identity on a live second OSS
            # server; this local sender has no published team-server authority.
            # An outage or invalid certificate cannot satisfy this refusal.
            if self.legacy_released_diagnostics:
                self.run_case(self.name + '/cross-server/' + kind, lambda: self.refused('t1', 'remote', kind,
                    422, "This message is missing this agent's team certificate.", 'local_sender_certificate_required'))
            else:
                self.run_case(self.name + '/cross-server/' + kind, lambda: self.refused('t1', 'remote', kind,
                    424, "This team's published messaging server could not be verified", 'local_sender_team_server_missing'))
        self.run_case(self.name + '/waiting-chat', self.waiting_chat)
        self.run_case(self.name + '/fresh-chat/plain-v2-plain', self.fresh_chat_modes)

    def waiting_chat(self):
        body = self.name + '/real-wait/' + uuid.uuid4().hex
        waiting = self.command('g1', 'chat', 'send-and-wait', self.actors['g2']['address'], body,
                               '--plaintext', '--wait', '15', wait=False)
        try:
            event = self.delivered('g2', body)
            conversation = event['meta'].get('session_id', event['meta'].get('conversation_id'))
            assert conversation, event
            self.assert_message('g2', 'g1', 'chat', body, conversation, event['meta']['message_id'], False)
            reply = body + '/reply'
            sent_reply = self.command('g2', 'chat', 'send', '--session-id', conversation, '--plaintext', '--body', reply)
            reply_id, _ = sent_identity(sent_reply, 'chat', conversation)
            stdout, stderr = waiting.communicate(timeout=20)
            assert waiting.returncode == 0, (stdout, stderr)
            result = json.loads(stdout)
            sent_id, _ = sent_identity(result, 'chat', conversation)
            assert sent_id == event['meta']['message_id'], result
            assert result['status'] == 'replied' and result['reply'] == reply, result
            events = [row for row in result['events'] if row.get('body') == reply]
            assert len(events) == 1 and events[0]['verification_status'] == 'verified', result
            assert events[0]['message_id'] == reply_id, result
        finally:
            if waiting.poll() is None:
                waiting.terminate()
                waiting.communicate(timeout=5)

    def fresh_chat_modes(self):
        sessions = []
        for mode in ['--plaintext', '--e2ee', '--plaintext']:
            body = self.name + '/fresh-order/' + mode + '/' + uuid.uuid4().hex
            sent = self.command('g1', 'chat', 'send-and-wait', self.actors['g2']['address'], body,
                                mode, '--start-conversation', '--wait', '0')
            message_id, conversation = sent_identity(sent, 'chat')
            assert sent['session_id'] not in sessions, sent
            sessions.append(sent['session_id'])
            self.assert_message('g2', 'g1', 'chat', body, conversation, message_id, mode == '--e2ee')

    def wait_event(self, name, predicate):
        path = self.actors[name]['events']
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if path.exists():
                for line in path.read_text().splitlines():
                    event = json.loads(line)
                    if predicate(event):
                        return event
            for proc, _ in self.receivers:
                assert proc.poll() is None, 'real channel-core exited; see channel log'
            time.sleep(.02)
        raise AssertionError(f'no matching real channel delivery for {name}: {path.read_text() if path.exists() else "no events"}')

    def delivered(self, receiver, body):
        event = self.wait_event(receiver, lambda event: event.get('type') == 'awakening' and body in event.get('content', ''))
        assert event['meta']['verified'] is True or event['meta']['verified'] == 'true', event
        assert event['meta']['trust_status'] == 'verified', event
        return event

    def assert_message(self, receiver, sender, kind, body, conversation, message_id, encrypted):
        # Wake proof is complete BEFORE any list/read/ack operation.
        event = self.delivered(receiver, body)
        assert event['kind'] == kind, event
        assert event['meta']['message_id'] == message_id, ('channel message', message_id, event)
        assert event['meta']['conversation_id'] == conversation, ('channel thread', conversation, event)
        if kind == 'chat':
            assert event['meta']['session_id'] == conversation, ('channel session', conversation, event)
        if kind == 'mail':
            inbox = self.command(receiver, 'mail', 'inbox', '--show-all')
            history = self.command(receiver, 'mail', 'show', '--conversation-id', conversation)
        else:
            inbox = self.command(receiver, 'chat', 'pending')
            history = self.command(receiver, 'chat', 'history', '--session-id', conversation)
            assert history['session_id'] == conversation, ('history session', conversation, history)
        expected = self.actors[sender]['address']
        for label, result in [('inbox/pending', inbox), ('history', history)]:
            matches = [r for r in rows(result) if r.get('body', r.get('last_message')) == body]
            assert len(matches) == 1, (label, body, result)
            message = matches[0]
            if kind == 'chat' and label == 'inbox/pending':
                # Pending exposes a session summary, not a message ID or mode.
                assert message['session_id'] == conversation, (label, conversation, message)
            else:
                assert message['message_id'] == message_id, (label, message_id, message)
                assert message['content_mode'] == ('encrypted_v2' if encrypted else 'legacy_plaintext_v1'), (label, encrypted, message)
                if kind == 'mail' or 'conversation_id' in message:
                    assert message['conversation_id'] == conversation, (label, conversation, message)
                if 'encrypted_envelope' in message and message['encrypted_envelope']:
                    proof = message['encrypted_envelope']
                elif message.get('signed_payload'):
                    proof = json.loads(message['signed_payload'])
                else:
                    proof = None
                if proof:
                    assert proof['message_id'] == message_id, (label, 'signed message', proof)
                    assert proof['conversation_id'] == conversation, (label, 'signed thread', proof)
            if kind == 'mail' or label == 'history':
                assert message['verification_status'] == 'verified', (label, message)
            address = message.get('from_address', message.get('last_from_address', ''))
            if expected:
                assert address == expected, (label, expected, address)
            else:
                # Released local labels are team-scoped; they are not global addresses.
                assert address in (None, '', self.actors[sender]['domain'] + '/' + sender, 'members:' + self.actors[sender]['domain'] + '/' + sender), (label, address)
                assert message.get('from_did', message.get('last_from_did')) == self.actors[sender]['did'], (label, message)
            saved = self.root / 'reads'
            saved.mkdir(exist_ok=True)
            (saved / (event['meta']['message_id'] + '-' + label.replace('/', '-') + '.json')).write_text(json.dumps(result, indent=2))
        Path(str(self.actors[receiver]['events']) + '.release-' + event['meta']['message_id']).touch()
        return event

    def flow(self, sender, receiver, kind, encrypted):
        case = f'{self.name}/{sender}->{receiver}/{kind}/{"v2" if encrypted else "plain"}'
        mode = '--e2ee' if encrypted else '--plaintext'
        body = case + '/' + uuid.uuid4().hex
        target = self.actors[receiver]['address'] or receiver
        if kind == 'mail':
            target_flag = '--to-address' if self.actors[receiver]['address'] else '--to'
            sent = self.command(sender, 'mail', 'send', mode, target_flag, target, '--subject', case, '--body', body)
        else:
            # Explicit zero wait leaves presentation to the channel on all three
            # turns. A concurrently waiting CLI would legitimately read the
            # reply before channel-core's unread reader. The real-wait control
            # below exercises that different, ordinary consumer path separately.
            sent = self.command(sender, 'chat', 'send-and-wait', target, body, mode, '--wait', '0')
        first_id, conversation = sent_identity(sent, kind)
        self.assert_message(receiver, sender, kind, body, conversation, first_id, encrypted)
        reply_body = body + '/reply'
        if kind == 'mail':
            reply = self.command(receiver, 'mail', 'reply', first_id, mode, '--body', reply_body)
        else:
            reply = self.command(receiver, 'chat', 'send', '--session-id', conversation, mode, '--body', reply_body)
        reply_id, _ = sent_identity(reply, kind, conversation)
        self.assert_message(sender, receiver, kind, reply_body, conversation, reply_id, encrypted)
        continuation = body + '/continuation'
        if kind == 'mail':
            continued = self.command(sender, 'mail', 'reply', reply_id, mode, '--body', continuation)
        else:
            continued = self.command(sender, 'chat', 'send', '--session-id', conversation, mode, '--body', continuation)
        continuation_id, _ = sent_identity(continued, kind, conversation)
        self.assert_message(receiver, sender, kind, continuation, conversation, continuation_id, encrypted)
        self.results.append(case)
        print('PASS', case, flush=True)

    def close(self):
        for proc, _ in self.receivers:
            proc.terminate()
        for proc, log in self.receivers:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--lane', required=True)
    parser.add_argument('--baseline-chat-only', action='store_true', help='author historical comparison, never a standing-stage PASS')
    parser.add_argument('--local-chat-direction', choices=['forward', 'reverse'], help='author actw component proof on fresh actors')
    args = parser.parse_args()
    lane = Lane(args.lane, os.environ['AW_BIN'])
    start = time.monotonic()
    try:
        lane.provision()
        provisioned = time.monotonic()
        if args.baseline_chat_only:
            lane.run_case(lane.name + '/fresh-chat/plain-v2-plain', lane.fresh_chat_modes)
        elif args.local_chat_direction:
            sender, receiver = ('t1', 't2') if args.local_chat_direction == 'forward' else ('t2', 't1')
            for encrypted in [False, True]:
                case = f'{lane.name}/{sender}->{receiver}/chat/{"v2" if encrypted else "plain"}'
                lane.run_case(case, lambda: lane.flow(sender, receiver, 'chat', encrypted), (sender, receiver, 'chat', encrypted))
        else:
            for sender, receiver in PAIRS:
                for kind in ['mail', 'chat']:
                    for encrypted in [False, True]:
                        case = f'{lane.name}/{sender}->{receiver}/{kind}/{"v2" if encrypted else "plain"}'
                        lane.run_case(case, lambda: lane.flow(sender, receiver, kind, encrypted), (sender, receiver, kind, encrypted))
            lane.controls()
    finally:
        lane.close()
        (lane.root / 'results.json').write_text(json.dumps(dict(version=lane.version, cases=lane.results, outcomes=lane.outcomes,
            required_human_coverage=HUMAN_STATUS, coverage_summary=COVERAGE_SUMMARY, elapsed=time.monotonic()-start), indent=2))
    if lane.failures:
        raise SystemExit(1)
