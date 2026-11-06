"""Public-CLI provisioning and exact encrypted reads for custody_bulk.py."""
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from custody_bulk_relay import UnixRelay

ROOT = Path('/work')
HOME = Path('/identities')
AW = '/work/aw'
PROVISION_AW = '/work/provision-aw'
RESULTS = []
ENV = {k: v for k, v in os.environ.items() if not k.startswith(('AW_', 'AWEB_', 'AWID_', 'OATS_'))}
ENV.update(HOME=str(HOME / 'home'), AW_NO_UPDATE_CHECK='1', APP_ENV='development',
           AWEB_FEDERATION_TEST='1', AWID_REGISTRY_URL='http://awid:8010', NO_COLOR='1')


def control(case, **mode):
    temporary = ROOT / 'control.tmp'
    temporary.write_text(json.dumps(dict(case=case, **mode)))
    temporary.replace(ROOT / 'control.json')


def command(actor, *args, binary=AW, timeout=90, budget=None):
    env = dict(ENV)
    if actor == 'seat':
        env['AWEB_IDENTITY_HOME'] = str(HOME / actor / '.aw')
    if budget:
        env['AWEB_HTTP_TIMEOUT'] = budget
    return subprocess.run([binary, '--json', *args], cwd=HOME / actor, env=env,
                          text=True, capture_output=True, timeout=timeout)


def cli(actor, *args, binary=PROVISION_AW):
    result = command(actor, *args, binary=binary)
    assert result.returncode == 0, (actor, args[:3], result.stdout, result.stderr)
    return json.loads(result.stdout)


def provision():
    (HOME / 'home').mkdir(mode=0o700)
    for actor in ('sender', 'resident'):
        (HOME / actor).mkdir(mode=0o700)
        domain = f'custody-bulk-{actor}.test'
        # Initial creation has no identity home yet; the CLI selects that fresh path.
        prepared = cli(actor, 'id', 'namespace', 'prepare-controller', '--domain', domain)
        zone = ROOT / 'dns/test.zone'
        text = re.sub(r'\((\d+) 1 1 1 1\)', lambda m: f'({int(m[1])+1} 1 1 1 1)', zone.read_text())
        zone.write_text(text + f'_awid.{domain}. 1 IN TXT "{prepared["dns_value"]}"\n')
    for actor in ('sender', 'resident'):
        domain = f'custody-bulk-{actor}.test'
        deadline = time.monotonic() + 15
        while command(actor, 'id', 'namespace', 'check-txt', '--domain', domain,
                      binary=PROVISION_AW).returncode:
            assert time.monotonic() < deadline, 'owned TXT did not become ready'
            time.sleep(.1)
        cli(actor, 'id', 'create', '--domain', domain, '--name', actor, '--root-parent')
        cli(actor, 'id', 'team', 'create', '--namespace', domain, '--name', 'members')
        invite = cli(actor, 'id', 'team', 'invite', '--namespace', domain, '--team', 'members', '--member-global')
        cli(actor, 'id', 'team', 'accept-invite', invite['token'], '--name', actor, '--global')
        cli(actor, 'init', '--url', 'http://front:8000', '--name', actor, '--do-not-touch-agents-md')
        cli(actor, 'id', 'namespace', 'set-delivery-origin', '--namespace', domain, '--origin', 'http://front:8000')
        cli(actor, 'id', 'encryption-key', 'setup')


def read(case, expected, *, actor='seat', budget=None, success=True, error='', attempts=None, message_id=None, **mode):
    control(case, **mode)
    started = time.monotonic()
    selection = ['--message-id', message_id] if message_id else ['--conversation-id', CONVERSATION, '--limit', '500']
    result = command(actor, 'mail', 'show', *selection, budget=budget)
    seconds = time.monotonic() - started
    (ROOT / (case + '.json')).write_text(json.dumps(dict(
        seconds=seconds, exit=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2))
    if success:
        assert result.returncode == 0, result.stderr
        wire = json.loads(result.stdout)
        messages = wire['messages']
        if message_id:
            expected = {message_id: expected[message_id]}
        assert len(messages) == len(expected)
        assert {m['message_id']: m['body'] for m in messages} == expected
        assert all(m['conversation_id'] == CONVERSATION and m['content_mode'] == 'encrypted_v2'
                   and m['verification_status'] == 'verified' for m in messages)
        if mode.get('rpc_delay') == .12:
            assert seconds > 30, 'long-read control did not exceed the former cumulative deadline'
        if budget:
            assert seconds > float(budget.removesuffix('s')), 'control did not outlive one request budget'
    else:
        assert result.returncode != 0 and error in result.stderr, result.stderr
        wire = json.loads(result.stdout)
        assert set(wire) == {'error'} and 'messages' not in wire  # No partial-success page.
        # A freshness stall also affects /status's independent readiness check;
        # count both bounded checks rather than imposing a new cumulative limit.
        maximum = 3 if budget else 13 if error in ('custody_unavailable', 'grant_freshness_unavailable') else 8
        assert seconds < maximum, (case, seconds)
    observed = [json.loads(line) for line in (ROOT / 'requests.jsonl').read_text().splitlines()]
    page_attempts = sum(r['case'] == case and r['phase'] == 'started'
                        and r['path'].startswith('/v1/messages/conversations/') for r in observed)
    if attempts is not None:
        assert page_attempts == attempts, (case, page_attempts)
    if mode.get('body_delay'):
        assert any(r['case'] == case and r['phase'] == 'headers' for r in observed)
        assert 'while reading body' in result.stderr
    if error in ('grant_freshness_unavailable', 'stored_message_unavailable'):
        required = {'/status', '/unwrap_e2ee_message'} if mode.get('freshness_delay') else {'/unwrap_e2ee_message'}
        deadline = time.monotonic() + 1
        while True:
            completed = [json.loads(line) for line in (ROOT / 'requests.jsonl').read_text().splitlines()]
            completed = [r for r in completed if r['case'] == case and r['phase'] == 'finished' and r['path'] in required]
            if {r['path'] for r in completed} == required:
                break
            assert time.monotonic() < deadline, 'custody completion records did not arrive'
            time.sleep(.01)
        assert all(4.5 < r['seconds'] < 5.8 for r in completed), completed
    RESULTS.append(dict(case=case, status='PASSED', seconds=round(seconds, 3), page_attempts=page_attempts))
    print(case, 'PASSED', round(seconds, 3), flush=True)


if __name__ == '__main__':
    control('provision')
    provision()
    for actor in ('sender', 'resident', 'seat'):
        if actor == 'seat':
            (HOME / actor).mkdir(mode=0o700)
    custody_log = (ROOT / 'custody.log').open('w')
    custody = subprocess.Popen([AW, '--identity-home', str(HOME / 'resident/.aw'), 'custody', 'serve'],
                               env=ENV, stdout=custody_log, stderr=custody_log)
    relay = None
    grant_id = None
    try:
        deadline = time.monotonic() + 15
        while True:
            status = command('resident', 'custody', 'status')
            if status.returncode == 0 and json.loads(status.stdout)['status'] == 'running':
                break
            assert time.monotonic() < deadline, status.stderr
            time.sleep(.1)
        path = '/identities/unwrap.sock'
        relay = UnixRelay(path, json.loads(status.stdout)['socket_path'])
        os.chmod(path, 0o600)
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        grant = cli('resident', 'id', 'grant', 'mint', '--bundle', 'normal-agent', '--ttl', '1h',
                    '--out', '/identities/seat/.aw', '--custody-socket', path, binary=AW)
        grant_id = grant['grant_id']
        assert command('seat', 'whoami').returncode == 0
        expected = {}
        first = cli('sender', 'mail', 'send', '--to-address', 'custody-bulk-resident.test/resident',
                    '--subject', 'Bulk custody regression', '--e2ee', '--body', 'body-000', binary=AW)
        CONVERSATION = first['conversation_id']
        expected[first['message_id']] = 'body-000'
        for index in range(1, 300):
            sent = cli('sender', 'mail', 'send', '--conversation-id', CONVERSATION, '--e2ee',
                       '--body', f'body-{index:03d}', binary=AW)
            assert sent['conversation_id'] == CONVERSATION
            expected[sent['message_id']] = f'body-{index:03d}'
        assert len(expected) == 300
        (ROOT / 'expected.json').write_text(json.dumps(dict(conversation_id=CONVERSATION, messages=expected), indent=2))
        cases = {
            'healthy': {},
            'single-message': dict(message_id=first['message_id']),
            'slow-unwrap': dict(rpc_delay=.12),
            'slow-page-and-unwrap': dict(page_delay=.7, rpc_delay=.012, budget='1s'),
            'local-key': dict(actor='resident'),
            'page-headers-stall': dict(page_delay=2, budget='200ms', success=False, error='deadline', attempts=1),
            'page-body-stall': dict(body_delay=2, budget='200ms', success=False, error='deadline', attempts=1),
            'page-connection-close': dict(page_close=True, success=False, error='EOF', attempts=4),
            'unwrap-stall': dict(rpc_delay=11, success=False, error='custody_unavailable'),
            'freshness-stall': dict(freshness_delay=6, success=False, error='grant_freshness_unavailable'),
            'stored-read-stall': dict(stored_delay=6, success=False, error='stored_message_unavailable'),
        }
        selected = os.environ.get('CUSTODY_BULK_CASES', '').split(',')
        failures = []
        for case, options in cases.items():
            if selected != [''] and case not in selected:
                continue
            try:
                read(case, expected, **options)
            except Exception as error:
                failures.append(dict(case=case, error=str(error)))
                print(case, 'FAILED', error, flush=True)
        (ROOT / 'results.json').write_text(json.dumps(dict(cases=RESULTS, failures=failures), indent=2))
        assert not failures, failures
    finally:
        control('cleanup')
        if grant_id:
            cli('resident', 'id', 'grant', 'revoke', grant_id, binary=AW)
        command('resident', 'custody', 'stop')
        custody.wait(timeout=10)
        custody_log.close()
        if relay:
            relay.shutdown()
            relay.server_close()
