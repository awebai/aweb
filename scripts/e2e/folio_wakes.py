#!/usr/bin/env python3
"""Real-stack acceptance. Requires folio-wakes.compose.yml up and AW_BIN built.
No mocked services: real CLI signatures, AWID certificates, Folio writes, aweb
registry/subscriptions/SSE and channel-core dispatch. Disposable identities only.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
AW = Path(os.environ['AW_BIN']).resolve()
REGISTRY = 'http://127.0.0.1:38010'
SERVER = 'http://127.0.0.1:38000'
FOLIO = 'http://127.0.0.1:38765'
COMPOSE = ['docker', 'compose', '-p', 'abrm-folio', '--project-directory', str(ROOT), '-f', str(ROOT / 'scripts/e2e/folio-wakes.compose.yml')]

def run(args, **kw):
    result = subprocess.run(args, text=True, capture_output=True, **kw)
    if result.returncode:
        raise AssertionError(f'{args[:4]} failed: {result.stderr}\n{result.stdout}')
    return result.stdout

def configure_manifest(version, events=True):
    # Configure the real Folio served file for this disposable deployment and
    # public test emitter. No substitute HTTP server or auth bypass.
    code = '''import json
from folio.aweb_manifest import MANIFEST_PATH, MANIFEST
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
m=json.loads(json.dumps(MANIFEST))
m['app']['origin']='http://127.0.0.1:38765'
m['app']['version']=VERSION
if not EVENTS: m['events']=[]
key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('01'*32))
m['event_emitters']=[{'kid':'folio:emit-test','did_key':did_from_public_key(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw))}]
MANIFEST_PATH.write_text(json.dumps(m))
'''.replace('VERSION', repr(version)).replace('EVENTS', repr(events))
    run(COMPOSE + ['exec', '-T', '-u', 'root', 'folio', '/app/.venv/bin/python', '-c', code])

with tempfile.TemporaryDirectory(prefix='awfw-', dir='/tmp') as td:
    root = Path(td).resolve()
    env = dict(os.environ, HOME=str(root / 'home'), AW_HOME=str(root / 'config'), AWEB_IDENTITY_HOME='', AWID_REGISTRY_URL=REGISTRY, AWID_SKIP_DNS_VERIFY='1', AW_NO_UPDATE_CHECK='1', NO_COLOR='1')
    (root / 'home').mkdir()
    namespace = 'wakes-' + uuid.uuid4().hex[:12] + '.test'
    team = 'dev:' + namespace
    homes = {}
    def aw(who, *args, check=True):
        result = subprocess.run([str(AW), *args], cwd=homes[who], env=env, text=True, capture_output=True)
        if check and result.returncode:
            raise AssertionError(f'aw {who} {args[:3]}: {result.stderr}\n{result.stdout}')
        return result
    def data(who, *args):
        return json.loads(aw(who, '--json', *args).stdout)
    def get(who, path):
        return json.loads(aw(who, 'id', 'request', 'GET', SERVER + path, '--team-auth', '--raw').stdout)
    def stream(who):
        return subprocess.Popen([str(AW), '--json', 'events', 'stream', '--timeout', '8'], cwd=homes[who], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def events(proc):
        out, err = proc.communicate(timeout=20)
        assert proc.returncode == 0, err
        rows = [json.loads(line) for line in out.splitlines()]
        assert any(r['type'] == 'connected' for r in rows), (rows, err)
        result = run(['node', str(ROOT / 'scripts/e2e/folio-wakes-channel.mjs')], input=out)
        return [json.loads(line) for line in result.splitlines()]
    configure_manifest('0.1.0')
    homes['discovery'] = root / 'discovery'
    homes['discovery'].mkdir()
    discovery = aw('discovery', '--json', 'plugin', 'install', FOLIO)
    warning = 'app events not registered: no resident identity here; run aw plugin install from a resident home to enable wakes'
    assert discovery.stderr.count(warning) == 1, discovery.stderr
    local = json.loads(discovery.stdout)
    assert not local.get('approved', False), local
    assert not local['provenance'].get('registered_digest'), local
    assert (Path(local['path']) / 'manifest.json').is_file()
    assert not list(homes['discovery'].iterdir()), 'discovery-only install created identity state'
    # A team-less install must not silently register anywhere on the real server.
    count = run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'aweb', '-Atc', 'SELECT count(*) FROM aweb.team_app_installs'])
    assert count.strip() == '0', count
    print('PASS identity-free install caches manifest, approves nobody, warns once and registers nothing', flush=True)
    for name in ['alice', 'bob']:
        homes[name] = root / name
        homes[name].mkdir()
        if name == 'alice':
            aw(name, 'id', 'create', '--name', name, '--domain', namespace, '--registry', REGISTRY, '--skip-dns-verify')
            aw(name, 'id', 'namespace', 'set-delivery-origin', '--namespace', namespace, '--origin', SERVER)
            aw(name, 'id', 'team', 'create', '--name', 'dev', '--namespace', namespace, '--registry', REGISTRY)
        else:
            aw(name, 'id', 'create', '--name', name, '--domain', 'bob-' + namespace, '--registry', REGISTRY, '--skip-dns-verify')
        invite = data('alice', 'id', 'team', 'invite', '--team', 'dev', '--namespace', namespace, '--global')['token']
        aw(name, 'id', 'team', 'accept-invite', invite, '--global', '--alias', name)
        aw(name, 'init', '--url', SERVER)
    configure_manifest('0.0.0', events=False)
    aw('alice', 'plugin', 'install', FOLIO)
    assert get('alice', '/v1/apps/installed?team_id=' + team)['apps'] == []
    configure_manifest('0.1.0')
    raw = urllib.request.urlopen(FOLIO + '/.well-known/aweb-app.json').read()
    aw('alice', 'plugin', 'install', FOLIO, '--dev-origin', FOLIO)
    apps = get('alice', '/v1/apps/installed?team_id=' + team)['apps']
    assert len(apps) == 1, f'install did not register Folio: {apps}'
    assert apps[0]['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    subscriptions = get('alice', '/v1/events/subscriptions')['subscriptions']
    assert len(subscriptions) == 1 and subscriptions[0]['delivery_intent'] == 'wake', subscriptions
    assert get('bob', '/v1/events/subscriptions')['subscriptions'] == []
    print('PASS exact fetched digest registered; installer subscribed; peer not subscribed', flush=True)
    aw('alice', 'folio', 'create', '--slug', 'wake-proof', '--title', 'Wake proof', '--body', 'first')
    a, b = stream('alice'), stream('bob')
    aw('alice', 'folio', 'append', '--slug', 'wake-proof', '--body', 'second')
    received, absent = events(a), events(b)
    assert any(e['kind'] == 'app' and e['deliveryIntent'] == 'wake' and e['meta']['resource_ref'] == 'wake-proof' for e in received), received
    assert absent == [], absent
    print('PASS Folio write wakes installer through channel-core; unsubscribed peer receives nothing', flush=True)
    data('bob', 'events', 'subscribe', 'folio/doc.changed', '--intent', 'steer', '--resource', 'wake-proof')
    b = stream('bob')
    aw('alice', 'folio', 'append', '--slug', 'wake-proof', '--body', 'third')
    assert any(e['deliveryIntent'] == 'steer' for e in events(b))
    print('PASS second member explicitly subscribes with resource and intent', flush=True)
    homes['grant'] = root / 'worker'
    homes['grant'].mkdir()
    grant = homes['grant'] / '.aw'
    data('alice', 'id', 'grant', 'mint', '--scope', 'events.read', '--ttl', '1h', '--out', str(grant))
    old = env['AWEB_IDENTITY_HOME']
    env['AWEB_IDENTITY_HOME'] = str(grant)
    try:
        denied = aw('grant', 'plugin', 'install', FOLIO, check=False)
        assert denied.returncode and 'app_management_denied' in denied.stderr, denied.stderr
        env['AWEB_IDENTITY_HOME'] = ''
        blocked = events(stream('grant'))
        assert blocked == [], blocked
    finally:
        env['AWEB_IDENTITY_HOME'] = old
    print('PASS grant cannot install and events.read without coord.read receives no app event', flush=True)
    configure_manifest('0.1.1')
    raw = urllib.request.urlopen(FOLIO + '/.well-known/aweb-app.json').read()
    aw('alice', 'plugin', 'update', 'folio')
    apps = get('alice', '/v1/apps/installed?team_id=' + team)['apps']
    assert apps[0]['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert apps[0]['app_version'] == '0.1.1'
    def install_stamp():
        return run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'aweb', '-Atc', "SELECT updated_at FROM aweb.team_app_installs WHERE team_id='" + team + "'"])
    stamp = install_stamp()
    aw('alice', 'plugin', 'update', 'folio')
    assert install_stamp() == stamp, 'unchanged update re-registered'
    assert get('bob', '/v1/events/subscriptions')['subscriptions'][0]['delivery_intent'] == 'steer'
    print('PASS changed manifest update re-registers; unchanged update succeeds; peer consent retained', flush=True)

    # A real service outage must not advance the receipt or corrupt cached bytes.
    configure_manifest('0.1.2')
    cache = root / 'config' / 'plugins' / 'folio'
    before = {str(p): p.read_bytes() for p in cache.rglob('*') if p.is_file()}
    assert len(before) >= 2, 'manifest and provenance cache missing'
    run(COMPOSE + ['pause', 'aweb'])
    try:
        failed = aw('alice', 'plugin', 'update', 'folio', check=False)
        assert failed.returncode != 0, 'offline registration unexpectedly succeeded'
        assert {str(p): p.read_bytes() for p in cache.rglob('*') if p.is_file()} == before
    finally:
        run(COMPOSE + ['unpause', 'aweb'])
    aw('alice', 'plugin', 'update', 'folio')
    assert get('alice', '/v1/apps/installed?team_id=' + team)['apps'][0]['app_version'] == '0.1.2'
    denied = aw('alice', 'plugin', 'install', FOLIO, '--dev-origin', 'http://localhost:38765', check=False)
    assert denied.returncode != 0 and '409' in denied.stderr, denied.stderr
    print('PASS failed registration preserves cache and retries; origin conflict refuses', flush=True)
