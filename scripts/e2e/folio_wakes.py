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
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
AW = Path(os.environ['AW_BIN']).resolve()
REGISTRY = 'http://awid:8010'
SERVER = 'http://127.0.0.1:38000'
FOLIO = os.environ['FOLIO_WAKES_ORIGIN']
COMPOSE = ['docker', 'compose', '-p', 'abrm-folio', '--project-directory', str(ROOT), '-f', str(ROOT / 'scripts/e2e/folio-wakes.compose.yml')]

def run(args, **kw):
    result = subprocess.run(args, text=True, capture_output=True, **kw)
    if result.returncode:
        raise AssertionError(f'{args[:4]} failed: {result.stderr}\n{result.stdout}')
    return result.stdout

def configure_manifest(version, events=True, manifest_version=1, extra_emitter=None):
    # The disposable deployment's real manifest file, declaring the public test
    # emitter. No substitute HTTP server or auth bypass. Version 2 declares the
    # emitter as an app-event app key and adds a hook-only tool, whose scope
    # install must not grant.
    arguments = ['docker', 'run', '--rm', '--entrypoint', '/app/.venv/bin/python', '-v', 'abrm-folio-fixture:/fixture:ro', '-e', 'FOLIO_WAKES_ORIGIN', 'abrm-folio-folio', '/fixture/e2e/folio_wakes_manifest.py', version, 'true' if events else 'false', str(manifest_version)]
    if extra_emitter:
        arguments.append(extra_emitter)
    manifest = run(arguments)
    with open(os.environ['FOLIO_WAKES_MANIFEST'], 'w', encoding='utf-8') as handle:
        handle.write(manifest.strip())
    document = json.loads(manifest)
    keys = document.get('app_keys', document.get('event_emitters', []))
    paths = {'folio:grant-read-1': '/fixture/tls/grant-read.key', 'folio:emit-other': '/fixture/tls/emit-other.key'}
    os.environ['FOLIO_WAKES_APP_KEY_FILES'] = json.dumps({key['kid']: paths[key['kid']] for key in keys if key['kid'] in paths})
    # Recreate applies both the changed bytes and purpose-specific key files.
    run(COMPOSE + ['up', '--no-build', '--no-deps', '-d', '--force-recreate', 'folio'])
    deadline = time.monotonic() + 60
    while True:
        container = run(COMPOSE + ['ps', '--all', '--quiet', 'folio']).strip()
        state = json.loads(run(['docker', 'inspect', '--format', '{{json .State}}', container]))
        if state['Status'] in ('exited', 'dead'):
            logs = run(COMPOSE + ['logs', '--no-color', '--tail', '80', 'folio'])
            raise AssertionError(f'folio exited after the manifest change: {state}\n{logs}')
        try:
            with urllib.request.urlopen(FOLIO + '/health', timeout=5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        if time.monotonic() > deadline:
            logs = run(COMPOSE + ['logs', '--no-color', '--tail', '80', 'folio'])
            raise AssertionError(f'folio did not come back after the manifest change\n{logs}')
        time.sleep(0.5)

def served_manifest():
    try:
        with urllib.request.urlopen(FOLIO + '/.well-known/aweb-app-versions.json') as response:
            catalog = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        return urllib.request.urlopen(FOLIO + '/.well-known/aweb-app.json').read()
    variant = max(catalog['variants'], key=lambda item: item['manifest_version'])
    return urllib.request.urlopen(FOLIO + variant['url']).read()


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
        if name == 'alice':
            aw(name, 'id', 'team', 'set-server', '--team', 'dev', '--namespace', namespace, '--url', SERVER, '--registry', REGISTRY)
    configure_manifest('0.0.0', events=False)
    refused = aw('alice', '--json', 'plugin', 'install', FOLIO, check=False)
    assert refused.returncode, refused.stdout
    refusal = json.loads(refused.stdout)['error']
    assert refusal['reason'] == 'admin_required' and refusal['http_status'] == 403, refusal
    requested = data('alice', 'plugin', 'request', FOLIO)
    assert requested['state'] == 'pending', requested
    assert get('alice', '/v1/apps/installed?team_id=' + team)['apps'] == []
    def grant_admin(who, team_id):
        did = data(who, 'id', 'show')['did_key']
        run(COMPOSE + ['exec', '-T', 'aweb', 'aweb', 'install-admin', 'grant',
                       '--team-id', team_id, '--principal-did', did, '--role', 'owner'])
    grant_admin('alice', team)
    configure_manifest('0.1.0')
    raw = served_manifest()
    aw('alice', 'plugin', 'install', FOLIO)
    apps = get('alice', '/v1/apps/installed?team_id=' + team)['apps']
    assert len(apps) == 1, f'install did not register Folio: {apps}'
    assert apps[0]['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert apps[0]['installation_id'] and apps[0]['generation'] > 0 and apps[0]['origin_verified']
    stale = aw('alice', 'id', 'request', 'POST', SERVER + '/v1/apps/install', '--team-auth', '--raw',
               '--header', 'Content-Type: application/json', '--body', json.dumps({
                   'app_id': 'folio', 'origin': FOLIO, 'digest': apps[0]['digest'],
                   'granted_scopes': apps[0]['granted_scopes'], 'expected_generation': apps[0]['generation'] + 1,
               }), check=False)
    assert stale.returncode != 0 and 'HTTP 409' in stale.stderr.splitlines(), stale.stderr
    assert json.loads(stale.stdout)['detail']['code'] == 'generation_conflict', stale.stdout
    after_conflict = get('alice', '/v1/apps/installed?team_id=' + team)['apps']
    assert after_conflict[0]['generation'] == apps[0]['generation'], after_conflict
    from_bytes = run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'aweb', '-Atc', "SELECT registered_from_manifest_bytes FROM aweb.team_app_installs WHERE team_id='" + team + "'"]).strip()
    assert from_bytes == 't', f'aw install did not register from the fetched manifest bytes: {from_bytes!r}'
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
    def stored(slug):
        # The events the real aweb server verified and stored for this document.
        rows = run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'aweb', '-Atc', "SELECT payload::text FROM aweb.app_events WHERE team_id='" + team + "' AND resource_ref='" + slug + "' ORDER BY created_at, event_id"])
        return [json.loads(line) for line in rows.splitlines()]
    def emitted(slug, count, within=60):
        # Folio delivers events from its outbox after the write commits, so wait
        # for the expected number, then long enough to see a duplicate arrive.
        deadline = time.monotonic() + within
        while len(stored(slug)) < count and time.monotonic() < deadline:
            time.sleep(0.5)
        time.sleep(2)
        return stored(slug)
    def folio_request(who, method, path, body):
        return json.loads(aw(who, 'id', 'request', method, FOLIO + path, '--team-auth', '--raw', '--header', 'Content-Type: application/json', '--body', json.dumps(body)).stdout)
    def human_edit(url, headers, body, base_version):
        request = urllib.request.Request(url + '/edit', data=json.dumps({'body': body, 'base_version': base_version, 'editor_name': 'Hana'}).encode(), headers=headers, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())
    aw('alice', 'folio', 'create', '--slug', 'every-change', '--title', 'Every change', '--body', 'one')
    assert emitted('every-change', 1) == [{'version': '1', 'source': 'api'}], stored('every-change')
    aw('alice', 'folio', 'append', '--slug', 'every-change', '--body', 'two')
    folio_request('alice', 'POST', '/v1/documents/every-change/versions/template', {'name': 'memo', 'slots': {'cover': {'title': 'Three'}}})
    assert emitted('every-change', 3)[1:] == [{'version': '2', 'source': 'api'}, {'version': '3', 'source': 'api'}], stored('every-change')
    print('PASS create, append and append-template each emit exactly one metadata-only event', flush=True)
    link = folio_request('alice', 'POST', '/v1/present', {'slug': 'every-change', 'editable': True})
    parts = urllib.parse.urlsplit(link['url'])
    editor_url = parts._replace(fragment='').geturl()
    session_request = urllib.request.Request(
        editor_url + '/session',
        data=json.dumps({'opener': urllib.parse.parse_qs(parts.fragment)['k'][0]}).encode(),
        headers={'Content-Type': 'application/json'}, method='POST',
    )
    with urllib.request.urlopen(session_request, timeout=10) as response:
        assert response.status == 200
        edit_headers = {'Content-Type': 'application/json', 'X-Folio-Edit-Session': json.load(response)['session_secret']}
    a = stream('alice')
    assert human_edit(editor_url, edit_headers, 'four, by a human', 3) == (200, {'version_number': 4})
    assert human_edit(editor_url, edit_headers, 'stale', 3)[0] == 409
    assert emitted('every-change', 4)[3:] == [{'version': '4', 'source': 'present-link'}], stored('every-change')
    # The stream replays its lookback window, so earlier api events arrive too; the
    # stored rows above prove exactly-one, this proves the human edit wakes the agent.
    woken = [e for e in events(a) if e['kind'] == 'app' and e['meta']['resource_ref'] == 'every-change' and json.loads(e['meta']['payload']) == {'version': '4', 'source': 'present-link'}]
    assert len(woken) == 1 and woken[0]['deliveryIntent'] == 'wake', woken
    print('PASS human edit through an editable link wakes the subscribed agent once; rejected edit emits nothing', flush=True)
    # Folio stores each event in its own outbox, in the write's transaction, and
    # delivers it from there: a committed write leaves exactly one row, a rejected
    # one none. (Folio's database is "library" on the shared Postgres.)
    def outboxed():
        return int(run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'library', '-Atc', "SELECT COUNT(*) FROM outbox_events WHERE team_id='" + team + "' AND kind='folio/doc.changed'"]).strip())
    before = outboxed()
    folio_request('alice', 'POST', '/v1/documents', {'slug': 'outboxed', 'title': 'Outboxed', 'body': 'one'})
    assert outboxed() == before + 1, (before, outboxed())
    assert human_edit(editor_url, edit_headers, 'stale again', 3)[0] == 409
    assert outboxed() == before + 1, (before, outboxed())
    assert emitted('outboxed', 1) == [{'version': '1', 'source': 'api'}], stored('outboxed')
    print('PASS each write stores its event in the outbox with the write; a rejected edit stores none', flush=True)
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
    raw = served_manifest()
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
    denied = aw('alice', 'plugin', 'install', FOLIO, '--dev-origin', 'http://localhost:8765', check=False)
    assert denied.returncode != 0 and 'origin_verification_required' in denied.stderr, denied.stderr
    print('PASS failed registration preserves cache and retries; origin rewrite refuses', flush=True)

    # Two teams on one server pin different, genuinely fetched Folio bytes.
    # Only the other team's pin declares the extra public test key; it cannot
    # sign for Alice's older pin or override its declarations with metadata.
    homes['carol'] = root / 'carol'
    homes['carol'].mkdir()
    other_namespace = 'other-' + namespace
    other_team = 'ops:' + other_namespace
    aw('carol', 'id', 'create', '--name', 'carol', '--domain', other_namespace, '--registry', REGISTRY, '--skip-dns-verify')
    aw('carol', 'id', 'namespace', 'set-delivery-origin', '--namespace', other_namespace, '--origin', SERVER)
    aw('carol', 'id', 'team', 'create', '--name', 'ops', '--namespace', other_namespace, '--registry', REGISTRY)
    invite = data('carol', 'id', 'team', 'invite', '--team', 'ops', '--namespace', other_namespace, '--global')['token']
    aw('carol', 'id', 'team', 'accept-invite', invite, '--global', '--alias', 'carol')
    aw('carol', 'init', '--url', SERVER)
    aw('carol', 'id', 'team', 'set-server', '--team', 'ops', '--namespace', other_namespace, '--url', SERVER, '--registry', REGISTRY)
    pinned = get('alice', '/v1/apps/installed?team_id=' + team)['apps'][0]
    grant_admin('carol', other_team)
    other_seed = run(COMPOSE + ['exec', '-T', 'folio', '/app/.venv/bin/python', '-c',
                                'from pathlib import Path; print(Path("/fixture/tls/emit-other.key").read_text().strip())']).strip()
    other_did = run(COMPOSE + ['exec', '-T', 'folio', '/app/.venv/bin/python', '-c',
                               'from awid.did import did_from_public_key; from nacl.signing import SigningKey; '
                               'print(did_from_public_key(bytes(SigningKey(bytes.fromhex(' + repr(other_seed) + ')).verify_key)))']).strip()
    def emit_with_other_key(team_id, kid):
        code = '''import json, urllib.error, urllib.request
from datetime import UTC, datetime
from aweb_naapp.runtime.app_emit import sign_app_emit_credential
target = "http://127.0.0.1:38000/v1/events/app"
body = json.dumps({"type": "folio/doc.changed", "resource_ref": "wake-proof", "payload": {}}).encode()
cred = sign_app_emit_credential(private_key=bytes.fromhex(SEED), method="POST", target=target, team_id=TEAM, app_id="folio", key_id=KID, body=body, timestamp=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
request = urllib.request.Request(target, data=body, method="POST", headers={**cred.headers, "Content-Type": "application/json"})
try:
    print(urllib.request.urlopen(request).status)
except urllib.error.HTTPError as exc:
    print(exc.code)
'''.replace('SEED', repr(other_seed)).replace('TEAM', repr(team_id)).replace('KID', repr(kid))
        return int(run(COMPOSE + ['exec', '-T', 'folio', '/app/.venv/bin/python', '-c', code]).strip())
    # Carol pins distinct origin-served bytes declaring the extra public key.
    # Alice keeps her earlier pin: no caller-supplied key metadata is trusted.
    configure_manifest('0.1.2', extra_emitter='folio:emit-other')
    deployed = json.loads(served_manifest())
    declared = deployed.get('app_keys', deployed.get('event_emitters', []))
    assert next(key for key in declared if key['kid'] == 'folio:emit-other')['did_key'] == other_did
    aw('carol', 'plugin', 'install', FOLIO)
    assert emit_with_other_key(team, 'folio:emit-test') == 403
    assert emit_with_other_key(team, 'folio:emit-other') == 403
    assert emit_with_other_key(other_team, 'folio:emit-other') == 200
    replaced = aw('alice', 'id', 'request', 'POST', SERVER + '/v1/apps/install', '--team-auth', '--raw',
                  '--header', 'Content-Type: application/json', '--body', json.dumps({
                      'app_id': 'folio', 'origin': FOLIO, 'digest': pinned['digest'],
                      'granted_scopes': pinned['granted_scopes'], 'expected_generation': pinned['generation'],
                      'event_emitters': [{'kid': 'folio:emit-test', 'did_key': other_did}],
                  }), check=False)
    assert replaced.returncode != 0 and 'HTTP 422' in replaced.stderr.splitlines(), replaced.stderr
    configure_manifest('0.1.2')
    a = stream('alice')
    aw('alice', 'folio', 'append', '--slug', 'wake-proof', '--body', 'fourth')
    assert any(e['kind'] == 'app' and e['meta']['resource_ref'] == 'wake-proof' for e in events(a))
    print('PASS another team on the server cannot emit as Folio into this team or replace its registered key', flush=True)

    # Operator repair restores missing keys/declarations for this verified
    # pin and reports the other team's different pin. Subscription choices
    # survive the repair. Migration activation is covered by the F6 tests.
    def psql(sql):
        return run(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-U', 'aweb', '-d', 'aweb', '-Atc', sql])
    psql("DELETE FROM aweb.team_app_emit_keys WHERE team_id='" + team + "'; DELETE FROM aweb.team_app_event_types WHERE team_id='" + team + "'")
    intents_before = get('bob', '/v1/events/subscriptions')['subscriptions']
    # Give the repair command the exact bytes served by this deployment.
    configure_manifest('0.1.2')
    served = served_manifest()
    run(COMPOSE + ['exec', '-T', 'aweb', 'sh', '-c', 'cat > /tmp/folio-manifest.json'], input=served.decode())
    reseed = subprocess.run(COMPOSE + ['exec', '-T', 'aweb', 'aweb', 'reseed-app-registrations', '--origin', FOLIO, '--manifest-file', '/tmp/folio-manifest.json'], text=True, capture_output=True)
    report = json.loads(reseed.stdout)
    assert team in report['reseeded'], report
    assert report['digest_mismatch'] == [other_team], report
    assert reseed.returncode == 1, reseed.stderr
    assert get('bob', '/v1/events/subscriptions')['subscriptions'] == intents_before
    a = stream('alice')
    aw('alice', 'folio', 'append', '--slug', 'wake-proof', '--body', 'fifth')
    assert any(e['kind'] == 'app' and e['meta']['resource_ref'] == 'wake-proof' for e in events(a))
    print("PASS operator reseed restores keys and declarations from origin bytes, keeps subscriptions, reports another team's different pin", flush=True)

    # A version 2 manifest is fetched and verified by the real server, grants
    # only the scopes of agent and surface tools, and takes its
    # emitter from the app-event app key, and refuses its hook-only verb.
    configure_manifest('0.2.0', manifest_version=2)
    # A v2 deployment is discovered through its variant catalog; the legacy
    # well-known path serves only v1 bytes, so it is absent here.
    catalog = json.loads(urllib.request.urlopen(FOLIO + '/.well-known/aweb-app-versions.json').read())
    variant = next(v for v in catalog['variants'] if v['manifest_version'] == 2)
    raw = urllib.request.urlopen(FOLIO + variant['url']).read()
    assert variant['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert json.loads(raw)['manifest_version'] == 2
    grant_keys = [key for key in json.loads(raw)['app_keys'] if key['kid'] == 'folio:grant-read-1']
    assert len(grant_keys) == 1 and grant_keys[0]['purposes'] == ['app-grant-read'], grant_keys
    aw('alice', 'plugin', 'update', 'folio')
    apps = get('alice', '/v1/apps/installed?team_id=' + team)['apps']
    assert len(apps) == 1, apps
    assert apps[0]['manifest_version'] == 2 and apps[0]['app_version'] == '0.2.0', apps[0]
    assert apps[0]['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    assert apps[0]['granted_scopes'] == ['folio:read', 'folio:write'], apps[0]['granted_scopes']
    assert psql("SELECT registered_from_manifest_bytes FROM aweb.team_app_installs WHERE team_id='" + team + "'").strip() == 't'
    hook_only = aw('alice', 'folio', 'audit-ingest', check=False)
    assert hook_only.returncode != 0 and 'tool_context_denied' in hook_only.stderr, hook_only.stderr
    a = stream('alice')
    aw('alice', 'folio', 'append', '--slug', 'wake-proof', '--body', 'sixth')
    assert any(e['kind'] == 'app' and e['meta']['resource_ref'] == 'wake-proof' for e in events(a))
    print('PASS v2 manifest registers from server-fetched bytes, grants only agent and surface scopes, emits through its app-event key, refuses its hook-only verb', flush=True)

    if os.environ.get('FOLIO_UNINSTALL_PROOF') == '1':
        from folio_uninstall import prove_uninstall
        prove_uninstall(aw=aw, data=data, get=get, folio_request=folio_request, run=run,
                        compose=COMPOSE, team=team, other_team=other_team, cache=cache, origin=FOLIO,
                        homes=homes, env=env, aw_bin=AW)
