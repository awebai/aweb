"""Opt-in F6 lifecycle acceptance inside the disposable real Folio stack.

A surviving link/session is a consumer finding. Keep the assertions: the OSS
uninstall path must not hide missing enforcement in the actual consumer.
"""
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


def prove_uninstall(*, aw, data, get, folio_request, run, compose, team, other_team, cache, origin):
    def status(url, headers=None, body=None):
        request = urllib.request.Request(url, headers=headers or {}, data=body)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def grant():
        return json.loads(run(compose + ['exec', '-T', 'folio', '/app/.venv/bin/python',
                                        '/fixture/e2e/folio_uninstall_grant.py', team]))

    first = get('alice', '/v1/apps/folio/installation?team_id=' + team)
    peer = get('carol', '/v1/apps/folio/installation?team_id=' + other_team)
    active = grant()
    assert active['state'] == 'active' and active['installation_id'] == first['installation_id']
    assert aw('alice', 'folio', 'show', '--slug', 'every-change').returncode == 0
    readonly = folio_request('alice', 'POST', '/v1/present', {'slug': 'every-change', 'ttl_seconds': 600})
    editable = folio_request('alice', 'POST', '/v1/present', {'slug': 'every-change', 'editable': True, 'ttl_seconds': 600})
    parts = urllib.parse.urlsplit(editable['url'])
    editor = parts._replace(fragment='').geturl()
    code, raw = status(editor + '/session', {'Content-Type': 'application/json'},
                       json.dumps({'opener': urllib.parse.parse_qs(parts.fragment)['k'][0]}).encode())
    assert code == 200, code
    session = {'X-Folio-Edit-Session': json.loads(raw)['session_secret']}
    assert status(readonly['url'])[0] == status(editor + '/state', session)[0] == 200
    cached = {str(p): p.read_bytes() for p in Path(cache).rglob('*') if p.is_file()}
    refused = aw('bob', 'plugin', 'uninstall', 'folio', check=False)
    assert refused.returncode and 'admin_required' in refused.stderr
    assert get('alice', '/v1/apps/folio/installation?team_id=' + team) == first
    retired = data('alice', 'plugin', 'uninstall', 'folio')
    assert retired['state'] == 'uninstalled' and retired['installation_id'] == first['installation_id']
    assert retired['generation'] > first['generation']
    assert {str(p): p.read_bytes() for p in Path(cache).rglob('*') if p.is_file()} == cached
    observed = grant()
    assert observed['state'] == 'uninstalled' and observed['generation'] == retired['generation']
    assert observed['granted_scopes'] == active['granted_scopes']
    assert data('alice', 'plugin', 'uninstall', 'folio')['generation'] == retired['generation']
    assert get('carol', '/v1/apps/folio/installation?team_id=' + other_team) == peer
    # Actual elapsed time, advertised server freshness and one refresh allowance.
    # No fake clock or direct mutation of the consumer's cache/installation data.
    time.sleep(active['max_age_seconds'] + 5)
    denied = aw('alice', 'folio', 'show', '--slug', 'every-change', check=False)
    assert denied.returncode != 0, 'CLI tool still authorizes the uninstalled app'
    before_reinstall = {'readonly': status(readonly['url'])[0], 'edit_session': status(editor + '/state', session)[0]}
    print('UNINSTALL surfaces before reinstall: ' + json.dumps(before_reinstall), flush=True)
    aw('alice', 'plugin', 'install', origin)
    replacement = get('alice', '/v1/apps/folio/installation?team_id=' + team)
    assert replacement['installation_id'] != first['installation_id'] and replacement['generation'] > retired['generation']
    after_reinstall = {'readonly': status(readonly['url'])[0], 'edit_session': status(editor + '/state', session)[0]}
    print('UNINSTALL surfaces after reinstall: ' + json.dumps(after_reinstall), flush=True)
    assert all(code in (401, 403, 404, 410) for code in before_reinstall.values()), before_reinstall
    assert all(code in (401, 403, 404, 410) for code in after_reinstall.values()), after_reinstall
    print('PASS real uninstall refuses tools and existing Folio links/sessions; reinstall cannot revive them', flush=True)
