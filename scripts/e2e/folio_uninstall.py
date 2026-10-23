"""Opt-in F6 lifecycle acceptance inside the disposable real Folio stack.

A surviving link/session is a consumer finding. Keep the assertions: the OSS
uninstall path must not hide missing enforcement in the actual consumer.
"""
import json
from pathlib import Path
import time
import subprocess
import urllib.error
import urllib.parse
import urllib.request


def prove_uninstall(*, aw, data, get, folio_request, run, compose, team, other_team, cache, origin, homes, env, aw_bin):
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

    # An independently approved resident delegates a real app-tool snapshot.
    # The old grant must never authorize the replacement, even at the same digest.
    aw('bob', 'plugin', 'install', origin)
    custody = subprocess.Popen([str(aw_bin), 'custody', 'serve'], cwd=homes['bob'], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    minted = {}
    def mint(name, *, explicit=False):
        homes[name] = homes['bob'].parent / name
        homes[name].mkdir()
        target = homes[name] / '.aw'
        args = ['id', 'grant', 'mint', '--bundle', 'normal-agent', '--ttl', '1h',
                '--custody-socket', 'auto', '--out', str(target)]
        if explicit:
            args += ['--app-tool', 'folio:show']
        minted[name] = data('bob', *args)
        return target

    def tool(name, target):
        previous = env['AWEB_IDENTITY_HOME']
        env['AWEB_IDENTITY_HOME'] = str(target)
        try:
            return aw(name, 'folio', 'show', '--slug', 'every-change', check=False)
        finally:
            env['AWEB_IDENTITY_HOME'] = previous

    try:
        deadline = time.monotonic() + 10
        while data('bob', 'custody', 'status')['status'] != 'running':
            assert custody.poll() is None, 'own custody process exited during startup'
            assert time.monotonic() < deadline, 'own custody did not start'
            time.sleep(0.1)
        # Recreate the released local JSON shapes, retaining the real server
        # grant, session key and signed requests. These are custody policy files,
        # not a substituted server, grant response or signature.
        upgrade_target = mint('upgrade-old-grant', explicit=True)
        snapshot_path = homes['bob'] / '.aw' / 'grants' / minted['upgrade-old-grant']['grant_id'] / 'app-tools.json'
        snapshot = json.loads(snapshot_path.read_text())
        snapshot['apps']['folio'].pop('installation_id')
        snapshot_path.write_text(json.dumps(snapshot))
        approval_path = homes['bob'] / '.aw' / 'app-approvals.json'
        approval = json.loads(approval_path.read_text())
        approval.pop('installations')
        approval_path.write_text(json.dumps(approval))
        custody.terminate()
        custody.wait(timeout=10)
        custody = subprocess.Popen([str(aw_bin), 'custody', 'serve'], cwd=homes['bob'], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while data('bob', 'custody', 'status')['status'] != 'running':
            assert custody.poll() is None, 'own upgraded custody exited during startup'
            assert time.monotonic() < deadline, 'own upgraded custody did not start'
            time.sleep(0.1)
        upgrade_old = tool('upgrade-old-grant', upgrade_target)
        assert upgrade_old.returncode and 'app_installation_required' in upgrade_old.stderr, upgrade_old.stderr
        listed = data('bob', 'plugin', 'list')['plugins']
        assert next(app for app in listed if app['name'] == 'folio')['approval_code'] == 'app_installation_approval_required'
        upgrade_default = mint('upgrade-default-grant')
        skipped = next(app for app in minted['upgrade-default-grant']['skipped_apps'] if app['app_id'] == 'folio')
        assert skipped['code'] == 'app_installation_approval_required', skipped
        assert skipped['recovery_command'] == ['aw', '--identity-home', str(homes['bob'] / '.aw'), '--team', team, 'plugin', 'install', origin], skipped
        assert tool('upgrade-default-grant', upgrade_default).returncode != 0
        upgrade_explicit_dir = homes['bob'].parent / 'upgrade-explicit-refused'
        upgrade_explicit_dir.mkdir()
        upgrade_explicit = aw('bob', 'id', 'grant', 'mint', '--bundle', 'normal-agent', '--ttl', '1h',
                              '--custody-socket', 'auto', '--app-tool', 'folio:show',
                              '--out', str(upgrade_explicit_dir / '.aw'), check=False)
        assert upgrade_explicit.returncode and 'app_installation_approval_required' in upgrade_explicit.stderr, upgrade_explicit.stderr
        aw('bob', 'plugin', 'install', origin)
        upgrade_fresh = mint('upgrade-fresh-grant', explicit=True)
        assert tool('upgrade-fresh-grant', upgrade_fresh).returncode == 0
        assert 'app_installation_required' in tool('upgrade-old-grant', upgrade_target).stderr
        print('PASS origin-only upgrade state never adopts an installation; old snapshot refused after custody restart; default/explicit mint require approval; explicit approval plus fresh grant recovers', flush=True)
        old_target = mint('uninstall-old-grant')
        assert tool('uninstall-old-grant', old_target).returncode == 0, 'pre-uninstall grant did not work'
        _prove_uninstall(aw=aw, data=data, get=get, folio_request=folio_request, run=run,
                         compose=compose, team=team, other_team=other_team, cache=cache,
                         origin=origin, grant=grant, status=status, mint=mint, tool=tool,
                         old_target=old_target, minted=minted, homes=homes, env=env)
    finally:
        custody.terminate()  # This harness owns this exact process.
        custody.wait(timeout=10)


def _prove_uninstall(*, aw, data, get, folio_request, run, compose, team, other_team,
                     cache, origin, grant, status, mint, tool, old_target, minted, homes, env):
    first = get('alice', '/v1/apps/folio/installation?team_id=' + team)
    peer = get('carol', '/v1/apps/folio/installation?team_id=' + other_team)
    active = grant()
    assert active['state'] == 'active' and active['installation_id'] == first['installation_id']
    assert aw('alice', 'folio', 'show', '--slug', 'every-change').returncode == 0
    readonly = folio_request('alice', 'POST', '/v1/present', {'slug': 'every-change', 'ttl_seconds': 600})
    link_started = time.monotonic()
    editable = folio_request('alice', 'POST', '/v1/present', {'slug': 'every-change', 'editable': True, 'ttl_seconds': 300})
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
    old_uninstalled = tool('uninstall-old-grant', old_target).returncode
    before_reinstall = {'readonly': status(readonly['url'])[0], 'edit_session': status(editor + '/state', session)[0]}
    print('UNINSTALL surfaces before reinstall: ' + json.dumps(before_reinstall), flush=True)
    aw('alice', 'plugin', 'install', origin)
    replacement = get('alice', '/v1/apps/folio/installation?team_id=' + team)
    assert replacement['installation_id'] != first['installation_id'] and replacement['generation'] > retired['generation']
    assert replacement['digest'] == first['digest'] and replacement['origin'] == first['origin']
    old_result = tool('uninstall-old-grant', old_target)
    old_reinstalled = old_result.returncode
    listed = data('bob', 'plugin', 'list')['plugins']
    folio_status = next(app for app in listed if app['name'] == 'folio')
    assert folio_status.get('approval_code') == 'app_installation_changed', folio_status
    default_target = mint('uninstall-default-grant')
    assert any(app['code'] == 'app_installation_changed' for app in minted['uninstall-default-grant']['skipped_apps'])
    default_reinstalled = tool('uninstall-default-grant', default_target).returncode
    explicit_dir = homes['bob'].parent / 'uninstall-explicit-refused'
    explicit_dir.mkdir()
    explicit = aw('bob', 'id', 'grant', 'mint', '--bundle', 'normal-agent', '--ttl', '1h',
                  '--custody-socket', 'auto', '--app-tool', 'folio:show',
                  '--out', str(explicit_dir / '.aw'), check=False)
    assert explicit.returncode != 0 and 'app_installation_changed' in explicit.stderr, 'explicit mint silently re-approved the replacement: ' + explicit.stderr
    aw('bob', 'plugin', 'install', origin)  # Explicit replacement approval.
    fresh_target = mint('uninstall-fresh-grant', explicit=True)
    fresh_reinstalled = tool('uninstall-fresh-grant', fresh_target).returncode
    delegation = {'resident_uninstalled': denied.returncode, 'old_grant_uninstalled': old_uninstalled,
                  'old_grant_reinstalled': old_reinstalled, 'default_without_reapproval': default_reinstalled,
                  'fresh_after_reapproval': fresh_reinstalled}
    print('UNINSTALL delegation exit codes: ' + json.dumps(delegation), flush=True)
    after_reinstall = {'readonly': status(readonly['url'])[0], 'edit_session': status(editor + '/state', session)[0]}
    print('UNINSTALL surfaces after reinstall: ' + json.dumps(after_reinstall), flush=True)
    assert time.monotonic() - link_started < 300, 'link expired during proof; refusal would be ambiguous'
    assert 'app_installation_changed' in old_result.stderr, 'old grant did not return stable replacement refusal'
    assert old_reinstalled != 0 and default_reinstalled != 0 and fresh_reinstalled == 0, delegation
    assert denied.returncode != 0 and old_uninstalled != 0, delegation
    assert all(code in (401, 403, 404, 410) for code in before_reinstall.values()), before_reinstall
    assert all(code in (401, 403, 404, 410) for code in after_reinstall.values()), after_reinstall
    print('PASS real uninstall refuses tools and existing Folio links/sessions; reinstall cannot revive them', flush=True)
