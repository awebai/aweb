"""Released client shapes use actual HTTP/AWID/PG/Redis for rollover recovery."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from awid.signing import canonical_json_bytes, sign_message
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401


async def _process(*args, cwd, env):
    process = await asyncio.create_subprocess_exec(*map(str, args), cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        data, _ = await asyncio.wait_for(process.communicate(), 45)
    except BaseException:
        process.kill()
        await process.wait()
        raise
    assert process.returncode == 0, data.decode()
    return data.decode()


def _child_env(tmp_path, registry_origin):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('AW_', 'AWEB_', 'AWID_', 'OATS_'))}
    return dict(env, HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / 'config'),
        AW_NO_UPDATE_CHECK='1', AWID_REGISTRY_URL=registry_origin)


async def _register(env, registry, cert):
    await registry.register_team_certificate('example.test', TEAM.split(':')[0],
        team_controller_signing_key=env.team_sk, certificate_id=cert['certificate_id'],
        member_did_key=cert['member_did_key'], member_did_aw=cert.get('member_did_aw'),
        member_address=cert.get('member_address'), alias=cert['alias'], identity_scope=cert['identity_scope'],
        certificate=base64.b64encode(json.dumps(cert).encode()).decode())


async def _rollover(env, registry, cert, **fields):
    fresh = {key: value for key, value in cert.items() if key != 'signature'}
    fresh.update(version=2, validity_class='member', certificate_id=str(uuid4()))
    fresh.update(fields)
    fresh['signature'] = sign_message(env.team_sk, canonical_json_bytes(fresh))
    await registry.rollover_team_certificate('example.test', TEAM.split(':')[0], cert['certificate_id'], dict(
        certificate_id=fresh['certificate_id'], member_did_key=fresh['member_did_key'],
        member_did_aw=fresh.get('member_did_aw'), member_address=fresh.get('member_address'),
        alias=fresh['alias'], identity_scope=fresh['identity_scope'],
        certificate=base64.b64encode(json.dumps(fresh).encode()).decode()), signing_key=env.team_sk)
    return fresh


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
async def test_aw_recovers_replaced_certificate_installs_and_retries(privacy_app, tmp_path, monkeypatch):
    env = privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    actor = env.actors['alice']
    old = json.loads(base64.b64decode(actor.certificate))
    old.pop('signature')
    for field in ('member_did_aw', 'member_address'):
        if not old.get(field): old.pop(field, None)
    old['signature'] = sign_message(env.team_sk, canonical_json_bytes(old))
    home = tmp_path / 'member' / '.aw'
    home.mkdir(parents=True)
    _pem(home / 'signing.key', 'ED25519 PRIVATE KEY', actor.sk)
    (home / 'identity.yaml').write_text(json.dumps(dict(did=actor.did, custody='self', identity_scope='local')))
    (home / 'certificate.json').write_text(json.dumps(old))
    membership = dict(team_id=TEAM, alias='alice', cert_path='certificate.json')
    (home / 'teams.yaml').write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
    (home / 'workspace.yaml').write_text(json.dumps(dict(aweb_url=str(env.client.base_url),
        memberships=[dict(membership, workspace_id=str(actor.workspace))])))
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    await env.registry_db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    # This server has no privileged AWID token; public current-key/status suffice.
    monkeypatch.setenv('AWEB_REQUIRE_REGISTERED_CERTIFICATES', 'true')
    async with registry_listener(env, service_token=False) as (registry, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        await _register(env, registry, old)
        fresh = await _rollover(env, registry, old)
        result = await _process(os.environ['AW_TEST_CLI_BINARY'], '--identity-home', home,
            'id', 'grant', 'list', '--json', cwd=tmp_path, env=_child_env(tmp_path, origin))
        assert json.loads(result)['grants'] == []
        assert json.loads((home / 'certificate.json').read_text())['certificate_id'] == fresh['certificate_id']
        assert await env.registry_db.fetch_value('SELECT count(*) FROM {{tables.team_certificates}} WHERE revoked_at IS NULL') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('second_rollover', [False, True])
async def test_channel_core_follows_real_rollover_and_stops_after_one_retry(privacy_app, tmp_path, monkeypatch, second_rollover):
    env = privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    actor = env.actors['alice']
    old = json.loads(base64.b64decode(actor.certificate))
    env.app.state.public_origin = str(env.client.base_url).rstrip('/')
    core = Path(__file__).resolve().parents[2] / 'channel-core/dist'
    async with registry_listener(env) as (registry, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        await _register(env, registry, old)
        fresh = await _rollover(env, registry, old)
        script = tmp_path / 'recover.mjs'
        script.write_text('''import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const {APIClient} = await import(process.env.CORE_CLIENT);
const {fetchReplacementCertificate, installTeamCertificate} = await import(process.env.CORE_CERT);
const old = JSON.parse(process.env.OLD_CERT);
const key = new Uint8Array(Buffer.from(process.env.MEMBER_SEED, 'base64'));
let fetches = 0;
const client = new APIClient(process.env.ORIGIN, {
  did: old.member_did_key, stableID: '', signingKey: key, teamID: old.team_id,
  teamCertificateHeader: Buffer.from(JSON.stringify(old)).toString('base64'),
  refreshCertificate: async id => {
    fetches++;
    const replacement = await fetchReplacementCertificate(old, id, key, process.env.REGISTRY);
    if (process.env.SECOND_ROLLOVER === 'true') {
      console.log('replacement fetched');
      await new Promise(resolve => process.stdin.once('data', resolve));
    }
    await installTeamCertificate(process.env.INSTALL, replacement.certificate);
    return replacement;
  }
});
try {
  const result = await client.get('/v1/identity-grants');
  assert.deepEqual(result.grants, []);
  assert.equal(process.env.SECOND_ROLLOVER, 'false');
} catch (error) {
  if (process.env.SECOND_ROLLOVER !== 'true') throw error;
  assert.equal(error.statusCode, 401);
  assert.equal(JSON.parse(error.message.slice(error.message.indexOf('{'))).detail.code, 'certificate_replaced');
}
assert.equal(fetches, 1);
assert.equal(JSON.parse(await fs.readFile(process.env.INSTALL, 'utf8')).certificate_id, process.env.NEW_ID);
console.log('recovered');
''')
        child_env = dict(_child_env(tmp_path, origin), CORE_CLIENT=(core / 'api/client.js').as_uri(),
            CORE_CERT=(core / 'identity/certificate.js').as_uri(), OLD_CERT=json.dumps(old),
            MEMBER_SEED=base64.b64encode(actor.sk).decode(), REGISTRY=origin,
            ORIGIN=str(env.client.base_url).rstrip('/'), INSTALL=str(tmp_path / 'installed.json'), NEW_ID=fresh['certificate_id'],
            SECOND_ROLLOVER=str(second_rollover).lower())
        if not second_rollover:
            assert 'recovered' in await _process('node', script, cwd=tmp_path, env=child_env)
        else:
            process = await asyncio.create_subprocess_exec('node', str(script), cwd=tmp_path, env=child_env,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            try:
                assert await asyncio.wait_for(process.stdout.readline(), 10) == b'replacement fetched\n'
                await _rollover(env, registry, fresh)
                process.stdin.write(b'continue\n')
                await process.stdin.drain()
                data, _ = await asyncio.wait_for(process.communicate(), 15)
                assert process.returncode == 0, data.decode()
                assert b'recovered' in data
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()


@pytest.mark.usefixtures('source_cli_binary')
@pytest.mark.asyncio
async def test_controller_batch_renewal_obeys_policy_and_preserves_revoked_tombstones(privacy_app, tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from awid.credential_policy import POLICY_FIELDS, policy_signing_bytes
    env = privacy_app
    monkeypatch.setenv('AWID_CERTIFICATE_V2_ISSUANCE_ENABLED', 'true')
    name = TEAM.split(':')[0]
    key_path = tmp_path / '.awid' / 'team-keys' / 'example.test' / (name + '.key')
    key_path.parent.mkdir(parents=True)
    _pem(key_path, 'ED25519 PRIVATE KEY', env.team_sk)
    home = tmp_path / 'controller'
    home.mkdir()
    async with registry_listener(env) as (registry, origin):
        env.registry_app.state.awid_public_origins = (origin,)
        for actor in env.actors.values():
            cert = json.loads(base64.b64decode(actor.certificate))
            # Released Go v1 certificates omit empty optional global fields.
            cert = {k: v for k, v in cert.items() if k != 'signature' and v not in (None, '')}
            cert['signature'] = sign_message(env.team_sk, canonical_json_bytes(cert))
            await _register(env, registry, cert)
        await registry.revoke_team_certificate('example.test', name, team_controller_signing_key=env.team_sk,
            certificate_id='privacy-carol')
        async def renew():
            data = await _process(os.environ['AW_TEST_CLI_BINARY'],
                'id', 'team', 'renew-certs', '--team', name, '--namespace', 'example.test',
                '--registry', origin, '--json', cwd=tmp_path, env=_child_env(tmp_path, origin))
            return json.loads(data)['renewed']
        async def policy(maximum, revision):
            record = dict(v=1, type='aweb.team-credential-policy', team_id=TEAM, team_did_key=env.team_did,
                revision=revision, issued_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
            record.update(dict.fromkeys(POLICY_FIELDS))
            record['member_certificate'] = maximum
            await registry.set_team_credential_policy('example.test', name, record,
                sign_message(env.team_sk, policy_signing_bytes(record)), signing_key=env.team_sk)
        assert await renew() == []  # No policy: existing members need no renewal.
        await policy(1200, 1)
        assert sorted(await renew()) == ['alice', 'bob']  # Missing-expiry certificates become due.
        rows = await env.registry_db.fetch_all('SELECT certificate,certificate_id FROM {{tables.team_certificates}} WHERE revoked_at IS NULL')
        signed = [json.loads(base64.b64decode(row['certificate'])) for row in rows]
        for cert in signed:
            assert cert['version'] == 2
            assert (datetime.fromisoformat(cert['expires_at'].replace('Z', '+00:00')) - datetime.fromisoformat(cert['issued_at'].replace('Z', '+00:00'))).total_seconds() == 1200
        assert await renew() == []  # A fresh bounded certificate is outside its renewal window.
        await policy(600, 2)
        assert sorted(await renew()) == ['alice', 'bob']  # Lowering makes over-limit members due.
        await policy(None, 3)
        assert sorted(await renew()) == ['alice', 'bob']  # Disabling issues unbounded new artifacts.
        for row in await env.registry_db.fetch_all('SELECT certificate FROM {{tables.team_certificates}} WHERE revoked_at IS NULL'):
            assert 'expires_at' not in json.loads(base64.b64decode(row['certificate']))
        # Signed history stays immutable; no delayed old ID can become active.
        for cert in signed:
            stored = await env.registry_db.fetch_one('SELECT certificate,revoked_at,replaced_by_certificate_id FROM {{tables.team_certificates}} WHERE certificate_id=$1', cert['certificate_id'])
            assert json.loads(base64.b64decode(stored['certificate'])) == cert
            assert stored['revoked_at'] and stored['replaced_by_certificate_id']
        assert await env.registry_db.fetch_value("SELECT count(*) FROM {{tables.team_certificates}} WHERE alias='carol'") == 1
