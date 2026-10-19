"""Attachment boundaries through the real app, PG and AWID authority fixtures."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest

from aweb.e2ee_messages import _inner_payload_map
from test_dashboard_privacy import _request, privacy_app  # noqa: F401


def descriptor():
    return {"id": str(uuid4()), "filename": "report.pdf", "media_type": "application/pdf",
            "size": 9, "sha256": sha256(b"filebytes").hexdigest(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")}


def test_attachment_inner_content_is_preserved_without_changing_header():
    old = {"inner_version": 2, "kind": "mail", "message_id": str(uuid4()),
           "conversation_id": str(uuid4()), "created_at": "2026-10-18T00:00:00Z",
           "from": {}, "recipients": [], "subject": "text", "body": "text"}
    attached = {**old, "attachments": [descriptor()]}
    assert _inner_payload_map(attached, include_content=True)["attachments"] == attached["attachments"]
    assert _inner_payload_map(attached, include_content=False) == _inner_payload_map(old, include_content=False)
    assert "attachments" not in _inner_payload_map(old, include_content=True)


@pytest.mark.asyncio
async def test_legacy_ref_send_has_a_safe_fixed_refusal(privacy_app):
    # Legacy refs are rejected through the safe attachment boundary rather than
    # an unknown-field error that can echo the submitted metadata.
    d = descriptor()
    response = await _request(privacy_app, "alice", "POST", "/v1/messages", {
        "to_did": privacy_app.actors["bob"].did, "body": "text",
        "attachment_refs": [{"id": d["id"], "size": d["size"], "descriptor_sha256": "0" * 64}],
    })
    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "request_invalid"}


@pytest.mark.asyncio
async def test_legacy_attachments_refused_without_echoing_filename(privacy_app):
    response = await _request(privacy_app, "alice", "POST", "/v1/messages", {
        "to_did": privacy_app.actors["bob"].did, "body": "text", "attachments": [descriptor()],
    })
    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "request_invalid"}
    assert "report.pdf" not in response.text


async def managed_fixture(env, kind="mail"):
    import json
    from uuid import UUID
    from aweb.attachments import AttachmentDescriptor, AttachmentError, descriptors
    from aweb.e2ee_messages import encrypt_e2ee_message, decrypt_e2ee_message, generate_x25519_keypair
    from awid.e2ee_keys import build_encryption_key_assertion
    from test_dashboard_privacy import TEAM
    keys = {}
    for name in ("alice", "bob"):
        actor = env.actors[name]
        private, public = generate_x25519_keypair()
        assertion = build_encryption_key_assertion(signing_key=actor.sk, identity_did=actor.did, identity_stable_id="",
            encryption_public_key=public, custody="hosted_custodial", now=datetime.now(timezone.utc))
        keys[name] = dict(did=actor.did, team_id=TEAM, signing_key=actor.sk,
                         private_key=private, encryption_key=assertion)
    d, cid = descriptor(), str(uuid4())
    if kind == "chat":
        start = await _request(env, "alice", "POST", "/v1/chat/sessions", {
            "to_dids": [env.actors['bob'].did], "message": "start"})
        assert start.status_code == 200, start.text
        cid = start.json()['session_id']
    await env.db.execute("CREATE TABLE {{tables.attachment_test_storage}} "
                        "(id uuid primary key,message_id uuid,descriptor jsonb,data bytea,binds int default 0)")
    await env.db.execute("INSERT INTO {{tables.attachment_test_storage}} (id,descriptor,data) VALUES ($1,$2::jsonb,$3)",
                        UUID(d['id']), json.dumps(d), b'filebytes')
    class Backend:
        reads, error, corrupt, fail = 0, None, False, False
        async def bind(self, tx, *, binding, refs, message):
            sender = keys['alice']
            inner = decrypt_e2ee_message(message['encrypted_envelope'], dict(did=sender['did'],
                encryption_key_id=sender['encryption_key']['encryption_key_id'], private_key=sender['private_key']))
            parsed = descriptors(inner.get('attachments', []))
            if [x.ref() for x in parsed] != refs:
                raise AttachmentError('attachment_conflict')
            for item in parsed:
                row = await tx.fetch_one("SELECT * FROM {{tables.attachment_test_storage}} WHERE id=$1 FOR UPDATE", UUID(item.id))
                if not row or row['message_id'] or json.loads(row['descriptor']) != item.model_dump():
                    raise AttachmentError('attachment_conflict')
                await tx.execute("UPDATE {{tables.attachment_test_storage}} SET message_id=$2,binds=binds+1 WHERE id=$1",
                                 UUID(item.id), UUID(binding.message_id))
            if self.fail:
                raise AttachmentError('attachment_conflict')
        async def read(self, db, *, binding, participant, ref):
            self.reads += 1
            assert set(participant.dids).intersection(binding.participant_dids)
            if self.error:
                raise AttachmentError(self.error)
            row = await db.get_manager('aweb').fetch_one(
                "SELECT descriptor,data FROM {{tables.attachment_test_storage}} WHERE id=$1 AND message_id=$2",
                UUID(ref.id), UUID(binding.message_id))
            if not row:
                raise AttachmentError('not_found')
            return AttachmentDescriptor.model_validate_json(row['descriptor']), b'bad' if self.corrupt else bytes(row['data'])
    backend = Backend()
    env.app.state.attachment_backend = backend
    env.attachment_keys = keys
    recipient = {k: v for k, v in keys['bob'].items() if k not in {'private_key', 'signing_key'}}
    envelope = encrypt_e2ee_message(kind=kind,sender=keys['alice'],recipients=[recipient],body='attached',
                                   attachments=[d],message_id=str(uuid4()),conversation_id=cid)
    wire = dict(body='',content_mode='encrypted_v2',message_version=2,encrypted_envelope=envelope,
                attachment_refs=[AttachmentDescriptor.model_validate(d).ref().model_dump()],
                message_id=envelope['message_id'],timestamp=envelope['created_at'],from_did=keys['alice']['did'])
    if kind == 'mail':
        wire.update(to_did=env.actors['bob'].did,conversation_id=cid,new_conversation=True)
    return backend, d, wire, cid


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['mail', 'chat'])
async def test_managed_bind_fetch_and_hidden_neighbors(privacy_app, kind):
    env = privacy_app
    backend, d, wire, cid = await managed_fixture(env, kind)
    path = '/v1/messages' if kind == 'mail' else f'/v1/chat/sessions/{cid}/messages'
    sent = await _request(env,'alice','POST',path,wire)
    assert sent.status_code == 200, sent.text
    mid = sent.json()['message_id']
    prefix = '/v1/messages' if kind == 'mail' else '/v1/chat/messages'
    url = f"{prefix}/{mid}/attachments/{d['id']}"
    hidden = await _request(env,'carol','GET',url)
    missing = await _request(env,'carol','GET',url.replace(d['id'],str(uuid4())))
    assert hidden.status_code == missing.status_code == 404
    assert hidden.content == missing.content and backend.reads == 0
    for actor in ['alice','bob']:
        got = await _request(env,actor,'GET',url)
        assert got.status_code == 200, got.text
        assert got.content == b'filebytes' and got.headers['x-content-type-options'] == 'nosniff'
        assert got.headers['content-disposition'].startswith('attachment;')
    assert (await _request(env,'bob','GET',url.replace(mid,str(uuid4())))).status_code == 404
    backend.error = 'attachment_expired'
    assert (await _request(env,'bob','GET',url)).status_code == 410
    assert (await _request(env,'carol','GET',url)).status_code == 404
    backend.error, backend.corrupt = None, True
    assert (await _request(env,'bob','GET',url)).status_code == 503
    if kind == 'mail':
        retry = await _request(env,'alice','POST',path,wire)
        assert retry.status_code == 200 and retry.json()['message_id'] == mid, retry.text
    assert await env.db.fetch_value('SELECT sum(binds) FROM {{tables.attachment_test_storage}}') == 1
    assert d['filename'] not in str(env.dispatched)


@pytest.mark.asyncio
async def test_managed_bind_failure_rolls_back_provider_and_message(privacy_app):
    env = privacy_app
    backend, d, wire, cid = await managed_fixture(env)
    backend.fail = True
    result = await _request(env,'alice','POST','/v1/messages',wire)
    assert result.status_code == 409, result.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.messages}}') == 0
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.message_attachments}}') == 0
    assert await env.db.fetch_value('SELECT sum(binds) FROM {{tables.attachment_test_storage}}') == 0


@pytest.mark.parametrize('name',['../x','x\u202ey','bad\nname','.','..',' leading','trailing '])
def test_bad_filename_refused_without_normalization(name):
    from aweb.attachments import AttachmentError, descriptors
    d = descriptor()
    d['filename'] = name
    with pytest.raises(AttachmentError):
        descriptors([d])


@pytest.mark.asyncio
async def test_actual_aw_fetches_exact_bytes_from_participant_endpoint(privacy_app, tmp_path):
    import asyncio
    import base64
    import json
    import os
    from pathlib import Path
    from awid.signing import canonical_json_bytes, sign_message
    from test_messages_http import _make_certificate
    from test_dashboard_privacy import TEAM
    env = privacy_app
    backend, d, wire, cid = await managed_fixture(env)
    sent = await _request(env, 'alice', 'POST', '/v1/messages', wire)
    assert sent.status_code == 200, sent.text
    mid = sent.json()['message_id']
    binary = Path(os.environ.get('AW_TEST_CLI_BINARY', str(tmp_path / 'aw')))
    if 'AW_TEST_CLI_BINARY' not in os.environ:
        repo = Path(__file__).resolve().parents[2]
        build_env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2')
        build = await asyncio.create_subprocess_exec('go','build','-o',str(binary),'./cmd/aw',
            cwd=repo/'cli/go',env=build_env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        output,_=await build.communicate()
        assert build.returncode == 0, output.decode()
    home = (tmp_path/'participant').resolve()
    aw = home/'.aw'
    (aw/'team-certs').mkdir(parents=True)
    (aw/'encryption-keys').mkdir()
    actor = env.actors['bob']
    certificate = _make_certificate(env.team_sk,env.team_did,actor.did,team_id=TEAM,alias='bob',identity_scope='local')
    for key in ['member_did_aw','member_address','signature']:
        certificate.pop(key,None)
    certificate['signature']=sign_message(env.team_sk,canonical_json_bytes(certificate))
    (aw/'team-certs/team.pem').write_text(json.dumps(certificate))
    member={'team_id':TEAM,'alias':'bob','cert_path':'team-certs/team.pem'}
    (aw/'teams.yaml').write_text(json.dumps({'active_team':TEAM,'memberships':[member]}))
    (aw/'workspace.yaml').write_text(json.dumps({'aweb_url':str(env.client.base_url),'memberships':[member]}))
    def pem(path,label,data):
        path.write_text(f'-----BEGIN {label}-----\n'+base64.b64encode(data).decode()+f'\n-----END {label}-----\n')
        path.chmod(0o600)
    pem(aw/'signing.key','ED25519 PRIVATE KEY',actor.sk)
    key = env.attachment_keys['bob']
    assertion=key['encryption_key']
    pem(aw/'encryption-keys/local.key','X25519 PRIVATE KEY',key['private_key'])
    (aw/'encryption-keys/assertion.json').write_text(json.dumps(assertion))
    record={'key_id':assertion['encryption_key_id'],'public_key':assertion['encryption_public_key'],
        'private_key_path':'.aw/encryption-keys/local.key','assertion_path':'.aw/encryption-keys/assertion.json',
        **{name:assertion[name] for name in ['created_at','not_before','expires_at']}}
    (aw/'encryption.yaml').write_text(json.dumps({'active_key_id':record['key_id'],'keys':[record]}))
    target=home/'download.pdf'
    child_env={k:v for k,v in os.environ.items() if not k.startswith(('AW_','AWEB_','AWID_','OATS_'))}
    child_env.update(HOME=str(home),AW_NO_UPDATE_CHECK='1',AWID_REGISTRY_URL='http://127.0.0.1:1')
    async def run(*arguments):
        process=await asyncio.create_subprocess_exec(str(binary),*arguments,cwd=home,env=child_env,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        try:
            output,_=await asyncio.wait_for(process.communicate(),30)
            return process.returncode,output.decode()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    code,output=await run('mail','show','--message-id',mid,'--json')
    assert code==0,output
    assert d['filename'] in output and d['id'] in output
    code,output=await run('mail','attachment','fetch',d['id'],'--message-id',mid,'--output',str(target))
    assert code==0,output
    assert target.read_bytes()==b'filebytes'
    code,output=await run('mail','attachment','fetch',d['id'],'--message-id',mid,'--output',str(target))
    assert code!=0 and target.read_bytes()==b'filebytes'


def test_custody_and_mcp_read_never_expose_partial_descriptors():
    from datetime import datetime, timezone
    from aweb.mcp.signing import HostedMessageDecryptionResult
    from aweb.mcp.tools.mail import mcp_mail_message_from_row
    good=descriptor()
    result=HostedMessageDecryptionResult(body='readable text',attachments=[good,{'filename':'../x'}])
    assert result.body=='readable text' and result.attachments==[] and not result.attachments_available
    row=dict(message_id=uuid4(),conversation_id=uuid4(),from_alias='alice',from_address=None,
        to_alias='bob',subject='',body='',priority='normal',read_at=None,created_at=datetime.now(timezone.utc),
        from_did=None,to_did=None,content_mode='encrypted_v2',message_version=2)
    projected=mcp_mail_message_from_row(row,hosted_plaintext=result)
    assert projected['body']=='readable text'
    assert projected['attachments']==[] and not projected['attachments_available']
    valid=mcp_mail_message_from_row(row,hosted_plaintext=HostedMessageDecryptionResult(body='text',attachments=[good]))
    assert valid['attachments']==[good] and valid['attachments_available']


@pytest.mark.asyncio
async def test_attachment_grant_is_subject_scoped_and_read_scope_required(privacy_app):
    from uuid import UUID
    from test_dashboard_privacy import TEAM
    from test_identity_grants import _session_keypair, _grant_headers
    env=privacy_app
    backend,d,wire,cid=await managed_fixture(env)
    sent=await _request(env,'alice','POST','/v1/messages',wire)
    assert sent.status_code==200,sent.text
    url=f"/v1/messages/{sent.json()['message_id']}/attachments/{d['id']}"
    origin=str(env.client.base_url).rstrip('/')
    env.app.state.public_origin=origin
    for actor,scope,expected in [('bob','mail.read',200),('carol','mail.read',404),('bob','chat.read',403)]:
        key,did=_session_keypair()
        grant=uuid4()
        now=datetime.now(timezone.utc)
        await env.db.execute('INSERT INTO {{tables.identity_session_grants}} '
            '(grant_id,team_id,subject_agent_id,grant_did_key,scopes,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
            grant,TEAM,env.actors[actor].id,did,[scope],now,now+timedelta(minutes=10))
        headers=_grant_headers(signing_key=key,did_key=did,grant_id=str(grant),method='GET',path=url,aud=origin)
        fetched=await env.client.get(url,headers=headers)
        assert fetched.status_code==expected,fetched.text
        if expected==200:
            assert fetched.content==b'filebytes'
            await env.db.execute('UPDATE {{tables.identity_session_grants}} SET revoked_at=now() WHERE grant_id=$1',grant)
            revoked=await env.client.get(url,headers=_grant_headers(signing_key=key,did_key=did,grant_id=str(grant),method='GET',path=url,aud=origin))
            assert revoked.status_code==403,revoked.text


@pytest.mark.asyncio
async def test_ref_commitment_tamper_cannot_bind_or_leave_a_message(privacy_app):
    env=privacy_app
    backend,d,wire,cid=await managed_fixture(env)
    wire['attachment_refs'][0]['descriptor_sha256']='0'*64
    failed=await _request(env,'alice','POST','/v1/messages',wire)
    assert failed.status_code==409,failed.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.messages}}')==0
    assert await env.db.fetch_value('SELECT sum(binds) FROM {{tables.attachment_test_storage}}')==0


@pytest.mark.asyncio
@pytest.mark.parametrize('condition',['missing_backend','undecryptable_archive'])
async def test_managed_send_unavailable_before_storage_bind(privacy_app,condition):
    env=privacy_app
    backend,d,wire,cid=await managed_fixture(env)
    if condition=='missing_backend':
        env.app.state.attachment_backend=None
    else:
        env.attachment_keys['alice']['private_key']=b'\0'*32
    failed=await _request(env,'alice','POST','/v1/messages',wire)
    assert failed.status_code==503,failed.text
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.messages}}')==0
    assert await env.db.fetch_value('SELECT sum(binds) FROM {{tables.attachment_test_storage}}')==0


def test_custody_plaintext_result_keeps_old_positional_constructor():
    from aweb.mcp.signing import HostedMessageDecryptionResult
    result=HostedMessageDecryptionResult('subject','body',True,None)
    assert result.subject=='subject' and result.body=='body' and result.decryptable
    assert result.attachments==[] and result.attachments_available


@pytest.mark.parametrize('bad',[{},'',False,0])
def test_present_malformed_attachment_content_is_not_silently_dropped(bad):
    from aweb.attachments import AttachmentError
    with pytest.raises(AttachmentError):
        _inner_payload_map({'kind':'mail','attachments':bad},include_content=True)


@pytest.mark.asyncio
async def test_invalid_envelope_message_id_is_a_safe_refusal(privacy_app):
    env=privacy_app
    backend,d,wire,cid=await managed_fixture(env)
    wire['encrypted_envelope']['message_id']='invalid'
    refused=await _request(env,'alice','POST','/v1/messages',wire)
    assert refused.status_code==422,refused.text
    assert refused.json()['detail']=={'code':'request_invalid'}
    assert await env.db.fetch_value('SELECT count(*) FROM {{tables.messages}}')==0


@pytest.mark.asyncio
@pytest.mark.parametrize('filename',['../x','bad\u202ename','bad\nname'])
async def test_hostile_authenticated_filename_is_refused_at_send(privacy_app,monkeypatch,filename):
    import aweb.e2ee_messages as crypto
    from awid.signing import canonical_json_bytes
    # Produce a correctly authenticated ciphertext from a nonconforming sender.
    # The normal public encrypt helper refuses these names before transport.
    original=crypto._inner_payload_canonical
    def hostile_content(inner):
        inner['attachments'][0]['filename']=filename
        return canonical_json_bytes(inner)
    with monkeypatch.context() as patch:
        patch.setattr(crypto,'_inner_payload_canonical',hostile_content)
        backend,d,wire,cid=await managed_fixture(privacy_app)
    assert crypto._inner_payload_canonical is original
    refused=await _request(privacy_app,'alice','POST','/v1/messages',wire)
    assert refused.status_code==422,refused.text
    assert refused.json()['detail']=={'code':'request_invalid'}
    assert filename not in refused.text
    assert await privacy_app.db.fetch_value('SELECT count(*) FROM {{tables.messages}}')==0
    assert await privacy_app.db.fetch_value('SELECT sum(binds) FROM {{tables.attachment_test_storage}}')==0
