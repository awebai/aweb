"""First owner and member requests go through the actual production root."""

import asyncio
import base64
import json
from dataclasses import replace
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.egress import DnsResolver, InternalDestinations
from aweb_naapp.hooks.envelope import KID_PATTERN, verify
from aweb_naapp.runtime.passkeys import contact_sha256
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key
from awid_service.testing import SERVICE_TOKEN
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey

from aweb_secrets import jobs, records, runners
from aweb_secrets.composition import create_service
from aweb_secrets.custody import Custody, LocalKeyFileProvider, encode_value
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.owners import owner_scope
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from tests.production_authority import authority, install, install_audit_receiver, no_dns_override
from tests.test_composition import settings
from tests.test_console_bootstrap import delivered_url
from tests.test_jobs import after as job_after
from tests.test_use_approvals import POLICY_BODY, SECRET


def test_committed_hook_keys_match_the_shared_event_and_delivery_identifier_contract():
    manifest = json.loads(MANIFEST_PATH.read_bytes())
    for key in manifest["app_keys"]:
        if {"hook-event", "hook-delivery"}.intersection(key["purposes"]):
            assert KID_PATTERN.fullmatch(key["kid"]), key["kid"]


async def envelopes(db, team_id):
    rows = await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
    return [verify(bytes(row["payload"]), row["signature"], team_id=team_id).fields for row in rows]


@pytest.fixture
async def root(test_db_factory, registry, tmp_path):
    member = Member(team_id="root:example.com")
    async with authority(test_db_factory, registry, member) as (aweb_db, transport):
        database = await test_db_factory.create_db(suffix="production_bootstrap")
        with SmtpServer(tmp_path / "smtp") as smtp:
            configured = settings(database, tmp_path, smtp).model_copy(
                update={
                    "public_origin": AUDIENCE,
                    "awid_service_token": SERVICE_TOKEN,
                }
            )
            service = create_service(
                configured,
                awid_transport=registry.transport,
                team_server_transport=transport,
            )
            service.runtime.team_server_directory()._registry_override = no_dns_override
            # The activated receiver is external fixture state, not a running
            # logs service. Keep the real drain/transport and give its resolver
            # a real local NXDOMAIN answer instead of querying public DNS.
            dns = DnsServer()
            await dns.start()
            hook_transport = service.runtime._hooks.transport
            assert hook_transport is not None
            hook_transport._egress = replace(
                hook_transport._egress,
                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            )
            try:
                async with service.api_app.router.lifespan_context(service.api_app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                        manifest = await client.get(AUDIENCE + "/manifests/v2.json")
                        assert manifest.status_code == 200
                        installed = await install(
                            aweb_db,
                            member,
                            manifest.content,
                            ["secrets:read", "secrets:use", "secrets:run", "secrets:admin"],
                        )
                        await install_audit_receiver(aweb_db, member)
                        assert (
                            await service.runtime.db().fetch_value(
                                "SELECT count(*) FROM installation_fences"
                            )
                            == 0
                        )
                        yield service, client, configured, member, installed, smtp, transport, dns
            finally:
                dns.close()


def owner_body(configured, member, installation_id):
    principal, contact = member.did_key, "owner@example.com"
    scope = owner_scope(installation_id, member.team_id, principal)
    # Only signing is used from the shared throwaway team-owner helper; the
    # production root builds and runs its own K2 verifier against actual AWID.
    owner = TeamOwner(member.team_key, verifier=None, team_id=member.team_id)
    signing, signature = owner.sign(
        "app-role.designate",
        {
            "app_id": configured.app_id,
            "installation_id": installation_id,
            "role": scope,
            "contact_sha256": contact_sha256(contact),
        },
    )
    return scope, {
        "signing": base64.b64encode(signing).decode(),
        "signature": signature,
        "team_id": member.team_id,
        "principal": principal,
        "contact": contact,
    }


async def test_first_owner_enrols_from_actual_smtp_and_logs_into_production_console(root):
    service, client, configured, member, installed, smtp, transport, dns = root
    installation_id = installed["installation_id"]
    scope, body = owner_body(configured, member, installation_id)
    human = configured.console_origin
    response = await client.post(human + f"/installations/{installation_id}/owner-acts", json=body)
    assert response.status_code == 200, (response.status_code, response.text)
    url = delivered_url(smtp.received, contact=body["contact"], path="/enrolment")
    assert (await client.get(url)).status_code == 200
    [token] = parse_qs(urlsplit(url).fragment)["token"]
    device = SoftAuthenticator(human)
    options = await client.post(human + "/enrolment/options", json={"link_token": token})
    assert options.status_code == 200
    enrolled = await client.post(
        human + "/enrolment",
        json={"link_token": token, "credential": device.create(options.json())},
    )
    assert enrolled.status_code == 200, enrolled.text
    options = await client.post(human + "/login/options", json={"scope": scope})
    assert options.status_code == 200
    logged = await client.post(
        human + "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert logged.status_code == 200, logged.text
    home = await client.get(human + "/")
    assert home.status_code == 200 and "Secrets console" in home.text
    assert (await client.get(AUDIENCE + "/enrolment")).status_code == 404
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM owner_principals") == 1
    assert await db.fetch_value("SELECT count(*) FROM console_sessions") == 1
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated",
        "credential.enrolled",
    ]
    assert any(call.url.path.endswith("/self/grant") for call in transport.calls)
    assert any(
        call.url.path.endswith("/post-governance-hook/registrations") for call in transport.calls
    )
    # B1 authorizes the genuine registered member through the real team-server
    # grant; Catalog sees the same installation/owner state and no secret rows.
    headers = member.headers(aud=AUDIENCE, method="GET", path="/v1/secrets")
    listed = await client.get(AUDIENCE + "/v1/secrets", headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["result"]["secrets"] == []
    assert (await client.get(AUDIENCE + "/v1/secrets")).status_code == 401
    assert (
        await client.post(human + "/enrolment/options", json={"link_token": token})
    ).status_code == 403
    async with asyncio.timeout(5):
        while dns.queries[("logs.example", "A")] == 0:
            await asyncio.sleep(0.01)
    assert dns.queries[("logs.example", "AAAA")] > 0


@pytest.mark.parametrize("fault", ["wrong_team", "wrong_installation", "unavailable"])
async def test_bootstrap_authority_controls_leave_no_owner_nonce_or_audit(root, fault):
    service, client, configured, member, installed, smtp, transport, _ = root
    installation_id = installed["installation_id"]
    _, body = owner_body(configured, member, installation_id)
    if fault == "wrong_team":
        body["team_id"] = "other:example.com"
    elif fault == "wrong_installation":
        installation_id = str(uuid4())
    else:
        transport.down = True
    response = await client.post(
        configured.console_origin + f"/installations/{installation_id}/owner-acts", json=body
    )
    expected = {
        "wrong_team": (503, "authority_unavailable"),
        "wrong_installation": (403, "owner_required"),
        "unavailable": (503, "authority_unavailable"),
    }[fault]
    assert (response.status_code, response.json()) == (expected[0], {"detail": expected[1]})
    db = service.runtime.db()
    for table in (
        "owner_principals",
        "owner_act_nonces",
        "credential_authorizations",
        "passkey_approvers",
    ):
        assert await db.fetch_value("SELECT count(*) FROM " + table) == 0, table
    assert await envelopes(db, member.team_id) == []
    assert smtp.received == []


async def approval_request(root, kind):
    """Seed confirmed metadata, then mint through the actual signed root tool.

    Configuration is fixture state; B1, admission, B2 association/audit and TLS
    mail delivery all run in the production composition, without a second B2.
    """
    service, client, configured, member, installed, smtp, _, _ = root
    installation_id = installed["installation_id"]
    scope, body = owner_body(configured, member, installation_id)
    human = configured.console_origin
    designated = await client.post(
        human + f"/installations/{installation_id}/owner-acts", json=body
    )
    assert designated.status_code == 200
    url = delivered_url(smtp.received, contact=body["contact"], path="/enrolment")
    [token] = parse_qs(urlsplit(url).fragment)["token"]
    options = await client.post(human + "/enrolment/options", json={"link_token": token})
    enrolled = await client.post(
        human + "/enrolment",
        json={"link_token": token, "credential": SoftAuthenticator(human).create(options.json())},
    )
    assert enrolled.status_code == 200
    policy = Policy.from_body({**POLICY_BODY, "approvers": ["owner:" + member.did_key]})
    db = service.runtime.db()
    custody = Custody(LocalKeyFileProvider(configured.custody_key_file), db)
    job_body = job_after()
    job_body["credentials"][0]["secret_ref"] = SECRET["ref"]
    job_body["env"] = {"DB_ADMIN": {"$credential": SECRET["ref"], "field": "value"}}
    job = jobs.JobDefinition.from_after(job_body)
    runner_id = job.after["runner_ids"][0]
    async with db.transaction() as tx:
        await records.create_policy(tx, installation_id, policy)
        await records.create_secret(
            tx, installation_id, member.team_id, SecretRecord.from_after(SECRET)
        )
        version = await custody.sealer.ingest(
            tx,
            installation_id=installation_id,
            team_id=member.team_id,
            secret_id=SECRET["secret_id"],
            value=encode_value("bearer", {"value": uuid4().hex}),
        )
        await records.set_active_version(
            tx, installation_id, member.team_id, SECRET["secret_id"], version
        )
        await records.create_grant(
            tx,
            installation_id,
            member.team_id,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_root_dispatch",
                    "secret_id": SECRET["secret_id"],
                    "subject": {"principal": member.did_key},
                    "capability": "use" if kind == "use" else "run",
                    "operations": [],
                    "open_request": kind == "use",
                    "jobs": [] if kind == "use" else [{"job_id": job.job_id, "digest": job.digest}],
                    "policy_digest": policy.digest,
                }
            ),
        )
        if kind == "use":
            await records.create_destination(
                tx,
                installation_id,
                member.team_id,
                DestinationRecord.from_after(
                    {
                        "v": 1,
                        "destination_id": "dst_root_dispatch",
                        "secret_id": SECRET["secret_id"],
                        "scheme": "https",
                        "host": "api.payments.example",
                        "port": 443,
                        "path": "/v1/**",
                        "methods": ["POST"],
                        "query_rules": {},
                        "header_allow": ["content-type"],
                        "network": "public",
                        "cidr": None,
                    },
                    internal_destinations=InternalDestinations.DISABLED,
                ),
            )
        else:
            from aweb_naapp.hooks.strictjson import encode_base64url

            await jobs.create_job(tx, installation_id, member.team_id, job)
            runner = runners.RunnerRecord.from_after(
                {
                    "v": 1,
                    "runner_id": runner_id,
                    "label": "Root dispatch",
                    "allowed_jobs": [job.job_id],
                }
            )
            code = await runners.create_runner(
                tx, installation_id, member.team_id, runner, now=datetime.now(UTC)
            )
            await runners.register_runner(
                tx,
                code=code,
                signing_key=did_from_public_key(bytes(SigningKey.generate().verify_key)),
                encryption_key=encode_base64url(
                    X25519PrivateKey.generate().public_key().public_bytes_raw()
                ),
            )
    path = (
        "/v1/secrets/" + SECRET["ref"] + "/requests"
        if kind == "use"
        else "/v1/jobs/" + job.job_id + "/runs"
    )
    request = {"request_id": uuid4().hex}
    request.update(
        {"method": "POST", "url": "https://api.payments.example/v1/charge", "data": "hello"}
        if kind == "use"
        else {"runner": runner_id, "params": {"database": "orders"}}
    )
    raw = json.dumps(request).encode()
    reply = await client.post(
        AUDIENCE + path,
        content=raw,
        headers=member.headers(aud=AUDIENCE, method="POST", path=path, body=raw)
        | {"Content-Type": "application/json"},
    )
    assert reply.status_code == 202 and reply.json()["state"] == "awaiting_approval", reply.text
    url = delivered_url(smtp.received, contact=body["contact"], path="/approvals")
    assert urlsplit(url).path == "/approvals"
    [token] = parse_qs(urlsplit(url).fragment)["token"]
    return token


@pytest.mark.parametrize("kind,path", [("use", "/use-approvals"), ("run", "/run-approvals")])
async def test_production_email_dispatch_uses_migrated_and_mounted_providers(root, kind, path):
    service, client, configured, *_ = root
    token = await approval_request(root, kind)
    db = service.runtime.db()
    # Reconciliation is deliberately uncomposed: routing must not query its tables.
    assert await db.fetch_value("SELECT to_regclass('reconciliation_controls')") is None
    before = await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
    for _ in range(2):
        dispatched = await client.post(
            configured.console_origin + "/approvals/dispatch", json={"token": token}
        )
        assert dispatched.status_code == 200, dispatched.text
        assert dispatched.json() == {"kind": kind, "path": path}
        assert (await client.get(configured.console_origin + path)).status_code == 200
    assert (await client.get(AUDIENCE + path)).status_code == 404
    assert await db.fetch_value("SELECT state FROM approvals") == "pending"
    assert (
        await db.fetch_all("SELECT payload,signature FROM outbox_events ORDER BY position")
        == before
    )
