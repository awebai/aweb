"""Existing canonical owners and member requests use the production root.

Owner setup is a shared-writer component; the old HTTP binding path refuses.
"""

import asyncio
import base64
import json
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import dns.asyncresolver as dns_api
import httpx
import pytest
from aweb_naapp.egress import DnsResolver, InternalDestinations
from aweb_naapp.hooks.envelope import KID_PATTERN, verify
from aweb_naapp.roles import PrincipalKey, unassign
from aweb_naapp.runtime.settings import AWIDMemberCredentialFiles
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer
from aweb_naapp_testing.owner_acts import AUDIENCE, TeamOwner
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key
from awid.dns_verify import DnsVerificationError
from awid_service.deps import get_domain_verifier
from awid_service.testing import SERVICE_TOKEN
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey
from pgdbm.core import TransactionManager

from aweb_secrets import jobs, records, runners
from aweb_secrets.composition import create_service
from aweb_secrets.custody import Custody, LocalKeyFileProvider
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretBackend, SecretRecord
from tests.human_owner import apply_holder, fixture_principal, member_key
from tests.production_authority import (
    authority,
    install,
    install_audit_receiver,
    no_dns_override,
)
from tests.production_database import prepared_service_databases as prepared_service_databases
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
async def root(
    test_db_factory,
    prepared_service_databases,
    registry,
    tmp_path,
    request,
    monkeypatch,
    production_settings,
):
    member = Member(team_id="root:example.com", member_key=member_key("alice"))
    options = getattr(request, "param", {})

    async def domain_authority(domain):
        # Forward the test registry's actual namespace authority, never a
        # fabricated record or fallback to the public example.com DNS.
        configured = registry.app.dependency_overrides.get(get_domain_verifier)
        if configured is None:
            raise DnsVerificationError("the test registry has no namespace verifier")
        return await configured()(domain)

    private = options.get("private_team", False)
    async with authority(
        test_db_factory, registry, member, visibility="private" if private else "public"
    ) as (aweb_db, transport):
        database = await prepared_service_databases.create_db(suffix="production_bootstrap")
        with SmtpServer(tmp_path / "smtp") as smtp:
            configured = settings(database, tmp_path, smtp).model_copy(
                update={
                    "public_origin": AUDIENCE,
                    "awid_service_token": SERVICE_TOKEN,
                    **production_settings,
                }
            )
            service_member = None
            if private:
                # An ordinary, separate service seat reads this private team.
                # The production loader consumes its files, never test injection.
                service_member = Member(
                    team_id=member.team_id,
                    team_key=member.team_key,
                    certificate_id="secrets-service",
                    alias="secrets-service",
                )
                await registry.add_certificate(service_member.certificate(), team_key=service_member.team_key)
                key_file = tmp_path / "service-member.key"
                key_file.write_text(
                    "-----BEGIN ED25519 PRIVATE KEY-----\n"
                    + base64.b64encode(bytes(service_member.member_key)).decode()
                    + "\n-----END ED25519 PRIVATE KEY-----\n"
                )
                key_file.chmod(0o600)
                cert_file = tmp_path / "service-member.pem"
                cert_file.write_text(json.dumps(service_member.certificate()))
                cert_file.chmod(0o600)
                configured = configured.model_copy(
                    update={
                        "awid_service_token": None,
                        "awid_member_credentials": {
                            member.team_id: AWIDMemberCredentialFiles(
                                signing_key_file=key_file, certificate_file=cert_file
                            )
                        },
                    }
                )
            service = create_service(
                configured,
                awid_transport=registry.transport,
                awid_domain_verifier=None if options.get("real_identity_dns") else domain_authority,
                team_server_transport=transport,
            )
            service.runtime.team_server_directory()._registry_override = no_dns_override
            # The activated receiver is external fixture state, not a running
            # logs service. Keep the real drain/transport and give its resolver
            # a real local NXDOMAIN answer instead of querying public DNS.
            dns = DnsServer()
            await dns.start()
            # The SDK's AWID authority lookups read TXT through dnspython's
            # default resolver. Point it at the same private server, so a test
            # publishes the TXT evidence it needs and nothing reaches public DNS.
            resolver = dns_api.Resolver(configure=False)
            resolver.nameservers, resolver.port = ["127.0.0.1"], dns.port
            monkeypatch.setattr(dns_api, "default_resolver", resolver)
            hook_transport = service.runtime._hooks.transport
            assert hook_transport is not None
            hook_transport._egress = replace(
                hook_transport._egress,
                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            )
            try:
                async with service.api_app.router.lifespan_context(service.api_app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                        client.owner_fixture_registry = registry
                        client.service_fixture_member = service_member
                        version = getattr(request, "param", {}).get("manifest_version", 2)
                        manifest = await client.get(AUDIENCE + f"/manifests/v{version}.json")
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


@dataclass(frozen=True, repr=False)
class EnrolledOwner:
    scope: str
    body: dict
    token: str | None
    device: SoftAuthenticator
    csrf_token: str


def _production_owner_services(service):
    if service.services is None:
        raise RuntimeError("the production owner services are not running")
    return service.services.owner


def mounted_owner_console(service):
    """Return the console composed for this running application."""
    return _production_owner_services(service).console


def mounted_owner_verifier(service):
    """Return the verifier used by this application's owner-act delivery."""
    return _production_owner_services(service).verifier


async def enrolled_owner(root):
    """Existing-holder component setup, followed by real production LOGIN.

    Supported controller designation is exercised through the production
    owner-act delivery route in test_owner_delivery.
    """
    from types import SimpleNamespace

    service, client, configured, member, installed, smtp, transport, dns = root
    # Read the actual mounted dependency; do not build a second app service or
    # replace its verifier, audit sink, installation lookup or Passkeys.
    console = mounted_owner_console(service)
    fixture = getattr(client, "owner_fixture", None)
    principal = fixture_principal(member.team_id, "alice")
    member.extra_cert_fields = {"member_did_aw": principal.principal_did}
    if fixture is None:
        admitted = await console.installation(installed["installation_id"], team_id=member.team_id)
        verifier = mounted_owner_verifier(service)
        owner = TeamOwner(member.team_key, verifier, member.team_id, verifier.current_team_key)
        fixture = SimpleNamespace(
            db=console.db,
            console=console,
            passkeys=console.passkeys,
            admitted=admitted,
            owner=owner,
            credential_audit=console.credential_audit,
            registry=client.owner_fixture_registry,
        )
        designation = await apply_holder(
            fixture, "human-role.designate", principal, "owner@example.com"
        )
        fixture.scope = designation.approver.scope
        client.owner_fixture = fixture
    scope = fixture.scope
    device = fixture.devices["owner@example.com"]
    human = configured.console_origin
    options = await client.post(human + "/login/options", json={"scope": scope})
    assert options.status_code == 200
    logged = await client.post(
        human + "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert logged.status_code == 200, logged.text
    return EnrolledOwner(
        scope,
        {"principal": principal.principal_did, "contact": "owner@example.com"},
        None,
        device,
        logged.json()["csrf_token"],
    )


async def signed_in_owner(root):
    """The existing three-field owner helper for consumers that need no decision."""
    owner = await enrolled_owner(root)
    return owner.scope, owner.body, owner.token


async def test_a_canonical_component_holder_logs_into_the_production_console(root):
    service, client, configured, member, installed, smtp, transport, dns = root
    human = configured.console_origin
    scope, body, _ = await signed_in_owner(root)
    home = await client.get(human + "/")
    assert home.status_code == 200 and "Secrets console" in home.text
    assert (await client.get(AUDIENCE + "/enrolment")).status_code == 404
    db = service.runtime.db()
    assert await db.fetch_value("SELECT count(*) FROM owner_principals") == 0
    assert await db.fetch_value("SELECT count(*) FROM role_holdings") == 1
    assert await db.fetch_value("SELECT count(*) FROM console_sessions") == 1
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated",
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
    # No enrolment link exists after the cutover: none is stored, a
    # well-formed token B3 never issued is refused, and governance records
    # nothing.
    assert await db.fetch_value("SELECT count(*) FROM passkey_enrolments") == 0
    refused = await client.post(
        human + "/enrolment/options", json={"link_token": secrets.token_urlsafe(32)}
    )
    assert (refused.status_code, refused.json()["detail"]) == (403, "enrolment_refused")
    assert [event["payload"]["act"] for event in await envelopes(db, member.team_id)] == [
        "role.designated",
    ]
    async with asyncio.timeout(5):
        while dns.queries[("logs.example", "A")] == 0:
            await asyncio.sleep(0.01)
    assert dns.queries[("logs.example", "AAAA")] > 0


async def test_the_production_console_serves_the_access_view_only_to_its_current_owner(root):
    service, client, configured, member, installed, smtp, transport, dns = root
    human = configured.console_origin
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as stranger:
        signed_out = await stranger.get(human + "/access")
        assert signed_out.status_code == 303 and signed_out.headers["location"] == "/login"
    assert (await client.get(AUDIENCE + "/access")).status_code == 404
    scope, body, _ = await signed_in_owner(root)
    shown = await client.get(human + "/access")
    assert shown.status_code == 200 and 'id="access-empty"' in shown.text
    assert (await client.get(human + "/console-access/access.js")).status_code == 200
    async with service.runtime.db().transaction() as tx:
        await unassign(
            tx, PrincipalKey(team_id=member.team_id, principal_did=body["principal"]), OWNER_ROLE
        )
    withdrawn = await client.get(human + "/access")
    assert withdrawn.status_code in (303, 401, 403)
    assert 'id="access-empty"' not in withdrawn.text


async def test_the_production_console_serves_audit_delivery_only_to_its_current_owner(root):
    service, client, configured, member, installed, smtp, transport, dns = root
    human = configured.console_origin
    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as stranger:
        signed_out = await stranger.get(human + "/audit-delivery")
        assert signed_out.status_code == 303 and signed_out.headers["location"] == "/login"
    assert (await client.get(AUDIENCE + "/audit-delivery")).status_code == 404
    scope, body, _ = await signed_in_owner(root)
    shown = await client.get(human + "/audit-delivery")
    assert shown.status_code == 200
    page = shown.text
    # Core's governance registration reaches the page, and the enrolment's
    # change records are owed to it but not yet stalled.
    assert 'data-hook="post-governance-hook" data-admission="open"' in page
    assert 'data-stalled="false"' in page and 'data-stalled="true"' not in page
    assert 'data-total="0"' in page
    css = await client.get(human + "/console-audit-delivery/audit.css")
    assert css.status_code == 200
    assert "audit-banner" not in (await client.get(human + "/")).text
    # Once the enrolment's change records wait past the configured bound, the
    # page and the owner's home both say widening changes are refused.
    db = service.runtime.db()
    bound = timedelta(seconds=configured.hook_events_stalled_after_seconds)
    await db.execute(
        "UPDATE {{tables.outbox_events}} SET created_at = created_at - $1::interval",
        2 * bound,
    )
    stalled = (await client.get(human + "/audit-delivery")).text
    assert 'data-hook="post-governance-hook" data-admission="refused"' in stalled
    home = (await client.get(human + "/")).text
    assert 'data-refused="post-governance-hook" data-undelivered="0"' in home
    async with service.runtime.db().transaction() as tx:
        await unassign(
            tx, PrincipalKey(team_id=member.team_id, principal_did=body["principal"]), OWNER_ROLE
        )
    withdrawn = await client.get(human + "/audit-delivery")
    assert withdrawn.status_code in (303, 401, 403)
    assert "data-hook=" not in withdrawn.text


@dataclass(repr=False)
class ProductionRequest:
    token: str | None
    device: SoftAuthenticator
    path: str
    raw: bytes
    reply: dict
    job_id: str
    runner_id: str
    runner_signing_key: SigningKey
    runner_encryption_key: X25519PrivateKey
    credential: str


class ApprovalAction(StrEnum):
    USE = "use"
    RUN = "run"


@dataclass(frozen=True, kw_only=True)
class MemberToolRequest:
    path: str
    raw: bytes


def _approval_destination(
    *, operation: OperationTemplate | None, agent_headers: Sequence[tuple[str, str]]
) -> DestinationRecord:
    """Permit exactly the fixed and agent headers used by this fixture (§7.4)."""
    fixed_header_names = (
        ()
        if operation is None
        else tuple(name.lower() for name in operation.after["headers"]["fixed"])
    )
    return DestinationRecord.from_after(
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
            "header_allow": sorted(
                {
                    "content-type",
                    *fixed_header_names,
                    *(name.lower() for name, _ in agent_headers),
                }
            ),
            "network": "public",
            "cidr": None,
        },
        internal_destinations=InternalDestinations.DISABLED,
    )


async def _stage_approval_secret(
    *,
    db,
    installation_id: str,
    member: Member,
    custody: Custody,
    operation: OperationTemplate | None,
    credential: str,
    onepassword_values,
) -> None:
    """Observe confirmed fixture metadata through the real remote custody path."""
    record = SecretRecord.from_after({**SECRET, "backend": SecretBackend.ONEPASSWORD})
    async with db.transaction() as tx:
        await records.create_secret(tx, installation_id, member.team_id, record)
        if operation is not None:
            await records.create_operation(tx, installation_id, member.team_id, operation)
    await onepassword_values.activate(
        db=db,
        custody=custody,
        installation_id=installation_id,
        team_id=member.team_id,
        record=record,
        values={"value": credential},
    )


async def _register_approval_runner(
    tx: TransactionManager,
    *,
    installation_id: str,
    member: Member,
    job: jobs.JobDefinition,
    runner_signing_key: SigningKey,
    runner_encryption_key: X25519PrivateKey,
) -> None:
    """Register the real fixture runner using its generated public keys."""
    from aweb_naapp.hooks.strictjson import encode_base64url

    runner_id = job.after["runner_ids"][0]
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
        signing_key=did_from_public_key(bytes(runner_signing_key.verify_key)),
        encryption_key=encode_base64url(runner_encryption_key.public_key().public_bytes_raw()),
    )


def _member_approval_request(
    *,
    kind: ApprovalAction,
    job,
    runner_id,
    operation,
    params,
    agent_headers,
    request_id: str,
    reason: str = "",
) -> MemberToolRequest:
    """Build the one signed member submission used for production approval tests."""
    path = (
        "/v1/secrets/" + SECRET["ref"] + "/requests"
        if kind is ApprovalAction.USE
        else "/v1/jobs/" + job.job_id + "/runs"
    )
    request = {"request_id": request_id}
    request.update(
        {"method": "POST", "url": "https://api.payments.example/v1/charge", "data": "hello"}
        if kind is ApprovalAction.USE
        else {"runner": runner_id, "params": {"database": "orders"}}
    )
    if operation is not None:
        request = {
            "request_id": request["request_id"],
            "operation": operation.operation_id,
            "params": params or {},
        }
    if agent_headers:
        request["headers"] = [name + ": " + value for name, value in agent_headers]
    if reason:
        request["reason"] = reason
    raw = json.dumps(request).encode()
    return MemberToolRequest(path=path, raw=raw)


def _approval_policy(*, member: Member, operation: OperationTemplate | None) -> Policy:
    """Build the confirmed fixture policy for the member and optional operation (§4.4)."""
    operations = (
        []
        if operation is None
        else [{"operation_id": operation.operation_id, "digest": operation.digest}]
    )
    return Policy.from_body(
        {
            **POLICY_BODY,
            "approvers": ["owner:" + member.extra_cert_fields["member_did_aw"]],
            "operations": operations,
            "open_request": operation is None,
        }
    )


def _approval_grant(
    *, member: Member, kind: ApprovalAction, policy: Policy, job: jobs.JobDefinition
) -> GrantRecord:
    """Build the exact fixture grant selected by the named use/run action (§4.3)."""
    return GrantRecord.from_after(
        {
            "v": 1,
            "grant_id": "grt_root_dispatch",
            "secret_id": SECRET["secret_id"],
            "subject": {"principal": member.extra_cert_fields["member_did_aw"]},
            "capability": kind.value,
            "operations": policy.body["operations"],
            "open_request": kind is ApprovalAction.USE and policy.body["open_request"],
            "jobs": []
            if kind is ApprovalAction.USE
            else [{"job_id": job.job_id, "digest": job.digest}],
            "policy_digest": policy.digest,
        }
    )


async def approval_request(
    root,
    *,
    kind: ApprovalAction,
    onepassword_values,
    agent_headers: Sequence[tuple[str, str]] = (),
    operation: OperationTemplate | None = None,
    params: Mapping[str, Any] | None = None,
    job_timeout_seconds: int | None = None,
    reason: str = "",
) -> ProductionRequest:
    """Seed confirmed metadata, then mint through the actual signed root tool.

    Configuration is fixture state; B1, admission, B2 association/audit and TLS
    mail delivery all run in the production composition, without a second B2.
    """
    service, client, configured, member, installed, smtp, _, _ = root
    installation_id = installed["installation_id"]
    holder = await enrolled_owner(root)
    body, device = holder.body, holder.device
    policy = _approval_policy(member=member, operation=operation)
    db = service.runtime.db()
    custody = Custody(LocalKeyFileProvider(configured.custody_key_file), db)
    job_body = job_after()
    if job_timeout_seconds is not None:
        job_body["timeout_s"] = job_timeout_seconds
    job_body["credentials"][0]["secret_ref"] = SECRET["ref"]
    job_body["env"] = {"DB_ADMIN": {"$credential": SECRET["ref"], "field": "value"}}
    job = jobs.JobDefinition.from_after(job_body)
    runner_id = job.after["runner_ids"][0]
    runner_signing_key = SigningKey.generate()
    runner_encryption_key = X25519PrivateKey.generate()
    credential = uuid4().hex
    await _stage_approval_secret(
        db=db,
        installation_id=installation_id,
        member=member,
        custody=custody,
        operation=operation,
        credential=credential,
        onepassword_values=onepassword_values,
    )
    async with db.transaction() as tx:
        await records.create_policy(tx, installation_id, policy, team_id=member.team_id)
        await records.create_grant(
            tx,
            installation_id,
            member.team_id,
            _approval_grant(member=member, kind=kind, policy=policy, job=job),
        )
        if kind is ApprovalAction.USE:
            await records.create_destination(
                tx,
                installation_id,
                member.team_id,
                _approval_destination(operation=operation, agent_headers=agent_headers),
            )
        else:
            await _register_approval_runner(
                tx,
                installation_id=installation_id,
                member=member,
                job=job,
                runner_signing_key=runner_signing_key,
                runner_encryption_key=runner_encryption_key,
            )
    submission = _member_approval_request(
        kind=kind,
        job=job,
        runner_id=runner_id,
        operation=operation,
        params=params,
        agent_headers=agent_headers,
        request_id=uuid4().hex,
        reason=reason,
    )
    path, raw = submission.path, submission.raw
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
    return ProductionRequest(
        token=token,
        device=device,
        path=path,
        raw=raw,
        reply=reply.json(),
        job_id=job.job_id,
        runner_id=runner_id,
        runner_signing_key=runner_signing_key,
        runner_encryption_key=runner_encryption_key,
        credential=credential,
    )


@pytest.mark.parametrize(
    "kind,path", [(ApprovalAction.USE, "/use-approvals"), (ApprovalAction.RUN, "/run-approvals")]
)
async def test_production_email_dispatch_uses_migrated_and_mounted_providers(
    root, kind, path, *, onepassword_values
):
    service, client, configured, *_ = root
    pending = await approval_request(root, kind=kind, onepassword_values=onepassword_values)
    token = pending.token
    db = service.runtime.db()
    # Typed use/run links coexist with the production settlement association.
    assert await db.fetch_value("SELECT to_regclass('reconciliation_controls')") is not None
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
