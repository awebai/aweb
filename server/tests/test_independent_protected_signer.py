"""One real independent protected effect: customer AWID + PostgreSQL + B2/B3."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.protected_signer import (
    AdmittedHuman,
    ProtectedKeyContext,
    ReceiptReader,
    RevokeHumanRole,
    SignerRefused,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid.did import did_from_public_key
from awid.dns_verify import DomainAuthority
from awid.id_certificates import sign_id_certificate
from awid.signing import canonical_json_bytes, sign_message
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, running_registry
from nacl.signing import SigningKey
from starlette.requests import Request

from aweb.protected_signing.authority import IndependentAuthority
from aweb.protected_signing.composition import (
    MAX_PREPARE_BYTES,
    IndependentProtectedSigner,
)
from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb.protected_signing.registry import CustomerRegistry

DOMAIN, TEAM, SERVICE = (
    "customer.example",
    "engineering:customer.example",
    "customer-signer",
)
ORIGIN, HUMAN_ORIGIN = (
    "https://signer.customer.example",
    "https://human.customer.example",
)


def did(key):
    return did_from_public_key(bytes(key.verify_key))


class Delivery:
    async def deliver_enrolment_link(self, approver, token):
        self.enrolment = token
        return DeliveryStatus.DELIVERED

    async def deliver_approval_link(self, *args):
        return DeliveryStatus.DELIVERED


def proof_request(
    world,
    *,
    key=None,
    authorization=None,
    body=b"{}",
    operation="protected_operation_prepare",
    method="POST",
    path="/protected-operations",
    context=None,
):
    key = key or world.root
    timestamp = datetime.now(UTC).isoformat()
    raw = canonical_json_bytes(
        {
            "v": 2,
            "type": "aweb.awid-controller-request",
            "aud": ORIGIN,
            "domain": DOMAIN,
            "operation": operation,
            "method": method,
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": timestamp,
            "service_id": SERVICE,
            "scope_sha256": hashlib.sha256(
                canonical_json_bytes(
                    (world.context if context is None else context).fields()
                )
            ).hexdigest(),
        }
    )
    headers = {
        "authorization": authorization
        or f"DIDKey {did(key)} {sign_message(bytes(key), raw)}",
        "x-aweb-timestamp": timestamp,
        "x-aweb-signed-payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        },
        receive,
    )


@pytest_asyncio.fixture
async def world(test_db_factory, tmp_path):
    db = await test_db_factory.create_db(suffix="independent_signer", schema="signer")
    registry_db = await test_db_factory.create_db(suffix="customer_awid")
    ns, controller, human_key, root = [SigningKey.generate() for _ in range(4)]
    async with running_registry(
        registry_db.config.get_dsn(), service_token=None
    ) as host:
        host.app.state.awid_public_origins = (REGISTRY_URL,)

        async def namespace_authority(domain):
            assert domain == DOMAIN
            return DomainAuthority(
                controller_did=did(ns),
                registry_url=REGISTRY_URL,
                dns_name="_awid." + DOMAIN,
            )

        host.app.dependency_overrides[get_domain_verifier] = lambda: namespace_authority
        registry = CustomerRegistry(
            registry_origin=REGISTRY_URL,
            namespace_keys={DOMAIN: did(ns)},
            transport=host.transport,
            member_signing_keys={TEAM: bytes(root)},
        )
        try:
            await registry.register_namespace(DOMAIN, did(ns), bytes(ns))
            human_id = (
                await registry.register_did(did(human_key), bytes(human_key))
            ).did_aw
            root_id = (await registry.register_did(did(root), bytes(root))).did_aw
            certificate = await sign_id_certificate(
                {
                    "v": 1,
                    "type": "aweb.id-certificate",
                    "id": human_id,
                    "domain": DOMAIN,
                    "parent": {"kind": "namespace", "id": DOMAIN},
                    "kind": "human",
                    "issuer_key": did(ns),
                    "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                signer=lambda raw: (did(ns), ns.sign(raw).signature),
            )
            await registry.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [certificate]},
                signer=lambda raw: (did(human_key), human_key.sign(raw).signature),
                expected_head=None,
                invitation_id=None,
            )
            await registry.register_team(
                domain=DOMAIN,
                name="engineering",
                display_name="Engineering",
                team_did_key=did(controller),
                visibility="private",
                namespace_controller_signing_key=bytes(ns),
            )
            certificate_id = str(uuid.uuid4())
            member = {
                "version": 1,
                "certificate_id": certificate_id,
                "team_id": TEAM,
                "team_did_key": did(controller),
                "member_did_key": did(root),
                "member_did_aw": root_id,
                "alias": "root",
                "lifetime": "persistent",
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            member["signature"] = sign_message(
                bytes(controller), canonical_json_bytes(member)
            )
            await registry.register_team_certificate(
                DOMAIN,
                "engineering",
                team_controller_signing_key=bytes(controller),
                certificate_id=certificate_id,
                member_did_key=did(root),
                member_did_aw=root_id,
                member_address=None,
                alias="root",
                identity_scope="global",
                certificate=base64.b64encode(canonical_json_bytes(member)).decode(),
            )
            directory = tmp_path / "custody"
            directory.mkdir(mode=0o700)
            path = directory / "controller.key"
            path.write_text(bytes(controller).hex())
            path.chmod(0o600)
            custody = ProtectedControllerCustody(
                service_id=SERVICE,
                team_id=TEAM,
                domain=DOMAIN,
                key_file=path,
                worker_uids=frozenset({65534}),
            )
            context = ProtectedKeyContext(
                SERVICE, "team_controller", TEAM, DOMAIN, human_id, DOMAIN, 1
            )
            delivery = Delivery()
            app = IndependentProtectedSigner(
                db,
                context=context,
                registry=registry,
                custody=custody,
                human_origin=HUMAN_ORIGIN,
                request_origin=ORIGIN,
                delivery=delivery,
            )
            await app.migrate()
            scope, subject = "controller-authorizer", str(uuid.uuid4())
            await db.execute(
                "INSERT INTO {{tables.protected_authorizer_bindings}} "
                "(service_id,team_id,human_id,human_domain,generation,subject,b3_scope,policy_version) "
                "VALUES($1,$2,$3,$4,1,$5,$6,1)",
                SERVICE,
                TEAM,
                human_id,
                DOMAIN,
                subject,
                scope,
            )
            await db.execute(
                "INSERT INTO {{tables.protected_requester_bindings}} "
                "(b3_scope,principal) VALUES($1,$2)",
                scope,
                root_id,
            )
            await db.execute(
                "INSERT INTO {{tables.passkey_approvers}} "
                "(subject,scope,contact,designated_by,designated_at,effective_at) "
                "VALUES($1,$2,'owner@customer.example','operator_bootstrap',now(),now())",
                subject,
                scope,
            )
            async with db.transaction() as tx:
                designation = await app.passkeys.reissue_enrolment(tx, scope=scope)
            await app.passkeys.deliver(designation)
            device = SoftAuthenticator(HUMAN_ORIGIN)
            options = await app.passkeys.enrolment_options(delivery.enrolment)
            await app.passkeys.complete_enrolment(
                delivery.enrolment, device.create(options)
            )
            # Actual B3 LOGIN authenticates the browser before building its
            # in-process actor. This is not a client-deserialized actor DTO.
            login = await app.passkeys.verify_login(
                scope, device.get(await app.passkeys.login_options(scope))
            )
            human = AdmittedHuman(human_id, login.subject, scope, context)
            operation = RevokeHumanRole(
                str(uuid.uuid4()),
                context,
                "https://app.customer.example",
                "customer-app",
                str(uuid.uuid4()),
                "customer.owner",
                human_id,
            )
            yield SimpleNamespace(
                app=app,
                db=db,
                host=host,
                registry=registry,
                controller=controller,
                human=human,
                human_key=human_key,
                human_certificate=certificate,
                context=context,
                operation=operation,
                root=root,
                root_id=root_id,
                device=device,
                scope=scope,
                delivery=delivery,
            )
        finally:
            await registry.aclose()


async def prepare(world):
    requester = await world.app.requester(
        proof_request(world),
        principal=world.root_id,
        operation="protected_operation_prepare",
    )
    return await world.app.signer.prepare(world.operation, requester=requester)


@pytest.mark.asyncio
async def test_one_shared_effect_with_customer_registry_private_reads_and_actual_uv(
    world,
):
    prepared = await prepare(world)
    options = await world.app.signer.approval_options(
        prepared.operation_id, human=world.human
    )
    proof = world.device.get(dict(options))
    receipt = await world.app.signer.execute(
        prepared.operation_id, proof, human=world.human
    )
    assert receipt.state == "committed"
    world.controller.verify_key.verify(
        base64.b64decode(receipt.result["signing"]),
        base64.b64decode(receipt.result["signature"]),
    )
    reader = await world.app.requester(
        proof_request(
            world, body=b"", operation="protected_operation_receipt", method="GET"
        ),
        principal=world.root_id,
        operation="protected_operation_receipt",
    )
    assert type(reader) is ReceiptReader
    assert (
        await world.app.signer.receipt(prepared.operation_id, reader=reader) == receipt
    )
    assert (
        await world.app.signer.execute(prepared.operation_id, proof, human=world.human)
        == receipt
    )
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} "
            "WHERE kind='protected_operation_signed'"
        )
        == 1
    )
    assert all(
        str(call.url).startswith(REGISTRY_URL + "/")
        for call in world.host.transport.calls
    )
    team_reads = [
        call
        for call in world.host.transport.calls
        if call.method == "GET" and "/teams/engineering" in call.url.path
    ]
    assert team_reads and all(
        call.headers["Authorization"].startswith("DIDKey " + did(world.root))
        for call in team_reads
    )
    assert all(
        "x-awid-service-token" not in call.headers
        for call in world.host.transport.calls
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization", ["Bearer stolen-token", "DIDKey plain-key"])
async def test_worker_tokens_and_plain_keys_cannot_prepare(world, authorization):
    from fastapi import HTTPException

    before = len(world.host.transport.calls)
    with pytest.raises(HTTPException):
        await world.app.requester(
            proof_request(world, authorization=authorization),
            principal=world.root_id,
            operation="protected_operation_prepare",
        )
    assert len(world.host.transport.calls) == before


@pytest.mark.asyncio
async def test_unprovisioned_registered_requester_cannot_prepare(world):
    key = SigningKey.generate()
    principal = (await world.registry.register_did(did(key), bytes(key))).did_aw
    requester = await world.app.requester(
        proof_request(world, key=key),
        principal=principal,
        operation="protected_operation_prepare",
    )
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.app.signer.prepare(world.operation, requester=requester)


@pytest.mark.asyncio
async def test_authorizer_removed_between_prepare_and_execute_cannot_sign(world):
    prepared = await prepare(world)
    options = await world.app.signer.approval_options(
        prepared.operation_id, human=world.human
    )
    proof = world.device.get(dict(options))
    await world.db.execute(
        "UPDATE {{tables.protected_authorizer_bindings}} SET active=false"
    )
    with pytest.raises(SignerRefused, match="authority_changed"):
        await world.app.signer.execute(prepared.operation_id, proof, human=world.human)
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} "
            "WHERE kind='protected_operation_signed'"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_registry_outage_has_no_cloud_or_public_fallback(world):
    world.host.transport.down = True
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await prepare(world)
    assert all(
        str(call.url).startswith(REGISTRY_URL + "/")
        for call in world.host.transport.calls
    )


@pytest.mark.asyncio
async def test_oversized_body_refuses_before_proof_or_registry_work(world):
    from awid.request_body_limit import RequestBodyTooLarge

    before = len(world.host.transport.calls)
    with pytest.raises(RequestBodyTooLarge):
        await world.app.requester(
            proof_request(world, body=b"x" * (MAX_PREPARE_BYTES + 1)),
            principal=world.root_id,
            operation="protected_operation_prepare",
        )
    assert len(world.host.transport.calls) == before


@pytest.mark.asyncio
async def test_root_old_key_stops_authenticating_after_continuity_rotation(world):
    next_key = SigningKey.generate()
    await world.registry.rotate_key(
        world.root_id, did(next_key), bytes(world.root), bytes(next_key)
    )
    with pytest.raises(SignerRefused, match="requester_invalid"):
        await world.app.requester(
            proof_request(world),
            principal=world.root_id,
            operation="protected_operation_prepare",
        )
    requester = await world.app.requester(
        proof_request(world, key=next_key),
        principal=world.root_id,
        operation="protected_operation_prepare",
    )
    assert requester.principal == world.root_id


@pytest.mark.asyncio
async def test_policy_changed_after_options_cannot_commit_the_old_approval(world):
    prepared = await prepare(world)
    options = await world.app.signer.approval_options(
        prepared.operation_id, human=world.human
    )
    proof = world.device.get(dict(options))
    await world.db.execute(
        "UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=2"
    )
    with pytest.raises(SignerRefused, match="policy_changed"):
        await world.app.signer.execute(prepared.operation_id, proof, human=world.human)
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} "
            "WHERE kind='protected_operation_signed'"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_changed_registry_controller_cannot_use_the_old_custody_key(world):
    await world.host.rotate_team_key(TEAM, did(SigningKey.generate()))
    with pytest.raises(SignerRefused, match="authority_changed"):
        await prepare(world)


@pytest.mark.asyncio
async def test_agent_with_verified_human_ancestor_cannot_be_an_authorizing_human(world):
    leaf = await sign_id_certificate(
        {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": world.root_id,
            "domain": DOMAIN,
            "parent": {"kind": "identity", "id": world.context.human_id},
            "kind": "agent",
            "issuer_key": did(world.human_key),
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        signer=lambda raw: (did(world.human_key), world.human_key.sign(raw).signature),
    )
    await world.registry.register_id_certificate(
        {
            "v": 1,
            "type": "aweb.id-chain",
            "certificates": [world.human_certificate, leaf],
        },
        signer=lambda raw: (did(world.root), world.root.sign(raw).signature),
        expected_head=None,
        invitation_id=None,
    )
    context = replace(world.context, human_id=world.root_id)
    authority = IndependentAuthority(
        world.db,
        context=context,
        registry=world.registry,
        custody=world.app.authority.custody,
    )
    with pytest.raises(SignerRefused, match="issuer_kind_forbidden"):
        await authority.observe(context, purpose="prepare")


@pytest.mark.asyncio
@pytest.mark.parametrize("elapsed,allowed", [(59, True), (61, False)])
async def test_registry_evidence_deadline_survives_an_actual_authority_lock_wait(
    world, elapsed, allowed
):
    now = 0
    world.app.authority.timer = lambda: now
    task = None
    try:
        async with world.db.transaction() as blocker:
            await blocker.fetch_one(
                "SELECT * FROM {{tables.protected_authorizer_bindings}} FOR UPDATE"
            )
            task = asyncio.create_task(prepare(world))
            # Observe PostgreSQL's lock wait, rather than assuming a sleep
            # allowed the executor to reach its authority fence.
            for _ in range(200):
                await blocker.execute("SELECT pg_stat_clear_snapshot()")
                waiting = await blocker.fetch_value(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                    "AND wait_event_type='Lock' AND query LIKE '%protected_authorizer_bindings%' "
                    "AND pid <> pg_backend_pid()"
                )
                if waiting:
                    break
                if task.done():
                    await task
                    pytest.fail("executor did not wait for authority")
                await asyncio.sleep(0.01)
            assert waiting, "authority lock wait was not established"
            now = elapsed
        if allowed:
            assert (await task).operation_id == world.operation.operation_id
        else:
            with pytest.raises(SignerRefused, match="evidence_unavailable"):
                await task
            assert (
                await world.db.fetch_value(
                    "SELECT count(*) FROM {{tables.protected_signer_operations}}"
                )
                == 0
            )
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_no_uv_cannot_authorize_the_controller_effect(world):
    prepared = await prepare(world)
    options = await world.app.signer.approval_options(
        prepared.operation_id, human=world.human
    )
    with pytest.raises(SignerRefused, match="proof_invalid"):
        await world.app.signer.execute(
            prepared.operation_id,
            world.device.get(dict(options), user_verified=False),
            human=world.human,
        )
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.protected_local_audit}} "
            "WHERE kind='protected_operation_signed'"
        )
        == 0
    )


@pytest.mark.asyncio
async def test_agent_requester_cannot_execute_a_live_floor_operation(world):
    requester = await world.app.requester(
        proof_request(world),
        principal=world.root_id,
        operation="protected_operation_prepare",
    )
    prepared = await world.app.signer.prepare(world.operation, requester=requester)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.app.signer.execute(prepared.operation_id, {}, human=requester)
    with pytest.raises(SignerRefused, match="scope_refused"):
        await world.app.requester(
            proof_request(world),
            principal=world.root_id,
            operation="protected_operation_execute",
        )
