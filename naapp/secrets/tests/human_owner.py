"""Component setup through real H2 and the canonical shared holder writers.

This is not an app bootstrap route. It supplies genuine registered humans and
signed acts to the same shared writers the delivery adapter will consume.
"""

import base64
import hashlib
import os
from contextlib import aclosing, asynccontextmanager
from datetime import UTC, datetime

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, HumanCredential
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier
from aweb_naapp.hooks.strictjson import canonical
from aweb_naapp.roles import PrincipalKey
from aweb_naapp.runtime.human_member import check_human_member
from aweb_naapp.runtime.passkeys import contact_sha256, prepare_retirement
from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member, did_key
from aweb_naapp_testing.owner_acts import TeamOwner
from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential
from awid.did import stable_id_from_public_key
from awid.dns_verify import DomainAuthority
from awid.id_certificates import id_certificate_signing_bytes
from awid.registry import RegistryClient
from awid_service.deps import get_domain_verifier
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

from aweb_secrets.owners import OWNER_ROLE


def member_key(alias):
    # Named, deterministic development identities; no production key is loaded.
    return SigningKey(hashlib.sha256(("secrets-test-human:" + alias).encode()).digest())


def fixture_principal(team_id, alias):
    return PrincipalKey(team_id, stable_id_from_public_key(bytes(member_key(alias).verify_key)))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@asynccontextmanager
async def human(world, principal, *, member=None, client=None):
    if member is not None:
        assert client is not None
        assert member.team_id == principal.team_id
        assert member.extra_cert_fields["member_did_aw"] == principal.principal_did
        yield member, client
        return
    alias = next(
        alias
        for alias in ("alice", "bob", "carol", "other")
        if fixture_principal(principal.team_id, alias) == principal
    )
    root = getattr(world, "human_root", None)
    if root is None:
        root = world.human_root = SigningKey.generate()
        world.human_members = {}

    async def dns(domain):
        assert domain == "example.com"
        return DomainAuthority(did_key(root), REGISTRY_URL, "_awid.example.com")

    world.registry.app.dependency_overrides[get_domain_verifier] = lambda: dns
    world.registry.app.state.awid_public_origins = (REGISTRY_URL,)
    async with aclosing(
        RegistryClient(
            REGISTRY_URL,
            transport=world.registry.transport,
            service_token=SERVICE_TOKEN,
            domain_verifier=dns,
        )
    ) as registry:
        member = world.human_members.get(principal)
        if member is None:
            if not world.human_members:
                await registry.register_namespace("example.com", did_key(root), bytes(root))
            member = Member(
                team_id=principal.team_id,
                team_key=world.owner.team_key,
                member_key=member_key(alias),
                certificate_id="owner-" + alias,
                alias="owner-" + alias,
            )
            mapping = await registry.register_did(member.did_key, bytes(member.member_key))
            assert mapping.did_aw == principal.principal_did
            member.extra_cert_fields = {"member_did_aw": mapping.did_aw}
            await world.registry.add_certificate(member.certificate())
            fields = {
                "v": 1,
                "type": "aweb.id-certificate",
                "id": mapping.did_aw,
                "domain": "example.com",
                "parent": {"kind": "namespace", "id": "example.com"},
                "kind": "human",
                "issuer_key": did_key(root),
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            signed = {
                "certificate": fields,
                "signature": b64(root.sign(id_certificate_signing_bytes(fields)).signature),
            }
            await registry.register_id_certificate(
                {"v": 1, "type": "aweb.id-chain", "certificates": [signed]},
                signer=lambda payload: (member.did_key, member.member_key.sign(payload).signature),
                expected_head=None,
                invitation_id=None,
            )
            world.human_members[principal] = member
        yield member, registry


async def apply_holder(world, act, principal, contact, *, member=None, client=None):
    assert act in ("human-role.designate", "human-credential.replace", "human-role.revoke")
    admitted = world.admitted
    fence = world.console.fence if hasattr(world, "console") else world.fence
    device = None
    credential = None
    subject = dict(
        app_id=admitted.app_id,
        installation_id=admitted.installation_id,
        role=OWNER_ROLE,
        principal=principal.principal_did,
    )
    proof = None
    certificate = None
    if act != "human-role.revoke":
        device = SoftAuthenticator(world.passkeys.rp.origin)
        soft = SoftCredential(
            os.urandom(32),
            ec.generate_private_key(ec.SECP256R1()),
            world.passkeys.rp.rp_id,
            os.urandom(16),
        )
        device.credentials[soft.credential_id] = soft
        credential = HumanCredential(soft.credential_id, soft.cose_public_key(), soft.rp_id)
        subject.update(
            credential_sha256=credential.sha256, notice_contact_sha256=contact_sha256(contact)
        )
        async with human(world, principal, member=member, client=client) as (holder, registry):
            cert = holder.certificate()
            cache = AWIDTeamCache(
                registry_url=REGISTRY_URL,
                ttl_seconds=60,
                transport=world.registry.transport,
                service_token=SERVICE_TOKEN,
            )
            proof = await check_human_member(
                cache,
                registry,
                team_id=principal.team_id,
                principal=principal.principal_did,
                certificate=cert,
            )
            certificate = canonical(cert)
    verifier = OwnerActVerifier(
        scope=world.owner.verifier.scope,
        audience=world.passkeys.rp.origin,
        acts=HUMAN_ROLE_ACTS,
        team_key_for=world.owner.team_key_for,
    )
    owner = TeamOwner(world.owner.team_key, verifier, world.owner.team_id, world.owner.team_key_for)
    signing, signature = owner.sign(act, subject)
    prepared = await owner.verifier.prepare(signing, signature, team_id=principal.team_id)
    context = await world.credential_audit.prepare_owner_act(
        admitted, signing=signing, signature=signature
    )
    with world.credential_audit.prepared(context):
        async with world.db.transaction() as tx:
            await fence.check(tx, admitted)
            verified = await owner.consume(tx, prepared, subject)
            if act != "human-role.designate":
                await prepare_retirement(tx, installation=admitted)
            if act == "human-role.revoke":
                result = await world.passkeys.revoke_holder(tx, act=verified)
            else:
                assert certificate is not None and credential is not None
                writer = (
                    world.passkeys.designate_holder
                    if act == "human-role.designate"
                    else world.passkeys.replace_holder_credential
                )
                result = await writer(
                    tx,
                    act=verified,
                    credential=credential,
                    certificate=certificate,
                    notice_contact=contact,
                )
            await fence.check(tx, admitted)
            if proof is not None:
                proof.require_fresh()
            assert (
                verified.issued_at.replace(tzinfo=UTC)
                <= datetime.now(UTC)
                < verified.expires_at.replace(tzinfo=UTC)
            )
    if result is not None:
        assert device is not None
        await world.passkeys.deliver(result)
        if not hasattr(world, "devices"):
            world.devices = {}
        world.devices[contact] = device
    return result


def canonical_actor(world, principal):
    """The genuine team member whose canonical holding the fixture designated."""
    from aweb_naapp.runtime.team_auth import Principal

    member = world.human_members[principal]
    assert member.extra_cert_fields["member_did_aw"] == principal.principal_did
    return Principal(
        team_id=member.team_id,
        did_key=member.did_key,
        did_aw=principal.principal_did,
        address=None,
        alias=member.alias,
        certificate_id=member.certificate_id,
        team_did_key=member.team_did_key,
        did_aw_registry_verified=True,
    )


async def bind_owner(db, fence, registry, *, team_id):
    """Give a metadata-only DB fixture a real controller-designated holder.

    Uses the same shared writers, verified human and recorder as the existing
    cutover worlds. No role-only shortcut or direct holding-row write.
    """
    from datetime import timedelta
    from types import SimpleNamespace

    from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
    from aweb_naapp.roles import apply_roles_migrations, is_holding_scope
    from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
    from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty
    from aweb_naapp_testing.owner_acts import team_owner

    from aweb_secrets.change_sets import apply_change_set_migrations
    from aweb_secrets.owners import apply_owner_migrations, is_owner_scope
    from aweb_secrets.passkey_context import PasskeyContexts
    from tests.governance import credential_audit
    from tests.test_owner_directory import Audit, Contacts

    store = PgApprovalStore(db)
    await store.migrate()
    await apply_roles_migrations(db)
    await apply_owner_act_migrations(db)
    await fence.refresh(team_id)
    grant = await fence.grants.grant_for(team_id)
    async with db.transaction() as tx:
        admitted = await fence.admit(tx, grant)
    owner = await team_owner(registry, team_id=team_id, acts=HUMAN_ROLE_ACTS)
    # Component credentials and their authorizing act must share the RP host.
    owner.verifier = OwnerActVerifier(
        scope=admitted.app_id,
        audience="https://secrets.example.com",
        acts=HUMAN_ROLE_ACTS,
        team_key_for=owner.team_key_for,
    )
    audit = Audit(db)
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin="https://secrets.example.com", name="Secrets"),
        delivery=Contacts(),
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        holding_scopes=is_holding_scope,
        proof_context=PasskeyContexts(app_id=admitted.app_id),
    )
    await passkeys.migrate()
    await apply_owner_migrations(db)
    await apply_change_set_migrations(db)
    recorder = await credential_audit(
        db=db,
        passkeys=passkeys,
        owner=owner,
        fence=fence,
        admitted=admitted,
        origin=passkeys.rp.origin,
    )
    world = SimpleNamespace(
        db=db,
        fence=fence,
        admitted=admitted,
        owner=owner,
        registry=registry,
        passkeys=passkeys,
        credential_audit=recorder,
    )
    principal = fixture_principal(team_id, "bob")
    await apply_holder(world, "human-role.designate", principal, "fixture-owner@example.com")
    return canonical_actor(world, principal)


async def install_virtual_credential(cdp, authenticator_id, device):
    """Give Chromium the real fixture credential bound by the human-role act."""
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    for credential in device.credentials.values():
        await cdp.send(
            "WebAuthn.addCredential",
            {
                "authenticatorId": authenticator_id,
                "credential": {
                    "credentialId": base64.b64encode(credential.credential_id).decode(),
                    "isResidentCredential": True,
                    "rpId": credential.rp_id,
                    "privateKey": base64.b64encode(
                        credential.key.private_bytes(
                            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
                        )
                    ).decode(),
                    "userHandle": base64.b64encode(credential.user_handle).decode(),
                    "signCount": credential.sign_count,
                },
            },
        )
