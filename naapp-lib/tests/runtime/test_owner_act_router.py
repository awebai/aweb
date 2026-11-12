"""Anonymous delivery through real AWID, G1, PostgreSQL and a small SQL app.

The app implements the effect protocol with transactional rows/outbox writes.
It does not replace the verifier, registry, installation fence or rate limiter.
Canonical B3 writer coverage stays with the shared human-role effect's tests.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import monotonic_ns
from uuid import uuid4

import httpx
import pytest
from aweb.app_manifests import FetchedManifest
from aweb.installations import install_verified_manifest_on
from aweb_naapp_testing.owner_acts import TeamOwner
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import APIRouter, FastAPI
from nacl.signing import SigningKey

from aweb_naapp import outbox
from aweb_naapp.console import ClientIdentity
from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, HumanCredential
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
from aweb_naapp.manifest import canonical_bytes, load_manifest
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.installation import apply_installation_migrations
from aweb_naapp.runtime.owner_act_delivery import (
    OwnerActDeliveryRefused,
    OwnerActEffectResult,
)
from aweb_naapp.runtime.passkeys import contact_sha256
from tests.runtime.approvals.test_human_role_holders import holder
from tests.runtime.test_human_member import human_of
from tests.runtime.test_served_manifest import ExampleSettings, _key_file, _v2_template

pytest_plugins = ("tests.runtime.test_human_member",)
ORIGIN = "https://app.example.com"
PATH = "/.well-known/aweb-owner-act"
ROLE = "example.owner"
NOTICE = "owner@example.test"


@pytest.fixture
def registry(coordination):
    return coordination.registry


@pytest.fixture
async def human(registry):
    # A team of its own: the coordination server caches each team's key for
    # 60 seconds in the Redis every test shares, so a fixed team id would
    # meet the key of an earlier test (or the other worker) there.
    async with human_of(registry, f"people-{uuid4().hex[:12]}:example.com") as registered:
        yield registered


@dataclass
class SqlEffect:
    """A relying app with actual SQL holdings and durable governance events."""

    runtime: NaappRuntime
    identity_client: object
    fail_write: bool = False
    fail_notice: str | None = None
    fail_governance: bool = False
    prepares: int = 0
    prepared: object = None
    applied: asyncio.Event = None
    committed: int = 0

    async def prepare(self, *, installation, delivery):
        self.prepares += 1
        db = self.runtime.db()
        current = await db.fetch_value(
            "SELECT credential FROM {{tables.delivery_holders}} WHERE principal=$1",
            delivery.subject["principal"],
        )
        if (delivery.act == "human-role.designate") == (current is not None):
            raise OwnerActDeliveryRefused("owner_required")
        checked = None
        if delivery.act != "human-role.revoke":
            checked = await self.runtime.check_human_role_member(
                delivery.team_id,
                principal=delivery.subject["principal"],
                certificate=delivery.certificate,
                identity_client=self.identity_client,
            )
        expected = {
            "app_id": installation.app_id,
            "installation_id": installation.installation_id,
            "role": ROLE,
            "principal": delivery.subject["principal"],
        }
        if delivery.credential is not None:
            expected["credential_sha256"] = delivery.credential.sha256
            expected["notice_contact_sha256"] = contact_sha256(delivery.notice_contact)
        prepared = SqlPreparedEffect(self, delivery, checked, expected)
        self.prepared = prepared
        return prepared


@dataclass
class SqlPreparedEffect:
    app: SqlEffect
    delivery: object
    checked: object
    expected_subject: dict

    async def apply(self, tx, *, installation, act):
        assert act.transaction_id == await tx.fetch_value("SELECT txid_current()")
        # An actual later authority gate, used by the observed lock-wait test.
        await tx.fetch_value("SELECT id FROM {{tables.delivery_gate}} WHERE id=1 FOR UPDATE")
        previous = await tx.fetch_value(
            "SELECT credential FROM {{tables.delivery_holders}} WHERE principal=$1 FOR UPDATE",
            act.subject["principal"],
        )
        if (act.act == "human-role.designate") == (previous is not None):
            raise OwnerActDeliveryRefused("owner_required")
        if act.act == "human-role.revoke":
            await tx.execute(
                "DELETE FROM {{tables.delivery_holders}} WHERE principal=$1",
                act.subject["principal"],
            )
        else:
            await tx.execute(
                "INSERT INTO {{tables.delivery_holders}} (principal,credential) VALUES($1,$2) "
                "ON CONFLICT(principal) DO UPDATE SET credential=EXCLUDED.credential",
                act.subject["principal"],
                self.delivery.credential.credential_id,
            )
        occurred = datetime.now(UTC)
        from uuid import uuid4

        await outbox.enqueue(
            tx,
            outbox.OutboxEvent(
                event_id=uuid4(),
                team_id=installation.team_id,
                kind="governance",
                occurred_at=occurred,
                payload=canonical_bytes({"act": act.act}),
            ),
        )
        self.app.applied.set()
        if self.app.fail_write:
            raise OwnerActDeliveryRefused("owner_required")
        if self.app.fail_governance:
            from aweb_naapp.runtime.credential_audit import GovernanceUnavailable

            raise GovernanceUnavailable()
        return OwnerActEffectResult(act.act, ROLE, act.subject["principal"], occurred)

    def require_fresh(self):
        if self.checked is not None:
            self.checked.require_fresh()

    async def after_commit(self, result):
        assert await self.app.runtime.db().fetch_value(
            "SELECT count(*) FROM {{tables.owner_act_nonces}}"
        )
        self.app.committed += 1
        if self.app.fail_notice:
            if self.app.fail_notice == "timeout":
                from aweb_naapp.email import EmailNotSent

                raise EmailNotSent("timeout")
            raise RuntimeError("notice delivery failed")


@dataclass
class World:
    runtime: NaappRuntime
    app: FastAPI
    effect: SqlEffect
    owner: TeamOwner
    member: object
    principal: str
    installation: dict
    coordination: object

    def body(self, *, act="human-role.designate", credential=None, principal=None):
        credential = credential or holder(rp_id="app.example.com").body
        subject = {
            "app_id": "example",
            "installation_id": self.installation["installation_id"],
            "role": ROLE,
            "principal": principal or self.principal,
        }
        if act != "human-role.revoke":
            subject.update(
                credential_sha256=HumanCredential.parse(credential).sha256,
                notice_contact_sha256=contact_sha256(NOTICE),
            )
        signing, signature = self.owner.sign(act, subject)
        body = {"signing": base64.b64encode(signing).decode(), "signature": signature}
        if act != "human-role.revoke":
            body.update(
                credential=credential,
                notice_contact=NOTICE,
                certificate=base64.b64encode(
                    json.dumps(self.member.certificate()).encode()
                ).decode(),
            )
        return body

    async def post(self, body, *, host="127.0.0.1", headers=None):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app, client=(host, 1234)),
            base_url=ORIGIN,
        ) as client:
            return await client.post(PATH, json=body, headers=headers)

    async def counts(self):
        db = self.runtime.db()
        return tuple(
            [
                await db.fetch_value(f"SELECT count(*) FROM {{{{tables.{name}}}}}")
                for name in ("owner_act_nonces", "delivery_holders", "outbox_events")
            ]
        )


@pytest.fixture
async def world(tmp_path, human, coordination, test_db_factory):
    from aweb_naapp.runtime.owner_act_router import OwnerActLimiter, mount_owner_act_routes

    member, principal, _, _, _ = human
    await coordination.connect(member)
    await coordination.publish_server(member)
    db = await test_db_factory.create_db(suffix="owner_act_router")
    key = SigningKey.generate()
    key_path = _key_file(tmp_path, "grant-read", bytes(key).hex())
    template = _v2_template(("grant-read", ["app-grant-read"]))
    template["app"]["version"] = "1.0.0"
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(template))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    runtime = NaappRuntime(
        ExampleSettings(
            _env_file=None,
            database_url=db.config.get_dsn(),
            db_schema=db.config.schema_name,
            app_key_files={"grant-read": key_path},
            awid_registry_url=REGISTRY_URL,
            awid_service_token=SERVICE_TOKEN,
            auth_cache_ttl_seconds=2,
        ),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        owner_acts={
            "roles": [
                {
                    "name": ROLE,
                    "label": "Owner",
                    "acts": list(HUMAN_ROLE_ACTS),
                    "notice_contact": True,
                }
            ]
        },
        owner_acts_origin=ORIGIN,
        stores=(
            apply_installation_migrations,
            apply_owner_act_migrations,
            apply_ratelimit_migrations,
        ),
        awid_transport=coordination.registry.transport,
        team_server_transport=coordination.server.transport,
    )

    # Explicitly select this test's real registry instead of external DNS discovery.
    async def registry_authority(domain):
        return REGISTRY_URL

    runtime.team_server_directory()._registry_override = registry_authority
    data = runtime.manifest_bytes
    fetched = FetchedManifest(
        origin=runtime.settings.public_origin,
        url=runtime.settings.public_origin + "/manifests/v3.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=load_manifest(data),
    )
    async with coordination.server.db.get_manager().transaction() as tx:
        installation = await install_verified_manifest_on(
            tx,
            team_id=member.team_id,
            fetched=fetched,
            granted_scopes=list(runtime.manifest.install_scopes),
        )

    async def current_key(team):
        return (await runtime.team_cache().get(team)).team_did_key

    verifier = OwnerActVerifier(
        scope="example", audience=ORIGIN, acts=HUMAN_ROLE_ACTS, team_key_for=current_key
    )
    owner = TeamOwner(member.team_key, verifier, member.team_id, current_key)
    effect = SqlEffect(runtime, human[2], applied=asyncio.Event())
    app = FastAPI(lifespan=runtime.lifespan)
    router = APIRouter()
    mount_owner_act_routes(
        router,
        runtime=runtime,
        effect=effect,
        verifier=verifier,
        limiter=OwnerActLimiter(
            client_identity=ClientIdentity(), limit=30, window=timedelta(hours=1)
        ),
    )
    app.include_router(router)
    async with app.router.lifespan_context(app):
        await runtime.db().execute(
            "CREATE TABLE {{tables.delivery_holders}} (principal TEXT PRIMARY KEY, credential BYTEA NOT NULL)"
        )
        await runtime.db().execute("CREATE TABLE {{tables.delivery_gate}} (id INTEGER PRIMARY KEY)")
        await runtime.db().execute("INSERT INTO {{tables.delivery_gate}} VALUES(1)")
        yield World(runtime, app, effect, owner, member, principal, installation, coordination)


async def test_designation_commits_nonce_effect_and_outbox_once(world):
    body = world.body()
    response = await world.post(body)
    assert response.status_code == 200, response.text
    assert response.json()["principal"] == world.principal
    assert response.json()["act"] == "human-role.designate"
    assert await world.counts() == (1, 1, 1)
    assert world.effect.committed == 1
    replay = await world.post(body)
    assert (replay.status_code, replay.json()) == (409, {"detail": "applied_earlier"})
    assert replay.headers["cache-control"] == "no-store"
    assert world.effect.prepares == world.effect.committed == 1
    assert await world.counts() == (1, 1, 1)


async def test_tls_termination_preserving_public_host_needs_no_forwarded_headers(world):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=world.app),
        base_url="http://app.example.com",
    ) as client:
        response = await client.post(PATH, json=world.body())
    assert response.status_code == 200
    assert await world.counts() == (1, 1, 1)


async def test_untrusted_forwarded_host_cannot_select_the_human_origin(world):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=world.app),
        base_url="http://wrong.example.com",
    ) as client:
        response = await client.post(
            PATH,
            json=world.body(),
            headers={
                "Forwarded": "host=app.example.com;proto=https",
                "X-Forwarded-Host": "app.example.com",
                "X-Forwarded-Proto": "https",
            },
        )
    assert response.status_code == 403
    assert await world.counts() == (0, 0, 0)


async def test_parallel_delivery_of_one_act_commits_only_one_effect(world):
    body = world.body()
    replies = await asyncio.gather(world.post(body), world.post(body))
    assert sum(reply.status_code == 200 for reply in replies) == 1
    other = next(reply for reply in replies if reply.status_code != 200)
    # A request that observes the committed nonce may acknowledge it; an
    # overlapping fresh request still refuses the losing consume/effect.
    assert (other.status_code, other.json()["detail"]) in {
        (403, "owner_required"),
        (409, "applied_earlier"),
    }
    assert await world.counts() == (1, 1, 1)
    replay = await world.post(body)
    assert (replay.status_code, replay.json()) == (409, {"detail": "applied_earlier"})


async def test_failed_effect_rolls_back_nonce_and_governance_then_same_act_can_retry(world):
    body = world.body()
    world.effect.fail_write = True
    response = await world.post(body)
    assert response.status_code == 403
    assert await world.counts() == (0, 0, 0)
    assert world.effect.committed == 0
    world.effect.fail_write = False
    assert (await world.post(body)).status_code == 200
    assert await world.counts() == (1, 1, 1)


@pytest.mark.parametrize("failure", ["unexpected", "timeout"])
async def test_notice_failure_does_not_report_a_committed_effect_as_failed(world, caplog, failure):
    world.effect.fail_notice = failure
    assert (await world.post(world.body())).status_code == 200
    assert await world.counts() == (1, 1, 1)
    records = [record for record in caplog.records if record.name.endswith("owner_act_router")]
    assert len(records) == 1
    assert records[0].act == "human-role.designate"
    assert records[0].role == ROLE
    assert records[0].installation_id == world.installation["installation_id"]
    assert records[0].failure_code == ("timeout" if failure == "timeout" else "notice_failed")
    assert NOTICE not in records[0].getMessage()


async def test_unavailable_governance_rolls_back_the_nonce_and_effect(world):
    world.effect.fail_governance = True
    response = await world.post(world.body())
    assert (response.status_code, response.json()["detail"]) == (503, "release_context_unavailable")
    assert await world.counts() == (0, 0, 0)


async def test_a_v2_pin_remains_readable_but_cannot_admit_v3_owner_acts(world):
    runtime = world.runtime
    data = runtime.manifest_variant_bytes(2)
    fetched = FetchedManifest(
        origin=runtime.settings.public_origin,
        url=runtime.settings.public_origin + "/manifests/v2.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=load_manifest(data),
    )
    async with world.coordination.server.db.get_manager().transaction() as tx:
        await install_verified_manifest_on(
            tx,
            team_id=world.member.team_id,
            fetched=fetched,
            granted_scopes=list(runtime.manifest.install_scopes),
            expected_generation=world.installation["generation"],
        )
    status = await runtime.installation_grants().status_for(world.member.team_id)
    assert status.manifest_version == 2
    assert status.digest == fetched.digest
    assert (await world.post(world.body())).status_code == 403
    assert await world.counts() == (0, 0, 0)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown_field",
        "missing_credential",
        "credential_encoding",
        "audience",
        "role",
        "credential_hash",
        "expired",
    ],
)
async def test_stateless_and_subject_binding_refusals_never_write_effects(world, fault):
    from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

    body = world.body()
    signing = base64.b64decode(body["signing"])
    fields = json.loads(signing.split(b"\n", 1)[1])
    expected = (403, "owner_required")
    if fault == "unknown_field":
        body["installation_id"] = fields["subject"]["installation_id"]
        expected = (400, "request_invalid")
    elif fault == "missing_credential":
        del body["credential"]
        expected = (400, "request_invalid")
    elif fault == "credential_encoding":
        body["credential"]["credential_id"] += "="
        expected = (400, "request_invalid")
    elif fault == "credential_hash":
        body["credential"] = holder(rp_id="app.example.com").body
    else:
        if fault == "audience":
            fields["aud"] = world.runtime.settings.public_origin
        elif fault == "role":
            fields["subject"]["role"] = "example.other"
        else:
            issued = datetime.now(UTC) - timedelta(minutes=2)
            fields["issued_at"] = issued.strftime("%Y-%m-%dT%H:%M:%SZ")
            fields["expires_at"] = (issued + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        signing = owner_act_signing_bytes(fields)
        body["signing"] = base64.b64encode(signing).decode()
        body["signature"] = (
            base64.b64encode(world.member.team_key.sign(signing).signature).decode().rstrip("=")
        )
    response = await world.post(body)
    assert (response.status_code, response.json()["detail"]) == expected
    assert await world.counts() == (0, 0, 0)


@pytest.mark.parametrize("holding", [False, True])
@pytest.mark.parametrize("unknown_team", [False, True])
async def test_forged_signature_cannot_observe_holding_or_installation(
    world, holding, unknown_team
):
    if holding:
        assert (await world.post(world.body())).status_code == 200
    before = await world.counts()
    before_reads = len(world.coordination.server.transport.calls)
    before_prepares = world.effect.prepares
    world.effect.prepared = None
    body = world.body()
    signing = base64.b64decode(body["signing"])
    if unknown_team:
        fields = json.loads(signing.split(b"\n", 1)[1])
        fields["team_id"] = "unknown:example.com"
        from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

        signing = owner_act_signing_bytes(fields)
        body["signing"] = base64.b64encode(signing).decode()
    body["signature"] = (
        base64.b64encode(SigningKey.generate().sign(signing).signature).decode().rstrip("=")
    )
    response = await world.post(body)
    assert (response.status_code, response.json()["detail"]) == (
        (503, "team_key_unavailable") if unknown_team else (403, "owner_required")
    )
    assert world.effect.prepared is None
    assert len(world.coordination.server.transport.calls) == before_reads
    assert world.effect.prepares == before_prepares
    assert await world.counts() == before


@pytest.mark.parametrize("certificate", [None, "", "not-base64", "e30=", "bm90LWpzb24="])
async def test_missing_or_failing_membership_certificate_refuses_without_effect(world, certificate):
    body = world.body()
    if certificate is None:
        del body["certificate"]
    else:
        body["certificate"] = certificate
    response = await world.post(body)
    assert (response.status_code, response.json()["detail"]) == (403, "principal_not_member")
    assert await world.counts() == (0, 0, 0)


async def test_revoke_needs_no_principal_membership_and_refuses_a_carried_certificate(world):
    assert (await world.post(world.body())).status_code == 200
    await world.coordination.registry.revoke(world.member.certificate_id)
    body = world.body(act="human-role.revoke")
    body["certificate"] = base64.b64encode(json.dumps(world.member.certificate()).encode()).decode()
    response = await world.post(body)
    assert (response.status_code, response.json()["detail"]) == (400, "request_invalid")
    del body["certificate"]
    assert (await world.post(body)).status_code == 200
    assert await world.counts() == (2, 0, 2)


async def test_withdrawal_and_expired_original_h2_after_observed_gate_wait_roll_back_everything(
    world,
):
    db = world.runtime.db()
    body = world.body()
    async with db.transaction() as blocker:
        await blocker.fetch_value("SELECT id FROM {{tables.delivery_gate}} WHERE id=1 FOR UPDATE")
        blocker_pid = await blocker.fetch_value("SELECT pg_backend_pid()")
        pending = asyncio.create_task(world.post(body))
        try:

            async def observed_wait():
                for _ in range(500):
                    blocked = await db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        blocker_pid,
                    )
                    if blocked and world.effect.prepared is not None:
                        return
                    await asyncio.sleep(0.01)
                raise AssertionError("delivery did not reach the observed authority-row wait")

            await asyncio.wait_for(observed_wait(), 8)
            checked = world.effect.prepared.checked
            deadline = checked.proof.fresh_until
            await world.coordination.registry.revoke(world.member.certificate_id)
            await asyncio.sleep(max(0, (deadline - monotonic_ns()) / 1e9) + 0.02)
            assert not pending.done()
        except BaseException:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            raise
    response = await asyncio.wait_for(pending, 8)
    assert world.effect.applied.is_set()  # tentative writes really preceded the final check
    assert response.status_code == 503, (
        "original H2 expiry after the observed gate wait must roll back the act"
    )
    assert response.json()["detail"] == "principal_status_unavailable"
    assert await world.counts() == (0, 0, 0)
    assert world.effect.committed == 0


async def test_client_budget_is_spent_on_refusals_and_cannot_be_reset_with_a_spoofed_header(world):
    for _ in range(30):
        response = await world.post({}, headers={"X-Forwarded-For": secrets.token_hex(8)})
        assert response.status_code == 400
    response = await world.post({}, headers={"X-Forwarded-For": "another-client"})
    assert (response.status_code, response.json()["detail"]) == (429, "owner_act_rate_limited")
    assert int(response.headers["Retry-After"]) >= 1
    assert (await world.post({}, host="127.0.0.2")).status_code == 400


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "DIDKey irrelevant"},
        {"Cookie": "session=irrelevant"},
        {"X-AWEB-Console-Session": "irrelevant"},
    ],
)
async def test_team_or_console_credentials_cannot_replace_the_owner_act(world, header):
    response = await world.post(world.body(), headers=header)
    assert response.status_code == 403
    assert await world.counts() == (0, 0, 0)


async def test_lost_revoke_response_replays_after_holding_is_gone_without_another_effect(world):
    assert (await world.post(world.body())).status_code == 200
    revoke = world.body(act="human-role.revoke")

    class DropCommittedResponse(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            transport = httpx.ASGITransport(app=world.app)
            response = await transport.handle_async_request(request)
            await response.aread()
            assert response.status_code == 200
            await transport.aclose()
            raise httpx.ReadError("test dropped the committed response", request=request)

    async with httpx.AsyncClient(transport=DropCommittedResponse(), base_url=ORIGIN) as client:
        with pytest.raises(httpx.ReadError, match="test dropped"):
            await client.post(PATH, json=revoke)
    assert await world.counts() == (2, 0, 2)
    prepares, committed = world.effect.prepares, world.effect.committed
    response = await world.post(revoke)
    assert (response.status_code, response.json()) == (409, {"detail": "applied_earlier"})
    assert world.effect.prepares == prepares
    assert world.effect.committed == committed
    assert await world.counts() == (2, 0, 2)

    # A later distinct act is not a receipt for the earlier revoke.
    distinct = world.body(act="human-role.revoke")
    assert distinct["signing"] != revoke["signing"]
    response = await world.post(distinct)
    assert (response.status_code, response.json()["detail"]) == (403, "owner_required")
    assert await world.counts() == (2, 0, 2)


async def test_correctly_signed_different_act_with_same_nonce_is_not_applied_earlier(world):
    from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

    first = world.body()
    assert (await world.post(first)).status_code == 200
    first_fields = json.loads(base64.b64decode(first["signing"]).split(b"\n", 1)[1])
    different = world.body(act="human-role.revoke")
    fields = json.loads(base64.b64decode(different["signing"]).split(b"\n", 1)[1])
    fields["nonce"] = first_fields["nonce"]
    signing = owner_act_signing_bytes(fields)
    signature = base64.b64encode(world.member.team_key.sign(signing).signature).decode().rstrip("=")
    # Prove the control reaches past signature verification with the current key.
    await world.owner.verifier.prepare(signing, signature, team_id=world.member.team_id)
    different.update(signing=base64.b64encode(signing).decode(), signature=signature)
    before = world.effect.prepares
    response = await world.post(different)
    assert (response.status_code, response.json()["detail"]) == (403, "owner_required")
    assert world.effect.prepares == before
    assert await world.counts() == (1, 1, 1)


@pytest.mark.parametrize("lost", ["installation", "controller", "expiry"])
async def test_applied_earlier_requires_current_authority_installation_and_valid_act(world, lost):
    assert (await world.post(world.body())).status_code == 200
    revoke = world.body(act="human-role.revoke")
    assert (await world.post(revoke)).status_code == 200
    before = world.effect.prepares
    expected = (403, "owner_required")
    if lost == "installation":
        from aweb.installations import uninstall_installation_on

        async with world.coordination.server.db.get_manager().transaction() as tx:
            await uninstall_installation_on(
                tx,
                team_id=world.member.team_id,
                app_id="example",
                expected_generation=world.installation["generation"],
            )
        expected = (403, "installation_inactive")
    elif lost == "controller":
        from aweb_naapp_testing import did_key

        await world.coordination.registry.rotate_team_key(
            world.member.team_id, did_key(SigningKey.generate())
        )
        deadline = world.runtime.team_cache()._cache[world.member.team_id].expires_at
        await asyncio.sleep(max(0, (deadline - monotonic_ns()) / 1e9) + 0.02)
    else:
        future = datetime.now(UTC) + timedelta(minutes=11)
        world.owner.verifier._clock = lambda: future
    response = await world.post(revoke)
    assert (response.status_code, response.json()["detail"]) == expected
    assert world.effect.prepares == before
    assert await world.counts() == (2, 0, 2)


@pytest.mark.parametrize("stale", [False, True])
async def test_replay_rechecks_original_key_deadline_after_observed_nonce_lock_wait(world, stale):
    body = world.body()
    assert (await world.post(body)).status_code == 200
    db = world.runtime.db()
    original = datetime.now(UTC)
    now = [original]
    world.owner.verifier._clock = lambda: now[0]
    async with db.transaction() as blocker:
        await blocker.fetch_value("SELECT nonce FROM {{tables.owner_act_nonces}} FOR UPDATE")
        blocker_pid = await blocker.fetch_value("SELECT pg_backend_pid()")
        pending = asyncio.create_task(world.post(body))
        try:

            async def observed_wait():
                for _ in range(500):
                    if await db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        blocker_pid,
                    ):
                        return
                    await asyncio.sleep(0.01)
                raise AssertionError("replay did not reach the observed nonce-row wait")

            await asyncio.wait_for(observed_wait(), 8)
            if stale:
                now[0] = original + timedelta(seconds=61)
            assert not pending.done()
        except BaseException:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            raise
    response = await asyncio.wait_for(pending, 8)
    expected = (
        (403, {"detail": "owner_required"}) if stale else (409, {"detail": "applied_earlier"})
    )
    assert (response.status_code, response.json()) == expected
    assert world.effect.prepares == world.effect.committed == 1
    assert await world.counts() == (1, 1, 1)


async def test_identical_act_with_substituted_body_credential_is_not_acknowledged(world):
    body = world.body()
    assert (await world.post(body)).status_code == 200
    body["credential"] = holder(rp_id="app.example.com").body
    response = await world.post(body)
    assert (response.status_code, response.json()["detail"]) == (403, "owner_required")
    assert await world.counts() == (1, 1, 1)
