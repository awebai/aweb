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
from tests.runtime.test_human_member import TEAM
from tests.runtime.test_served_manifest import ExampleSettings, _key_file, _v2_template

pytest_plugins = ("tests.runtime.test_human_member",)
ORIGIN = "https://app.example.com"
PATH = "/.well-known/aweb-owner-act"
ROLE = "example.owner"
NOTICE = "owner@example.test"


@pytest.fixture
def registry(coordination):
    return coordination.registry


@dataclass
class SqlEffect:
    """A relying app with actual SQL holdings and durable governance events."""

    runtime: NaappRuntime
    identity_client: object
    fail_write: bool = False
    fail_notice: bool = False
    prepared: object = None
    applied: asyncio.Event = None
    committed: int = 0

    async def prepare(self, *, installation, delivery):
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
            db_schema=db.config.schema,
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
            tx, team_id=TEAM, fetched=fetched, granted_scopes=list(runtime.manifest.install_scopes)
        )

    async def current_key(team):
        return (await runtime.team_cache().get(team)).team_did_key

    verifier = OwnerActVerifier(
        scope="example", audience=ORIGIN, acts=HUMAN_ROLE_ACTS, team_key_for=current_key
    )
    owner = TeamOwner(member.team_key, verifier, TEAM, current_key)
    effect = SqlEffect(runtime, human[2], applied=asyncio.Event())
    app = FastAPI(lifespan=runtime.lifespan)
    router = APIRouter()
    mount_owner_act_routes(
        router,
        runtime=runtime,
        effect=effect,
        verifier=verifier,
        limiter=OwnerActLimiter(
            client_identity=ClientIdentity(), limit=30, window=timedelta(minutes=1)
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
    assert (replay.status_code, replay.json()["detail"]) == (403, "owner_required")
    assert await world.counts() == (1, 1, 1)


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


async def test_notice_failure_does_not_report_a_committed_effect_as_failed(world):
    world.effect.fail_notice = True
    assert (await world.post(world.body())).status_code == 200
    assert await world.counts() == (1, 1, 1)


@pytest.mark.parametrize("holding", [False, True])
@pytest.mark.parametrize("unknown_team", [False, True])
async def test_forged_signature_cannot_observe_holding_or_installation(
    world, holding, unknown_team
):
    if holding:
        assert (await world.post(world.body())).status_code == 200
    before = await world.counts()
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
    assert (response.status_code, response.json()["detail"]) == (
        503,
        "principal_status_unavailable",
    )
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
    response = await world.post({}, headers=header)
    assert response.status_code in (400, 403)
    assert await world.counts() == (0, 0, 0)
