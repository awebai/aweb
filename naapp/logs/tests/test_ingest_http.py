"""Logs admission through its HTTP route and the real AWID/aweb fixture.

Installation uses the server's pinned-manifest writer. Binding rows are
provisioned as already activated: owner activation itself is covered by core's
tests and the release E2E. No verifier, resolver, signature or database is mocked.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from aweb.app_manifests import FetchedManifest
from aweb.installations import install_verified_manifest_on
from aweb_naapp.hooks import envelope
from aweb_naapp.hooks.delivery import sign_delivery
from aweb_naapp.hooks.strictjson import decode_base64url
from aweb_naapp.manifest import load_manifest
from aweb_naapp_testing import Member
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from nacl.signing import SigningKey

from aweb_logs.app import create_app
from aweb_logs.chain import open_receipt
from aweb_logs.config import LogsSettings
from aweb_logs.ledger import load_epoch
from aweb_logs.verify import verify_chain

from .deployment import TEST_APP_ID, served_manifest, write_key_files
from .fixtures import (
    CORE_SEED,
    MEMBER_SEED,
    SECRETS_ORIGIN,
    SECRETS_SEED,
    did_key,
    signed_event,
)

ORIGIN = "https://logs.example.test"
PATH = "/v1/hooks/ingest"
APP_ID = "secrets-test"
SEEDS = {"core": CORE_SEED, "app": SECRETS_SEED, "client": MEMBER_SEED}


async def _install(db, team_id, data):
    manifest = load_manifest(data)
    origin = manifest.document["app"]["origin"]
    fetched = FetchedManifest(
        origin=origin,
        url=origin + "/.well-known/aweb-app.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=manifest,
    )
    async with db.transaction() as tx:
        return await install_verified_manifest_on(
            tx, team_id=team_id, fetched=fetched, granted_scopes=[],
        )


@dataclass
class World:
    coordination: object
    db: object
    server_db: object
    member: Member
    settings: LogsSettings
    installation: dict
    bindings: dict[str, str]
    now: datetime
    client: httpx.AsyncClient

    def event(self, kind, *, event_id=None, payload=None, producer=None, occurred_at=None, hook=None):
        signing, _ = signed_event(kind, team_id=self.member.team_id, event_id=event_id or str(uuid4()))
        fields = envelope.open_envelope(signing).fields
        at = occurred_at or self.now
        fields["occurred_at"] = fields["fired_at"] = at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if kind == "core":
            fields["producer"]["origin"] = self.coordination.server.url
        elif kind == "app":
            fields["producer"].update(
                app_id=APP_ID,
                installation_id=self.installation["installation_id"],
                generation=self.installation["generation"],
            )
        if hook is not None:
            fields["hook"] = hook
        if payload is not None:
            fields["payload"] = payload
        fields["producer"].update(producer or {})
        return envelope.sign(SEEDS[kind], fields)

    def delivery(self, kind, *, binding_id=None, target=None, **event_changes):
        signing, signature = self.event(kind, **event_changes)
        hook = envelope.open_envelope(signing).hook
        certificate = (
            base64.b64encode(json.dumps(self.member.certificate()).encode()).decode()
            if kind == "client" else None
        )
        return sign_delivery(
            SEEDS[kind], "POST", target or ORIGIN + PATH,
            binding_id or self.bindings[hook], signing, signature, certificate, self.now,
        )

    async def send(self, delivery, *, body=None, path=None):
        return await self.client.post(
            path or delivery.path, headers=delivery.headers,
            content=delivery.body if body is None else body,
        )


@pytest.fixture
async def world(coordination, test_db_factory, tmp_path, monkeypatch, request):
    now = datetime.now(UTC).replace(microsecond=0)
    member = Member(
        team_id=f"logs-{uuid4().hex[:12]}:ingest.example", certificate_id="c_41",
        alias="bond", member_key=SigningKey(MEMBER_SEED),
    )
    await coordination.add_member(member)
    await coordination.publish_server(member)
    await coordination.connect(member)
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([{
        "kid": "hook-2026-10", "did_key": did_key(CORE_SEED),
        "valid_from": "2026-01-01T00:00:00Z", "valid_until": None,
    }]))
    db = await test_db_factory.create_db(suffix="logs_http")
    server_db = coordination.server.db.get_manager("aweb")
    settings = LogsSettings(
        _env_file=None, database_url=db.config.get_dsn(), db_schema=db.schema,
        app_id=TEST_APP_ID, public_origin=ORIGIN,
        awid_registry_url=REGISTRY_URL, awid_service_token=SERVICE_TOKEN,
        app_key_files=write_key_files(tmp_path),
        **{"client_events_per_minute": 1, **getattr(request, "param", {})},
    )
    await _install(server_db, member.team_id, served_manifest(settings.app_key_files, origin=ORIGIN))
    producer_manifest = {
        "manifest_version": 2,
        "app": {"id": APP_ID, "origin": SECRETS_ORIGIN, "version": "1.0.0"},
        "tools": [],
        "app_keys": [{"kid": "hook-2026-10", "did_key": did_key(SECRETS_SEED),
                      "purposes": ["hook-event"]}],
        "hooks": {"registration_version": 1, "productions": [
            {"catalog": {"id": "aweb.hooks", "version": 1}, "hook": hook}
            for hook in ("post-secret-use-hook", "post-governance-hook")
        ]},
    }
    installation = await _install(server_db, member.team_id, json.dumps(producer_manifest).encode())
    await server_db.execute(
        "UPDATE {{tables.app_hook_bindings}} SET state='active', activated_at=$2::timestamptz - INTERVAL '60 seconds', "
        "active_from=$2, activation_act_sha256=$3 WHERE team_id=$1",
        member.team_id, now - timedelta(minutes=1), "ab" * 32,
    )
    bindings = {row["hook"]: str(row["binding_id"]) for row in await server_db.fetch_all(
        "SELECT hook, binding_id FROM {{tables.app_hook_bindings}} WHERE team_id=$1 AND app_id=$2",
        member.team_id, TEST_APP_ID,
    )}
    app = create_app(
        settings, awid_transport=coordination.registry.transport,
        team_server_transport=coordination.server.transport, now=lambda: now,
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield World(coordination, db, server_db, member, settings, installation, bindings, now, client)


def _code(response):
    return response.json()["detail"]["code"]


@pytest.mark.parametrize("kind", ["core", "app", "client"])
async def test_a_real_delivery_appends_reverifiable_content_and_a_signed_receipt(world, kind):
    delivery = world.delivery(kind)
    response = await world.send(delivery)
    assert response.status_code == 200, response.text
    ack = response.json()
    assert ack["disposition"] == "appended"
    receipt = open_receipt(decode_base64url(ack["receipt"]["signing_bytes"], "receipt"), ack["receipt"]["signature"])
    assert (receipt.event_id, receipt.team_id, receipt.team_seq) == (ack["event_id"], world.member.team_id, 1)
    genesis, events = await load_epoch(world.db, world.member.team_id, 1)
    assert verify_chain(genesis, events, receipt_keys=frozenset({receipt.did_key}), checkpoint_keys=frozenset()).intact
    evidence = json.loads(await world.db.fetch_value(
        "SELECT key_evidence FROM {{tables.chain_events}} WHERE team_id=$1", world.member.team_id,
    ))
    assert evidence["did_key"] == did_key(SEEDS[kind])
    assert world.bindings[envelope.open_envelope(world.event(kind)[0]).hook] in evidence["binding_ids"]
    assert (evidence["installation_id"], evidence["generation"]) == (
        (world.installation["installation_id"], world.installation["generation"]) if kind == "app" else (None, None)
    )


async def test_bad_transport_precedes_binding_and_writes_nothing(world):
    delivery = world.delivery("core", binding_id=str(uuid4()))
    response = await world.send(delivery, body=delivery.body + b" ")
    assert (response.status_code, _code(response)) == (401, "transport_body_mismatch")
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.chain_events}}") == 0


async def test_transport_signs_the_external_raw_path_and_query(world):
    response = await world.send(world.delivery("core"), path=PATH + "?other=1")
    assert (response.status_code, _code(response)) == (401, "transport_request_mismatch")


async def test_binding_precedes_producer_authority_and_schema(world):
    response = await world.send(world.delivery("core", binding_id=str(uuid4()), payload={"unknown": "field"}))
    assert (response.status_code, _code(response)) == (403, "binding_required")
    assert not any(call.url.path == "/v1/hooks/producer-keys" for call in world.coordination.server.transport.calls)


@pytest.mark.parametrize("state", ["pending", "revoked", "superseded"])
async def test_a_nonactive_registration_is_refused(world, state):
    await world.server_db.execute(
        "UPDATE {{tables.app_hook_bindings}} SET state=$3, "
        "activated_at=CASE WHEN $3='pending' THEN NULL ELSE activated_at END, "
        "active_from=CASE WHEN $3='pending' THEN NULL ELSE active_from END, "
        "activation_act_sha256=CASE WHEN $3='pending' THEN NULL ELSE activation_act_sha256 END, "
        "revoked_at=CASE WHEN $3='pending' THEN NULL ELSE date_trunc('milliseconds', now()) END, "
        "ended_by=CASE WHEN $3='pending' THEN NULL WHEN $3='revoked' THEN 'owner_act' ELSE 'generation' END, "
        "revocation_act_sha256=CASE WHEN $3='revoked' THEN $4 ELSE NULL END "
        "WHERE team_id=$1 AND app_id=$2",
        world.member.team_id, TEST_APP_ID, state, "cd" * 32,
    )
    response = await world.send(world.delivery("core"))
    assert (response.status_code, _code(response)) == (403, "binding_required")


async def test_an_event_before_the_registration_pad_is_refused(world):
    response = await world.send(world.delivery("core", occurred_at=world.now - timedelta(minutes=2)))
    assert (response.status_code, _code(response)) == (403, "binding_required")


async def test_unavailable_binding_authority_is_retryable(world):
    world.coordination.server.transport.down = True
    response = await world.send(world.delivery("core"))
    assert (response.status_code, _code(response)) == (503, "binding_authority_unavailable")
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.chain_events}}") == 0


async def test_a_core_key_cannot_assert_an_unanchored_origin(world):
    response = await world.send(world.delivery("core", producer={"origin": "https://forged.example"}))
    assert (response.status_code, _code(response)) == (403, "provenance_core_key")
    assert not any(call.url.host == "forged.example" for call in world.coordination.server.transport.calls)


async def test_a_core_key_is_checked_at_the_events_occurrence(world, monkeypatch):
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([{
        "kid": "hook-2026-10", "did_key": did_key(CORE_SEED),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": (world.now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }]))
    response = await world.send(world.delivery("core"))
    assert (response.status_code, _code(response)) == (403, "provenance_core_key")


@pytest.mark.parametrize("producer", [
    {"installation_id": "10000000-0000-4000-8000-000000000000"},
    {"generation": 99}, {"origin": "https://forged.example"}, {"kid": "unregistered"},
])
async def test_an_app_must_match_the_registered_installation_generation_origin_and_key(world, producer):
    response = await world.send(world.delivery("app", producer=producer))
    assert (response.status_code, _code(response)) == (403, "provenance_app_production")


async def test_an_app_production_without_a_hook_event_key_is_refused(world):
    await world.server_db.execute(
        "UPDATE {{tables.team_app_keys}} SET purposes=ARRAY['hook-delivery'] WHERE team_id=$1 AND app_id=$2",
        world.member.team_id, APP_ID,
    )
    response = await world.send(world.delivery("app"))
    assert (response.status_code, _code(response)) == (403, "provenance_app_production")


async def test_schema_refusal_follows_valid_authority(world):
    response = await world.send(world.delivery("core", payload={"unknown": "field"}))
    assert response.status_code == 422
    assert _code(response).startswith("schema_")


async def test_a_revoked_client_certificate_is_refused_by_shared_publication_policy(world):
    await world.coordination.registry.revoke(world.member.certificate_id)
    response = await world.send(world.delivery("client"))
    assert (response.status_code, _code(response)) == (401, "provenance_client_certificate")


async def test_client_certificate_verification_reads_the_controller_key_fresh(world):
    assert (await world.send(world.delivery("client"))).status_code == 200
    await world.coordination.registry.rotate_team_key(world.member.team_id, did_key(bytes(SigningKey.generate())))
    response = await world.send(world.delivery("client"))
    assert (response.status_code, _code(response)) == (401, "transport_certificate_invalid")


async def test_a_client_cannot_use_a_warm_key_cache_during_a_registry_outage(world):
    assert (await world.send(world.delivery("client"))).status_code == 200
    world.coordination.registry.transport.down = True
    response = await world.send(world.delivery("client"))
    assert (response.status_code, _code(response)) == (503, "client_authority_unavailable")


async def test_identical_redelivery_returns_the_original_receipt_without_spending_quota(world):
    delivery = world.delivery("client")
    first = await world.send(delivery)
    duplicate = await world.send(delivery)
    assert (first.status_code, duplicate.status_code) == (200, 200)
    assert duplicate.json() == {**first.json(), "disposition": "duplicate"}
    refused = await world.send(world.delivery("client"))
    assert (refused.status_code, _code(refused)) == (429, "client_quota_exceeded")
    assert await world.db.fetch_value("SELECT events FROM {{tables.client_ingest_usage}}") == 1
    assert await world.db.fetch_value("SELECT team_seq FROM {{tables.chain_heads}}") == 1


async def test_a_conflict_is_recorded_without_charging_quota_or_overwriting_content(world):
    event_id = str(uuid4())
    first = await world.send(world.delivery("client", event_id=event_id))
    payload = envelope.open_envelope(world.event("client")[0]).fields["payload"]
    response = await world.send(world.delivery("client", event_id=event_id, payload={**payload, "flags": ["--quiet"]}))
    assert first.status_code == 200
    assert (response.status_code, _code(response)) == (409, "event_conflict")
    assert await world.db.fetch_value("SELECT kind FROM {{tables.chain_faults}}") == "event_conflict"
    assert await world.db.fetch_value("SELECT events FROM {{tables.client_ingest_usage}}") == 1
    assert await world.db.fetch_value("SELECT team_seq FROM {{tables.chain_heads}}") == 1


async def test_concurrent_client_appends_charge_and_append_atomically(world):
    responses = await asyncio.gather(*(world.send(world.delivery("client")) for _ in range(3)))
    assert sorted(response.status_code for response in responses) == [200, 429, 429]
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.chain_events}}") == 1
    assert await world.db.fetch_value("SELECT team_seq FROM {{tables.chain_heads}}") == 1
    assert await world.db.fetch_value("SELECT events FROM {{tables.client_ingest_usage}}") == 1


@pytest.mark.parametrize("world", [{"client_events_per_minute": 30, "client_bytes_per_minute": 1}], indirect=True)
async def test_client_byte_quota_rolls_back_the_entire_first_append(world):
    response = await world.send(world.delivery("client"))
    assert (response.status_code, _code(response)) == (429, "client_quota_exceeded")
    for table in ("chain_events", "chain_heads", "client_ingest_usage"):
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


async def test_a_registration_for_another_hook_cannot_admit_the_delivery(world):
    response = await world.send(world.delivery("core", binding_id=world.bindings["post-command-hook"]))
    assert (response.status_code, _code(response)) == (403, "binding_required")


async def test_a_member_team_auth_request_is_not_a_hook_delivery(world):
    delivery = world.delivery("client")
    headers = world.member.headers(aud=ORIGIN, method="POST", path=PATH, body=delivery.body)
    response = await world.client.post(PATH, content=delivery.body, headers=headers)
    assert (response.status_code, _code(response)) == (401, "transport_wrong_scheme")


async def test_backend_version_observation_uses_the_packaged_catalog(world):
    response = await world.send(world.delivery("app", hook="post-governance-hook", payload={
        "act": "resource.version_observed", "direction": "narrowing", "authority": "backend_observation",
        "resource_type": "secret", "resource_ref": "sec_19ab42",
        "before_ref": "sv_38b8149372e841309188c09c50e46104",
        "after_ref": "sv_6220f33627bf41049cef7a9ba04e7c9b", "reason_code": "external_version_changed",
    }))
    assert response.status_code == 200, response.text


async def test_invalid_observed_value_refusal_uses_the_packaged_catalog(world):
    response = await world.send(world.delivery("app", payload={
        "action": "refused", "op_kind": "broker", "secret_id": "sec_19ab42",
        "secret_version": 4, "secret_backend": "onepassword", "refusal_code": "secret_value_invalid",
    }))
    assert response.status_code == 200, response.text
