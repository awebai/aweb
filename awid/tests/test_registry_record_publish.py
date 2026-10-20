"""RegistryClient's team-key-signed record publishes against real AWID.

AWID, PostgreSQL and Redis are real, reached over HTTP. The custodian, member
custody and member person publishes carry the covering controller envelope;
the team-server record is its own authority. Each accepted publish is read back
through the anonymous GET exactly as signed.
"""
from __future__ import annotations

import httpx
import pytest

from awid.attestation_records import sign_record
from awid.controller_signing import build_controller_payload, parse_controller_request
from awid.registry import RegistryClient, RegistryError
from awid.signing import sign_message
from awid.team_server_record import record_signing_bytes
from test_attestation_record_routes import BASE, TEAM_ID, _custodian, _custody, _now, _person, register_certificate
from test_controller_clients_http import network_registry  # noqa: F401
from test_controller_request_v2_http import controller_app, keypair  # noqa: F401


def _signed(key, record):
    return record, sign_record(key, record)


def _server_record(env, *, issued_at=None):
    record = {"v": 1, "type": "aweb.team-server", "team_id": TEAM_ID, "team_did_key": env.team[1],
              "server_url": "https://coord.example/api", "issued_at": issued_at or _now(-30)}
    return record, sign_message(env.team[0], record_signing_bytes(record))


async def _stored(origin, path):
    async with httpx.AsyncClient(base_url=origin) as reader:
        return await reader.get(path)


@pytest.mark.asyncio
async def test_the_team_key_publishes_every_kind_and_each_reads_back_as_signed(network_registry):
    env, state, origin = network_registry
    registry = RegistryClient(registry_url=origin)
    team_key = env.team[0]
    try:
        custodian, custodian_sig = _signed(team_key, _custodian(env))
        await registry.publish_team_custodian(
            "local", "base", record=custodian, signature=custodian_sig, team_controller_signing_key=team_key,
        )
        cert = await register_certificate(env)
        custody, custody_sig = _signed(team_key, _custody(env, cert))
        await registry.publish_member_custody(
            "local", "base", record=custody, signature=custody_sig, team_controller_signing_key=team_key,
        )
        person, person_sig = _signed(team_key, _person(env, cert))
        await registry.publish_member_person(
            "local", "base", record=person, signature=person_sig, team_controller_signing_key=team_key,
        )
        server, server_sig = _server_record(env)
        await registry.publish_team_server("local", "base", record=server, signature=server_sig)

        reads = {
            f"{BASE}/custodians/{custodian['custodian_id']}": (custodian, custodian_sig),
            f"{BASE}/certificates/{cert['certificate_id']}/custody": (custody, custody_sig),
            f"{BASE}/certificates/{cert['certificate_id']}/person": (person, person_sig),
            f"{BASE}/server": (server, server_sig),
        }
        for path, (record, signature) in reads.items():
            stored = await _stored(origin, path)
            assert stored.status_code == 200, (path, stored.text)
            assert stored.json() == {"record": record, "signature": signature}
        assert [dict(m["headers"]).get(b"x-aweb-signed-payload") is not None for m in state.mutations] == [
            True, True, True, False,
        ]

        await registry.publish_team_custodian(
            "local", "base", record=custodian, signature=custodian_sig, team_controller_signing_key=team_key,
        )
        await registry.publish_team_server("local", "base", record=server, signature=server_sig)
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_a_policy_bound_signer_publishes_under_the_team_key(network_registry):
    env, state, origin = network_registry
    registry = RegistryClient(registry_url=origin)
    operations = []

    async def team_signer(request):
        parsed = parse_controller_request(request.canonical_payload)
        operations.append((parsed.operation, request.controller_did_key))
        return sign_message(env.team[0], build_controller_payload(parsed))

    try:
        custodian, signature = _signed(env.team[0], _custodian(env))
        await registry.publish_team_custodian(
            "local", "base", record=custodian, signature=signature,
            controller_did_key=env.team[1], signer=team_signer,
        )
        assert operations == [("publish_team_custodian", env.team[1])]
        stored = await _stored(origin, f"{BASE}/custodians/{custodian['custodian_id']}")
        assert stored.json() == {"record": custodian, "signature": signature}
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_a_key_other_than_the_team_key_is_refused_and_nothing_is_stored(network_registry):
    env, state, origin = network_registry
    registry = RegistryClient(registry_url=origin)
    other_key, _ = keypair()
    try:
        custodian, signature = _signed(env.team[0], _custodian(env))
        with pytest.raises(RegistryError) as refused:
            await registry.publish_team_custodian(
                "local", "base", record=custodian, signature=signature, team_controller_signing_key=other_key,
            )
        assert refused.value.status_code == 403
        cert = await register_certificate(env)
        person, person_sig = _signed(env.team[0], _person(env, cert))
        with pytest.raises(RegistryError) as refused:
            await registry.publish_member_person(
                "local", "base", record=person, signature=person_sig, team_controller_signing_key=other_key,
            )
        assert refused.value.status_code == 403
        assert (await _stored(origin, f"{BASE}/custodians/{custodian['custodian_id']}")).status_code == 404
        assert (await _stored(origin, f"{BASE}/certificates/{cert['certificate_id']}/person")).status_code == 404
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_a_record_not_signed_by_the_team_key_is_refused(network_registry):
    env, state, origin = network_registry
    registry = RegistryClient(registry_url=origin)
    other_key, _ = keypair()
    try:
        custodian = _custodian(env)
        with pytest.raises(RegistryError) as refused:
            await registry.publish_team_custodian(
                "local", "base", record=custodian, signature=sign_record(other_key, custodian),
                team_controller_signing_key=env.team[0],
            )
        assert refused.value.status_code == 422
        server, _ = _server_record(env)
        with pytest.raises(RegistryError) as refused:
            await registry.publish_team_server(
                "local", "base", record=server, signature=sign_message(other_key, record_signing_bytes(server)),
            )
        assert refused.value.status_code == 404
        assert (await _stored(origin, f"{BASE}/custodians/{custodian['custodian_id']}")).status_code == 404
        assert (await _stored(origin, f"{BASE}/server")).status_code == 404
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_member_records_name_the_certificate_they_are_written_to(network_registry):
    env, state, origin = network_registry
    registry = RegistryClient(registry_url=origin)
    try:
        custodian, signature = _signed(env.team[0], _custodian(env))
        await registry.publish_team_custodian(
            "local", "base", record=custodian, signature=signature, team_controller_signing_key=env.team[0],
        )
        alice, bob = await register_certificate(env), await register_certificate(env)
        swapped = dict(_custody(env, alice), member_did_key=bob["member_did_key"])
        with pytest.raises(RegistryError) as refused:
            await registry.publish_member_custody(
                "local", "base", record=swapped, signature=sign_record(env.team[0], swapped),
                team_controller_signing_key=env.team[0],
            )
        assert refused.value.status_code == 422
        assert (await _stored(origin, f"{BASE}/certificates/{alice['certificate_id']}/custody")).status_code == 404
    finally:
        await registry.aclose()
