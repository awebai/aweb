"""The namespace controller's team-key act is kept and served as evidence.

Rotation goes through the real AWID route in both signed forms; the served
record is checked by the SDK verifier a relying server uses, with no registry
trust beyond the bytes it returns.
"""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from awid.external_authority import DNSLookup
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_key_acts import (
    MemoryTeamKeyPins,
    TeamKeyActError,
    TeamKeyPin,
    TeamKeyUnverified,
    pinned_team_key,
    verify_team_key_act,
    verify_team_key_change,
)
from test_controller_request_v2_http import ORIGIN, controller_app, keypair, send  # noqa: F401

ROTATE_PATH = '/v1/namespaces/local/teams/base/rotate'
ACT_PATH = '/v1/namespaces/local/teams/base/key-act'


async def _rotate(env, new_did_key, *, covering=True):
    response = await send(
        env, 'POST', ROTATE_PATH,
        {'domain': 'local', 'operation': 'rotate_team_key', 'name': 'base', 'new_team_did_key': new_did_key},
        {'new_team_did_key': new_did_key}, covering=covering,
    )
    assert response.status_code == 200, response.text


def _legacy_act(signer, claims, timestamp=None):
    key, did = signer
    payload = canonical_json_bytes({**claims, 'timestamp': timestamp or datetime.now(timezone.utc).isoformat()})
    return {
        'signer_did_key': did,
        'signed_payload': base64.urlsafe_b64encode(payload).rstrip(b'=').decode(),
        'signature': sign_message(key, payload),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize('covering', [True, False])
async def test_rotation_keeps_a_verifiable_controller_act(controller_app, covering):
    env = controller_app
    _, new_did_key = keypair()
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    await _rotate(env, new_did_key, covering=covering)

    response = await env.client.get(ACT_PATH)

    assert response.status_code == 200, response.text
    record = response.json()
    assert record['team_id'] == 'base:local'
    assert record['team_did_key'] == new_did_key
    act = verify_team_key_act(record, domain='local', name='base', team_did_key=new_did_key)
    assert act.signer_did_key == env.controller[1]
    assert before <= act.signed_at <= datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_the_served_act_is_the_one_that_set_the_current_key(controller_app):
    env = controller_app
    _, first = keypair()
    _, second = keypair()
    await _rotate(env, first)
    first_act = (await env.client.get(ACT_PATH)).json()
    await _rotate(env, second)

    record = (await env.client.get(ACT_PATH)).json()

    assert verify_team_key_act(record, domain='local', name='base', team_did_key=second)
    # An older act cannot stand in for the current key.
    with pytest.raises(TeamKeyActError) as refused:
        verify_team_key_act(first_act, domain='local', name='base', team_did_key=second)
    assert refused.value.reason == 'key_mismatch'


@pytest.mark.asyncio
async def test_rotation_to_the_same_key_records_a_fresh_act(controller_app):
    env = controller_app
    _, new_did_key = keypair()
    await _rotate(env, new_did_key)
    first = verify_team_key_act((await env.client.get(ACT_PATH)).json(), domain='local', name='base', team_did_key=new_did_key)
    await _rotate(env, new_did_key)

    again = verify_team_key_act((await env.client.get(ACT_PATH)).json(), domain='local', name='base', team_did_key=new_did_key)

    assert again.signed_at > first.signed_at


@pytest.mark.asyncio
async def test_a_private_team_act_is_read_anonymously(controller_app):
    env = controller_app
    _, new_did_key = keypair()
    await _rotate(env, new_did_key)
    await env.db.execute("UPDATE {{tables.teams}} SET visibility='private' WHERE domain='local' AND name='base'")

    team = await env.client.get('/v1/namespaces/local/teams/base')
    act = await env.client.get(ACT_PATH)

    assert team.status_code != 200
    assert act.status_code == 200, act.text
    assert verify_team_key_act(act.json(), domain='local', name='base', team_did_key=new_did_key)


@pytest.mark.asyncio
async def test_an_unknown_team_and_a_team_without_an_act_answer_the_same_404(controller_app):
    env = controller_app
    unknown = await env.client.get('/v1/namespaces/local/teams/nobody/key-act')
    without_act = await env.client.get(ACT_PATH)
    assert (unknown.status_code, unknown.json()) == (without_act.status_code, without_act.json()) == (
        404, {'detail': 'Team key act not found'})


def _claims(**overrides):
    return {'domain': 'local', 'operation': 'rotate_team_key', 'name': 'base', 'new_team_did_key': 'K', **overrides}


def test_verifier_accepts_the_exact_act():
    signer = keypair()
    _, team = keypair()
    act = verify_team_key_act(_legacy_act(signer, _claims(new_team_did_key=team)), domain='local', name='base', team_did_key=team)
    assert act.signer_did_key == signer[1]


@pytest.mark.parametrize(('claims', 'reason'), [
    ({'operation': 'create_team'}, 'wrong_operation'),
    ({'domain': 'other.test'}, 'team_mismatch'),
    ({'name': 'other'}, 'team_mismatch'),
])
def test_verifier_refuses_an_act_for_another_operation_or_team(claims, reason):
    signer = keypair()
    _, team = keypair()
    record = _legacy_act(signer, _claims(new_team_did_key=team, **claims))
    with pytest.raises(TeamKeyActError) as refused:
        verify_team_key_act(record, domain='local', name='base', team_did_key=team)
    assert refused.value.reason == reason


def test_verifier_refuses_a_signature_by_another_key():
    _, team = keypair()
    record = _legacy_act(keypair(), _claims(new_team_did_key=team))
    record['signer_did_key'] = keypair()[1]
    with pytest.raises(TeamKeyActError) as refused:
        verify_team_key_act(record, domain='local', name='base', team_did_key=team)
    assert refused.value.reason == 'bad_signature'


@pytest.mark.parametrize('timestamp', ['2026-11-12T10:00:00', 'not-a-time'])
def test_verifier_refuses_an_act_without_a_zoned_timestamp(timestamp):
    _, team = keypair()
    record = _legacy_act(keypair(), _claims(new_team_did_key=team), timestamp=timestamp)
    with pytest.raises(TeamKeyActError) as refused:
        verify_team_key_act(record, domain='local', name='base', team_did_key=team)
    assert refused.value.reason == 'malformed'


@pytest.mark.parametrize('record', [{}, {'signer_did_key': 'x', 'signed_payload': '!!', 'signature': 'y'}, None])
def test_verifier_refuses_a_malformed_record(record):
    with pytest.raises(TeamKeyActError) as refused:
        verify_team_key_act(record, domain='local', name='base', team_did_key='K')
    assert refused.value.reason == 'malformed'


class TXTAnswers:
    """The DNS answers a relying server would see, by query name."""

    def __init__(self, answers: dict[str, DNSLookup]) -> None:
        self._answers = answers

    async def lookup_txt(self, name: str) -> DNSLookup:
        return self._answers.get(name, DNSLookup('nxdomain'))


def _dns(name: str, controller: str) -> TXTAnswers:
    return TXTAnswers({name: DNSLookup('record', (f'awid=v1; controller={controller};',))})


def _example_act(signer, team, timestamp=None):
    return _legacy_act(signer, _claims(domain='team.example.com', new_team_did_key=team), timestamp=timestamp)


async def _change(record, team, *, resolver, pinned_at=None):
    return await verify_team_key_change(
        record, domain='team.example.com', name='base', team_did_key=team, pinned_at=pinned_at, resolver=resolver,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('dns_name', ['_awid.team.example.com', '_awid.example.com'])
async def test_change_is_accepted_from_the_controller_dns_names(dns_name):
    signer = keypair()
    _, team = keypair()
    act = await _change(_example_act(signer, team), team, resolver=_dns(dns_name, signer[1]))
    assert act.signer_did_key == signer[1]


@pytest.mark.asyncio
async def test_change_signed_by_a_controller_dns_does_not_name_is_refused():
    registry_controller = keypair()
    _, team = keypair()
    with pytest.raises(TeamKeyActError) as refused:
        await _change(_example_act(registry_controller, team), team, resolver=_dns('_awid.team.example.com', keypair()[1]))
    assert refused.value.reason == 'signer_not_controller'


@pytest.mark.asyncio
@pytest.mark.parametrize('lookup', [DNSLookup('nxdomain'), DNSLookup('servfail'), DNSLookup('timeout')])
async def test_change_without_a_dns_controller_is_refused(lookup):
    signer = keypair()
    _, team = keypair()
    resolver = TXTAnswers({'_awid.team.example.com': lookup, '_awid.example.com': lookup})
    with pytest.raises(TeamKeyActError) as refused:
        await _change(_example_act(signer, team), team, resolver=resolver)
    assert refused.value.reason == 'controller_unavailable'


@pytest.mark.asyncio
async def test_change_must_be_newer_than_the_act_behind_the_pin():
    signer = keypair()
    _, team = keypair()
    signed_at = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
    record = _example_act(signer, team, timestamp=signed_at.isoformat())
    resolver = _dns('_awid.team.example.com', signer[1])
    for pinned_at in (signed_at, signed_at + timedelta(seconds=1)):
        with pytest.raises(TeamKeyActError) as refused:
            await _change(record, team, resolver=resolver, pinned_at=pinned_at)
        assert refused.value.reason == 'not_newer'
    act = await _change(record, team, resolver=resolver, pinned_at=signed_at - timedelta(seconds=1))
    assert act.signed_at == signed_at


@pytest.mark.asyncio
async def test_registry_client_reads_the_served_act(controller_app):
    env = controller_app
    _, new_did_key = keypair()
    await _rotate(env, new_did_key)
    client = RegistryClient(registry_url=ORIGIN, transport=httpx.ASGITransport(app=env.app))
    try:
        record = await client.get_team_key_act('local', 'base')
        verify_team_key_act(record, domain='local', name='base', team_did_key=new_did_key)
        await env.db.execute("DELETE FROM {{tables.team_key_acts}}")
        assert await client.get_team_key_act('local', 'base') is None
    finally:
        await client.aclose()


TEAM_ID = 'base:team.example.com'


def _fetch(record):
    async def fetch():
        return record
    return fetch


@pytest.mark.asyncio
async def test_a_team_never_seen_is_pinned_to_the_first_key():
    pins = MemoryTeamKeyPins()
    _, team = keypair()
    resolver = TXTAnswers({})
    assert await pinned_team_key(TEAM_ID, team, pins=pins, fetch_act=_fetch(None), resolver=resolver, enforce=True) == team
    assert await pins.pin(TEAM_ID) == TeamKeyPin(team, None)


@pytest.mark.asyncio
@pytest.mark.parametrize('record', [None, 'stale-act'])
async def test_a_different_key_without_a_valid_act_is_refused(record):
    pins = MemoryTeamKeyPins()
    controller = keypair()
    _, pinned = keypair()
    _, served = keypair()
    await pins.first_sight(TEAM_ID, pinned)
    if record == 'stale-act':
        record = _example_act(controller, pinned)  # an act, but for another key
    with pytest.raises(TeamKeyUnverified) as refused:
        await pinned_team_key(
            TEAM_ID, served, pins=pins, fetch_act=_fetch(record),
            resolver=_dns('_awid.team.example.com', controller[1]), enforce=True,
        )
    assert refused.value.reason == ('no_act' if record is None else 'key_mismatch')
    assert await pins.pin(TEAM_ID) == TeamKeyPin(pinned, None)


@pytest.mark.asyncio
async def test_a_valid_act_moves_the_pin():
    pins = MemoryTeamKeyPins()
    controller = keypair()
    _, pinned = keypair()
    _, served = keypair()
    await pins.first_sight(TEAM_ID, pinned)
    record = _example_act(controller, served)
    key = await pinned_team_key(
        TEAM_ID, served, pins=pins, fetch_act=_fetch(record), resolver=_dns('_awid.team.example.com', controller[1]),
        enforce=True,
    )
    assert key == served
    moved = await pins.pin(TEAM_ID)
    assert moved.team_did_key == served
    assert moved.act_at == verify_team_key_act(record, domain='team.example.com', name='base', team_did_key=served).signed_at


@pytest.mark.asyncio
async def test_a_pin_that_moved_elsewhere_meanwhile_is_not_overwritten():
    controller = keypair()
    _, pinned = keypair()
    _, served = keypair()
    _, elsewhere = keypair()

    class Racing(MemoryTeamKeyPins):
        async def move(self, team_id, *, expected, new):
            self._pins[team_id] = TeamKeyPin(elsewhere, None)
            return False

    pins = Racing()
    await pins.first_sight(TEAM_ID, pinned)
    with pytest.raises(TeamKeyUnverified) as refused:
        await pinned_team_key(
            TEAM_ID, served, pins=pins, fetch_act=_fetch(_example_act(controller, served)),
            resolver=_dns('_awid.team.example.com', controller[1]), enforce=True,
        )
    assert refused.value.reason == 'pin_moved'
    assert (await pins.pin(TEAM_ID)).team_did_key == elsewhere


@pytest.mark.asyncio
async def test_without_enforcement_a_mismatch_is_logged_served_and_the_pin_kept(caplog):
    pins = MemoryTeamKeyPins()
    _, pinned = keypair()
    _, served = keypair()
    await pins.first_sight(TEAM_ID, pinned)
    with caplog.at_level(logging.WARNING, logger='awid.team_key_acts'):
        key = await pinned_team_key(
            TEAM_ID, served, pins=pins, fetch_act=_fetch(None), resolver=TXTAnswers({}), enforce=False,
        )
    assert key == served
    assert await pins.pin(TEAM_ID) == TeamKeyPin(pinned, None)
    assert [r.getMessage() for r in caplog.records] == [
        f'team_key_pin_mismatch team={TEAM_ID} pinned={pinned} served={served} reason=no_act enforced=false',
    ]


@pytest.mark.asyncio
async def test_with_enforcement_the_refusal_logs_the_same_line(caplog):
    pins = MemoryTeamKeyPins()
    _, pinned = keypair()
    _, served = keypair()
    await pins.first_sight(TEAM_ID, pinned)
    with caplog.at_level(logging.WARNING, logger='awid.team_key_acts'), pytest.raises(TeamKeyUnverified):
        await pinned_team_key(
            TEAM_ID, served, pins=pins, fetch_act=_fetch(None), resolver=TXTAnswers({}), enforce=True,
        )
    assert [r.getMessage() for r in caplog.records] == [
        f'team_key_pin_mismatch team={TEAM_ID} pinned={pinned} served={served} reason=no_act enforced=true',
    ]
