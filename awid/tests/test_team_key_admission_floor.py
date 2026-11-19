"""A first-sight pin cannot be rolled back with a genuine historical act."""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from awid.did import did_from_public_key
from awid.external_authority import DNSLookup
from awid.signing import canonical_json_bytes, sign_message
from awid.team_key_acts import MemoryTeamKeyPins, TeamKeyUnverified, pinned_team_key
from nacl.signing import SigningKey


class NamespaceControllerDNS:
    def __init__(self, controller_did: str):
        self.controller_did = controller_did

    async def lookup_txt(self, name: str) -> DNSLookup:
        assert name == "_awid.example.test"
        return DNSLookup("record", (f"awid=v1; controller={self.controller_did};",))


def _keypair():
    key = SigningKey.generate()
    return bytes(key), did_from_public_key(bytes(key.verify_key))


def _rotation_act(*, signing_key: bytes, signer_did: str, new_key: str, signed_at: datetime):
    payload = canonical_json_bytes(
        {
            "operation": "rotate_team_key",
            "domain": "example.test",
            "name": "team",
            "new_team_did_key": new_key,
            "timestamp": signed_at.isoformat(),
        }
    )
    return {
        "signer_did_key": signer_did,
        "signed_payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
        "signature": sign_message(signing_key, payload),
    }


@pytest.mark.asyncio
async def test_first_sight_pin_refuses_a_genuine_act_older_than_admission():
    # docs/trust-model.md:524-528: the admission time is the floor when the
    # pin has no act time. The historical act is valid, just too old.
    controller_key, controller_did = _keypair()
    _, current_key = _keypair()
    _, historical_key = _keypair()
    record = _rotation_act(
        signing_key=controller_key,
        signer_did=controller_did,
        new_key=historical_key,
        signed_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    pins = MemoryTeamKeyPins()
    await pins.first_sight("team:example.test", current_key)

    async def fetch_act():
        return record

    with pytest.raises(TeamKeyUnverified) as refused:
        await pinned_team_key(
            "team:example.test",
            historical_key,
            pins=pins,
            fetch_act=fetch_act,
            resolver=NamespaceControllerDNS(controller_did),
            enforce=True,
        )
    assert refused.value.reason == "not_newer"
    recorded_pin = await pins.pin("team:example.test")
    assert recorded_pin is not None
    assert recorded_pin.team_did_key == current_key


@pytest.mark.asyncio
async def test_first_sight_pin_accepts_a_genuine_act_after_admission():
    controller_key, controller_did = _keypair()
    _, current_key = _keypair()
    _, next_key = _keypair()
    pins = MemoryTeamKeyPins()
    await pins.first_sight("team:example.test", current_key)
    record = _rotation_act(
        signing_key=controller_key,
        signer_did=controller_did,
        new_key=next_key,
        signed_at=datetime.now(timezone.utc),
    )

    async def fetch_act():
        return record

    assert (
        await pinned_team_key(
            "team:example.test",
            next_key,
            pins=pins,
            fetch_act=fetch_act,
            resolver=NamespaceControllerDNS(controller_did),
            enforce=True,
        )
        == next_key
    )


@pytest.mark.asyncio
async def test_staged_admission_floor_records_would_refuse_without_breaking_the_flow(caplog):
    controller_key, controller_did = _keypair()
    _, current_key = _keypair()
    _, historical_key = _keypair()
    record = _rotation_act(
        signing_key=controller_key,
        signer_did=controller_did,
        new_key=historical_key,
        signed_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    pins = MemoryTeamKeyPins()
    first = await pins.first_sight("team:example.test", current_key)

    async def fetch_act():
        return record

    assert (
        await pinned_team_key(
            "team:example.test",
            historical_key,
            pins=pins,
            fetch_act=fetch_act,
            resolver=NamespaceControllerDNS(controller_did),
            enforce=False,
        )
        == historical_key
    )
    assert "reason=not_newer enforced=false" in caplog.text
    admitted = await pins.pin("team:example.test")
    assert admitted is not None
    assert admitted.act_at is None
    assert admitted.admitted_at == first.admitted_at
