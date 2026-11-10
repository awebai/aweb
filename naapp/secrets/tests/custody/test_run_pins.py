"""Whole-value equivalence uses native-sealed random keys, never a value copy."""

import secrets
from dataclasses import replace
from uuid import uuid4

import pytest

from aweb_secrets.custody import CustodyUnavailable, Plaintext, SealContext, unseal
from aweb_secrets.custody.run_pins import RunPins, key_context


@pytest.fixture
def pins(provider):
    return RunPins(provider)


async def original(pins):
    context = SealContext("installation", "team", "sec_original", 7)
    value = Plaintext(secrets.token_bytes(48))
    return value, await pins.prepare(context, uuid4(), value, observation=None)


async def test_digest_proves_the_whole_original_value(pins):
    value, pin = await original(pins)
    assert await pins.matches(pin, value)
    for changed in (value.reveal()[:-1], value.reveal() + b"x", secrets.token_bytes(48)):
        assert not await pins.matches(pin, Plaintext(changed))


async def test_envelope_contains_only_an_independent_random_key(pins, provider):
    value, pin = await original(pins)
    key = unseal(provider, key_context(pin.context, pin.dispatch_id), pin.sealed_key).reveal()
    assert len(key) == 32
    if key == value.reveal():
        raise AssertionError("key envelope contains the released value")
    assert len(pin.digest) == 32
    if value.reveal() in pin.sealed_key.ciphertext:
        raise AssertionError("released value was copied into key storage")


async def test_identical_values_have_independent_assignment_keys(pins):
    value, pin = await original(pins)
    another = await pins.prepare(pin.context, uuid4(), value, observation=None)
    assert pin.digest != another.digest
    assert pin.sealed_key != another.sealed_key
    assert await pins.matches(another, value)


@pytest.mark.parametrize(
    "field", ["installation_id", "team_id", "secret_id", "version", "dispatch_id"]
)
async def test_key_cannot_be_relabelled_to_another_slot_or_dispatch(pins, field):
    value, pin = await original(pins)
    if field == "dispatch_id":
        copied = replace(pin, dispatch_id=uuid4())
    else:
        copied = replace(
            pin, context=replace(pin.context, **{field: 8 if field == "version" else "other"})
        )
    with pytest.raises(CustodyUnavailable):
        await pins.matches(copied, value)


async def test_corrupt_or_missing_equivalence_does_not_match(pins):
    value, pin = await original(pins)
    assert not await pins.matches(replace(pin, digest=secrets.token_bytes(32)), value)
    corrupt = replace(
        pin, sealed_key=replace(pin.sealed_key, ciphertext=pin.sealed_key.ciphertext + b"x")
    )
    with pytest.raises(CustodyUnavailable):
        await pins.matches(corrupt, value)


async def test_onepassword_value_equivalence_does_not_depend_on_metadata_completeness(pins):
    """Actual SDK-model projection; this is not a successful SDK/vault call."""
    from aweb_secrets.custody.onepassword import project_item
    from aweb_secrets.custody.opening import ActiveOnePasswordBinding, BackendObservation
    from aweb_secrets.custody.run_pins import observation_pin
    from aweb_secrets.custody.store import BACKEND_CREDENTIAL_ID
    from tests.custody.test_onepassword import field, reference, sdk_item

    context = SealContext("installation", "team", "sec_original", 7)
    token = replace(context, secret_id=BACKEND_CREDENTIAL_ID, version=3)
    item = sdk_item([field("credential", secrets.token_urlsafe(32))])
    read = project_item(reference(), item, credential_context=token)
    binding = ActiveOnePasswordBinding(context, token, reference(), 7, "version-ref", "{}")
    observed = BackendObservation(binding, read.item_version, read.updated_at)
    pin = await pins.prepare(context, uuid4(), read.value, observation=observed)
    assert pin.credential_version == 3
    assert pin.observation == observation_pin(observed)
    assert await pins.matches(pin, read.value)
    changed = project_item(
        reference(),
        sdk_item(
            [field("credential", secrets.token_urlsafe(32))],
            updated_at=item.updated_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        ),
        credential_context=token,
    )
    # Even identical version/timestamp observations cannot bless changed bytes.
    assert (
        observation_pin(BackendObservation(binding, changed.item_version, changed.updated_at))
        == pin.observation
    )
    assert not await pins.matches(pin, changed.value)
    assert observation_pin(replace(observed, item_version=8)) != pin.observation
    assert (
        observation_pin(
            replace(
                observed, binding=replace(binding, credential_context=replace(token, version=4))
            )
        )
        != pin.observation
    )
