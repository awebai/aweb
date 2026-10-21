"""Envelope sealing with the local key file: a fresh data key per value, bound to its context."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from aweb_secrets.custody import (
    CustodyUnavailable,
    LocalKeyFileProvider,
    SealContext,
    seal,
    seal_canary,
    unseal,
)

from .conftest import write_key_file

CONTEXT = SealContext(
    installation_id="installation-1", team_id="team-1", secret_id="secret-1", version=1
)


def test_a_sealed_value_unseals_under_its_context(
    provider: LocalKeyFileProvider, canary: bytes
) -> None:
    sealed = seal(provider, CONTEXT, canary)
    assert unseal(provider, CONTEXT, sealed).reveal() == canary


def test_the_sealed_form_does_not_hold_the_value(
    provider: LocalKeyFileProvider, canary: bytes
) -> None:
    sealed = seal(provider, CONTEXT, canary)
    for part in (sealed.ciphertext, sealed.nonce, sealed.wrapped_key):
        assert canary not in part
    assert canary.decode() not in repr(sealed)


def test_each_value_gets_its_own_data_key(provider: LocalKeyFileProvider, canary: bytes) -> None:
    first = seal(provider, CONTEXT, canary)
    second = seal(provider, CONTEXT, canary)
    assert first.wrapped_key != second.wrapped_key
    assert first.ciphertext != second.ciphertext


@pytest.mark.parametrize(
    "field, other",
    [
        ("installation_id", "installation-2"),
        ("team_id", "team-2"),
        ("secret_id", "secret-2"),
        ("version", 2),
    ],
)
def test_a_value_sealed_for_one_context_does_not_unseal_under_another(
    provider: LocalKeyFileProvider, canary: bytes, field: str, other: object
) -> None:
    sealed = seal(provider, CONTEXT, canary)
    elsewhere = dataclasses.replace(CONTEXT, **{field: other})
    with pytest.raises(CustodyUnavailable):
        unseal(provider, elsewhere, sealed)


def test_a_data_key_moved_onto_another_value_does_not_unseal(
    provider: LocalKeyFileProvider, canary: bytes
) -> None:
    first = seal(provider, CONTEXT, canary)
    second = seal(provider, CONTEXT, os.urandom(8))
    spliced = dataclasses.replace(second, wrapped_key=first.wrapped_key)
    with pytest.raises(CustodyUnavailable):
        unseal(provider, CONTEXT, spliced)


def test_another_key_encryption_key_cannot_unseal(
    provider: LocalKeyFileProvider, canary: bytes, tmp_path: Path
) -> None:
    sealed = seal(provider, CONTEXT, canary)
    other = LocalKeyFileProvider(write_key_file(tmp_path / "other-kek", os.urandom(32)))
    with pytest.raises(CustodyUnavailable):
        unseal(other, CONTEXT, sealed)


def test_an_unsealed_value_does_not_show_itself(
    provider: LocalKeyFileProvider, canary: bytes
) -> None:
    plaintext = unseal(provider, CONTEXT, seal(provider, CONTEXT, canary))
    assert canary.decode() not in repr(plaintext)
    assert canary.decode() not in str(plaintext)
    assert canary.decode() not in f"{plaintext}"


def test_a_refused_unseal_does_not_carry_the_value(
    provider: LocalKeyFileProvider, canary: bytes
) -> None:
    sealed = seal(provider, CONTEXT, canary)
    with pytest.raises(CustodyUnavailable) as refused:
        unseal(provider, dataclasses.replace(CONTEXT, version=2), sealed)
    assert refused.value.code == "custody_unavailable"
    assert canary.decode() not in str(refused.value)


def test_the_canary_passes_with_a_working_key(provider: LocalKeyFileProvider) -> None:
    seal_canary(provider)
