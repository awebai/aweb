"""DID text is refused on its length before it is base58-decoded.

An Ed25519 did:key and a did:aw have fixed decoded sizes, so text longer than
those sizes can encode is refused without decoding it.
"""

from __future__ import annotations

import pytest

from awid import did as did_module
from awid.did import (
    did_from_public_key,
    generate_keypair,
    public_key_from_did,
    stable_id_from_public_key,
    validate_did,
    validate_stable_id,
)
from awid.dns_auth import validate_did_key


@pytest.fixture
def decoded(monkeypatch):
    """Every text handed to the base58 decoder, in order."""
    seen: list[str] = []
    decode = did_module.b58.b58decode

    def record(text):
        seen.append(text)
        return decode(text)

    monkeypatch.setattr(did_module.b58, "b58decode", record)
    return seen


def _did_key() -> str:
    _, public_key = generate_keypair()
    return did_from_public_key(public_key)


def _stable_id() -> str:
    _, public_key = generate_keypair()
    return stable_id_from_public_key(public_key)


def test_a_real_did_key_still_decodes():
    did_key = _did_key()
    assert did_from_public_key(public_key_from_did(did_key)) == did_key


def test_a_real_stable_id_still_validates():
    stable_id = _stable_id()
    assert validate_stable_id(stable_id) == stable_id


def test_a_stable_id_of_twenty_zero_bytes_still_validates():
    # The shortest encoding of twenty bytes: one character per zero byte.
    assert validate_stable_id("did:aw:" + "1" * 20) == "did:aw:" + "1" * 20


@pytest.mark.parametrize("extra", [1, 100, 20_000])
def test_an_over_long_did_key_is_refused_without_decoding(decoded, extra):
    did_key = _did_key() + "1" * extra
    with pytest.raises(ValueError):
        public_key_from_did(did_key)
    assert validate_did(did_key) is False
    with pytest.raises(ValueError):
        validate_did_key(did_key)
    assert decoded == []


@pytest.mark.parametrize("extra", [1, 100, 20_000])
def test_an_over_long_stable_id_is_refused_without_decoding(decoded, extra):
    with pytest.raises(ValueError):
        validate_stable_id(_stable_id() + "1" * extra)
    assert decoded == []


def test_text_within_the_bound_reaches_the_decoder(decoded):
    did_key = _did_key()
    public_key_from_did(did_key)
    assert decoded == [did_key.removeprefix("did:key:z")]


def test_the_longest_text_a_did_key_can_have_is_still_decoded():
    # Forty-seven characters is the most that thirty-four bytes encode to, so
    # text of that length is decoded and judged on what it decodes to.
    with pytest.raises(ValueError, match="multicodec|34 bytes|canonical"):
        public_key_from_did("did:key:z" + "z" * 47)


def test_the_longest_text_a_stable_id_can_have_is_still_decoded():
    with pytest.raises(ValueError, match="20 bytes"):
        validate_stable_id("did:aw:" + "z" * 28)
