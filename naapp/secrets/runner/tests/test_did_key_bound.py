"""A did:key is refused on its length before it is base58-decoded.

An Ed25519 did:key decodes to 34 bytes, so text longer than those bytes can
encode is refused without decoding it.
"""

import base58
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aweb_secrets_runner import protocol
from aweb_secrets_runner.protocol import public_did, public_key


@pytest.fixture
def decoded(monkeypatch):
    """Every text handed to the base58 decoder, in order."""
    seen: list[str] = []
    decode = protocol.base58.b58decode

    def record(text):
        seen.append(text)
        return decode(text)

    monkeypatch.setattr(protocol.base58, "b58decode", record)
    return seen


def test_the_bound_is_the_longest_base58_of_a_did_key():
    # awid's Python did.py derives _DID_KEY_ENCODED_MAX (47) the same way.
    assert protocol.DID_KEY_ENCODED_MAX == len(base58.b58encode(b"\xff" * 34)) == 47


def test_a_real_did_key_still_decodes(decoded):
    did = public_did(Ed25519PrivateKey.generate().public_key())
    assert len(did) == len("did:key:z") + 47
    assert public_did(public_key(did)) == did
    assert decoded == [did.removeprefix("did:key:z")]


def test_text_at_the_bound_is_decoded(decoded):
    with pytest.raises(ValueError, match="key type"):
        public_key("did:key:z" + "1" * 47)
    assert decoded == ["1" * 47]


@pytest.mark.parametrize("extra", [1, 100, 20_000])
def test_an_over_long_did_key_is_refused_without_decoding(decoded, extra):
    did = public_did(Ed25519PrivateKey.generate().public_key()) + "1" * extra
    with pytest.raises(ValueError, match="key encoding"):
        public_key(did)
    assert decoded == []
