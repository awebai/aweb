"""A manifest's did:keys are decoded by awid's did:key decoder.

That decoder refuses text longer than an Ed25519 did:key can encode before it
base58-decodes it, so a manifest carrying an over-long key is refused unread.
"""

from __future__ import annotations

from typing import Any

import pytest
from awid import did as did_module
from awid.did import did_from_public_key, generate_keypair

from aweb_naapp.manifest import ManifestError, canonical_bytes, load_manifest


@pytest.fixture
def decoded(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every text handed to awid's base58 decoder, in order."""
    seen: list[str] = []
    decode = did_module.b58.b58decode

    def record(text: Any) -> bytes:
        seen.append(text)
        return decode(text)

    monkeypatch.setattr(did_module.b58, "b58decode", record)
    return seen


def _did_key() -> str:
    _, public_key = generate_keypair()
    return did_from_public_key(public_key)


def _v1(did_key: str) -> bytes:
    return canonical_bytes({
        "manifest_version": 1,
        "app": {"id": "example", "origin": "https://example.test"},
        "tools": [],
        "event_emitters": [{"kid": "emit-1", "did_key": did_key}],
    })


def _v2(did_key: str) -> bytes:
    return canonical_bytes({
        "manifest_version": 2,
        "app": {"id": "example", "origin": "https://example.test"},
        "tools": [],
        "app_keys": [{"kid": "app-1", "did_key": did_key, "purposes": ["app-event"]}],
    })


# Each manifest version with the refusal code its did:key rule carries.
VERSIONS = [pytest.param(_v1, "manifest_invalid", id="v1"), pytest.param(_v2, "app_keys_invalid", id="v2")]


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize("extra", [1, 100, 20_000])
def test_an_over_long_did_key_is_refused_without_decoding(decoded, build, code, extra):
    valid = _did_key()
    load_manifest(build(valid))
    # The recorder sees the manifest's own decoding: a valid key passes through it.
    assert decoded == [valid.removeprefix("did:key:z")]
    decoded.clear()

    over_long = "did:key:z" + valid.removeprefix("did:key:z").ljust(47, "1") + "1" * extra
    with pytest.raises(ManifestError) as refused:
        load_manifest(build(over_long))
    assert refused.value.code == code
    assert decoded == []


@pytest.mark.parametrize(("build", "code"), VERSIONS)
def test_a_valid_did_key_validates(build, code):
    did_key = _did_key()
    manifest = load_manifest(build(did_key))
    assert list(manifest.app_keys_for("app-event").values()) == [did_key]


def _small_order_did_key() -> str:
    # The encoding of the identity point, a small-order Ed25519 key anyone can sign as.
    return did_from_public_key(b"\x01" + b"\x00" * 31)


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize(
    "did_key",
    [
        "did:key:zNotAKey",
        "did:key:z0OIl",
        "did:key:x6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
        "did:web:example.test",
        "did:key:z",
        "did:key:z" + did_module.b58.b58encode(b"\xec\x01" + b"\x07" * 32).decode(),
        pytest.param(_small_order_did_key(), id="small-order"),
    ],
)
def test_a_malformed_did_key_is_refused_with_the_version_code(build, code, did_key):
    with pytest.raises(ManifestError) as refused:
        load_manifest(build(did_key))
    assert refused.value.code == code
