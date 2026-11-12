"""A manifest's did:keys: their shape at load, their key where they are used.

:func:`load_manifest` is standard library only, so it checks a declared
did:key's shape (the ``did:key:z`` prefix, awid's encoded-length bound and the
base58 alphabet) and decodes nothing. :func:`check_manifest_keys` decodes every
declared key with awid, which refuses anything that is not a canonical
prime-order Ed25519 key; every consumer that acts on a manifest's keys calls it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from awid import did as did_module
from awid.did import did_from_public_key, generate_keypair

from aweb_naapp import manifest as manifest_module
from aweb_naapp.did_key import DID_KEY_ENCODED_MAX
from aweb_naapp.manifest import Manifest, ManifestError, canonical_bytes, load_manifest

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors" / "app-manifests"
V2 = json.loads((VECTORS / "app-manifest-v2-v1.json").read_text(encoding="utf-8"))
# The shared vector's well-shaped did:key that is no Ed25519 key.
BAD_DID = next(
    case for case in V2["cases"] if case["name"] == "app_key_bad_did"
)["mutations"][0]["value"]


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


def check_manifest_keys(manifest: Manifest) -> None:
    from aweb_naapp.manifest_keys import check_manifest_keys as check

    check(manifest)


def _did_key() -> str:
    _, public_key = generate_keypair()
    return did_from_public_key(public_key)


def _small_order_did_key() -> str:
    # The encoding of the identity point, a small-order Ed25519 key anyone can sign as.
    return did_from_public_key(b"\x01" + b"\x00" * 31)


def _wrong_multicodec_did_key() -> str:
    return "did:key:z" + did_module.b58.b58encode(b"\xec\x01" + b"\x07" * 32).decode()


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


def _base58_length(byte_count: int) -> int:
    """How many base58 characters the largest value of byte_count bytes takes."""
    value, length = 256**byte_count - 1, 0
    while value:
        value, length = value // 58, length + 1
    return length


def test_the_encoded_bound_is_the_longest_base58_of_a_did_key():
    # 34 bytes: the two of the Ed25519 multicodec and the 32 of the key.
    assert DID_KEY_ENCODED_MAX == _base58_length(34)


def test_load_checks_the_shape_against_the_one_bound():
    assert manifest_module._DID_KEY_SHAPE.pattern.endswith(f"{{1,{DID_KEY_ENCODED_MAX}}}")


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize("extra", [1, 100, 20_000])
def test_an_over_long_did_key_is_refused_at_load_without_decoding(decoded, build, code, extra):
    over_long = "did:key:z" + _did_key().removeprefix("did:key:z").ljust(47, "1") + "1" * extra
    with pytest.raises(ManifestError) as refused:
        load_manifest(build(over_long))
    assert refused.value.code == code
    assert decoded == []


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize(
    "did_key",
    [
        "did:key:z",
        "did:key:z0OIl",
        "did:key:z6Mk+",
        "did:key:x6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2",
        "did:web:example.test",
        "did:key:z" + "2" * 48,
    ],
)
def test_a_badly_shaped_did_key_is_refused_at_load(build, code, did_key):
    with pytest.raises(ManifestError) as refused:
        load_manifest(build(did_key))
    assert refused.value.code == code


# Well-shaped text that is no canonical prime-order Ed25519 key.
NOT_A_KEY = [
    pytest.param(BAD_DID, id="app_key_bad_did"),
    pytest.param("did:key:z" + "2" * 47, id="longest-shape"),
    pytest.param(_wrong_multicodec_did_key(), id="wrong-multicodec"),
    pytest.param(_small_order_did_key(), id="small-order"),
]


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize("did_key", NOT_A_KEY)
def test_load_checks_shape_and_decodes_nothing(decoded, build, code, did_key):
    manifest = load_manifest(build(did_key))
    assert list(manifest.app_keys_for("app-event").values()) == [did_key]
    assert decoded == []


@pytest.mark.parametrize(("build", "code"), VERSIONS)
@pytest.mark.parametrize("did_key", NOT_A_KEY)
def test_a_well_shaped_key_that_is_no_ed25519_key_is_refused_where_it_is_used(build, code, did_key):
    manifest = load_manifest(build(did_key))
    with pytest.raises(ManifestError) as refused:
        check_manifest_keys(manifest)
    assert refused.value.code == code


@pytest.mark.parametrize(("build", "code"), VERSIONS)
def test_a_valid_did_key_validates(decoded, build, code):
    did_key = _did_key()
    manifest = load_manifest(build(did_key))
    check_manifest_keys(manifest)
    assert list(manifest.app_keys_for("app-event").values()) == [did_key]
    assert decoded == [did_key.removeprefix("did:key:z")]
