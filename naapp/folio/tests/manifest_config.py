"""Public, deterministic deployment key material used only by Folio's tests."""

import copy

from awid.did import did_from_public_key
from nacl.signing import SigningKey

from folio.aweb_manifest import MANIFEST

TEST_EMIT_SEED_HEX = "01" * 32
TEST_GRANT_SEED_HEX = "02" * 32
TEST_GRANT_DID_KEY = did_from_public_key(bytes(SigningKey(bytes.fromhex(TEST_GRANT_SEED_HEX)).verify_key))
TEST_EMIT_DID_KEY = did_from_public_key(bytes(SigningKey(bytes.fromhex(TEST_EMIT_SEED_HEX)).verify_key))


def served_manifest(origin: str) -> dict:
    """Expected deployment document: template declarations plus its public key."""
    manifest = copy.deepcopy(MANIFEST)
    manifest["app"]["origin"] = origin.rstrip("/")
    manifest["app_keys"] = [
        {"kid": "folio:emit-1", "did_key": TEST_EMIT_DID_KEY, "purposes": ["app-event"]},
        {"kid": "folio:grant-read-1", "did_key": TEST_GRANT_DID_KEY, "purposes": ["app-grant-read"]},
    ]
    return manifest
