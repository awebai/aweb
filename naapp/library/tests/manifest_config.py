"""Public, deterministic deployment key material used only by Library's tests."""

import copy

from awid.did import did_from_public_key
from nacl.signing import SigningKey

from library.aweb_manifest import MANIFEST

TEST_GRANT_SEED_HEX = "03" * 32
TEST_GRANT_DID_KEY = did_from_public_key(
    bytes(SigningKey(bytes.fromhex(TEST_GRANT_SEED_HEX)).verify_key)
)


def served_manifest(origin: str) -> dict:
    """Expected deployment document: template declarations plus its public key."""
    manifest = copy.deepcopy(MANIFEST)
    manifest["app"]["origin"] = origin.rstrip("/")
    manifest["app_keys"] = [
        {
            "kid": "library:grant-read-1",
            "did_key": TEST_GRANT_DID_KEY,
            "purposes": ["app-grant-read"],
        },
    ]
    return manifest
