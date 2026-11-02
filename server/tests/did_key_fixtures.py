"""Real did:keys for tests that need a named, stable key rather than a signer.

did:key fields decode with the strict shared decoder, so a placeholder such as
"did:key:bob" is not a key. named_did_key(label) always gives the same valid
key for a label. SQL text keeps the key literal followed by a /* label */
comment; test_did_key_fixture_labels.py checks every such pair.
"""

from __future__ import annotations

import hashlib

from nacl.signing import SigningKey

from awid.did import did_from_public_key


def named_did_key(label: str) -> str:
    seed = hashlib.sha256(f"aweb-test-did-key:{label}".encode()).digest()
    return did_from_public_key(bytes(SigningKey(seed).verify_key))
