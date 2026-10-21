"""Every DID in secrets' vectors is one the identity grammar accepts.

A did:aw must pass AWID's stable-id validation and a did:key must decode to an
Ed25519 public key, so a consumer that validates principals, such as change/1,
can read the same fixtures.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from awid.did import public_key_from_did, validate_stable_id

ROOT = Path(__file__).resolve().parents[3]
VECTORS = [
    ROOT / "naapp" / "secrets" / "vectors" / "use-approval-v1.json",
    ROOT / "naapp" / "secrets" / "vectors" / "hook-actions-v1.json",
    ROOT / "docs" / "vectors" / "secrets-runner-protocol-v1.json",
]
DID = re.compile(r"did:(?:aw|key):[A-Za-z0-9]+")


@pytest.mark.parametrize("vector", VECTORS, ids=lambda path: path.name)
def test_every_did_is_valid(vector):
    dids = set(DID.findall(vector.read_text()))
    assert dids
    for did in dids:
        if did.startswith("did:aw:"):
            validate_stable_id(did)
        else:
            public_key_from_did(did)
