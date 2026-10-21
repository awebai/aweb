"""The DID grammar of a secrets principal: S5's stable principal key.

A principal is a member's did:aw, or its did:key when its certificate carries
no did:aw. Both are matched against the ASCII base58btc alphabet first, so a
DID is ASCII and bounded before AWID decodes it, and then decoded by AWID.
"""

from __future__ import annotations

import re
from typing import Any

from awid.did import public_key_from_did, validate_stable_id

_BASE58 = "[1-9A-HJ-NP-Za-km-z]"
_DID_AW = re.compile(f"did:aw:{_BASE58}{{1,64}}")
_DID_KEY = re.compile(f"did:key:z{_BASE58}{{1,64}}")


def is_did_aw(value: Any) -> bool:
    if not isinstance(value, str) or not _DID_AW.fullmatch(value):
        return False
    try:
        validate_stable_id(value)
    except ValueError:
        return False
    return True


def is_did_key(value: Any) -> bool:
    """Whether ``value`` is an Ed25519 did:key."""
    if not isinstance(value, str) or not _DID_KEY.fullmatch(value):
        return False
    try:
        public_key_from_did(value)
    except ValueError:
        return False
    return True


def is_principal(value: Any) -> bool:
    if isinstance(value, str) and value.startswith("did:aw:"):
        return is_did_aw(value)
    return is_did_key(value)
