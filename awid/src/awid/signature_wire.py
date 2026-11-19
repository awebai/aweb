"""Ed25519 wire primitives; typed artifacts retain their own authority and profiles.

Legacy signature spelling is deliberately preserved for released Python callers.
Strict artifact codecs select their alphabet/canonical-bit policy explicitly.
"""

from __future__ import annotations

import base64
import re
from enum import Enum, auto

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class NoncanonicalBase64(ValueError):
    """An otherwise decodable value has another canonical spelling."""


class Ed25519Profile(Enum):
    MESSAGE = auto()
    ID_CERTIFICATE = auto()


class Base64Profile(Enum):
    CANONICAL_STANDARD = auto()
    CANONICAL_URL = auto()
    UNPADDED_STANDARD = auto()
    UNPADDED_URL = auto()
    PADDED_STANDARD = auto()
    LEGACY_PYTHON_SIGNATURE = auto()


def sign_bytes(*, key: bytes | SigningKey, payload: bytes) -> bytes:
    return (
        (key if isinstance(key, SigningKey) else SigningKey(key))
        .sign(payload)
        .signature
    )


def verify_bytes(
    *,
    key: bytes | VerifyKey,
    payload: bytes,
    signature: bytes,
    profile: Ed25519Profile = Ed25519Profile.MESSAGE,
) -> bytes:
    """Verify exact bytes per docs/signature-primitives.md:13-18; callers map errors."""
    if not prime_point(bytes(key)):
        raise BadSignatureError("invalid Ed25519 public key")
    if len(signature) != 64 or not canonical_point_encoding(signature[:32]):
        raise BadSignatureError("invalid Ed25519 R encoding")
    if profile is Ed25519Profile.ID_CERTIFICATE and (
        len(signature) != 64
        or not prime_point(signature[:32])
        or int.from_bytes(signature[32:], "little")
        >= 2**252 + 27742317777372353535851937790883648493
    ):
        raise BadSignatureError("invalid strict Ed25519 signature")
    return (key if isinstance(key, VerifyKey) else VerifyKey(key)).verify(
        payload, signature
    )


def decode_base64(
    value: str, *, profile: Base64Profile = Base64Profile.CANONICAL_STANDARD
) -> bytes:
    """Decode one explicit wire profile (docs/signature-primitives.md).

    Released Python spellings and padded E2EE fields retain their existing
    grammar. Strict artifact families require one canonical spelling.
    """
    if profile is Base64Profile.LEGACY_PYTHON_SIGNATURE:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if profile is Base64Profile.PADDED_STANDARD:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if not isinstance(value, str):
        raise ValueError("base64 must be text")
    url_alphabet = profile in {Base64Profile.CANONICAL_URL, Base64Profile.UNPADDED_URL}
    alphabet = r"[A-Za-z0-9_-]*" if url_alphabet else r"[A-Za-z0-9+/]*"
    if re.fullmatch(alphabet, value) is None:
        raise ValueError("invalid base64 alphabet")
    raw = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_" if url_alphabet else None,
        validate=True,
    )
    if profile in {Base64Profile.CANONICAL_URL, Base64Profile.CANONICAL_STANDARD}:
        encode = base64.urlsafe_b64encode if url_alphabet else base64.b64encode
        if encode(raw).rstrip(b"=").decode("ascii") != value:
            raise NoncanonicalBase64("noncanonical base64")
    return raw


def decode_legacy_signature(value: str) -> bytes:
    """Released Python spelling policy; narrowing requires measured cutoff."""
    return decode_base64(value, profile=Base64Profile.LEGACY_PYTHON_SIGNATURE)


def prime_point(encoded: bytes) -> bool:
    """Canonical, nonidentity Ed25519 point in the prime subgroup."""
    return canonical_point_encoding(encoded) and bool(
        crypto_core_ed25519_is_valid_point(encoded)
    )


def canonical_point_encoding(encoded: bytes) -> bool:
    """Representation only, per RFC 8032 5.1.2-3; curve/subgroup checks are separate.

    Both A and R reach this production predicate; the shared v2 component
    corpus does not claim full-signature isolation of noncanonical encodings.
    """
    if len(encoded) != 32:
        return False
    coordinate = int.from_bytes(encoded, "little")
    sign = coordinate >> 255
    y = coordinate & (2**255 - 1)
    field_prime = 2**255 - 19
    return y < field_prime and not (sign == 1 and y in {1, field_prime - 1})
