"""Ed25519 for the standalone runner and its existing cryptography backend."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_FIELD = 2**255 - 19
_ORDER = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _FIELD) % _FIELD
_SQRT_MINUS_ONE = pow(2, (_FIELD - 1) // 4, _FIELD)
type _Point = tuple[int, int, int, int]
_IDENTITY: _Point = (0, 1, 1, 0)


def canonical_point_encoding(encoded: bytes) -> bool:
    """Check the shared wire representation rule before interpreting a point."""
    if len(encoded) != 32:
        return False
    coordinate = int.from_bytes(encoded, "little")
    sign = coordinate >> 255
    y = coordinate & (2**255 - 1)
    return y < _FIELD and not (sign == 1 and y in {1, _FIELD - 1})


def _add(left: _Point, right: _Point) -> _Point:
    # Complete addition in extended Edwards coordinates, RFC 8032 section 5.1.4.
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _FIELD
    b = (y1 + x1) * (y2 + x2) % _FIELD
    c = 2 * _D * t1 * t2 % _FIELD
    d = 2 * z1 * z2 % _FIELD
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _FIELD, g * h % _FIELD, f * g % _FIELD, e * h % _FIELD


def _prime_point(encoded: bytes) -> bool:
    if not canonical_point_encoding(encoded):
        return False
    coordinate = int.from_bytes(encoded, "little")
    y = coordinate & (2**255 - 1)
    if y == 1:
        return False
    y_squared = y * y % _FIELD
    # Recover x from the canonical compressed point (RFC 8032 section 5.1.3).
    x_squared = (y_squared - 1) * pow(_D * y_squared + 1, _FIELD - 2, _FIELD) % _FIELD
    x = pow(x_squared, (_FIELD + 3) // 8, _FIELD)
    if x * x % _FIELD != x_squared:
        x = x * _SQRT_MINUS_ONE % _FIELD
    if x * x % _FIELD != x_squared:
        return False
    if x & 1 != coordinate >> 255:
        x = (-x) % _FIELD

    # A nonidentity point belongs to the prime subgroup iff [L]P is identity.
    # These coordinates and the scalar are public. The backend owns the
    # signature equation and all operations on the private key.
    point: _Point = (x, y, 1, x * y % _FIELD)
    result = _IDENTITY
    order = _ORDER
    while order:
        if order & 1:
            result = _add(result, point)
        point = _add(point, point)
        order >>= 1
    x, y, z, _ = result
    return x == 0 and y == z and z != 0


def sign_bytes(key: Ed25519PrivateKey, payload: bytes) -> bytes:
    return key.sign(payload)


def verify_bytes(key: Ed25519PublicKey, signature: bytes, payload: bytes) -> None:
    if (
        len(signature) != 64
        or int.from_bytes(signature[32:], "little") >= _ORDER
        or not _prime_point(key.public_bytes_raw())
        or not _prime_point(signature[:32])
    ):
        raise InvalidSignature("invalid Ed25519 point or scalar")
    key.verify(signature, payload)
