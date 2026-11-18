"""OneDrive's quickXorHash, the content hash Graph reports on personal and business drives."""

import base64

_WIDTH_BITS = 160
_SHIFT_BITS = 11
_WIDTH_BYTES = _WIDTH_BITS // 8
_MASK = (1 << _WIDTH_BITS) - 1
_FOLD_BYTES = _WIDTH_BITS * 4096


def quick_xor_hash(data: bytes) -> str:
    """Return the base64 quickXorHash of data.

    Byte i is XORed into the 160-bit register at bit (11 * i) mod 160, so
    bytes 160 positions apart land on the same bit. The data is first folded
    into 160 byte columns by XOR, then each column is placed once.
    """
    columns = _fold_columns(data)
    register = 0
    for index, value in enumerate(columns):
        shifted = value << ((index * _SHIFT_BITS) % _WIDTH_BITS)
        register ^= (shifted & _MASK) | (shifted >> _WIDTH_BITS)
    digest = bytearray(register.to_bytes(_WIDTH_BYTES, "little"))
    for offset, value in enumerate(len(data).to_bytes(8, "little")):
        digest[_WIDTH_BYTES - 8 + offset] ^= value
    return base64.b64encode(bytes(digest)).decode("ascii")


def _fold_columns(data: bytes) -> bytes:
    """XOR every 160-byte block of data together, zero-padding the last."""
    folded = 0
    for start in range(0, len(data), _FOLD_BYTES):
        block = data[start : start + _FOLD_BYTES].ljust(_FOLD_BYTES, b"\0")
        folded ^= int.from_bytes(block, "little")
    wide = folded.to_bytes(_FOLD_BYTES, "little")
    columns = 0
    for start in range(0, _FOLD_BYTES, _WIDTH_BITS):
        columns ^= int.from_bytes(wide[start : start + _WIDTH_BITS], "little")
    return columns.to_bytes(_WIDTH_BITS, "little")
