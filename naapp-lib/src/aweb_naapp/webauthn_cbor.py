"""Bounded tag-free CBOR profile, before cbor2 can erase semantic tags.

This reads lengths/types, never serializes or changes the signed bytes. Actual
value and duplicate-key decoding remains cbor2's. Limits share the wire source
with Go's DecOptions; a CBOR tag must not turn a non-integer into a COSE integer.
"""

import io

import cbor2

# Approval protocol.md:337-345 and format-v1.json x-cbor-limits.
# One bounded, tag-free profile for the original authenticator extension bytes.
LIMITS = {"max_depth": 8, "max_map_pairs": 16, "max_array_elements": 16}


class CBORProfileError(ValueError):
    """The signed CBOR is outside the bounded authenticator profile."""


def cbor_item_end(raw: bytes, start: int = 0) -> int:
    if len(raw) > 1 << 20:
        raise CBORProfileError("cbor_size")

    def walk(pos, depth):
        if pos >= len(raw):
            raise CBORProfileError("cbor_truncated")
        initial = raw[pos]
        pos += 1
        major = initial >> 5
        additional = initial & 31
        if major == 6:
            raise CBORProfileError("cbor_tag_refused")
        if additional < 24:
            value = additional
        elif additional in (24, 25, 26, 27):
            size = 1 << (additional - 24)
            if pos + size > len(raw):
                raise CBORProfileError("cbor_truncated")
            value = int.from_bytes(raw[pos : pos + size])
            pos += size
        elif additional == 31:
            value = None
        else:
            raise CBORProfileError("cbor_reserved")
        if major in (0, 1):
            if value is None:
                raise CBORProfileError("cbor_integer_invalid")
            return pos
        if major in (2, 3):
            if value is not None:
                end = pos + value
                if end > len(raw):
                    raise CBORProfileError("cbor_truncated")
                if major == 3:
                    raw[pos:end].decode("utf-8")
                return end
            while pos < len(raw) and raw[pos] != 255:
                if raw[pos] >> 5 != major or raw[pos] & 31 == 31:
                    raise CBORProfileError("cbor_chunk_invalid")
                pos = walk(pos, depth)
            if pos >= len(raw):
                raise CBORProfileError("cbor_truncated")
            return pos + 1
        if major in (4, 5):
            if depth >= LIMITS["max_depth"]:
                raise CBORProfileError("cbor_depth")
            limit = LIMITS["max_array_elements"] if major == 4 else LIMITS["max_map_pairs"]
            if value is not None and value > limit:
                raise CBORProfileError("cbor_container_limit")
            count = 0
            while value is None or count < value:
                if value is None and pos < len(raw) and raw[pos] == 255:
                    return pos + 1
                if count >= limit:
                    raise CBORProfileError("cbor_container_limit")
                pos = walk(pos, depth + 1)
                if major == 5:
                    pos = walk(pos, depth + 1)
                count += 1
            return pos
        if major == 7:
            if value is None:
                raise CBORProfileError("cbor_unexpected_break")
            return pos
        raise CBORProfileError("cbor_type_invalid")

    return walk(start, 0)


def read_cbor_item(stream: io.BytesIO):
    raw = stream.getvalue()
    end = cbor_item_end(raw, stream.tell())
    value = cbor2.CBORDecoder(
        stream, allow_duplicate_keys=False, max_depth=LIMITS["max_depth"]
    ).decode()
    if stream.tell() != end:
        raise CBORProfileError("cbor_decoder_boundary")
    return value


def decode_cbor_map(raw: bytes) -> dict:
    stream = io.BytesIO(raw)
    value = read_cbor_item(stream)
    if stream.tell() != len(raw) or not isinstance(value, dict):
        raise CBORProfileError("cbor_map_required")
    return value
