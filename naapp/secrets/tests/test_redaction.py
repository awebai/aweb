"""Known-value redaction: every value opened or derived in a dispatch is
replaced, in every encoding it can come back in (secrets §7.6 step 4)."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus

import pytest

from aweb_secrets.redaction import KnownValues

# Generated for these tests; not a credential of any service.
VALUE = 'tok/en+with=chars"and\\more'


def test_known_values_is_the_standalone_shared_class() -> None:
    from aweb_secrets_values.redaction import KnownValues as SharedKnownValues

    assert KnownValues is SharedKnownValues


def _encodings(value: str) -> dict[str, str]:
    raw = value.encode()
    return {
        "raw": value,
        "base64": base64.b64encode(raw).decode(),
        "base64-unpadded": base64.b64encode(raw).decode().rstrip("="),
        "base64url": base64.urlsafe_b64encode(raw).decode(),
        "base64url-unpadded": base64.urlsafe_b64encode(raw).decode().rstrip("="),
        "hex": raw.hex(),
        "hex-upper": raw.hex().upper(),
        "percent": quote(value, safe=""),
        "percent-lower": re.sub(
            r"%[0-9A-F]{2}", lambda m: m.group().lower(), quote(value, safe="")
        ),
        "percent-plus": quote_plus(value),
        "json-escaped": json.dumps(value)[1:-1],
    }


@pytest.mark.parametrize("encoding", list(_encodings(VALUE)))
def test_each_encoding_of_a_known_value_is_redacted_and_counted(encoding: str) -> None:
    known = KnownValues()
    known.add("stripe-test", VALUE)
    text = f"before {_encodings(VALUE)[encoding]} after".encode()
    redacted, count = known.redact(text)
    assert redacted == b"before [REDACTED:stripe-test] after"
    assert count == 1


def test_a_non_ascii_value_is_redacted_in_its_json_unicode_escapes() -> None:
    known = KnownValues()
    known.add("db", "pässwörd-välue")
    body = json.dumps({"echo": "pässwörd-välue"}, ensure_ascii=True).encode()
    redacted, count = known.redact(body)
    assert json.loads(redacted) == {"echo": "[REDACTED:db]"}
    assert count == 1


def test_every_occurrence_is_counted() -> None:
    known = KnownValues()
    known.add("gh", "ghsecretvalue123")
    body = json.dumps({"a": "ghsecretvalue123", "b": ["x ghsecretvalue123 y"]}).encode()
    redacted, count = known.redact(body)
    assert b"ghsecretvalue123" not in redacted
    assert count == 2
    assert json.loads(redacted) == {"a": "[REDACTED:gh]", "b": ["x [REDACTED:gh] y"]}


def test_the_basic_composite_and_its_base64_are_redacted_alongside_its_parts() -> None:
    known = KnownValues()
    known.add_basic("db", "svc-user", "pa55-word-value")
    header = base64.b64encode(b"svc-user:pa55-word-value").decode()
    redacted, count = known.redact(f"auth={header} pass=pa55-word-value".encode())
    assert redacted == b"auth=[REDACTED:db] pass=[REDACTED:db]"
    assert count == 2


def test_a_longer_encoding_wins_over_a_value_it_contains() -> None:
    known = KnownValues()
    known.add("a", "abc123def456")
    known.add("b", "abc123")
    redacted, count = known.redact(b"x abc123def456 y abc123 z")
    assert redacted == b"x [REDACTED:a] y [REDACTED:b] z"
    assert count == 2


def test_text_with_no_known_value_is_unchanged() -> None:
    known = KnownValues()
    known.add("a", "abc123def456")
    assert known.redact(b"nothing to see") == (b"nothing to see", 0)
    assert KnownValues().redact(b"nothing to see") == (b"nothing to see", 0)


def test_redacting_a_string_redacts_and_counts_the_same() -> None:
    known = KnownValues()
    known.add("a", "abc123def456")
    assert known.redact_text("https://x.example/?q=abc123def456") == (
        "https://x.example/?q=[REDACTED:a]",
        1,
    )


def test_an_empty_value_is_refused() -> None:
    with pytest.raises(ValueError):
        KnownValues().add("a", "")


SLASHED = 'a/b"c\\dé-' + "k3y/v4lue"


def test_json_escape_variants_of_a_value_are_redacted() -> None:
    known = KnownValues()
    known.add("k", SLASHED)
    plain = json.dumps(SLASHED)[1:-1]
    ascii_escaped = json.dumps(SLASHED, ensure_ascii=True)[1:-1]
    upper_hex = re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), ascii_escaped)
    for form in (
        plain.replace("/", "\\/"),
        ascii_escaped,
        ascii_escaped.replace("/", "\\/"),
        upper_hex,
        upper_hex.replace("/", "\\/"),
    ):
        redacted, count = known.redact(f'{{"v": "{form}"}}'.encode())
        assert redacted == b'{"v": "[REDACTED:k]"}', form
        assert count == 1


def test_a_value_inside_json_is_redacted_whatever_its_escaping() -> None:
    known = KnownValues()
    known.add("k", "p&ss<w>rd")
    # Go's encoding/json escapes <, > and & as <, > and &.
    body = b'{"echo": "p\\u0026ss\\u003cw\\u003erd", "n": 1}'
    redacted, count = known.redact_json(body)
    assert json.loads(redacted) == {"echo": "[REDACTED:k]", "n": 1}
    assert count == 1


def test_json_without_a_known_value_keeps_its_bytes() -> None:
    known = KnownValues()
    known.add("k", "abc123def456")
    body = b'{ "a" : 1,\n  "b": "x" }'
    assert known.redact_json(body) == (body, 0)
    assert known.redact_json(b"not json") == (b"not json", 0)


@pytest.mark.parametrize("offset", [0, 1, 2])
@pytest.mark.parametrize("alphabet", ["standard", "urlsafe"])
def test_a_value_inside_a_longer_base64_payload_is_redacted_at_any_alignment(
    offset: int, alphabet: str
) -> None:
    value = "s3cr3t/v+lue-0123456789"
    encode = base64.b64encode if alphabet == "standard" else base64.urlsafe_b64encode
    payload = encode(b"\x00" * offset + b'{"debug": "' + value.encode() + b'", "n": 1}').decode()
    known = KnownValues()
    known.add("k", value)
    redacted, count = known.redact(payload.encode())
    assert count == 1
    assert b"[REDACTED:k]" in redacted
    # No run of the encoded value survives.
    assert encode(value.encode())[4:12] not in redacted


def test_percent_escapes_in_mixed_case_are_redacted() -> None:
    known = KnownValues()
    known.add("k", "a/b+c=d")
    redacted, count = known.redact(b"x a%2f b%2Bc%3d d y a%2Fb%2bc%3Dd")
    assert count == 1
    assert redacted.endswith(b"[REDACTED:k]")


@pytest.mark.parametrize("cut", range(1, 23))
def test_the_tail_of_a_cut_body_never_ends_in_part_of_a_value(cut: int) -> None:
    value = "Q9w8E7r6T5y4U3i2O1p0Zz"
    known = KnownValues()
    known.add("k", value)
    body = ("-" * 10 + value)[: 10 + cut].encode()
    redacted, count = known.redact_tail(body)
    if cut < len(value):
        assert redacted == b"-" * 10 + b"[REDACTED:k]"
        assert count == 1
    else:
        assert redacted == body


def test_a_tail_that_is_part_of_no_value_is_kept() -> None:
    known = KnownValues()
    known.add("k", "Q9w8E7r6T5y4U3i2O1p0Zz")
    assert known.redact_tail(b"ends with nothing") == (b"ends with nothing", 0)
