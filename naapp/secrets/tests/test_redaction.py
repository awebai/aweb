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
VALUE = "tok/en+with=chars\"and\\more"


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
        "percent-lower": re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), quote(value, safe="")),
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
