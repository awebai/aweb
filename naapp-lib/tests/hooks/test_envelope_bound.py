"""The catalog's largest possible event stays under MAX_ENVELOPE_BYTES.

Every value an event can carry is bounded: the envelope's own fields by their
patterns, at most four attestations of at most 8192 characters, and each
payload field by its catalog type, enum or list bounds. This computes, per
hook, an upper bound of the signing bytes from those bounds alone, so a
catalog change that lets an event approach the limit fails here, naming how
close each hook comes."""

from __future__ import annotations

import json
import re
import re._parser as regex_parser
from pathlib import Path
from typing import Any

from aweb_naapp.hooks import envelope
from aweb_naapp.hooks.catalog import load_catalog
from aweb_naapp.hooks.envelope import MAX_ENVELOPE_BYTES, PREFIX
from aweb_naapp.hooks.strictjson import MAX_SAFE_INTEGER

AWEB_ROOT = Path(__file__).resolve().parents[3]
CATALOG_JSON = json.loads((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())
# A JSON string of printable ASCII escapes at most `"` and `\`, so a value
# of n characters encodes in at most 2n + 2 bytes.
QUOTE = 2


def pattern_width(pattern: re.Pattern[str] | str, max_length: int | None = None) -> int:
    """The most characters a value of this pattern can have."""
    source = pattern.pattern if isinstance(pattern, re.Pattern) else pattern
    widest = regex_parser.parse(source).getwidth()[1]
    if max_length is not None:
        widest = min(widest, max_length)
    assert widest < regex_parser.MAXREPEAT, f"{source} bounds nothing"
    return widest


def text(characters: int) -> int:
    return 2 * characters + QUOTE


def field(name: str, value: int) -> int:
    """A member of a canonical object: its key, a colon, its value and a comma."""
    return text(len(name)) + 1 + value + 1


def integer(maximum: int) -> int:
    return len(str(maximum))


def payload_bound(hook: dict[str, Any]) -> int:
    types = CATALOG_JSON["types"]

    def type_value(type_name: str) -> int:
        spec = types[type_name]
        if spec["kind"] == "string":
            return text(pattern_width(spec["pattern"], spec.get("max_length")))
        if spec["kind"] == "integer":
            return integer(spec["max"])
        return len("false")

    total = 2
    for name, spec in hook["fields"].items():
        if "enum" in spec:
            value = max(len(json.dumps(option)) for option in spec["enum"])
        elif "list_of" in spec:
            value = 2 + spec["max_items"] * (type_value(spec["list_of"]) + 1)
        elif "list_of_enum" in spec:
            value = 2 + sum(len(json.dumps(option)) + 1 for option in spec["list_of_enum"])
        else:
            value = type_value(spec["type"])
        total += field(name, value)
    return total


def frame_bound() -> int:
    """Every envelope field but the payload, at its widest, for any producer."""
    hook = max(len(name) for name in envelope.HOOKS)
    origin = pattern_width(envelope.ORIGIN_PATTERN)
    did_key = pattern_width(envelope._DID_KEY)
    producer = 2 + sum(
        (
            field("kind", text(len("client"))),
            field("origin", text(origin)),
            field("app_id", text(pattern_width(envelope._APP_ID))),
            field("installation_id", text(36)),
            field("generation", integer(MAX_SAFE_INTEGER)),
            field("kid", text(pattern_width(envelope.KID_PATTERN))),
            field("did_key", text(did_key)),
            field("seq", integer(MAX_SAFE_INTEGER)),
            field("certificate_id", text(pattern_width(envelope._CERTIFICATE_ID))),
        )
    )
    # Attestations are base64url, which never needs escaping.
    attestations = 2 + envelope._MAX_ATTESTATIONS * (envelope._MAX_ATTESTATION_BYTES + QUOTE + 1)
    actor = 2 + sum(
        (
            field(
                "authority_mode", max(len(json.dumps(mode)) for mode in envelope._AUTHORITY_MODES)
            ),
            field("attestations", attestations),
            field("did_key", text(did_key)),
            field("did_aw", text(pattern_width(envelope._DID_AW))),
            field("certificate_id", text(pattern_width(envelope._CERTIFICATE_ID))),
            field("alias", text(pattern_width(envelope._ALIAS))),
            field("grant_id", text(36)),
        )
    )
    time = text(len("2026-10-21T12:00:00.000Z"))
    return (
        len(PREFIX)
        + 2
        + sum(
            (
                field("v", 1),
                field("type", text(len("aweb.hook-event"))),
                field(
                    "catalog", 2 + field("id", text(len(envelope.CATALOG_ID))) + field("version", 1)
                ),
                field("hook", text(hook)),
                field("event_id", text(36)),
                field(
                    "trace",
                    2 + field("id", text(32)) + field("origin", text(len("signed_request"))),
                ),
                field("team_id", text(pattern_width(envelope.TEAM_ID_PATTERN))),
                field("producer", producer),
                field("actor", actor),
                field("occurred_at", time),
                field("fired_at", time),
                field("result_status", max(len(json.dumps(s)) for s in envelope._RESULT_STATUSES)),
                field("payload", 0),
            )
        )
    )


def test_the_frame_covers_every_envelope_field() -> None:
    assert set(envelope._TOP_FIELDS) == {
        "v", "type", "catalog", "hook", "event_id", "trace", "team_id", "producer",
        "actor", "occurred_at", "fired_at", "result_status", "payload",
    }  # fmt: skip


def test_every_catalog_string_is_bounded() -> None:
    for name, spec in CATALOG_JSON["types"].items():
        if spec["kind"] == "string":
            assert pattern_width(spec["pattern"], spec.get("max_length")) > 0, name


def test_the_catalogs_largest_event_is_under_the_envelope_bound() -> None:
    load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())
    frame = frame_bound()
    worst = {name: frame + payload_bound(hook) for name, hook in CATALOG_JSON["hooks"].items()}
    assert max(worst.values()) < MAX_ENVELOPE_BYTES, (
        f"worst-case signing bytes per hook {worst} reach MAX_ENVELOPE_BYTES {MAX_ENVELOPE_BYTES}"
    )
