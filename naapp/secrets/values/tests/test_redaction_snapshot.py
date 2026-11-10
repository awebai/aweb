"""Original redaction inputs survive sealing and a fresh renderer instance."""

import base64
import json
import secrets
from urllib.parse import quote

import pytest

from aweb_secrets_values.redaction import KnownValues


def test_restored_snapshot_uses_the_same_encoding_and_tail_renderer():
    value = secrets.token_urlsafe(32) + '/päss "end'
    known = KnownValues()
    known.add("original", value)
    known.add_basic("basic", "user", value)
    bodies = [
        value.encode(),
        value.encode().hex().encode(),
        base64.b64encode(value.encode()),
        quote(value, safe="").encode(),
        json.dumps({"echo": value}).encode(),
        base64.b64encode(f"user:{value}".encode()),
    ]
    # Populate the lazy compiled matcher before snapshotting it.
    for body in bodies:
        known.redact(body)
    restored = KnownValues.restore(known.snapshot())
    for body in bodies:
        if restored.redact(body) != known.redact(body):
            raise AssertionError("restored redaction differs")
    if restored.redact_tail(value[:-3].encode()) != known.redact_tail(value[:-3].encode()):
        raise AssertionError("restored tail redaction differs")
    # Restoring constructs an independent renderer, not a shared mutable cache.
    known.add("later", "added-after-snapshot")
    assert restored.redact(b"added-after-snapshot") == (b"added-after-snapshot", 0)


def test_empty_snapshot_restores_an_empty_renderer():
    assert KnownValues.restore(KnownValues().snapshot()).redact(b"public") == (b"public", 0)


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        {"version": 2, "values": []},
        {"version": True, "values": []},
        {"version": 1, "values": "invalid"},
        {"version": 1, "values": [["ref", ""]]},
        {"version": 1, "values": [["ref", None]]},
        {"version": 1, "values": [[1, "value"]]},
        {"version": 1, "values": [["ref", "value", "extra"]]},
        {"version": 1, "values": [], "extra": True},
    ],
)
def test_invalid_snapshot_is_refused(document):
    with pytest.raises(ValueError):
        KnownValues.restore(json.dumps(document).encode())


def test_non_json_snapshot_is_refused():
    with pytest.raises(ValueError):
        KnownValues.restore(b"\xff")
