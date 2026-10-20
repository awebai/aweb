"""The envelope vector's payloads, read through the strict catalog reader.

Positive envelopes carry payloads the catalog allows. Catalog-layer negatives
pass every envelope check and are refused by the catalog with the stated
fault, so the two layers together refuse every negative.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aweb_naapp.hooks.catalog import PayloadRefused, load_catalog

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((AWEB_ROOT / "docs" / "vectors" / "hook-event-envelope-v1.json").read_bytes())
CATALOG = load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())
PREFIX = b"aweb.hook-event/1\n"


def _envelope(signing_b64url: str) -> dict:
    padded = signing_b64url + "=" * (-len(signing_b64url) % 4)
    signing = base64.urlsafe_b64decode(padded)
    assert signing.startswith(PREFIX)
    return json.loads(signing[len(PREFIX) :])


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_positive_envelope_payload_is_allowed(case) -> None:
    envelope = _envelope(case["signing_bytes_b64url"])
    assert envelope == case["envelope"]
    CATALOG.validate(envelope["hook"], envelope["payload"])


CATALOG_NEGATIVES = [c for c in VECTOR["negative_cases"] if c["layer"] == "catalog"]


@pytest.mark.parametrize("case", CATALOG_NEGATIVES, ids=lambda c: c["name"])
def test_catalog_layer_negative_is_refused_by_the_catalog(case) -> None:
    envelope = _envelope(case["signing_bytes_b64url"])
    with pytest.raises(PayloadRefused) as refused:
        CATALOG.validate(envelope["hook"], envelope["payload"])
    assert (refused.value.code, refused.value.field) == (case["error"], case["field"])


def test_vector_has_catalog_layer_negatives() -> None:
    assert len(CATALOG_NEGATIVES) >= 2
