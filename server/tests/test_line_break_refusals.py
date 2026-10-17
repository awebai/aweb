"""Anchored patterns refuse a value that ends in a line break.

Python's ``$`` also matches before a final ``"\\n"``, so a pattern checked with
``re.match`` accepts ``"value\\n"``. These are the sites that check a value as
received, without stripping it first.
"""

from __future__ import annotations

import base64
import copy
from datetime import datetime
import json
from pathlib import Path

import pytest

from awid.signing import canonical_json_bytes, sign_message
from aweb import app_registry
from aweb.agent_status import StatusDocumentError, verify_status_document
from aweb.internal_auth import _is_valid_proxy_team_id
from aweb.signed_document import decode_payload

LINE_BREAKS = pytest.mark.parametrize("suffix", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"])

STATUS_VECTOR = json.loads(
    (Path(__file__).parents[2] / "docs" / "vectors" / "agent-status-v1.json").read_text()
)
STATUS_NOW = datetime.fromisoformat(STATUS_VECTOR["valid"][0]["now"].replace("Z", "+00:00"))


def _signed_status(**changes) -> tuple[str, str]:
    document = copy.deepcopy(STATUS_VECTOR["valid"][0]["document"])
    document.update(changes)
    canonical = canonical_json_bytes(document)
    return (
        base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
        sign_message(bytes.fromhex(STATUS_VECTOR["signing_seed_hex"]), canonical),
    )


def _verify_status(signed_payload: str, signature: str) -> dict:
    return verify_status_document(
        signed_payload,
        signature,
        signer_did=STATUS_VECTOR["publisher_did_key"],
        now=STATUS_NOW,
    )


def test_proxy_team_id_accepts_the_bare_value():
    assert _is_valid_proxy_team_id("ops:acme.com")


@LINE_BREAKS
def test_proxy_team_id_refuses_a_line_break_after_the_team_name(suffix):
    assert not _is_valid_proxy_team_id(f"ops{suffix}:acme.com")


def test_signed_payload_without_a_line_break_verifies():
    reason = {"code": "oats.grant_expired", "text": "Its connection expired."}
    assert _verify_status(*_signed_status(reachable="no", reason=reason))["reason"] == reason


# A payload whose length is a multiple of four decodes with the line break
# discarded, so the refusal has to come from the pattern.
WHOLE_QUANTUM_PAYLOAD = base64.urlsafe_b64encode(b'{"ab"}').decode("ascii")


def test_whole_quantum_payload_decodes():
    assert len(WHOLE_QUANTUM_PAYLOAD) % 4 == 0
    assert decode_payload(WHOLE_QUANTUM_PAYLOAD, max_bytes=64, error=StatusDocumentError) == b'{"ab"}'


@LINE_BREAKS
def test_signed_payload_refuses_a_trailing_line_break(suffix):
    with pytest.raises(StatusDocumentError) as refused:
        decode_payload(WHOLE_QUANTUM_PAYLOAD + suffix, max_bytes=64, error=StatusDocumentError)
    assert refused.value.code == "malformed_payload"


@LINE_BREAKS
def test_status_reason_code_refuses_a_trailing_line_break(suffix):
    reason = {"code": "oats.grant_expired" + suffix, "text": "Its connection expired."}
    with pytest.raises(StatusDocumentError) as refused:
        _verify_status(*_signed_status(reachable="no", reason=reason))
    assert refused.value.code == "invalid_value"


@LINE_BREAKS
def test_status_timestamp_refuses_a_trailing_line_break(suffix):
    observed_at = STATUS_VECTOR["valid"][0]["document"]["observed_at"]
    with pytest.raises(StatusDocumentError) as refused:
        _verify_status(*_signed_status(observed_at=observed_at + suffix))
    assert refused.value.code == "invalid_value"


@pytest.fixture
def reserved_artifact(monkeypatch):
    def use(app_ids: list[str]) -> None:
        payload = json.dumps({"schema": app_registry.RESERVED_APP_IDS_SCHEMA, "reserved_app_ids": app_ids})
        monkeypatch.setattr(app_registry, "_read_reserved_app_ids_artifact", lambda: payload)
        app_registry.reserved_app_ids.cache_clear()

    yield use
    app_registry.reserved_app_ids.cache_clear()


def test_reserved_app_ids_artifact_accepts_a_bare_id(reserved_artifact):
    reserved_artifact(["status"])
    assert app_registry.reserved_app_ids() == frozenset({"status"})


@LINE_BREAKS
def test_reserved_app_ids_artifact_refuses_an_id_with_a_trailing_line_break(reserved_artifact, suffix):
    reserved_artifact(["status" + suffix])
    with pytest.raises(RuntimeError):
        app_registry.reserved_app_ids()
