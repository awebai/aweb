"""Compatibility encodings stay usable while verified noncanonical use is counted."""

import logging

import pytest
from awid.did import did_key_from_signing_key
from awid.signing import VerifyResult, sign_message, verify_signature


@pytest.mark.parametrize(
    "spelling", ["url", "padded", "ignored", "newline", "canonical", "invalid"]
)
def test_only_verified_noncanonical_signatures_are_measured(caplog, spelling):
    seed = bytes(range(32))
    payload = b"measure released spellings"
    signature = sign_message(seed, payload)
    variants = {
        "canonical": signature,
        "url": signature.replace("+", "-").replace("/", "_"),
        "padded": signature + "==",
        "ignored": "!" + signature + "!!!",
        "newline": signature[:8] + "\r\n\r\n" + signature[8:],
        "invalid": signature[:-4] + "AAAA",
    }
    candidate = variants[spelling]
    if spelling == "url":
        assert candidate != signature
    with caplog.at_level(logging.INFO, logger="awid.signing"):
        result = verify_signature(did_key_from_signing_key(seed), payload, candidate)
    assert result is (
        VerifyResult.FAILED if spelling == "invalid" else VerifyResult.VERIFIED
    )
    records = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "awid_noncanonical_signature_accepted"
    ]
    if spelling not in {"canonical", "invalid"}:
        assert records and records[-1].value >= 1
        assert signature not in records[-1].getMessage()
    else:
        assert records == []
