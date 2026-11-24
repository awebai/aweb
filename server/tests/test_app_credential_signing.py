"""The tests' app credential signer reproduces the frozen app credential vectors."""

import json
from pathlib import Path

import pytest

from tests.app_credential_signing import app_credential_headers

ROOT = Path(__file__).resolve().parents[2]
REQUEST = json.loads((ROOT / "naapp-contracts" / "src" / "aweb_naapp_contracts" / "vectors" / "app-request-credential-v1.json").read_text())
READ = json.loads((ROOT / "test-vectors" / "app-read-credential-v1.json").read_text())


def test_an_app_request_credential_is_the_vectors_bytes():
    payload = REQUEST["payload"]
    headers = app_credential_headers(
        purpose="app-request",
        seed=bytes.fromhex(REQUEST["keys"]["app"]["seed_hex"]),
        method=REQUEST["request"]["method"],
        aud=payload["aud"],
        path=REQUEST["request"]["path"],
        team_id=payload["team_id"],
        app_id=payload["app_id"],
        kid=payload["kid"],
        body=REQUEST["request"]["body"].encode(),
        timestamp=payload["timestamp"],
        installation_id=payload["installation_id"],
        installation_generation=payload["installation_generation"],
    )
    assert headers == REQUEST["headers"]


@pytest.mark.parametrize("case", READ["cases"], ids=lambda case: case["name"])
def test_a_read_credential_is_the_vectors_bytes(case):
    payload = case["payload"]
    headers = app_credential_headers(
        purpose=case["purpose"],
        seed=bytes.fromhex(READ["seed_hex"]),
        method=case["method"],
        aud=payload["aud"],
        path=case["path"],
        team_id=payload["team_id"],
        app_id=payload["app_id"],
        kid=payload["kid"],
        body=case["body"].encode(),
        timestamp=payload["timestamp"],
    )
    assert headers == case["headers"]
