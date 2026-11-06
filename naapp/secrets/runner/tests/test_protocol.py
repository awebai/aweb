"""The runner consumes the public S0 vectors independently of the server."""

import json
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aweb_secrets_runner.journal import Journal
from aweb_secrets_runner.protocol import (
    Refused,
    canonical,
    decode64,
    decrypt_credential,
    sign_request,
    verify_assignment,
)

VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[4] / "docs/vectors/secrets-runner-protocol-v1.json"
    ).read_text()
)


def test_request_has_exact_public_signature():
    vector = VECTORS["signed"][0]
    payload = vector["payload"]
    received = VECTORS["requests"][0]["received"]
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["keys"]["runner"]["seed_hex"]))
    header = sign_request(
        key,
        origin=payload["origin"],
        runner_id=payload["runner_id"],
        method=payload["method"],
        path=payload["path"],
        body=decode64(received["body_b64url"]),
        now=datetime.fromisoformat(payload["timestamp"]),
        nonce=decode64(payload["nonce"]),
    )
    assert header == VECTORS["requests"][0]["header"]
    assert decode64(vector["signing_bytes_b64url"]) == (
        b"aweb.secrets.runner-request/1\n" + canonical(payload)
    )


@pytest.mark.parametrize("vector", VECTORS["assignments"], ids=lambda v: v["name"])
def test_assignment_vectors(vector, tmp_path):
    runner = vector["runner"]
    now = datetime.fromisoformat(vector["now"])
    journal = Journal(tmp_path / "journal.sqlite3", clock=now.timestamp)
    for dispatch in runner["journal"]:
        journal.accept(dispatch, expires_at=now.timestamp() + 300)
    kwargs = dict(
        origin=runner["origin"],
        runner_id=runner["runner_id"],
        service_kid=runner["service_kid"],
        now=now,
        journal=journal,
    )
    body = vector["body_json"].encode()
    if "error" in vector["expected"]:
        with pytest.raises(Refused) as error:
            verify_assignment(body, **kwargs)
        assert error.value.code == vector["expected"]["error"]
    else:
        result = verify_assignment(body, **kwargs)
        assert result.dispatch_id == vector["expected"]["dispatch_id"]
        with pytest.raises(Refused, match="assignment_replayed"):
            verify_assignment(body, **kwargs)


@pytest.mark.parametrize("vector", VECTORS["sealed_credentials"], ids=lambda v: v["name"])
def test_sealing_vectors(vector):
    key = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTORS["keys"][vector["recipient"]]["private_hex"])
    )
    if "plaintext" in vector["expected"]:
        assert decrypt_credential(vector["sealed"], key, vector["info"]) == (
            vector["expected"]["plaintext"].encode()
        )
    else:
        with pytest.raises(Refused, match="credential_invalid"):
            decrypt_credential(vector["sealed"], key, vector["info"])


def test_invalid_assignments_do_not_poison_journal(tmp_path):
    good = VECTORS["assignments"][0]
    wrong = next(v for v in VECTORS["assignments"] if v["name"] == "forged-signature")
    journal = Journal(
        tmp_path / "journal.sqlite3", clock=datetime.fromisoformat(good["now"]).timestamp
    )
    kwargs = {k: good["runner"][k] for k in ("origin", "runner_id", "service_kid")}
    kwargs.update(now=datetime.fromisoformat(good["now"]), journal=journal)
    with pytest.raises(Refused, match="assignment_invalid"):
        verify_assignment(wrong["body_json"].encode(), **kwargs)
    assert verify_assignment(good["body_json"].encode(), **kwargs).dispatch_id


def test_assignment_size_is_raw_bytes(tmp_path):
    good = VECTORS["assignments"][0]
    kwargs = {k: good["runner"][k] for k in ("origin", "runner_id", "service_kid")}
    with pytest.raises(Refused, match="assignment_invalid"):
        verify_assignment(
            b" " * (1024 * 1024 + 1),
            **kwargs,
            now=datetime.fromisoformat(good["now"]),
            journal=Journal(tmp_path / "journal.sqlite3"),
        )


@pytest.mark.parametrize("value", [float("nan"), 1.0, 2**53, "\ud800", {"\ud800": 1}])
def test_canonical_refuses_nonportable_values(value):
    with pytest.raises(ValueError):
        canonical(value)
