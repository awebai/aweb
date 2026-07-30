from __future__ import annotations

import hashlib
import json
from pathlib import Path

from awid.signing import canonical_json_bytes

from folio.app_emit import sign_app_emit_credential

_VECTOR_PATH = Path(__file__).parent / "vectors" / "app-emit-credential-v1.json"
# Digest-pinned snapshot of cli/go/internal/conformance/vectors/app-emit-credential-v1.json
# at aweb 2f45b2f1 (frozen wire ed1b8ef2). aw-coordinator hands new bytes + sha if it bumps;
# it never moves silently. This is a vendored copy — folio does NOT depend on the aweb monorepo.
_VECTOR_SHA256 = "56f9fcd34f3d63c56da8bddb41e25659c30d2931631c7021602ee8d554f52f24"

_PAYLOAD_KEYS = (
    "v",
    "auth",
    "aud",
    "method",
    "path",
    "team_id",
    "app_id",
    "kid",
    "did_key",
    "body_sha256",
    "timestamp",
)


def _load_vector() -> dict:
    return json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))


def test_vendored_vector_matches_pinned_digest() -> None:
    # The byte SOT we claim parity with — pinned so a silent vector change is caught.
    assert hashlib.sha256(_VECTOR_PATH.read_bytes()).hexdigest() == _VECTOR_SHA256


def test_signer_is_byte_identical_to_frozen_go_vector() -> None:
    vector = _load_vector()
    assert vector["schema"] == "aweb.app-emit-credential.v1"
    assert vector["cases"], "vector must carry at least one positive case"

    for case in vector["cases"]:
        payload = case["payload"]
        target = f"{payload['aud']}{payload['path']}"
        credential = sign_app_emit_credential(
            private_key=bytes.fromhex(case["seed_hex"]),
            method=payload["method"],
            target=target,
            team_id=payload["team_id"],
            app_id=payload["app_id"],
            key_id=payload["kid"],
            body=case["body"].encode("utf-8"),
            timestamp=payload["timestamp"],
        )

        assert credential.did_key == case["did_key"], case["name"]
        assert credential.body_sha256 == payload["body_sha256"], case["name"]
        assert credential.canonical_payload == case["canonical_payload"], case["name"]
        assert credential.signed_payload_b64url == case["signed_payload_b64url"], case["name"]
        assert credential.signature_b64 == case["signature_b64"], case["name"]

        # The wire envelope the core verifier reads.
        assert credential.headers["Authorization"] == (
            f"AWEB-App DIDKey {case['did_key']} {case['signature_b64']}"
        ), case["name"]
        assert credential.headers["X-AWEB-App-ID"] == payload["app_id"], case["name"]
        assert credential.headers["X-AWEB-App-Key-ID"] == payload["kid"], case["name"]
        assert credential.headers["X-AWEB-Team-ID"] == payload["team_id"], case["name"]
        assert credential.headers["X-AWEB-Timestamp"] == payload["timestamp"], case["name"]
        assert credential.headers["X-AWEB-Signed-Payload"] == case["signed_payload_b64url"], case["name"]


def test_signer_reuses_the_shared_canonical_json_primitive() -> None:
    # One-definition invariant: the signed canonical payload is exactly what the
    # shared awid canonical_json_bytes primitive produces — not a second impl.
    case = _load_vector()["cases"][0]
    payload = {key: case["payload"][key] for key in _PAYLOAD_KEYS}
    assert canonical_json_bytes(payload).decode("utf-8") == case["canonical_payload"]
