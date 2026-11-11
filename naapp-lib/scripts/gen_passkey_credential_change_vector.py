"""Generate docs/vectors/passkey-credential-change-v1.json.

Real ES256 assertions over the hook-events `credential_change` binding: a
current credential of the holding approves adding a credential, or replacing
one it names. Every byte is built from the contract text here, independently
of B3; B3's helper then checks that each positive case commits to the same
digest and that each negative case is refused. Private keys exist only in this
process's memory and are never written.

    uv run python scripts/gen_passkey_credential_change_vector.py
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any

from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential, b64url, from_b64url
from awid.signing import canonical_json_bytes
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.runtime.passkeys.proof import (
    PasskeyProofUnavailable,
    RetainedPasskeyProof,
    passkey_evidence_commitment,
)

OUT = Path(__file__).resolve().parents[2] / "docs" / "vectors" / "passkey-credential-change-v1.json"
ORIGIN = "https://app.example.com"
RP_ID = "app.example.com"
PREFIX = b"aweb.passkey-credential-change/1\n"
REQUEST_PREFIX = b"aweb.passkey-credential-change-request/1\n"
CREDENTIAL_PREFIX = b"aweb.human-credential/1\n"
DOMAIN = b"aweb.passkey-evidence/1\n"
BINARY_ORDER = [
    "challenge_preimage",
    "credential_public_key_cose",
    "credential_id",
    "authenticator_data",
    "client_data_json",
    "signature",
]
CONTEXT = {
    "app_id": "fixture",
    "team_id": "demo:example.com",
    "installation_id": "install-1",
    "generation": 3,
    "scope": "operator",
    "origin": ORIGIN,
    "rp_id": RP_ID,
    "require_up": True,
    "require_uv": True,
    "binding_kind": "credential_change",
}
METADATA = {
    "evidence_ref": "evidence-1",
    "subject": "app-subject-1",
    "purpose": "credential_change",
    "verified_at": "2026-11-12T12:00:00.123456Z",
    "challenge_issued_at": "2026-11-12T11:59:00.000000Z",
    "challenge_expires_at": "2026-11-12T12:04:00.000000Z",
    "sign_count_before": 0,
    "sign_count_after": 1,
}


def new_key() -> SoftCredential:
    return SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), RP_ID, b"app-subject-1"
    )


def public(key: SoftCredential, rp_id: str = RP_ID) -> dict[str, str]:
    return {
        "credential_id": b64url(key.credential_id),
        "public_key": b64url(key.cose_public_key()),
        "rp_id": rp_id,
    }


def digest(credential: dict[str, str]) -> str:
    return hashlib.sha256(CREDENTIAL_PREFIX + canonical_json_bytes(credential)).hexdigest()


def without_none(value: dict[str, Any], *, keep_null: bool = False) -> dict[str, Any]:
    return {k: v for k, v in value.items() if keep_null or v is not None}


def build(
    name: str,
    *,
    asserting: SoftCredential,
    operation: str,
    new: dict[str, str],
    retire: dict[str, str] | None = None,
    fields: dict[str, Any] | None = None,
    sidecar: dict[str, Any] | None = None,
    prefix: bytes = PREFIX,
    null_fields: bool = False,
) -> dict[str, Any]:
    nonce = os.urandom(32).hex()
    signed: dict[str, Any] = {
        "credential_sha256": digest(new),
        "nonce": nonce,
        "operation": operation,
        "scope": CONTEXT["scope"],
        "subject": METADATA["subject"],
    }
    body: dict[str, Any] = {"credential": new}
    if retire is not None:
        signed["retire_credential_sha256"] = digest(retire)
        body["retire_credential"] = retire
    signed.update(fields or {})
    body.update(sidecar or {})
    preimage = prefix + canonical_json_bytes(without_none(signed, keep_null=null_fields))
    covered = REQUEST_PREFIX + canonical_json_bytes(without_none(body))
    challenge = hashlib.sha256(preimage).digest()
    device = SoftAuthenticator(ORIGIN)
    device.credentials[asserting.credential_id] = SoftCredential(
        asserting.credential_id, asserting.key, asserting.rp_id, asserting.user_handle
    )
    assertion = device.get({"rpId": RP_ID, "challenge": b64url(challenge)})
    binary = {
        "challenge_preimage": preimage,
        "credential_public_key_cose": asserting.cose_public_key(),
        "credential_id": asserting.credential_id,
        "authenticator_data": from_b64url(assertion["response"]["authenticatorData"]),
        "client_data_json": from_b64url(assertion["response"]["clientDataJSON"]),
        "signature": from_b64url(assertion["response"]["signature"]),
    }
    pieces = [canonical_json_bytes(CONTEXT), canonical_json_bytes(METADATA)]
    pieces.extend(binary[field] for field in BINARY_ORDER)
    message = DOMAIN + b"".join(struct.pack(">Q", len(piece)) + piece for piece in pieces)
    return {
        "name": name,
        "context": CONTEXT,
        "metadata": METADATA,
        "expected_challenge_hex": challenge.hex(),
        "binary_hex": {field: binary[field].hex() for field in BINARY_ORDER},
        "covered_request_hex": covered.hex(),
        "canonical_context_utf8": canonical_json_bytes(CONTEXT).decode(),
        "canonical_metadata_utf8": canonical_json_bytes(METADATA).decode(),
        "commitment_input_hex": message.hex(),
        "commitment_sha256": hashlib.sha256(message).hexdigest(),
        "trusted_key": "approver-1",
    }


def retained(case: dict[str, Any]) -> RetainedPasskeyProof:
    return RetainedPasskeyProof.from_parts(
        context=case["context"],
        metadata=case["metadata"],
        expected_challenge=bytes.fromhex(case["expected_challenge_hex"]),
        covered_request=bytes.fromhex(case["covered_request_hex"]),
        **{key: bytes.fromhex(value) for key, value in case["binary_hex"].items()},
    )


def main() -> None:
    current = new_key()
    added, retired, other = public(new_key()), public(new_key()), public(new_key())
    cases = [
        build("add", asserting=current, operation="add", new=added),
        build("replace", asserting=current, operation="replace", new=added, retire=retired),
    ]
    elsewhere = public(new_key(), "elsewhere.example.com")
    self_signing = new_key()
    negatives = [
        ("swapped_scope", {"operation": "add", "fields": {"scope": "another"}}),
        ("swapped_subject", {"operation": "add", "fields": {"subject": "app-subject-2"}}),
        ("swapped_operation", {"operation": "add", "fields": {"operation": "replace"}}),
        (
            "swapped_retire_target",
            {
                "operation": "replace",
                "retire": retired,
                "fields": {"retire_credential_sha256": digest(other)},
            },
        ),
        ("other_kind_prefix", {"operation": "add", "prefix": b"aweb.passkey-contact-change/1\n"}),
        ("sidecar_digest_mismatch", {"operation": "add", "sidecar": {"credential": other}}),
        (
            "sidecar_at_another_rp",
            {"operation": "add", "new": elsewhere},
        ),
        (
            "add_with_retire_field",
            {"operation": "add", "fields": {"retire_credential_sha256": digest(retired)}},
        ),
        (
            "replace_missing_retire_field",
            {
                "operation": "replace",
                "retire": retired,
                "fields": {"retire_credential_sha256": None},
            },
        ),
        (
            "null_retire_field",
            {"operation": "add", "fields": {"retire_credential_sha256": None}, "null_fields": True},
        ),
    ]
    negative_cases = []
    for name, spec in negatives:
        spec = dict(spec)
        spec.setdefault("new", added)
        negative_cases.append(
            {**build(name, asserting=current, **spec), "error": "binding_mismatch"}
        )
    negative_cases.append(
        {
            **build(
                "asserted_by_the_new_credential",
                asserting=self_signing,
                operation="add",
                new=public(self_signing),
            ),
            "trusted_key": "new-credential",
            "error": "self_approval",
        }
    )
    for case in cases:
        assert passkey_evidence_commitment(retained(case)) == case["commitment_sha256"]
    for case in negative_cases:
        try:
            passkey_evidence_commitment(retained(case))
        except PasskeyProofUnavailable:
            continue
        raise AssertionError(f"B3 accepted the negative case {case['name']}")
    vector = {
        "name": "passkey-credential-change-v1",
        "status": "frozen under aweb-acxy.3; no private key retained in vector",
        "authority": "docs/hook-events.md#passkey-evidence-commitments-and-console-actors",
        "binding_kind": "credential_change",
        "domain": DOMAIN.decode(),
        "challenge_prefix": PREFIX.decode(),
        "request_prefix": REQUEST_PREFIX.decode(),
        "credential_prefix": CREDENTIAL_PREFIX.decode(),
        "binary_order": BINARY_ORDER,
        "trust_anchors": {
            "approver-1": {
                "public_key_cose_hex": current.cose_public_key().hex(),
                "origin": ORIGIN,
                "rp_id": RP_ID,
            },
            "new-credential": {
                "public_key_cose_hex": self_signing.cose_public_key().hex(),
                "origin": ORIGIN,
                "rp_id": RP_ID,
            },
        },
        "cases": cases,
        "negative_cases": negative_cases,
    }
    OUT.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
