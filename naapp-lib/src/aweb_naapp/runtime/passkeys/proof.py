"""Restricted exact-byte WebAuthn evidence and its decision-84 commitment.

A proof is historical data, never authority. Its public key and service context
are not their own trust anchors. Only the commitment belongs in hook payloads.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import cbor2
from awid.signing import canonical_json_bytes
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals.model import AuthenticationFailed
from aweb_naapp.runtime.approvals.request import parse_request_json
from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.runtime.passkeys.webauthn import WebAuthnRefused, verify_assertion

DOMAIN = b"aweb.passkey-evidence/1\n"
BINARY_FIELDS = (
    "challenge_preimage",
    "credential_public_key_cose",
    "credential_id",
    "authenticator_data",
    "client_data_json",
    "signature",
)
CONTEXT_FIELDS = {
    "app_id",
    "team_id",
    "installation_id",
    "generation",
    "scope",
    "origin",
    "rp_id",
    "require_up",
    "require_uv",
    "binding_kind",
}
METADATA_FIELDS = {
    "evidence_ref",
    "subject",
    "purpose",
    "verified_at",
    "challenge_issued_at",
    "challenge_expires_at",
    "sign_count_before",
    "sign_count_after",
}
APPROVAL_FIELDS = {
    "approval_id",
    "request_sha256",
    "policy_ref",
    "policy_version",
    "task_answer_ref",
}
SAFE_INTEGER = 2**53 - 1


class ProofContextUnavailable(AuthenticationFailed):
    """The app cannot resolve one authoritative installation for this scope."""

    code = "proof_context_unavailable"

    def __init__(self) -> None:
        super().__init__(self.code)


class PasskeyProofUnavailable(AuthenticationFailed):
    """Missing, malformed or inconsistent proof; no summary fallback exists."""

    code = "passkey_proof_unavailable"

    def __init__(self) -> None:
        super().__init__(self.code)


def _require(condition: bool) -> None:
    if not condition:
        raise PasskeyProofUnavailable()


def _text(value: Any) -> bool:
    try:
        return isinstance(value, str) and bool(value) and bool(value.encode("utf-8"))
    except UnicodeError:
        return False


def _integer(value: Any, minimum=0, maximum=SAFE_INTEGER) -> bool:
    return type(value) is int and minimum <= value <= maximum


@dataclass(frozen=True)
class PasskeyInstallationContext:
    app_id: str
    team_id: str
    installation_id: str
    generation: int

    def __post_init__(self) -> None:
        if not all(
            _text(v) for v in (self.app_id, self.team_id, self.installation_id)
        ) or not _integer(self.generation, 1):
            raise ProofContextUnavailable()

    def fields(self) -> dict[str, Any]:
        return dict(
            app_id=self.app_id,
            team_id=self.team_id,
            installation_id=self.installation_id,
            generation=self.generation,
        )


class ProofContextResolver(Protocol):
    async def __call__(self, scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
        """Read the exact authoritative scope binding; take no authority locks."""
        ...


def _instant(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        _require(isinstance(value, str))
        # Python 3.12 accepts malformed offset minutes and loses excess precision.
        _require(
            bool(
                re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)",
                    value,
                )
            )
        )
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(result.tzinfo is not None and result.utcoffset() is not None)
    return result.astimezone(UTC)


def _metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    for field in ("verified_at", "challenge_issued_at", "challenge_expires_at"):
        result[field] = _instant(result[field]).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return result


@dataclass(frozen=True, repr=False)
class RetainedPasskeyProof:
    context_canonical: bytes
    metadata_canonical: bytes
    challenge_preimage: bytes
    expected_challenge: bytes
    credential_public_key_cose: bytes
    credential_id: bytes
    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes
    covered_request: bytes | None

    @property
    def context(self) -> dict[str, Any]:
        return json.loads(self.context_canonical)

    @property
    def metadata(self) -> dict[str, Any]:
        return json.loads(self.metadata_canonical)

    @classmethod
    def from_parts(
        cls, *, context: Mapping[str, Any], metadata: Mapping[str, Any], **binary
    ) -> RetainedPasskeyProof:
        try:
            return cls(
                canonical_json_bytes(dict(context)),
                canonical_json_bytes(_metadata(metadata)),
                **binary,
            )
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise PasskeyProofUnavailable() from None

    def export(self) -> dict[str, Any]:
        """Restricted export; contains proof and possibly credential-bearing sidecar."""
        binary = {field: getattr(self, field).hex() for field in BINARY_FIELDS}
        return dict(
            context=self.context,
            metadata=self.metadata,
            binary_hex=binary,
            expected_challenge_hex=self.expected_challenge.hex(),
            covered_request_hex=None
            if self.covered_request is None
            else self.covered_request.hex(),
        )

    @classmethod
    def from_export(cls, value: Mapping[str, Any]) -> RetainedPasskeyProof:
        def unhex(encoded):
            _require(isinstance(encoded, str) and bool(re.fullmatch(r"(?:[0-9a-f]{2})+", encoded)))
            return bytes.fromhex(encoded)

        try:
            _require(
                set(value)
                == {
                    "context",
                    "metadata",
                    "binary_hex",
                    "expected_challenge_hex",
                    "covered_request_hex",
                }
            )
            _require(set(value["binary_hex"]) == set(BINARY_FIELDS))
            proof = cls.from_parts(
                context=value["context"],
                metadata=value["metadata"],
                expected_challenge=unhex(value["expected_challenge_hex"]),
                covered_request=None
                if value["covered_request_hex"] is None
                else unhex(value["covered_request_hex"]),
                **{key: unhex(raw) for key, raw in value["binary_hex"].items()},
            )
            passkey_evidence_commitment(proof)
            return proof
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise PasskeyProofUnavailable() from None


def _checked(proof: RetainedPasskeyProof) -> tuple[dict[str, Any], dict[str, Any]]:
    context = parse_request_json(proof.context_canonical)
    metadata = parse_request_json(proof.metadata_canonical)
    _require(canonical_json_bytes(context) == proof.context_canonical)
    _require(canonical_json_bytes(metadata) == proof.metadata_canonical)
    _require(set(context) == CONTEXT_FIELDS)
    _require(METADATA_FIELDS <= set(metadata) <= METADATA_FIELDS | APPROVAL_FIELDS)
    _require(all(value is not None for value in metadata.values()))
    _require(
        all(_text(context[k]) for k in CONTEXT_FIELDS - {"generation", "require_up", "require_uv"})
    )
    _require(_integer(context["generation"], 1))
    _require(context["require_up"] is True and context["require_uv"] is True)
    _require(all(_text(metadata[k]) for k in ("evidence_ref", "subject", "purpose")))
    _require(
        all(
            _integer(metadata[k], maximum=2**32 - 1)
            for k in ("sign_count_before", "sign_count_after")
        )
    )
    _require(_metadata(metadata) == metadata)
    _require(
        _instant(metadata["challenge_issued_at"])
        <= _instant(metadata["verified_at"])
        < _instant(metadata["challenge_expires_at"])
    )
    _require(
        all(
            isinstance(getattr(proof, field), bytes) and bool(getattr(proof, field))
            for field in (*BINARY_FIELDS, "expected_challenge")
        )
    )
    _require(len(proof.expected_challenge) == 32 and len(proof.authenticator_data) >= 37)
    prefixes = {
        "approval": b"aweb.approval-challenge/1\n",
        "login": b"aweb.passkey-login/1\n",
        "contact_change": b"aweb.passkey-contact-change/1\n",
        "contact_cancel": b"aweb.passkey-contact-cancel/1\n",
    }
    prefix = prefixes[context["binding_kind"]]
    _require(proof.challenge_preimage.startswith(prefix))
    fields = parse_request_json(proof.challenge_preimage[len(prefix) :])
    _require(prefix + canonical_json_bytes(fields) == proof.challenge_preimage)
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", fields["nonce"])))
    if context["binding_kind"] == "approval":
        _require(
            set(fields)
            == {
                "approval_id",
                "candidate_subject",
                "candidate_subject_type",
                "nonce",
                "policy_ref",
                "policy_version",
                "purpose",
                "request_sha256",
                "task_answer_ref",
            }
        )
        _require(APPROVAL_FIELDS - {"task_answer_ref"} <= set(metadata))
        _require(metadata["purpose"] in {"approve", "reject", "view"})
        _require(_integer(metadata["policy_version"], 1))
        _require(all(_text(metadata[k]) for k in ("approval_id", "request_sha256", "policy_ref")))
        _require(
            fields["candidate_subject"] == metadata["subject"]
            and fields["candidate_subject_type"] == "app_local"
        )
        _require(all(fields[key] == metadata.get(key) for key in APPROVAL_FIELDS | {"purpose"}))
        _require(bool(re.fullmatch(r"[0-9a-f]{64}", metadata["request_sha256"])))
        if not isinstance(proof.covered_request, bytes):
            raise PasskeyProofUnavailable()
        _require(proof.covered_request.startswith(b"aweb.approval-request/1\n"))
        _require(hashlib.sha256(proof.covered_request).hexdigest() == metadata["request_sha256"])
        wrapper = parse_request_json(proof.covered_request[len(b"aweb.approval-request/1\n") :])
        _require(set(wrapper) == {"policy", "request"})
        _require(
            b"aweb.approval-request/1\n" + canonical_json_bytes(wrapper) == proof.covered_request
        )
        _require(
            wrapper["policy"]
            == {"ref": metadata["policy_ref"], "version": metadata["policy_version"]}
        )
        request = wrapper["request"]
        if isinstance(request, dict):
            for key, value in (
                ("team_id", context["team_id"]),
                ("installation_id", context["installation_id"]),
                ("install_generation", context["generation"]),
            ):
                if key in request:
                    _require(type(request[key]) is type(value) and request[key] == value)
    else:
        _require(not (set(metadata) & APPROVAL_FIELDS) and proof.covered_request is None)
        _require(fields["subject"] == metadata["subject"])
        if context["binding_kind"] == "login":
            _require(set(fields) == {"nonce", "scope", "subject"})
            _require(metadata["purpose"] == "login" and fields["scope"] == context["scope"])
        else:
            key = (
                "contact_sha256"
                if context["binding_kind"] == "contact_change"
                else "pending_contact_sha256"
            )
            _require(set(fields) == {"nonce", "subject", key})
            _require(
                metadata["purpose"] == "contact_change"
                and bool(re.fullmatch(r"[0-9a-f]{64}", fields[key]))
            )
    _require(hashlib.sha256(proof.challenge_preimage).digest() == proof.expected_challenge)
    rp = RelyingParty(context["origin"], "retained proof")
    _require(rp.rp_id == context["rp_id"])
    # Decode exactly one complete COSE object without rewriting its bytes.
    stream = io.BytesIO(proof.credential_public_key_cose)
    try:
        key = cbor2.CBORDecoder(stream, allow_duplicate_keys=False).decode()
    except cbor2.CBORDecodeError:
        raise PasskeyProofUnavailable() from None
    _require(isinstance(key, dict) and stream.tell() == len(proof.credential_public_key_cose))
    # py_webauthn intentionally reads public values only. Retention must also
    # reject private key parameters that its decoder would otherwise ignore.
    _require(type(key.get(1)) is int)
    if key[1] in (1, 2):  # OKP and EC2: d is private.
        _require(-4 not in key)
    elif key[1] == 3:  # RSA: only n/e are public negative-label parameters.
        _require(not any(label in key for label in (-3, -4, -5, -6, -7, -8, -9)))

    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    credential = b64(proof.credential_id)
    assertion = dict(
        id=credential,
        rawId=credential,
        type="public-key",
        response={
            "authenticatorData": b64(proof.authenticator_data),
            "clientDataJSON": b64(proof.client_data_json),
            "signature": b64(proof.signature),
        },
    )
    verified = verify_assertion(
        assertion,
        challenge=proof.expected_challenge,
        rp=rp,
        credential_id=proof.credential_id,
        public_key=proof.credential_public_key_cose,
        sign_count=metadata["sign_count_before"],
    )
    _require(verified.new_sign_count == metadata["sign_count_after"])
    return context, metadata


def passkey_evidence_commitment(proof: RetainedPasskeyProof) -> str:
    """Validate exact retained proof and reproduce the unkeyed public commitment.

    Verification here checks internal integrity under the retained key. An
    independent reviewer must separately trust that key and the expected context.
    """
    try:
        _checked(proof)
        pieces = [proof.context_canonical, proof.metadata_canonical]
        pieces.extend(getattr(proof, field) for field in BINARY_FIELDS)
        return hashlib.sha256(
            DOMAIN + b"".join(struct.pack(">Q", len(piece)) + piece for piece in pieces)
        ).hexdigest()
    except (ValueError, KeyError, TypeError, UnicodeError, WebAuthnRefused, OverflowError):
        raise PasskeyProofUnavailable() from None
