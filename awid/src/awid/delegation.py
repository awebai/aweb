"""Portable parent-delegation assertion primitives.

This module owns the exact ``awid.namespace-delegation.v1`` byte, hash, and
signature boundary.  It deliberately contains no registry-state decisions.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from publicsuffix2 import get_sld

from awid.did import validate_did
from awid.external_authority import canonical_protocol_domain
from awid.signing import canonical_json_bytes, verify_did_key_signature

DELEGATION_VERSION = "awid.namespace-delegation.v1"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9+/]+$")


class DelegationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[DELEGATION_VERSION]
    operation: Literal["delegate", "rotate", "revoke"]
    parent_domain: str = Field(min_length=1, max_length=253)
    child_domain: str = Field(min_length=1, max_length=253)
    child_controller_did: str = Field(min_length=1, max_length=256)
    sequence: StrictInt = Field(gt=0)
    previous_delegation_hash: str | None

    @field_validator("parent_domain", "child_domain")
    @classmethod
    def canonicalize_domain(cls, value: str) -> str:
        try:
            canonical = canonical_protocol_domain(value)
        except Exception as exc:
            raise ValueError("domain must be canonicalizable ASCII DNS") from exc
        if canonical != value:
            raise ValueError("domain must already be lowercase canonical DNS without trailing dot")
        return value

    @field_validator("child_controller_did")
    @classmethod
    def validate_controller(cls, value: str) -> str:
        if not validate_did(value):
            raise ValueError("child_controller_did must be an Ed25519 did:key")
        return value

    @field_validator("previous_delegation_hash")
    @classmethod
    def validate_previous_hash(cls, value: str | None) -> str | None:
        if value is not None and not _HASH_RE.fullmatch(value):
            raise ValueError("previous_delegation_hash must be sha256:<lowercase hex>")
        return value

    @model_validator(mode="after")
    def validate_hierarchy_and_sequence(self) -> "DelegationPayload":
        if not self.child_domain.endswith("." + self.parent_domain):
            raise ValueError("child_domain must be a strict descendant of parent_domain")

        boundary = get_sld(self.child_domain, strict=True)
        if boundary:
            labels = self.child_domain.split(".")
            boundary_labels = boundary.split(".")
            candidates = {
                ".".join(labels[index:])
                for index in range(1, len(labels) - len(boundary_labels) + 1)
            }
            if self.parent_domain not in candidates:
                raise ValueError("parent_domain is outside the registrable-domain ancestor set")

        if self.sequence == 1 and self.previous_delegation_hash is not None:
            raise ValueError("sequence one must have a null previous_delegation_hash")
        if self.sequence > 1 and self.previous_delegation_hash is None:
            raise ValueError("successor entries require previous_delegation_hash")
        return self


class DelegationSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    controller_did: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=128)

    @field_validator("controller_did")
    @classmethod
    def validate_controller(cls, value: str) -> str:
        if not validate_did(value):
            raise ValueError("controller_did must be an Ed25519 did:key")
        return value

    @field_validator("signature")
    @classmethod
    def validate_signature_encoding(cls, value: str) -> str:
        if "=" in value or not _SIGNATURE_RE.fullmatch(value):
            raise ValueError("signature must be unpadded standard base64")
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        except Exception as exc:
            raise ValueError("signature must be unpadded standard base64") from exc
        if len(decoded) != 64:
            raise ValueError("signature must encode exactly 64 bytes")
        canonical = base64.b64encode(decoded).rstrip(b"=").decode("ascii")
        if canonical != value:
            raise ValueError("signature base64 encoding is noncanonical")
        return value


class DelegationAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: DelegationPayload
    entry_hash: str
    signatures: tuple[DelegationSignature, ...] = Field(min_length=1)

    @field_validator("entry_hash")
    @classmethod
    def validate_entry_hash(cls, value: str) -> str:
        if not _HASH_RE.fullmatch(value):
            raise ValueError("entry_hash must be sha256:<lowercase hex>")
        return value

    @model_validator(mode="after")
    def validate_unique_sorted_signatures(self) -> "DelegationAssertion":
        controllers = [item.controller_did for item in self.signatures]
        if len(set(controllers)) != len(controllers):
            raise ValueError("duplicate signature controller_did")
        sorted_signatures = tuple(sorted(self.signatures, key=lambda item: item.controller_did))
        if sorted_signatures != self.signatures:
            object.__setattr__(self, "signatures", sorted_signatures)
        return self


def canonical_delegation_payload(payload: DelegationPayload) -> bytes:
    return canonical_json_bytes(payload.model_dump(mode="json"))


def delegation_entry_hash(canonical_payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(canonical_payload).hexdigest()


def verify_delegation_signature(
    *, controller_did: str, signature: str, canonical_payload: bytes
) -> None:
    # Apply the strict wire validator before the shared cryptographic verifier.
    validated = DelegationSignature(controller_did=controller_did, signature=signature)
    verify_did_key_signature(
        did_key=validated.controller_did,
        payload=canonical_payload,
        signature_b64=validated.signature,
    )


def parse_delegation_assertion(value: object) -> DelegationAssertion:
    assertion = DelegationAssertion.model_validate(value)
    canonical = canonical_delegation_payload(assertion.payload)
    expected_hash = delegation_entry_hash(canonical)
    if assertion.entry_hash != expected_hash:
        raise ValueError("delegation entry_hash does not match canonical payload bytes")
    for attachment in assertion.signatures:
        verify_delegation_signature(
            controller_did=attachment.controller_did,
            signature=attachment.signature,
            canonical_payload=canonical,
        )
    return assertion
