"""Canonical operator receipts for registry migration cutovers."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Annotated, Literal, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from awid.did import validate_did
from awid.external_authority import canonical_protocol_domain
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def _canonical_timestamp(value: str) -> str:
    if not _UTC_RE.fullmatch(value):
        raise ValueError("timestamp must be canonical RFC3339 UTC")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a real RFC3339 UTC instant") from exc
    return value


def _canonical_dns_name(value: str) -> str:
    if not value.startswith("_awid."):
        raise ValueError("DNS name must start with _awid.")
    domain = canonical_protocol_domain(value.removeprefix("_awid."))
    if value != "_awid." + domain:
        raise ValueError("DNS name must already be canonical")
    return value


def _controller_did(value: str) -> str:
    if not validate_did(value):
        raise ValueError("controller must be an Ed25519 did:key")
    return value


class _ReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_registry_id: str
    destination_registry_id: str
    cutover_id: str
    source_generation: StrictInt = Field(ge=0)
    snapshot_digest: str
    manifest_digest: str
    old_selection_evidence_hash: str
    destination_registry_origin: str

    @field_validator("source_registry_id", "destination_registry_id", "cutover_id")
    @classmethod
    def canonical_uuid(cls, value: str) -> str:
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("UUID must use canonical lowercase form")
        return value

    @field_validator("snapshot_digest", "manifest_digest", "old_selection_evidence_hash")
    @classmethod
    def digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("digest must be sha256:<lowercase hex>")
        return value

    @field_validator("destination_registry_origin")
    @classmethod
    def origin(cls, value: str) -> str:
        canonical = canonical_server_origin(value)
        if canonical != value:
            raise ValueError("registry origin must already be canonical")
        return value


class DNSAuthorizationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["awid.registry-migration-dns-authorization.v1"]
    source_registry_id: str
    destination_registry_id: str
    cutover_id: str
    source_generation: StrictInt = Field(ge=0)
    snapshot_digest: str
    manifest_digest: str
    destination_readback_hash: str
    expected_destination_origin: str

    @field_validator("source_registry_id", "destination_registry_id", "cutover_id")
    @classmethod
    def canonical_uuid(cls, value: str) -> str:
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("UUID must use canonical lowercase form")
        return value

    @field_validator("snapshot_digest", "manifest_digest", "destination_readback_hash")
    @classmethod
    def digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("digest must be sha256:<lowercase hex>")
        return value

    @field_validator("expected_destination_origin")
    @classmethod
    def destination_origin(cls, value: str) -> str:
        canonical = canonical_server_origin(value)
        if canonical != value:
            raise ValueError("destination origin must already be canonical")
        return value


class OverlapObservationPayload(_ReceiptPayload):
    version: Literal["awid.registry-migration-overlap-observation.v1"]
    old_registry_origin: str
    old_ttl_seconds: StrictInt = Field(gt=0)
    destination_dns_name: str
    destination_controller_did: str
    destination_dns_answer_digest: str
    destination_observed_at: str

    @field_validator("old_registry_origin")
    @classmethod
    def old_origin(cls, value: str) -> str:
        canonical = canonical_server_origin(value)
        if canonical != value:
            raise ValueError("old registry origin must already be canonical")
        return value

    @field_validator("destination_dns_name")
    @classmethod
    def dns_name(cls, value: str) -> str:
        return _canonical_dns_name(value)

    @field_validator("destination_controller_did")
    @classmethod
    def controller(cls, value: str) -> str:
        return _controller_did(value)

    @field_validator("destination_dns_answer_digest")
    @classmethod
    def answer_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("DNS answer digest must be sha256:<lowercase hex>")
        return value

    @field_validator("destination_observed_at")
    @classmethod
    def timestamp(cls, value: str) -> str:
        return _canonical_timestamp(value)


class CanonicalOverlapPayload(_ReceiptPayload):
    version: Literal["awid.registry-migration-overlap.v1"]
    old_registry_origin: str
    old_ttl_seconds: StrictInt = Field(gt=0)
    destination_observation_hash: str
    destination_dns_name: str
    destination_controller_did: str
    destination_dns_answer_digest: str
    destination_observed_at: str
    source_dns_answer_digest: str
    source_observed_at: str
    overlap_started_at: str
    clock_skew_allowance_seconds: Literal[300]
    complete_after: str

    @field_validator("destination_dns_name")
    @classmethod
    def dns_name(cls, value: str) -> str:
        return _canonical_dns_name(value)

    @field_validator("destination_controller_did")
    @classmethod
    def controller(cls, value: str) -> str:
        return _controller_did(value)

    @field_validator(
        "destination_observation_hash",
        "destination_dns_answer_digest",
        "source_dns_answer_digest",
    )
    @classmethod
    def derived_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("derived hash must be sha256:<lowercase hex>")
        return value

    @field_validator("old_registry_origin")
    @classmethod
    def old_origin(cls, value: str) -> str:
        canonical = canonical_server_origin(value)
        if canonical != value:
            raise ValueError("old registry origin must already be canonical")
        return value

    @field_validator(
        "destination_observed_at", "source_observed_at", "overlap_started_at", "complete_after"
    )
    @classmethod
    def timestamp(cls, value: str) -> str:
        return _canonical_timestamp(value)


class DestinationCompletePayload(_ReceiptPayload):
    version: Literal["awid.registry-migration-destination-complete.v1"]
    overlap_receipt_hash: str
    destination_dns_name: str
    destination_controller_did: str
    destination_dns_answer_digest: str
    destination_final_observed_at: str
    complete_after: str
    destination_completed_at: str

    @field_validator("destination_dns_name")
    @classmethod
    def dns_name(cls, value: str) -> str:
        return _canonical_dns_name(value)

    @field_validator("destination_controller_did")
    @classmethod
    def controller(cls, value: str) -> str:
        return _controller_did(value)

    @field_validator("overlap_receipt_hash", "destination_dns_answer_digest")
    @classmethod
    def overlap_hash(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("overlap_receipt_hash must be sha256:<lowercase hex>")
        return value

    @field_validator(
        "complete_after", "destination_completed_at", "destination_final_observed_at"
    )
    @classmethod
    def timestamp(cls, value: str) -> str:
        return _canonical_timestamp(value)


ReceiptPayload = Annotated[
    Union[
        DNSAuthorizationPayload,
        OverlapObservationPayload,
        CanonicalOverlapPayload,
        DestinationCompletePayload,
    ],
    Field(discriminator="version"),
]


class RegistryMigrationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: ReceiptPayload
    receipt_hash: str

    @field_validator("receipt_hash")
    @classmethod
    def receipt_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("receipt_hash must be sha256:<lowercase hex>")
        return value


def receipt_payload_bytes(payload: BaseModel) -> bytes:
    return canonical_json_bytes(payload.model_dump(mode="json"))


def receipt_payload_hash(payload: BaseModel) -> str:
    return "sha256:" + hashlib.sha256(receipt_payload_bytes(payload)).hexdigest()


def make_receipt(payload: BaseModel) -> RegistryMigrationReceipt:
    return RegistryMigrationReceipt(payload=payload, receipt_hash=receipt_payload_hash(payload))


def parse_receipt(value: object) -> RegistryMigrationReceipt:
    receipt = RegistryMigrationReceipt.model_validate(value)
    expected = receipt_payload_hash(receipt.payload)
    if receipt.receipt_hash != expected:
        raise ValueError("receipt_hash does not match canonical payload bytes")
    return receipt
