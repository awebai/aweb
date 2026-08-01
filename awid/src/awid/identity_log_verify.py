"""Strict genesis-anchored DID-log verification for external federation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Sequence

from awid.did import public_key_from_did, stable_id_from_did_key, validate_stable_id
from awid.federation_errors import FederationAuthorityError
from awid.log import identity_state_hash, log_entry_payload
from awid.signing import verify_did_key_signature

MAX_SAFE_SEQUENCE = 2**53 - 1
MAX_LOG_ENTRIES = 4096
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$")


@dataclass(frozen=True)
class IdentityCheckpoint:
    seq: int
    entry_hash: str
    state_hash: str
    current_did_key: str
    revision: int


@dataclass(frozen=True)
class VerifiedIdentityLog:
    seq: int
    entry_hash: str
    state_hash: str
    current_did_key: str
    contains_checkpoint: bool


def _invalid(*, did_aw: str | None = None, seq: int | None = None) -> FederationAuthorityError:
    return FederationAuthorityError(
        "sender_did_log_invalid",
        did_aw=did_aw,
        observed_sequence=seq,
    )


def _require_sequence(value: object, *, did_aw: str | None = None) -> int:
    if type(value) is not int or value < 1 or value > MAX_SAFE_SEQUENCE:
        raise _invalid(did_aw=did_aw)
    return value


def _require_text(entry: Mapping[str, object], name: str, *, did_aw: str, seq: int) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or not value or value != value.strip():
        raise _invalid(did_aw=did_aw, seq=seq)
    return value


def _require_hash(value: object, *, did_aw: str, seq: int) -> str:
    if not isinstance(value, str) or not _HEX_256.fullmatch(value):
        raise _invalid(did_aw=did_aw, seq=seq)
    return value


def _verify_signature(*, did_key: str, payload: bytes, signature: object, did_aw: str, seq: int) -> None:
    if not isinstance(signature, str) or not signature or "=" in signature:
        raise _invalid(did_aw=did_aw, seq=seq)
    try:
        decoded = base64.b64decode(signature + "=" * (-len(signature) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _invalid(did_aw=did_aw, seq=seq) from exc
    if len(decoded) != 64:
        raise _invalid(did_aw=did_aw, seq=seq)
    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=signature)
    except ValueError as exc:
        raise _invalid(did_aw=did_aw, seq=seq) from exc


def _verify_entry(
    *,
    did_aw: str,
    current_did_key: str,
    entry: Mapping[str, object],
    previous: IdentityCheckpoint | None,
) -> VerifiedIdentityLog:
    seq = _require_sequence(entry.get("seq"), did_aw=did_aw)
    entry_did = entry.get("did_aw")
    if entry_did is not None and entry_did != did_aw:
        raise _invalid(did_aw=did_aw, seq=seq)
    operation = _require_text(entry, "operation", did_aw=did_aw, seq=seq)
    new_did_key = _require_text(entry, "new_did_key", did_aw=did_aw, seq=seq)
    authorized_by = _require_text(entry, "authorized_by", did_aw=did_aw, seq=seq)
    timestamp = _require_text(entry, "timestamp", did_aw=did_aw, seq=seq)
    if not _TIMESTAMP.fullmatch(timestamp):
        raise _invalid(did_aw=did_aw, seq=seq)
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid(did_aw=did_aw, seq=seq) from exc
    try:
        public_key_from_did(new_did_key)
        public_key_from_did(authorized_by)
    except ValueError as exc:
        raise _invalid(did_aw=did_aw, seq=seq) from exc

    previous_key = entry.get("previous_did_key")
    previous_hash = entry.get("prev_entry_hash")
    if seq == 1:
        if (
            operation not in {"create", "register_did"}
            or previous_key is not None
            or previous_hash is not None
            or authorized_by != new_did_key
        ):
            raise _invalid(did_aw=did_aw, seq=seq)
        try:
            if stable_id_from_did_key(new_did_key) != did_aw:
                raise _invalid(did_aw=did_aw, seq=seq)
        except ValueError as exc:
            raise _invalid(did_aw=did_aw, seq=seq) from exc
    else:
        if operation != "rotate_key" or not isinstance(previous_key, str):
            raise _invalid(did_aw=did_aw, seq=seq)
        previous_hash = _require_hash(previous_hash, did_aw=did_aw, seq=seq)
        try:
            public_key_from_did(previous_key)
        except ValueError as exc:
            raise _invalid(did_aw=did_aw, seq=seq) from exc
        if authorized_by != previous_key:
            raise _invalid(did_aw=did_aw, seq=seq)
        if previous is None:
            # Internally valid unanchored heads still cannot authorize.
            pass
        elif previous_key != previous.current_did_key or previous_hash != previous.entry_hash:
            raise _invalid(did_aw=did_aw, seq=seq)

    state_hash = _require_hash(entry.get("state_hash"), did_aw=did_aw, seq=seq)
    if state_hash != identity_state_hash(did_aw=did_aw, current_did_key=new_did_key):
        raise _invalid(did_aw=did_aw, seq=seq)
    entry_hash = _require_hash(entry.get("entry_hash"), did_aw=did_aw, seq=seq)
    payload = log_entry_payload(
        did_aw=did_aw,
        seq=seq,
        operation=operation,
        previous_did_key=previous_key if isinstance(previous_key, str) else None,
        new_did_key=new_did_key,
        prev_entry_hash=previous_hash if isinstance(previous_hash, str) else None,
        state_hash=state_hash,
        authorized_by=authorized_by,
        timestamp=timestamp,
    )
    if hashlib.sha256(payload).hexdigest() != entry_hash:
        raise _invalid(did_aw=did_aw, seq=seq)
    _verify_signature(
        did_key=authorized_by,
        payload=payload,
        signature=entry.get("signature"),
        did_aw=did_aw,
        seq=seq,
    )
    if new_did_key != current_did_key:
        raise FederationAuthorityError(
            "sender_current_key_mismatch",
            did_aw=did_aw,
            observed_sequence=seq,
        )
    return VerifiedIdentityLog(
        seq=seq,
        entry_hash=entry_hash,
        state_hash=state_hash,
        current_did_key=new_did_key,
        contains_checkpoint=previous is not None,
    )


def verify_identity_head(
    *,
    did_aw: str,
    current_did_key: str,
    entry: Mapping[str, object],
    checkpoint: IdentityCheckpoint | None = None,
) -> VerifiedIdentityLog:
    try:
        validate_stable_id(did_aw)
    except ValueError as exc:
        raise _invalid(did_aw=did_aw) from exc
    seq = _require_sequence(entry.get("seq"), did_aw=did_aw)
    if checkpoint is not None:
        if seq < checkpoint.seq:
            raise FederationAuthorityError(
                "sender_did_log_rollback", did_aw=did_aw, observed_sequence=seq
            )
        if seq == checkpoint.seq:
            if entry.get("entry_hash") != checkpoint.entry_hash:
                raise FederationAuthorityError(
                    "sender_did_log_split_view", did_aw=did_aw, observed_sequence=seq
                )
            if (
                entry.get("state_hash") != checkpoint.state_hash
                or entry.get("new_did_key") != checkpoint.current_did_key
            ):
                raise FederationAuthorityError(
                    "sender_did_log_split_view", did_aw=did_aw, observed_sequence=seq
                )
            return _verify_entry(
                did_aw=did_aw,
                current_did_key=current_did_key,
                entry=entry,
                previous=None if seq == 1 else IdentityCheckpoint(
                    seq=seq - 1,
                    entry_hash=str(entry.get("prev_entry_hash")),
                    state_hash="",
                    current_did_key=str(entry.get("previous_did_key")),
                    revision=checkpoint.revision,
                ),
            )
        if seq != checkpoint.seq + 1:
            raise FederationAuthorityError(
                "sender_identity_unverifiable", did_aw=did_aw, observed_sequence=seq
            )
    elif seq > 1:
        # Verify internal cryptography before classifying it as unanchored.
        _verify_entry(
            did_aw=did_aw,
            current_did_key=current_did_key,
            entry=entry,
            previous=None,
        )
        raise FederationAuthorityError(
            "sender_identity_unverifiable", did_aw=did_aw, observed_sequence=seq
        )
    verified = _verify_entry(
        did_aw=did_aw,
        current_did_key=current_did_key,
        entry=entry,
        previous=checkpoint,
    )
    return VerifiedIdentityLog(
        seq=verified.seq,
        entry_hash=verified.entry_hash,
        state_hash=verified.state_hash,
        current_did_key=verified.current_did_key,
        contains_checkpoint=True,
    )


def verify_identity_log(
    *,
    did_aw: str,
    entries: Sequence[Mapping[str, object]],
    expected_current_did_key: str | None = None,
    checkpoint: IdentityCheckpoint | None = None,
) -> VerifiedIdentityLog:
    try:
        validate_stable_id(did_aw)
    except ValueError as exc:
        raise _invalid(did_aw=did_aw) from exc
    if not entries:
        raise FederationAuthorityError("sender_identity_unverifiable", did_aw=did_aw)
    if len(entries) > MAX_LOG_ENTRIES:
        raise FederationAuthorityError("sender_identity_evidence_too_large", did_aw=did_aw)
    if any(not isinstance(entry, Mapping) for entry in entries):
        raise _invalid(did_aw=did_aw)
    if _require_sequence(entries[0].get("seq"), did_aw=did_aw) != 1:
        raise _invalid(did_aw=did_aw)

    previous: IdentityCheckpoint | None = None
    verified: VerifiedIdentityLog | None = None
    contains_checkpoint = checkpoint is None
    for index, entry in enumerate(entries):
        seq = _require_sequence(entry.get("seq"), did_aw=did_aw)
        if seq != index + 1:
            raise _invalid(did_aw=did_aw, seq=seq)
        current_key = _require_text(entry, "new_did_key", did_aw=did_aw, seq=seq)
        verified = _verify_entry(
            did_aw=did_aw,
            current_did_key=current_key,
            entry=entry,
            previous=previous,
        )
        if checkpoint is not None and seq == checkpoint.seq:
            if (
                verified.entry_hash != checkpoint.entry_hash
                or verified.state_hash != checkpoint.state_hash
                or verified.current_did_key != checkpoint.current_did_key
            ):
                raise FederationAuthorityError(
                    "sender_did_log_split_view", did_aw=did_aw, observed_sequence=seq
                )
            contains_checkpoint = True
        previous = IdentityCheckpoint(
            seq=verified.seq,
            entry_hash=verified.entry_hash,
            state_hash=verified.state_hash,
            current_did_key=verified.current_did_key,
            revision=0,
        )
    assert verified is not None
    if checkpoint is not None and not contains_checkpoint:
        reason = (
            "sender_did_log_rollback"
            if verified.seq < checkpoint.seq
            else "sender_did_log_split_view"
        )
        raise FederationAuthorityError(reason, did_aw=did_aw, observed_sequence=verified.seq)
    if expected_current_did_key is not None and verified.current_did_key != expected_current_did_key:
        raise FederationAuthorityError(
            "sender_current_key_mismatch",
            did_aw=did_aw,
            observed_sequence=verified.seq,
        )
    return VerifiedIdentityLog(
        seq=verified.seq,
        entry_hash=verified.entry_hash,
        state_hash=verified.state_hash,
        current_did_key=verified.current_did_key,
        contains_checkpoint=contains_checkpoint,
    )


def decode_identity_key_resolution(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid() from exc
    if not isinstance(value, dict):
        raise _invalid()
    head = value.get("log_head")
    if head is not None:
        if not isinstance(head, dict):
            raise _invalid()
        _require_sequence(head.get("seq"), did_aw=value.get("did_aw") if isinstance(value.get("did_aw"), str) else None)
    return value
