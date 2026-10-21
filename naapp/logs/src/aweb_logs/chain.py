"""The bytes logs commits to and signs: genesis, commitments, links, receipts and checkpoints.

``docs/logs-chain.md`` is the contract, and its vector pins the bytes. Objects are strict canonical JSON under the hook event rules
(:mod:`aweb_naapp.hooks.strictjson`), each behind its own domain prefix.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from aweb_naapp.hooks.envelope import (
    KID_PATTERN,
    ORIGIN_PATTERN,
    TEAM_ID_PATTERN,
    UUID_PATTERN,
    Envelope,
    check_keys,
    ed25519_did_key,
    exact_time,
    verify_signature,
)
from aweb_naapp.hooks.strictjson import (
    MAX_SAFE_INTEGER,
    Refused,
    canonical,
    decode_signature,
    encode_signature,
    parse_canonical_object,
)
from awid.did import did_from_public_key
from nacl.signing import SigningKey

RECEIPT_PURPOSE = "logs-receipt"
CHECKPOINT_PURPOSE = "logs-checkpoint"

GENESIS_PREFIX = b"aweb.logs-genesis/1\n"
COMMIT_PREFIX = b"aweb.logs-commit/1\n"
CHAIN_PREFIX = b"aweb.logs-chain/1\n"
RECEIPT_PREFIX = b"aweb.logs-receipt/1\n"
CHECKPOINT_PREFIX = b"aweb.logs-checkpoint/1\n"

SALT_BYTES = 32
TIME_LAYOUT = "%Y-%m-%dT%H:%M:%S.%fZ"
_DIGEST = re.compile(r"[0-9a-f]{64}")


def format_time(moment: datetime) -> str:
    """A moment in the chain's one time spelling: UTC to the millisecond."""
    if moment.tzinfo is None:
        raise ValueError("a chain time needs a timezone")
    utc = moment.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artefact_sha256(signing_bytes: bytes) -> str:
    """The digest by which a later checkpoint or epoch names a checkpoint."""
    return sha256_hex(signing_bytes)


@dataclass(frozen=True)
class Genesis:
    """The start of one team's chain epoch."""

    team_id: str
    chain_epoch: int
    logs_origin: str
    created_at: str
    # The SHA-256 of the previous epoch's final checkpoint; every epoch after the first has one.
    previous_checkpoint_sha256: str | None = None

    def fields(self) -> dict[str, Any]:
        fields = _present(self)
        _check_team(fields)
        _counter(fields, "chain_epoch", minimum=1)
        _match(fields, "logs_origin", ORIGIN_PATTERN)
        exact_time(fields, "created_at", TIME_LAYOUT, milliseconds=True)
        if self.chain_epoch == 1:
            if self.previous_checkpoint_sha256 is not None:
                raise Refused("invalid_value", "the first epoch has no previous checkpoint")
        else:
            if self.previous_checkpoint_sha256 is None:
                raise Refused("missing_field", "previous_checkpoint_sha256")
            _match(fields, "previous_checkpoint_sha256", _DIGEST)
        return fields

    def hash(self) -> str:
        return sha256_hex(GENESIS_PREFIX + canonical(self.fields()))


def content_commitment(salt: bytes, signing_bytes: bytes, signature: str) -> str:
    """Commit to an event's retained content: its salt, envelope bytes and raw signature."""
    if len(salt) != SALT_BYTES:
        raise Refused("invalid_value", f"a salt is {SALT_BYTES} bytes")
    return sha256_hex(COMMIT_PREFIX + salt + signing_bytes + decode_signature(signature))


def producer_origin(event: Envelope) -> str:
    """The producer as the chain names it: its origin, or its certificate for a client."""
    producer = event.fields["producer"]
    if event.producer_kind == "client":
        return "client:" + producer["certificate_id"]
    origin: str = producer["origin"]
    return origin


@dataclass(frozen=True)
class Link:
    """An event's skeleton: what the chain hashes, and what a purge keeps."""

    chain_epoch: int
    team_id: str
    team_seq: int
    prev_event_hash: str
    received_at: str
    hook: str
    producer_origin: str
    content_commitment: str

    def fields(self) -> dict[str, Any]:
        fields = _present(self)
        _counter(fields, "chain_epoch", minimum=1)
        _check_team(fields)
        _counter(fields, "team_seq", minimum=1)
        _match(fields, "prev_event_hash", _DIGEST)
        exact_time(fields, "received_at", TIME_LAYOUT, milliseconds=True)
        for name in ("hook", "producer_origin"):
            if not isinstance(fields[name], str) or not fields[name]:
                raise Refused("invalid_value", name)
        _match(fields, "content_commitment", _DIGEST)
        return fields

    def event_hash(self) -> str:
        return sha256_hex(CHAIN_PREFIX + canonical(self.fields()))


def link_for(
    event: Envelope,
    *,
    chain_epoch: int,
    team_seq: int,
    prev_event_hash: str,
    received_at: str,
    content_commitment: str,
) -> Link:
    """The link that appends ``event`` to its team's chain."""
    return Link(
        chain_epoch=chain_epoch,
        team_id=event.team_id,
        team_seq=team_seq,
        prev_event_hash=prev_event_hash,
        received_at=received_at,
        hook=event.hook,
        producer_origin=producer_origin(event),
        content_commitment=content_commitment,
    )


@dataclass(frozen=True)
class Receipt:
    """``aweb.logs-receipt/1``: logs' signed statement that it appended one event."""

    team_id: str
    event_id: str
    chain_epoch: int
    team_seq: int
    event_hash: str
    received_at: str
    logs_origin: str
    kid: str
    did_key: str

    TYPE = "aweb.logs-receipt"
    PREFIX = RECEIPT_PREFIX

    def fields(self) -> dict[str, Any]:
        fields = {"v": 1, "type": self.TYPE, **_present(self)}
        _check_team(fields)
        _match(fields, "event_id", UUID_PATTERN)
        _counter(fields, "chain_epoch", minimum=1)
        _counter(fields, "team_seq", minimum=1)
        _match(fields, "event_hash", _DIGEST)
        exact_time(fields, "received_at", TIME_LAYOUT, milliseconds=True)
        _check_signer(fields)
        return fields

    def signing_bytes(self) -> bytes:
        return self.PREFIX + canonical(self.fields())


@dataclass(frozen=True)
class Checkpoint:
    """``aweb.logs-checkpoint/1``: logs' signed witness of a chain head."""

    team_id: str
    chain_epoch: int
    team_seq: int
    event_hash: str
    issued_at: str
    logs_origin: str
    kid: str
    did_key: str
    # The SHA-256 of the epoch's previous checkpoint; the epoch's first has none.
    previous_checkpoint_sha256: str | None = None

    TYPE = "aweb.logs-checkpoint"
    PREFIX = CHECKPOINT_PREFIX

    def fields(self) -> dict[str, Any]:
        fields = {"v": 1, "type": self.TYPE, **_present(self)}
        _check_team(fields)
        _counter(fields, "chain_epoch", minimum=1)
        _counter(fields, "team_seq", minimum=0)
        _match(fields, "event_hash", _DIGEST)
        exact_time(fields, "issued_at", TIME_LAYOUT, milliseconds=True)
        _check_signer(fields)
        if "previous_checkpoint_sha256" in fields:
            _match(fields, "previous_checkpoint_sha256", _DIGEST)
        return fields

    def signing_bytes(self) -> bytes:
        return self.PREFIX + canonical(self.fields())


def sign_receipt(key: SigningKey, receipt: Receipt) -> tuple[bytes, str]:
    """A receipt's signing bytes and logs' signature over them."""
    return _sign(key, receipt.did_key, receipt.signing_bytes())


def sign_checkpoint(key: SigningKey, checkpoint: Checkpoint) -> tuple[bytes, str]:
    """A checkpoint's signing bytes and logs' signature over them."""
    return _sign(key, checkpoint.did_key, checkpoint.signing_bytes())


def open_receipt(signing_bytes: bytes, signature: str) -> Receipt:
    """The receipt these bytes hold, signed by the key it names, or :class:`Refused`.

    Whether that key is logs' key for receipts is the caller's to check."""
    fields = _open(signing_bytes, signature, RECEIPT_PREFIX, Receipt)
    return _rebuild(Receipt, fields, signing_bytes)


def open_checkpoint(signing_bytes: bytes, signature: str) -> Checkpoint:
    """The checkpoint these bytes hold, signed by the key it names, or :class:`Refused`.

    Whether that key is logs' key for checkpoints is the caller's to check."""
    fields = _open(signing_bytes, signature, CHECKPOINT_PREFIX, Checkpoint)
    return _rebuild(Checkpoint, fields, signing_bytes)


def _sign(key: SigningKey, did_key: str, signing_bytes: bytes) -> tuple[bytes, str]:
    if did_from_public_key(bytes(key.verify_key)) != did_key:
        raise Refused("signer_mismatch", "the key is not the artefact's did_key")
    return signing_bytes, encode_signature(key.sign(signing_bytes).signature)


def _open(
    signing_bytes: bytes, signature: str, prefix: bytes, kind: type[Receipt] | type[Checkpoint]
) -> dict[str, Any]:
    if not signing_bytes.startswith(prefix):
        raise Refused("wrong_prefix", f"signing bytes do not start with {prefix!r}")
    fields = parse_canonical_object(signing_bytes[len(prefix) :])
    names = tuple(field.name for field in dataclasses.fields(kind))
    optional = tuple(field.name for field in dataclasses.fields(kind) if field.default is None)
    required = tuple(name for name in names if name not in optional)
    check_keys(fields, "", ("v", "type", *required), optional)
    if fields["v"] != 1 or fields["type"] != kind.TYPE:
        raise Refused("invalid_value", "v or type")
    _check_signer(fields)
    verify_signature(fields["did_key"], signing_bytes, signature)
    return fields


def _rebuild[T: (Receipt, Checkpoint)](kind: type[T], fields: dict[str, Any], signing: bytes) -> T:
    artefact = kind(**{name: value for name, value in fields.items() if name not in ("v", "type")})
    if artefact.signing_bytes() != signing:
        raise Refused("invalid_value", "the artefact's fields do not hold")
    return artefact


def _present(artefact: Any) -> dict[str, Any]:
    return {
        name: value for name, value in dataclasses.asdict(artefact).items() if value is not None
    }


def _check_team(fields: dict[str, Any]) -> None:
    _match(fields, "team_id", TEAM_ID_PATTERN)


def _check_signer(fields: dict[str, Any]) -> None:
    _match(fields, "logs_origin", ORIGIN_PATTERN)
    _match(fields, "kid", KID_PATTERN)
    ed25519_did_key(fields, "did_key", "")


def _match(fields: dict[str, Any], name: str, pattern: re.Pattern[str]) -> None:
    value = fields[name]
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refused("invalid_value", name)


def _counter(fields: dict[str, Any], name: str, *, minimum: int) -> None:
    value = fields[name]
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_SAFE_INTEGER
    ):
        raise Refused("invalid_value", name)
