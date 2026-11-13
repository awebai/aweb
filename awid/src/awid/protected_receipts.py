"""Exact historical consumer receipts; no effect or signing authority."""

import hashlib
import base64
import json
import logging
from uuid import UUID

from awid.protected_effect import EffectRefused, MAX_HEADER_BYTES, decode_proofs

PATH = "/.well-known/aweb-protected-effect-receipts"
logger = logging.getLogger(__name__)


def header_digest(header):
    if not isinstance(header, str) or not 0 < len(header) <= MAX_HEADER_BYTES:
        raise ValueError("invalid receipt evidence")
    return hashlib.sha256(header.encode("ascii")).hexdigest()


async def record_receipt(tx, fields, header):
    """Only call with verified proof fields in the effect's own transaction."""
    values = (
        fields["service_id"],
        fields["operation"],
        fields["variant"],
        fields["artifact_sha256"],
        header_digest(header),
    )
    try:
        row = await tx.fetch_one(
            "INSERT INTO {{tables.protected_effect_receipts}} "
            "(operation_id,team_id,service_id,operation,variant,artifact_sha256,header_sha256) "
            "VALUES($1::uuid,$2,$3,$4,$5,$6,$7) "
            "ON CONFLICT(operation_id,team_id) DO UPDATE SET operation_id=EXCLUDED.operation_id "
            "RETURNING service_id,operation,variant,artifact_sha256,header_sha256",
            fields["operation_id"],
            fields["team_id"],
            *values,
        )
        if (
            tuple(
                row[k]
                for k in (
                    "service_id",
                    "operation",
                    "variant",
                    "artifact_sha256",
                    "header_sha256",
                )
            )
            != values
        ):
            raise EffectRefused("protected_controller_required")
    except EffectRefused:
        raise
    except Exception:
        logger.exception("Protected effect receipt storage unavailable")
        raise EffectRefused("protected_state_unavailable") from None


async def read_receipt(db, operation_id, header):
    """Exact retained header possession identifies only its committed history.

    Expiry/current generation never authorizes an effect here. No request or
    artifact is returned; receipt reads cannot consume, sign or mutate.
    """
    try:
        if str(UUID(operation_id)) != operation_id:
            return None
        digest = header_digest(header)
        fields = [
            json.loads(
                base64.urlsafe_b64decode(
                    proof["payload"] + "=" * (-len(proof["payload"]) % 4)
                )
            )
            for proof in decode_proofs(header)
        ]
        if any(item["operation_id"] != operation_id for item in fields):
            return None
        expected = {
            item["team_id"]: tuple(
                item[k]
                for k in ("service_id", "operation", "variant", "artifact_sha256")
            )
            for item in fields
        }
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None
    try:
        rows = await db.fetch_all(
            "SELECT team_id,service_id,operation,variant,artifact_sha256 FROM {{tables.protected_effect_receipts}} "
            "WHERE operation_id=$1::uuid AND header_sha256=$2",
            operation_id,
            digest,
        )
        if not rows:
            return None
        actual = {
            row["team_id"]: tuple(
                row[k]
                for k in ("service_id", "operation", "variant", "artifact_sha256")
            )
            for row in rows
        }
        if actual != expected:
            return None
        artifacts = {row["artifact_sha256"] for row in rows}
        if len(artifacts) != 1:
            raise EffectRefused("protected_state_unavailable")
        return {
            "v": 1,
            "operation_id": operation_id,
            "artifact_sha256": artifacts.pop(),
        }
    except EffectRefused:
        raise
    except Exception:
        logger.exception("Protected effect receipt read unavailable")
        raise EffectRefused("protected_state_unavailable") from None
