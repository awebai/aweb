"""Canonical JSON payload construction plus Ed25519 signing and verification."""

from __future__ import annotations

import base64
import enum
import json
import logging
from dataclasses import dataclass
from uuid import UUID

import httpx

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from aweb.awid.did import decode_public_key, did_from_public_key, public_key_from_did

logger = logging.getLogger(__name__)

SIGNED_FIELDS = frozenset(
    {
        "body",
        "from",
        "from_did",
        "from_stable_id",
        "message_id",
        "subject",
        "timestamp",
        "to",
        "to_did",
        "to_stable_id",
        "type",
    }
)


class VerifyResult(enum.Enum):
    VERIFIED = "verified"
    VERIFIED_CUSTODIAL = "verified_custodial"
    UNVERIFIED = "unverified"
    FAILED = "failed"


def canonical_json_bytes(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def canonical_payload(fields: dict) -> bytes:
    filtered = {k: v for k, v in fields.items() if k in SIGNED_FIELDS}
    return canonical_json_bytes(filtered)


def sign_message(private_key: bytes, payload: bytes) -> str:
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(payload)
    return base64.b64encode(signed.signature).rstrip(b"=").decode("ascii")


def _decode_signature(signature_b64: str) -> bytes:
    padded = signature_b64 + "=" * (-len(signature_b64) % 4)
    return base64.urlsafe_b64decode(padded)


def verify_signature_with_public_key(
    public_key: bytes, payload: bytes, signature_b64: str | None
) -> VerifyResult:
    if not signature_b64:
        return VerifyResult.UNVERIFIED

    try:
        sig_bytes = _decode_signature(signature_b64)
    except Exception:
        return VerifyResult.FAILED

    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(payload, sig_bytes)
        return VerifyResult.VERIFIED
    except BadSignatureError:
        return VerifyResult.FAILED
    except Exception:
        return VerifyResult.FAILED


def verify_signature(did: str | None, payload: bytes, signature_b64: str | None) -> VerifyResult:
    if not did or not signature_b64:
        return VerifyResult.UNVERIFIED

    if not did.startswith("did:key:z"):
        return VerifyResult.UNVERIFIED

    try:
        public_key = public_key_from_did(did)
    except Exception:
        return VerifyResult.FAILED

    return verify_signature_with_public_key(public_key, payload, signature_b64)


def verify_did_key_signature(*, did_key: str, payload: bytes, signature_b64: str) -> None:
    result = verify_signature(did_key, payload, signature_b64)
    if result != VerifyResult.VERIFIED:
        raise ValueError("invalid signature")


@dataclass(frozen=True)
class AgentSignatureVerification:
    did_key: str
    status: str
    source: str


async def _resolve_agent_verification_material(
    *, request, db, agent_id: str
) -> tuple[bytes, str, str, str]:
    from aweb.awid.registry import RegistryError

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT stable_id, did, public_key
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        UUID(agent_id),
    )
    if row is None:
        raise ValueError("sender agent not found")

    stable_id = (row.get("stable_id") or "").strip() or None
    cached_did = (row.get("did") or "").strip() or None
    cached_public_key = (row.get("public_key") or "").strip() or None

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if stable_id is not None and registry_client is None:
        logger.warning(
            "No registry client available for stable identity %s; using cached key",
            stable_id,
        )
    if stable_id is not None and registry_client is not None:
        try:
            resolve_key = getattr(registry_client, "resolve_key_fresh", None)
            if callable(resolve_key):
                resolution = await resolve_key(stable_id)
            else:
                resolution = await registry_client.resolve_key(stable_id)
            return (
                public_key_from_did(resolution.current_did_key),
                resolution.current_did_key,
                "OK_VERIFIED",
                "registry",
            )
        except RegistryError as exc:
            if exc.status_code < 500:
                raise ValueError("sender key lookup failed") from exc
            logger.warning(
                "AWID registry unavailable resolving %s; falling back to cached agent key",
                stable_id,
                exc_info=True,
            )
        except httpx.HTTPError:
            logger.warning(
                "AWID registry transport error resolving %s; falling back to cached agent key",
                stable_id,
                exc_info=True,
            )
        except Exception:
            logger.warning(
                "Unexpected AWID registry error resolving %s; falling back to cached agent key",
                stable_id,
                exc_info=True,
            )

    if cached_public_key is not None:
        public_key = decode_public_key(cached_public_key)
        resolved_did = cached_did or did_from_public_key(public_key)
        if stable_id is None:
            logger.info(
                "Using cached local key for ephemeral sender %s",
                agent_id,
            )
            return public_key, resolved_did, "OK_VERIFIED", "ephemeral_cached_key"
        logger.warning(
            "Using cached local key for stable identity %s because registry verification is unavailable",
            stable_id,
        )
        return public_key, resolved_did, "OK_DEGRADED", "stable_cached_key"

    if cached_did is not None and cached_did.startswith("did:key:z"):
        if stable_id is None:
            logger.info(
                "Using cached local did:key for ephemeral sender %s",
                agent_id,
            )
            return public_key_from_did(cached_did), cached_did, "OK_VERIFIED", "ephemeral_cached_did"
        logger.warning(
            "Using cached local did:key for stable identity %s because registry verification is unavailable",
            stable_id,
        )
        return public_key_from_did(cached_did), cached_did, "OK_DEGRADED", "stable_cached_did"

    raise ValueError("sender key unavailable")


async def verify_agent_did_key_signature(
    *,
    request,
    db,
    agent_id: str,
    did_key: str,
    payload: bytes,
    signature_b64: str,
) -> AgentSignatureVerification:
    public_key, expected_did, status, source = await _resolve_agent_verification_material(
        request=request,
        db=db,
        agent_id=agent_id,
    )
    if did_key != expected_did:
        raise ValueError("from_did does not match current sender did:key")
    result = verify_signature_with_public_key(public_key, payload, signature_b64)
    if result != VerifyResult.VERIFIED:
        raise ValueError("invalid signature")
    return AgentSignatureVerification(did_key=expected_did, status=status, source=source)
