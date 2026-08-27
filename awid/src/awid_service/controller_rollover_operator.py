"""Audited DB-operator controls for exact-DNS rollover recovery."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature


MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS = 2_147_483_647


class RolloverRiskAcceptanceError(RuntimeError):
    pass


class ControllerRolloverOperator:
    @staticmethod
    def validate_safety_window_seconds(value: object) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS
        ):
            raise RolloverRiskAcceptanceError(
                "assumed previous TTL must be an integer between 1 and "
                f"{MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS} seconds"
            )
        return value

    def __init__(self, db, *, verify_domain, public_origin: str | None = None) -> None:
        self.db = db
        self.verify_domain = verify_domain
        self.public_origin = (
            None if public_origin is None else canonical_server_origin(public_origin)
        )

    @staticmethod
    def acceptance_payload(
        *,
        domain: str,
        rollover_id: str,
        dns_changed_at: str,
        assumed_previous_ttl_seconds: int,
        reason_bytes: bytes,
        signature_timestamp: str,
    ) -> dict:
        return {
            "assumed_previous_ttl_seconds": assumed_previous_ttl_seconds,
            "dns_changed_at": dns_changed_at,
            "domain": domain,
            "operation": "accept_controller_rollover_overlap_risk",
            "reason_sha256": "sha256:" + hashlib.sha256(reason_bytes).hexdigest(),
            "rollover_id": rollover_id,
            "timestamp": signature_timestamp,
        }

    async def accept_overlap_risk(
        self,
        *,
        rollover_id: str,
        dns_changed_at: str,
        assumed_previous_ttl_seconds: int,
        reason_bytes: bytes,
        operator_id: str,
        new_controller_signature: str,
        signature_timestamp: str,
        explicit_acceptance: bool,
        now: datetime | None = None,
    ) -> dict:
        if not explicit_acceptance:
            raise RolloverRiskAcceptanceError("explicit risk-acceptance flag is required")
        if not operator_id.strip() or not reason_bytes:
            raise RolloverRiskAcceptanceError("operator id and risk reason are required")
        assumed_previous_ttl_seconds = self.validate_safety_window_seconds(
            assumed_previous_ttl_seconds
        )
        injected_now = now
        canonical_utc = re.compile(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
        )
        if not canonical_utc.fullmatch(dns_changed_at) or not canonical_utc.fullmatch(
            signature_timestamp
        ):
            raise RolloverRiskAcceptanceError(
                "timestamps must use canonical RFC3339 UTC Z representation"
            )
        try:
            changed_at = datetime.fromisoformat(dns_changed_at.replace("Z", "+00:00"))
            signed_at = datetime.fromisoformat(signature_timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RolloverRiskAcceptanceError("timestamps must be RFC3339 UTC") from exc
        if changed_at.tzinfo is None or signed_at.tzinfo is None:
            raise RolloverRiskAcceptanceError("DNS change time is invalid")
        async with self.db.transaction() as tx:
            rollover = await tx.fetch_one(
                """
                SELECT * FROM {{tables.namespace_controller_rollovers}}
                WHERE rollover_id=$1::uuid FOR UPDATE
                """,
                rollover_id,
            )
            if rollover is None:
                raise RolloverRiskAcceptanceError("controller rollover not found")
            payload = self.acceptance_payload(
                domain=rollover["parent_domain"],
                rollover_id=rollover_id,
                dns_changed_at=dns_changed_at,
                assumed_previous_ttl_seconds=assumed_previous_ttl_seconds,
                reason_bytes=reason_bytes,
                signature_timestamp=signature_timestamp,
            )
            canonical = canonical_json_bytes(payload)
            acceptance_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
            existing = await tx.fetch_one(
                "SELECT * FROM {{tables.namespace_controller_rollover_risk_acceptances}} WHERE rollover_id=$1::uuid",
                rollover_id,
            )
            if existing is not None:
                if (
                    bytes(existing["canonical_acceptance"]) == canonical
                    and existing["acceptance_hash"] == acceptance_hash
                    and existing["new_controller_signature"] == new_controller_signature
                    and existing["operator_id"] == operator_id
                    and bytes(existing["reason_bytes"]) == reason_bytes
                ):
                    return self._readback(existing)
                raise RolloverRiskAcceptanceError("controller rollover risk acceptance conflicts")
            admission_now = injected_now or datetime.now(timezone.utc)
            if changed_at > admission_now:
                raise RolloverRiskAcceptanceError("DNS change time is invalid")
            if abs((admission_now - signed_at).total_seconds()) > 300:
                raise RolloverRiskAcceptanceError("new-controller signature timestamp is stale")
            if rollover["state"] != "recovery_overlap_unbounded" or rollover["recovery_mode"] != "exact_dns":
                raise RolloverRiskAcceptanceError("rollover is not awaiting exact-DNS overlap risk acceptance")
            try:
                verify_did_key_signature(
                    did_key=rollover["new_controller_did"],
                    payload=canonical,
                    signature_b64=new_controller_signature,
                )
            except Exception as exc:
                raise RolloverRiskAcceptanceError("new-controller risk signature is invalid") from exc
            authority = await self.verify_domain(rollover["parent_domain"])
            dns_observed_at = injected_now or datetime.now(timezone.utc)
            if self.public_origin is None:
                raise RolloverRiskAcceptanceError("configured AWID public origin is required")
            if (
                authority.inherited
                or authority.controller_did != rollover["new_controller_did"]
                or authority.registry_url != self.public_origin
            ):
                raise RolloverRiskAcceptanceError("live exact DNS does not name the recovered controller")
            first_observed = rollover["first_new_dns_observed_at"] or rollover["cutover_at"]
            if first_observed is None:
                raise RolloverRiskAcceptanceError("rollover has no new-DNS observation")
            complete_after = max(changed_at, first_observed) + timedelta(
                seconds=assumed_previous_ttl_seconds
            )
            answer_digest = "sha256:" + hashlib.sha256(
                canonical_json_bytes(
                    {
                        "controller_did": authority.controller_did,
                        "dns_name": authority.dns_name,
                        "registry_origin": authority.registry_url,
                    }
                )
            ).hexdigest()
            row = await tx.fetch_one(
                """
                INSERT INTO {{tables.namespace_controller_rollover_risk_acceptances}}
                    (rollover_id,canonical_acceptance,acceptance_hash,operator_id,
                     reason_bytes,reason_hash,dns_changed_at,assumed_previous_ttl_seconds,
                     new_controller_signature,signature_timestamp,live_dns_name,
                     live_dns_answer_digest,live_dns_observed_at,complete_after)
                VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                RETURNING *
                """,
                rollover_id,
                canonical,
                acceptance_hash,
                operator_id,
                reason_bytes,
                payload["reason_sha256"],
                changed_at,
                assumed_previous_ttl_seconds,
                new_controller_signature,
                signed_at,
                authority.dns_name,
                answer_digest,
                dns_observed_at,
                complete_after,
            )
            await tx.execute(
                """
                UPDATE {{tables.namespace_controller_rollovers}}
                SET state='overlap_risk_accepted',complete_after=$2,updated_at=NOW()
                WHERE rollover_id=$1::uuid AND state='recovery_overlap_unbounded'
                """,
                rollover_id,
                complete_after,
            )
            return self._readback(row)

    @staticmethod
    def _readback(row) -> dict:
        def canonical(value: datetime) -> str:
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "rollover_id": str(row["rollover_id"]),
            "canonical_acceptance": bytes(row["canonical_acceptance"]).decode(),
            "acceptance_hash": row["acceptance_hash"],
            "operator_id": row["operator_id"],
            "reason_hash": row["reason_hash"],
            "dns_changed_at": canonical(row["dns_changed_at"]),
            "assumed_previous_ttl_seconds": row["assumed_previous_ttl_seconds"],
            "new_controller_signature": row["new_controller_signature"],
            "signature_timestamp": canonical(row["signature_timestamp"]),
            "live_dns_name": row["live_dns_name"],
            "live_dns_answer_digest": row["live_dns_answer_digest"],
            "live_dns_observed_at": canonical(row["live_dns_observed_at"]),
            "complete_after": canonical(row["complete_after"]),
            "created_at": canonical(row["created_at"]),
            "previous_ttl_independently_established": False,
            "risk_accepted": True,
            "warning": (
                "old-authority readers may fail until all prior DNS caches expire; "
                "the assumed previous TTL may be too short"
            ),
        }
