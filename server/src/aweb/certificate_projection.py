"""Fenced certificate replacement without reconstructing an existing member.

Antares16d02630 keeps team generation and member identity binding separate.
Only an independently fresh binding can change signed member identity claims;
its canonical refresh and certificate acceptance share this transaction.
"""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from pgdbm import AsyncDatabaseManager, TransactionManager

from aweb.certificate_auth import VerifiedCertificateGeneration
from aweb.identity_binding import (
    IdentityBinding,
    refresh_projection_binding,
    verified_projection,
)
from aweb.identity_scope import normalize_identity_scope
from aweb.member_status import MemberStatus
from aweb.service_errors import ServiceError


class CertificateProjectionDisposition(StrEnum):
    """Whether the fenced member projection changed on this invocation."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"


class CertificateProjectionConflictReason(StrEnum):
    """Named refusals for an exact retained member/certificate replacement."""

    MEMBER = "certificate_member_conflict"
    EXPECTED_CERTIFICATE = "certificate_projection_conflict"
    TEAM_KEY = "certificate_generation_stale"
    BINDING = "certificate_binding_conflict"


_MESSAGES = {
    CertificateProjectionConflictReason.MEMBER: "Reload the current member and use its exact team, key, alias and identity scope before replacing the certificate.",
    CertificateProjectionConflictReason.EXPECTED_CERTIFICATE: "Reload the member's current certificate ID and retry the retained replacement with that expected value.",
    CertificateProjectionConflictReason.TEAM_KEY: "Verify the retained certificate under the team's current controller key before retrying this replacement.",
    CertificateProjectionConflictReason.BINDING: "Supply a fresh IdentityBinding for the certificate's exact member key, stable identity and address, then retry the replacement.",
}


class CertificateProjectionConflict(ServiceError):
    """A replacement fence or independent binding assertion did not hold."""

    status_code = 409

    def __init__(self, reason: CertificateProjectionConflictReason) -> None:
        self.reason = reason
        self.code = reason.value
        self.message = _MESSAGES[reason]
        super().__init__({"code": self.code, "message": self.message})


@dataclass(frozen=True, kw_only=True)
class CertificateProjectionResult:
    """The exact retained member and generation accepted by this operation."""

    disposition: CertificateProjectionDisposition
    agent_id: UUID
    certificate_id: str
    verified_team_did_key: str
    certificate_fingerprint: str


async def replace_member_certificate(
    *,
    db: AsyncDatabaseManager | TransactionManager,
    agent_id: UUID,
    team_id: str,
    member_did_key: str,
    expected_certificate_id: str | None,
    generation: VerifiedCertificateGeneration,
    identity_binding: IdentityBinding | None = None,
) -> CertificateProjectionResult:
    """Replace certificate acceptance under team/member/expected-old fences.

    Absence of identity_binding asserts unchanged verified member claims; this
    operation checks that assertion. A supplied binding must be independently
    fresh and match the exact signed claims. No registry I/O, mint, registration,
    profile/kind reset or workspace mutation occurs here. The caller may share
    this transaction with its complete certificate cache and retained intent.
    """
    if not isinstance(generation, VerifiedCertificateGeneration):
        raise TypeError(
            "Pass the result of verify_certificate_generation for certificate replacement."
        )
    if not isinstance(agent_id, UUID):
        raise TypeError("Pass the exact native agent UUID for certificate replacement.")
    claims = generation.certificate.claims
    if claims["team_id"] != team_id or claims["member_did_key"] != member_did_key:
        raise CertificateProjectionConflict(CertificateProjectionConflictReason.MEMBER)
    target_binding = (
        claims.get("member_did_aw") or "",
        claims.get("member_address") or "",
    )
    if identity_binding is not None and (
        not isinstance(identity_binding, IdentityBinding)
        or not identity_binding.fresh_observation
        or identity_binding.did_key != member_did_key
        or (identity_binding.did_aw, identity_binding.address) != target_binding
    ):
        raise CertificateProjectionConflict(CertificateProjectionConflictReason.BINDING)

    async with db.transaction() as tx:
        # Same lock order as generation admission: admitted team, then member.
        current_key = await tx.fetch_value(
            "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1 FOR SHARE",
            team_id,
        )
        if current_key is None:
            raise CertificateProjectionConflict(
                CertificateProjectionConflictReason.MEMBER
            )
        if current_key != generation.verified_team_did_key:
            raise CertificateProjectionConflict(
                CertificateProjectionConflictReason.TEAM_KEY
            )
        row = await tx.fetch_one(
            """SELECT agent_id,team_id,did_key,alias,identity_scope,status,deleted_at,
                      certificate_id,accepted_team_did_key,did_aw,address,did_aw_verified_key
               FROM {{tables.agents}} WHERE agent_id=$1 FOR UPDATE""",
            agent_id,
        )
        if (
            row is None
            or row["deleted_at"] is not None
            or row["status"] != MemberStatus.ACTIVE
            or row["team_id"] != team_id
            or row["did_key"] != member_did_key
            or row["alias"] != claims["alias"]
            or normalize_identity_scope(row["identity_scope"])
            != normalize_identity_scope(
                claims.get("identity_scope") or claims.get("lifetime")
            )
        ):
            raise CertificateProjectionConflict(
                CertificateProjectionConflictReason.MEMBER
            )
        certificate_id = claims["certificate_id"]
        already_applied = (
            row["certificate_id"] == certificate_id
            and row["accepted_team_did_key"] == generation.verified_team_did_key
        )
        if not already_applied and row["certificate_id"] != expected_certificate_id:
            raise CertificateProjectionConflict(
                CertificateProjectionConflictReason.EXPECTED_CERTIFICATE
            )
        verified = verified_projection(row)
        binding_changed = target_binding != (
            verified.get("did_aw") or "",
            verified.get("address") or "",
        )
        if binding_changed:
            if identity_binding is None:
                raise CertificateProjectionConflict(
                    CertificateProjectionConflictReason.BINDING
                )
            await refresh_projection_binding(
                tx, agent_id=agent_id, did_key=member_did_key, binding=identity_binding
            )
        if not already_applied:
            await tx.execute(
                """UPDATE {{tables.agents}}
                   SET certificate_id=$2, accepted_team_did_key=$3
                   WHERE agent_id=$1""",
                agent_id,
                certificate_id,
                generation.verified_team_did_key,
            )
    return CertificateProjectionResult(
        disposition=(
            CertificateProjectionDisposition.UPDATED
            if binding_changed or not already_applied
            else CertificateProjectionDisposition.UNCHANGED
        ),
        agent_id=agent_id,
        certificate_id=certificate_id,
        verified_team_did_key=generation.verified_team_did_key,
        certificate_fingerprint=generation.certificate_fingerprint,
    )
