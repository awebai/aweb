"""Shared current protection evidence and exact protected membership binding.

An observation has an original 60-second deadline. It is NOT distributed atomic
cutover: provisioning must drain/invalidate all consumers at every transition.
Call require_fresh synchronously after the effect's final await, before commit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any
from time import monotonic
from types import MappingProxyType

from awid.did import public_key_from_did
from awid.protected_effect import EffectRefused, validate_binding
from awid.signing import canonical_json_bytes
from awid.team_certificate import TeamCertificateError, check_team_certificate
from awid.team_ids import parse_team_id

logger = logging.getLogger(__name__)


def certificate_digest(certificate):
    return hashlib.sha256(canonical_json_bytes(certificate)).hexdigest()


def registered_certificate_digest(blob):
    """The registry's exact retained artifact, including all signed fields."""
    try:
        value = json.loads(base64.b64decode(blob, validate=True))
        if not isinstance(value, dict) or not value.get("signature"):
            raise ValueError()
        return certificate_digest(value)
    except (ValueError, TypeError, UnicodeError):
        return None


@dataclass(frozen=True)
class TeamProtectionObservation:
    team_id: str
    controller_did_key: str
    binding: Mapping[str, Any]
    deadline: float
    certificate_id: str | None = None
    certificate_sha256: str | None = None
    certificate_status: str | None = None

    def __post_init__(self):
        object.__setattr__(
            self, "binding", MappingProxyType(validate_binding(dict(self.binding)))
        )

    @property
    def protected(self):
        return self.binding["mode"] == "protected"

    def require_fresh(self):
        if monotonic() >= self.deadline:
            raise EffectRefused("protected_state_unavailable")

    def require_legacy_admission(self):
        self.require_fresh()
        if self.protected:
            raise EffectRefused("protected_admission_required")


async def observe_team_protection(registry, team_id, *, certificate_id=None):
    started = monotonic()
    try:
        domain, name = parse_team_id(team_id)
        if certificate_id is not None:
            status = await registry.get_team_certificate_status_fresh(
                domain, name, certificate_id, include_protection=True
            )
            if status is None:
                raise TeamCertificateError("unregistered")
            if (
                not isinstance(status, dict)
                or status.get("team_id") != team_id
                or status.get("status") not in {"active", "revoked"}
                or (
                    status["status"] == "active"
                    and status.get("revoked_at") is not None
                )
                or (
                    status["status"] == "revoked"
                    and not isinstance(status.get("revoked_at"), str)
                )
            ):
                raise ValueError("malformed certificate status")
            public_key_from_did(status["team_did_key"])
            result = TeamProtectionObservation(
                team_id,
                status["team_did_key"],
                status.get("protection"),
                started + 60,
                certificate_id,
                status.get("certificate_sha256"),
                status["status"],
            )
        else:
            team = await registry.get_team_fresh(domain, name)
            if team is None or team.team_id != team_id or not team.team_did_key:
                raise ValueError("current team unavailable")
            public_key_from_did(team.team_did_key)
            result = TeamProtectionObservation(
                team_id, team.team_did_key, team.protection, started + 60
            )
        result.require_fresh()
        return result
    except TeamCertificateError:
        raise
    except Exception:
        logger.exception("Current protected-team evidence unavailable")
        raise EffectRefused("protected_state_unavailable") from None


def check_presented_membership(observation, certificate):
    """Pure exact presentation check using one negotiated public observation."""
    observation.require_fresh()
    if observation.certificate_status == "revoked":
        raise TeamCertificateError("revoked")
    if not observation.protected:
        return certificate
    if certificate.get("team_id") != observation.team_id:
        raise TeamCertificateError("certificate_binding_mismatch")
    if observation.certificate_id is None or observation.certificate_status not in {
        "active",
        "revoked",
    }:
        raise EffectRefused("protected_state_unavailable")
    checked = check_team_certificate(
        base64.b64encode(canonical_json_bytes(certificate)).decode(),
        subject_did_key=certificate.get("member_did_key"),
        team_did_key=observation.controller_did_key,
        revoked_certificate_ids={observation.certificate_id}
        if observation.certificate_status == "revoked"
        else set(),
        registered_certificate_ids={observation.certificate_id},
    )
    digest = observation.certificate_sha256
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise EffectRefused("protected_state_unavailable")
    if digest != certificate_digest(checked):
        raise TeamCertificateError("certificate_binding_mismatch")
    observation.require_fresh()
    return checked


async def verify_registered_membership(registry, observation, certificate):
    """Use the same pure verifier for public status or a full-authority list."""
    observation.require_fresh()
    if observation.certificate_status == "revoked":
        raise TeamCertificateError("revoked")
    if not observation.protected:
        return certificate
    if observation.certificate_id is not None:
        return check_presented_membership(observation, certificate)
    record = await resolve_registered_membership(
        registry, observation, certificate.get("certificate_id")
    )
    from dataclasses import replace

    exact = replace(
        observation,
        certificate_id=record.certificate_id,
        certificate_sha256=record.certificate_sha256,
        certificate_status="revoked" if record.revoked_at else "active",
    )
    return check_presented_membership(exact, certificate)


async def resolve_registered_membership(registry, observation, certificate_id):
    """Resolve a full-artifact-backed row for a retained certificate reference.

    This alone is NOT authorization of a retained grant/agent projection. Its
    original subject and exact artifact digest must match, and that surface's
    independent grant/rights checks still apply. Pre-cutover ID-only evidence
    needs .8's explicitly inventoried baseline; do not manufacture its digest.
    """
    observation.require_fresh()
    domain, name = parse_team_id(observation.team_id)
    try:
        records = await registry.list_team_certificates_fresh(
            domain, name, active_only=False
        )
    except Exception:
        logger.exception("Retained protected membership evidence unavailable")
        raise EffectRefused("protected_state_unavailable") from None
    record = next((r for r in records if r.certificate_id == certificate_id), None)
    if record is None:
        raise TeamCertificateError("unregistered")
    if record.revoked_at:
        raise TeamCertificateError("revoked")
    if getattr(record, "certificate_sha256", None) is None:
        raise EffectRefused("protected_state_unavailable")
    observation.require_fresh()
    return record


def check_retained_membership_record(
    observation,
    record,
    *,
    certificate_id,
    member_did_key,
    alias,
    identity_scope,
    member_did_aw,
    member_address,
    certificate_sha256=None,
):
    """Pure check of EVERY membership field a retained consumer uses.

    This carries no HTTP/runtime dependency. A known original digest is also
    compared. A pre-cutover projection without one is eligible only under .8's
    explicitly inventoried field-exact historical baseline, never by guessing
    or writing a digest into that original evidence. The authoritative row must
    itself have a full retained certificate digest, even for that baseline.
    Independent grant/resource rights remain with their original verifier.
    """
    observation.require_fresh()
    if not observation.protected:
        return
    if record is None or record.certificate_id != certificate_id:
        raise TeamCertificateError("unregistered")
    if record.revoked_at:
        raise TeamCertificateError("revoked")
    if getattr(record, "certificate_sha256", None) is None:
        raise EffectRefused("protected_state_unavailable")
    expected = {
        "member_did_key": member_did_key,
        "alias": alias,
        "identity_scope": identity_scope,
        "member_did_aw": member_did_aw or "",
        "member_address": member_address or "",
    }
    if any((getattr(record, key) or "") != value for key, value in expected.items()):
        raise TeamCertificateError("certificate_binding_mismatch")
    if (
        certificate_sha256 is not None
        and record.certificate_sha256 != certificate_sha256
    ):
        raise TeamCertificateError("certificate_binding_mismatch")


async def verify_retained_membership(
    registry,
    observation,
    *,
    certificate_id,
    member_did_key,
    alias,
    identity_scope,
    member_did_aw,
    member_address,
    certificate_sha256=None,
):
    observation.require_fresh()
    if not observation.protected:
        return None
    record = await resolve_registered_membership(registry, observation, certificate_id)
    check_retained_membership_record(
        observation,
        record,
        certificate_id=certificate_id,
        member_did_key=member_did_key,
        alias=alias,
        identity_scope=identity_scope,
        member_did_aw=member_did_aw,
        member_address=member_address,
        certificate_sha256=certificate_sha256,
    )
    return record


def check_retained_subject_record(
    observation,
    record,
    *,
    certificate_id,
    controller_did_key,
    principal,
    certificate_sha256=None,
):
    """Pure subject-only baseline for consumers that use no alias/scope/rights.

    The caller supplies its ORIGINAL literal subject, ID and controller. It
    must not copy missing provenance out of record. A did:aw binding still
    requires the consumer's independent current identity/key proof. Only .8's
    explicit baseline permits pre-cutover references; resource ACLs are separate.
    """
    observation.require_fresh()
    if not observation.protected:
        return
    if record is None or record.certificate_id != certificate_id:
        raise TeamCertificateError("unregistered")
    if record.revoked_at:
        raise TeamCertificateError("revoked")
    if not getattr(record, "certificate_sha256", None):
        raise EffectRefused("protected_state_unavailable")
    if not isinstance(principal, str):
        raise TeamCertificateError("certificate_binding_mismatch")
    if principal.startswith("did:key:"):
        matches = principal == record.member_did_key
    elif principal.startswith("did:aw:"):
        matches = principal == record.member_did_aw
    else:
        matches = False
    if not matches or controller_did_key != observation.controller_did_key:
        raise TeamCertificateError("certificate_binding_mismatch")
    if (
        certificate_sha256 is not None
        and certificate_sha256 != record.certificate_sha256
    ):
        raise TeamCertificateError("certificate_binding_mismatch")
