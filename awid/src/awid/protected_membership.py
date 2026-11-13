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


async def observe_team_protection(registry, team_id):
    started = monotonic()
    try:
        domain, name = parse_team_id(team_id)
        team = await registry.get_team_fresh(domain, name)
        if team is None or team.team_id != team_id or not team.team_did_key:
            raise ValueError("current team unavailable")
        result = TeamProtectionObservation(
            team_id, team.team_did_key, team.protection, started + 60
        )
        result.require_fresh()
        return result
    except Exception:
        logger.exception("Current protected-team evidence unavailable")
        raise EffectRefused("protected_state_unavailable") from None


async def verify_registered_membership(registry, observation, certificate):
    """A full signature/registry check on a protected team, no ID-set shortcut.

    certificate is the complete decoded signed v1 artifact. The returned
    observation remains the caller's original freshness fence.
    """
    observation.require_fresh()
    if not observation.protected:
        return certificate
    if certificate.get("team_id") != observation.team_id:
        raise TeamCertificateError("certificate_binding_mismatch")
    domain, name = parse_team_id(observation.team_id)
    try:
        records = await registry.list_team_certificates_fresh(
            domain, name, active_only=False
        )
    except Exception:
        logger.exception("Exact protected membership evidence unavailable")
        raise EffectRefused("protected_state_unavailable") from None
    checked = check_team_certificate(
        base64.b64encode(canonical_json_bytes(certificate)).decode(),
        subject_did_key=certificate.get("member_did_key"),
        team_did_key=observation.controller_did_key,
        revoked_certificate_ids={r.certificate_id for r in records if r.revoked_at},
        registered_certificate_ids={r.certificate_id for r in records},
    )
    record = next(r for r in records if r.certificate_id == checked["certificate_id"])
    digest = getattr(record, "certificate_sha256", None)
    if digest is None:
        raise EffectRefused("protected_state_unavailable")
    if digest != certificate_digest(checked):
        raise TeamCertificateError("certificate_binding_mismatch")
    observation.require_fresh()
    return checked


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
