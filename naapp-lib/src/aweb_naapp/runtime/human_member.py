"""Current human admission, separate from app-owned role and B3 holdings."""

import copy
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from awid.did import validate_stable_id
from awid.identity_observation import (
    IdentityObservationRefused,
    observe_identity_binding,
    observe_identity_kind,
)
from awid.registry import RegistryClient
from awid.team_certificate import TeamCertificateError, verify_team_certificate_signature
from fastapi import HTTPException

from aweb_naapp.runtime.team_auth import (
    AWIDTeamCache,
    MembershipProof,
    require_active_certificate,
)


@dataclass(frozen=True)
class HumanMemberProof:
    """Trusted in-process output, never a request DTO or role authorization.

    Consumers retain the membership proof's original freshness deadline across
    their effect lock. Identity-chain evidence keeps the public verifier's own
    acquisition-time rules. App holdings and exact B3 credentials remain separate.
    """

    principal: str
    did_key: str
    membership: MembershipProof


def _refused(status: int, code: str) -> HTTPException:
    return HTTPException(status_code=status, detail=code)


async def check_human_member(
    team_cache: AWIDTeamCache,
    registry: RegistryClient,
    *,
    team_id: str,
    principal: str,
    certificate: Mapping[str, Any],
) -> HumanMemberProof:
    """Check the exact signed certificate, current key and subject's OWN kind.

    `registry` is the caller-owned SDK client: plain means live reads, and an
    existing CachedRegistryClient retains its public bounded cache. Resolve
    this remote evidence before opening effect transactions. An observed row,
    certificate ID or nearest-human label cannot substitute for these checks.
    """
    try:
        validate_stable_id(principal)
        cert = copy.deepcopy(dict(certificate))
        certificate_id = cert.get("certificate_id")
        did_key = cert.get("member_did_key")
        if (
            cert.get("team_id") != team_id
            or cert.get("member_did_aw") != principal
            or not isinstance(certificate_id, str)
            or not certificate_id.strip()
            or not isinstance(did_key, str)
            or not did_key
        ):
            raise ValueError()
    except (TypeError, ValueError, RecursionError):
        raise _refused(403, "principal_not_member") from None
    try:
        facts = await require_active_certificate(
            team_cache, team_id=team_id, certificate_id=certificate_id
        )
    except HTTPException as exc:
        # The public verifier uses 401 for definitive unknown/revoked evidence;
        # an unreadable private listing is unavailable, including its 403.
        raise _refused(
            403 if exc.status_code == 401 else 503,
            "principal_not_member" if exc.status_code == 401 else "principal_status_unavailable",
        ) from None
    try:
        verify_team_certificate_signature(cert, facts.team_did_key)
    except TeamCertificateError:
        raise _refused(403, "principal_not_member") from None
    try:
        membership = await team_cache.check_current_member(
            team_id, certificate_id=certificate_id, team_did_key=facts.team_did_key
        )
    except HTTPException as exc:
        raise _refused(
            403 if exc.status_code == 403 else 503,
            "principal_not_member" if exc.status_code == 403 else "principal_status_unavailable",
        ) from None
    try:
        binding = await observe_identity_binding(registry, did_key=did_key, did_aw=principal)
    except IdentityObservationRefused as exc:
        if exc.code == "identity_binding_unavailable":
            raise _refused(503, "principal_status_unavailable") from None
        raise _refused(403, "principal_not_member") from None
    observation = await observe_identity_kind(registry, binding)
    if observation.result["outcome"] == "unavailable":
        raise _refused(503, "principal_status_unavailable")
    if not observation.is_human:
        raise _refused(403, "principal_not_human")
    if not membership.is_fresh_at(time.monotonic_ns()):
        raise _refused(503, "principal_status_unavailable")
    return HumanMemberProof(principal, did_key, membership)
