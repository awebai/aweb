"""HTTP adapter for the shared protected-team membership verifier.

Remote evidence is collected before effect locks. Retained projections compare
all consumed member fields; independent delegation/resource rights stay with
their existing verifier. Observations retain their original deadline.
"""

from awid.protected_effect import EffectRefused
from awid.protected_membership import (
    observe_team_protection,
    verify_registered_membership,
    verify_retained_membership,
)
from awid.team_certificate import TeamCertificateError, refusal_answer
from fastapi import HTTPException


def refuse(error):
    if isinstance(error, TeamCertificateError):
        status, detail = refusal_answer(error)
        return HTTPException(status_code=status, detail=detail)
    return HTTPException(status_code=503, detail={"code": error.code})


def require_fresh(observation):
    try:
        observation.require_fresh()
    except EffectRefused as exc:
        raise refuse(exc) from exc


async def observe(registry, team_id):
    try:
        return await observe_team_protection(registry, team_id)
    except EffectRefused as exc:
        raise refuse(exc) from exc


async def verify_presented(registry, observation, certificate):
    try:
        await verify_registered_membership(registry, observation, certificate)
    except (EffectRefused, TeamCertificateError) as exc:
        raise refuse(exc) from exc


async def verify_retained(registry, row, *, certificate_id=None, observation=None):
    if observation is None:
        observation = await observe(registry, row["team_id"])
    try:
        await verify_retained_membership(
            registry, observation,
            certificate_id=certificate_id if certificate_id is not None else row.get("certificate_id"),
            member_did_key=row.get("subject_did_key") or row.get("did_key"),
            alias=row.get("alias"), identity_scope=row.get("identity_scope"),
            member_did_aw=row.get("did_aw"), member_address=row.get("address"),
            certificate_sha256=row.get("certificate_sha256"),
        )
    except (EffectRefused, TeamCertificateError) as exc:
        raise refuse(exc) from exc
    return observation
