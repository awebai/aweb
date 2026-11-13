"""Current protected-team authority and in-transaction verifier fences.

Every mutation locks even an absent canonical binding. Initial activation and
all subsequent operator generation transitions use these same locks. Nothing
here discovers a service origin, accepts worker provisioning or signs a proof.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone

from fastapi import HTTPException

from awid.controller_request import raw_controller_request_target
from awid.dns_auth import parse_didkey_auth
from awid.protected_effect import (
    HEADER,
    EffectRefused,
    decode_proofs,
    http_consumer,
    validate_binding,
    verify_proof,
)
from awid.signing import canonical_json_bytes
from awid.team_ids import build_team_id

logger = logging.getLogger(__name__)
# These are existing catalog classes, never caller-selected classifications.
OPERATIONS = {
    "register_certificate": {
        ("team.agent.admit", "default"),
        ("team.agent.admit", "owner_approved"),
        ("team.agent.renew", "default"),
        ("team.human.admit", "default"),
    },
    "revoke_certificate": {
        ("team.agent.remove", "default"),
        ("team.human.remove", "default"),
    },
    "set_team_visibility": {("team.controller-permissions.change", "default")},
    "create_team": {("team.create", "default")},
    "delete_team": {("team.delete", "default")},
    "rotate_team_key": {("team.controller.rotate", "default")},
    "delete_namespace": {("namespace.delete", "default")},
    "publish_team_server": {("team.server-record.publish", "default")},
    "publish_team_custodian": {("team.controller-permissions.change", "default")},
    "publish_member_custody": {("team.controller-permissions.change", "default")},
    "publish_member_person": {("team.controller-permissions.change", "default")},
}


def refusal(code):
    return HTTPException(
        status_code=503 if code == "protected_state_unavailable" else 403,
        detail={"code": code, "message": code},
    )


def _lock_key(kind, value):
    return int.from_bytes(
        hashlib.sha256(
            ("aweb.team-protection/1\n" + kind + "\n" + value).encode()
        ).digest()[:8],
        "big",
        signed=True,
    )


async def namespace_guard(tx, domain, *, exclusive=False):
    function = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    await tx.execute(f"SELECT {function}($1::bigint)", _lock_key("namespace", domain))


async def team_guard(tx, domain, name):
    await namespace_guard(tx, domain)
    await tx.execute(
        "SELECT pg_advisory_xact_lock($1::bigint)",
        _lock_key("team", build_team_id(domain, name)),
    )


async def protection(tx, domain, name):
    """The upgraded registry explicitly projects absence of a row as legacy."""
    try:
        row = await tx.fetch_one(
            "SELECT mode, service_id, service_did_key, history_id, generation "
            "FROM {{tables.team_protection}} WHERE domain=$1 AND name=$2",
            domain,
            name,
        )
        if row is None or row["mode"] == "legacy":
            return {"mode": "legacy"}
        binding = dict(row)
        binding["history_id"] = str(binding["history_id"])
        return validate_binding(binding)
    except Exception:
        logger.exception("Authoritative protected-team binding unavailable")
        raise refusal("protected_state_unavailable") from None


async def _request_body(request):
    retained = getattr(request.state, "protected_effect_body", None)
    return retained if retained is not None else await request.body()


async def _artifact(request, operation):
    body = await _request_body(request)
    payload = json.loads(body) if body else {}
    if operation == "register_certificate":
        cert = json.loads(base64.b64decode(payload["certificate"], validate=True))
        return (
            "team-certificate",
            canonical_json_bytes({k: v for k, v in cert.items() if k != "signature"}),
            cert["signature"],
        )
    if operation == "publish_team_server":
        from awid.team_server_record import record_signing_bytes

        return (
            "team-server-record",
            record_signing_bytes(payload["record"]),
            payload["signature"],
        )
    if operation in {
        "publish_team_custodian",
        "publish_member_custody",
        "publish_member_person",
    }:
        from awid.attestation_records import signing_bytes

        return (
            payload["record"]["type"],
            signing_bytes(payload["record"]),
            payload["signature"],
        )
    encoded = request.headers.get("X-AWEB-Signed-Payload", "")
    _, signature = parse_didkey_auth(request.headers.get("Authorization"))
    return (
        "controller-request",
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)),
        signature,
    )


async def require_effect(request, tx, *, domain, name, operation):
    """Call inside the effect transaction, BEFORE any team/record row lock."""
    await team_guard(tx, domain, name)
    binding = await protection(tx, domain, name)
    if binding["mode"] == "legacy":
        return binding
    code = (
        "protected_admission_required"
        if operation == "register_certificate"
        else "protected_controller_required"
    )
    try:
        team = await tx.fetch_one(
            "SELECT team_did_key FROM {{tables.teams}} WHERE domain=$1 AND name=$2 "
            "ORDER BY (deleted_at IS NULL) DESC, created_at DESC, team_uuid DESC LIMIT 1 FOR SHARE",
            domain,
            name,
        )
        if team is None or team["team_did_key"] == binding["service_did_key"]:
            raise EffectRefused()
        artifact_type, signing, signature = await _artifact(request, operation)
        covering = request.headers.get("X-AWEB-Signed-Payload", "")
        envelope = (
            base64.urlsafe_b64decode(covering + "=" * (-len(covering) % 4))
            if covering
            else b""
        )
        origins = getattr(request.app.state, "awid_public_origins", ())
        # Independently signed artifacts have no covering HTTP audience. Their
        # detached proof may use any pinned registry origin, never an origin
        # supplied solely by the request or by an unverified proof.
        audiences = (json.loads(envelope)["aud"],) if envelope else origins
        body = await _request_body(request)
        proofs = decode_proofs(request.headers.get(HEADER))
        for audience in audiences:
            if audience not in origins:
                continue
            consumer = http_consumer(
                audience=audience,
                method=request.method,
                path=raw_controller_request_target(request),
                body=body,
                controller_envelope=envelope,
            )
            for proof in proofs:
                try:
                    verify_proof(
                        proof,
                        binding=binding,
                        team_id=build_team_id(domain, name),
                        controller_did_key=team["team_did_key"],
                        operations=OPERATIONS[operation],
                        artifact_type=artifact_type,
                        artifact=signing,
                        artifact_signature=signature,
                        consumer=consumer,
                        now=datetime.now(timezone.utc),
                    )
                    return binding
                except EffectRefused:
                    continue
    except (ValueError, TypeError, KeyError, IndexError):
        pass
    logger.warning(
        "Protected controller effect refused: operation=%s code=%s", operation, code
    )
    raise refusal(code)


async def require_namespace_effect(request, tx, *, domain, operation):
    await namespace_guard(tx, domain, exclusive=True)
    teams = await tx.fetch_all(
        "SELECT name FROM {{tables.team_protection}} WHERE domain=$1 AND mode='protected' ORDER BY name",
        domain,
    )
    for row in teams:
        await require_effect(
            request, tx, domain=domain, name=row["name"], operation=operation
        )


async def provision_team_protection(
    tx,
    *,
    domain,
    name,
    service_id,
    service_did_key,
    expected_generation,
    approval_ref,
    mode="protected",
):
    """Recorded registry-host administrator action; intentionally no HTTP route.

    The operator's .8 procedure must prove custody, consumer drain/invalidation,
    exact historical baseline and approval before invoking this function. A
    worker signature/profile is never this provisioning authority.
    """
    from uuid import uuid4
    from awid.did import public_key_from_did

    if (
        type(expected_generation) is not int
        or expected_generation < 0
        or not isinstance(approval_ref, str)
        or not approval_ref.strip()
        or len(approval_ref) > 1024
        or mode not in {"legacy", "protected"}
    ):
        raise ValueError("protection_transition_invalid")
    public_key_from_did(service_did_key)
    await team_guard(tx, domain, name)
    row = await tx.fetch_one(
        "SELECT * FROM {{tables.team_protection}} WHERE domain=$1 AND name=$2 FOR UPDATE",
        domain,
        name,
    )
    generation = row["generation"] if row is not None else 0
    if generation != expected_generation:
        raise ValueError("protection_generation_changed")
    if generation >= 9007199254740991:
        raise ValueError("protection_generation_exhausted")
    if row is None:
        exists = await tx.fetch_value(
            "SELECT 1 FROM {{tables.teams}} WHERE domain=$1 AND name=$2 AND deleted_at IS NULL",
            domain,
            name,
        )
        if not exists or mode != "protected":
            raise ValueError("protection_team_required")
    reused = await tx.fetch_value(
        "SELECT EXISTS(SELECT 1 FROM {{tables.teams}} WHERE team_did_key=$1) "
        "OR EXISTS(SELECT 1 FROM {{tables.dns_namespaces}} WHERE controller_did=$1) "
        "OR EXISTS(SELECT 1 FROM {{tables.team_certificates}} WHERE member_did_key=$1) "
        "OR EXISTS(SELECT 1 FROM {{tables.did_aw_mappings}} WHERE current_did_key=$1)",
        service_did_key,
    )
    if reused:
        raise ValueError("service_key_not_distinct")
    history = str(row["history_id"]) if row is not None else str(uuid4())
    binding = {
        "mode": "protected",
        "service_id": service_id,
        "service_did_key": service_did_key,
        "history_id": history,
        "generation": generation + 1,
    }
    validate_binding(binding)
    await tx.execute(
        "INSERT INTO {{tables.team_protection}} (domain,name,mode,service_id,service_did_key,history_id,generation,approval_ref) "
        "VALUES($1,$2,$3,$4,$5,$6::uuid,$7,$8) ON CONFLICT(domain,name) DO UPDATE SET "
        "mode=EXCLUDED.mode,service_id=EXCLUDED.service_id,service_did_key=EXCLUDED.service_did_key,"
        "generation=EXCLUDED.generation,approval_ref=EXCLUDED.approval_ref",
        domain,
        name,
        mode,
        service_id,
        service_did_key,
        history,
        generation + 1,
        approval_ref,
    )
    return binding if mode == "protected" else {"mode": "legacy"}


async def advance_incarnation(tx, *, domain, name, operation):
    """After the guarded controller effect, invalidate older retained proofs.

    Caller holds canonical namespace/team guards for this entire transaction.
    History remains fixed through retirement/recreation; generation never resets.
    """
    await tx.execute(
        "UPDATE {{tables.team_protection}} SET generation=generation+1,approval_ref=$3 "
        "WHERE domain=$1 AND name=$2",
        domain,
        name,
        "controller-effect:" + operation,
    )
