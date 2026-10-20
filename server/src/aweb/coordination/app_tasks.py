"""App task ingress and reconciliation under the installation lifecycle lock."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import HTTPException, Request

from awid.team_ids import parse_team_id
from aweb.app_credentials import APP_REQUEST, AppCredential, verify_app_credential
from aweb.service_errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from aweb.task_contracts import validate_app_task
from aweb.team_auth import parse_and_verify_certificate
from aweb.team_auth_deps import _get_revoked_certificates, _resolve_team_key
from .tasks_service import (
    _allocate_root_task_seq_on, _allocate_task_number_on, _answer_receipt,
    _encode_alpha_component, _get_team_slug, format_task_ref,
)

from aweb_naapp.runtime.task_requests import (
    AUTHORIZATION_PREFIX, TaskRequestRefused, task_body_sha256,
    verify_task_authorization as shared_verify_task_authorization,
)


def _json(value):
    return json.loads(value) if isinstance(value, str) else value


def _time(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scopes(installation):
    return set(_json(installation["granted_scopes"]))


async def app_request_transport_on(request: Request, tx) -> tuple[AppCredential, dict]:
    # F6 owns this reader and every lifecycle writer. The same tx holds the
    # installation lock from credential verification through create/read.
    from aweb.app_registry import get_installation_on

    team_id = (request.headers.get("X-AWEB-Team-ID") or "").strip()
    app_id = (request.headers.get("X-AWEB-App-ID") or "").strip().lower()
    installation = await get_installation_on(tx, team_id=team_id, app_id=app_id, for_update=True)
    credential = await verify_app_credential(request, tx, APP_REQUEST, installation=installation)
    return credential, installation


async def _current_certificates(request, team_id):
    registry = getattr(request.app.state, "awid_registry_client", None)
    try:
        domain, name = parse_team_id(team_id)
        if registry is None:
            raise RuntimeError("registry absent")
        return await registry.list_team_certificates(domain, name, active_only=True)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="authority_unavailable") from exc


def validate_task_authorization(payload, signature, *, expected, now):
    """Use the shared verifier; expose only C2's stable public error code."""
    try:
        shared_verify_task_authorization(payload, signature, expected=expected, now=now)
    except TaskRequestRefused as exc:
        status = 403 if exc.code == "target_mismatch" else 401
        raise HTTPException(status_code=status, detail=exc.code) from exc


async def verify_authorization_certificate(request, authorization):
    payload = authorization["payload"]
    try:
        team_key = await _resolve_team_key(request, payload["team_id"])
        revoked = await _get_revoked_certificates(request, payload["team_id"])
    except HTTPException as exc:
        raise HTTPException(status_code=503, detail="authority_unavailable") from exc
    if payload["certificate_id"] in revoked:
        raise HTTPException(status_code=401, detail="certificate_revoked")
    try:
        info = parse_and_verify_certificate(authorization["certificate"],
            request_did_key=payload["actor_did_key"],
            team_public_key_resolver=lambda _: team_key,
            revocation_checker=lambda team, cert: cert in revoked)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="signature_invalid") from exc
    if info["team_id"] != payload["team_id"] or info["certificate_id"] != payload["certificate_id"]:
        raise HTTPException(status_code=401, detail="signature_invalid")
    certificates = await _current_certificates(request, payload["team_id"])
    matches = [c for c in certificates if c.certificate_id == info["certificate_id"]
               and c.member_did_key == info["did_key"]
               and (c.member_did_aw or "") == info["member_did_aw"] and not c.revoked_at]
    if len(matches) != 1:
        raise HTTPException(status_code=401, detail="signature_invalid")
    return info, certificates


async def create_app_task_on(request: Request, tx, *, credential: AppCredential, installation: dict, body: dict):
    if not isinstance(body, dict) or set(body) != {"task", "task_authorization"}:
        raise ValidationError("schema_invalid")
    task = validate_app_task(body["task"])
    metadata = task["app_request"]
    authorization = body["task_authorization"]
    if (not isinstance(authorization, dict) or set(authorization) != {"payload", "signature", "certificate"}
            or not isinstance(authorization["certificate"], str)):
        raise HTTPException(status_code=401, detail="signature_invalid")
    payload = authorization["payload"]
    digest = task_body_sha256(task)
    from aweb.app_credentials import _allowed_audiences

    expected = {
        "aud": next(iter(_allowed_audiences(request))),
        "team_id": credential.team_id, "app_id": credential.app_id,
        "installation_id": credential.installation_id,
        "installation_generation": credential.installation_generation,
        "app_origin": installation["origin"], "task_body_sha256": digest,
        "target_did": task["assignee_did"], "external_request_id": metadata["external_request_id"],
        "action_id": metadata["action_ref"], "proposal_rev": metadata["proposal_rev"],
        "proposal_sha256": metadata["proposal_sha256"],
    }
    expired = None
    try:
        validate_task_authorization(payload, authorization["signature"], expected=expected, now=datetime.now(timezone.utc))
    except HTTPException as exc:
        if exc.detail != "authorization_expired":
            raise
        expired = exc
    # A time-only failure is eligible for replay only after CURRENT certificate
    # authority has also passed. Shared verification checks bindings before time.
    info, certificates = await verify_authorization_certificate(request, authorization)
    principal = info["member_did_aw"] or info["did_key"]
    existing = await tx.fetch_one(
        """SELECT r.task_body_sha256, r.receipt, t.cancellation
           FROM {{tables.task_app_requests}} r JOIN {{tables.tasks}} t ON t.task_id = r.task_id
           WHERE r.team_id = $1 AND r.app_id = $2 AND r.installation_id = $3
             AND r.originator_did = $4 AND r.external_request_id = $5""",
        credential.team_id, credential.app_id, credential.installation_id, principal, metadata["external_request_id"],
    )
    if existing:
        if not _scopes(installation) & {"requests.create", "requests.read"}:
            raise ForbiddenError("scope_denied")
        if existing["task_body_sha256"] != digest:
            raise ConflictError("idempotency_conflict")
        return {**_json(existing["receipt"]), "cancellation": _json(existing["cancellation"])}, False
    if expired is not None:
        raise expired
    if "requests.create" not in _scopes(installation):
        raise ForbiddenError("scope_denied")
    targets = [c for c in certificates if (c.member_did_aw or c.member_did_key) == task["assignee_did"] and not c.revoked_at]
    if len(targets) != 1:
        raise ValidationError("target_unresolved")
    target = targets[0]
    number = await _allocate_task_number_on(tx, team_id=credential.team_id)
    root = await _allocate_root_task_seq_on(tx, team_id=credential.team_id)
    suffix = _encode_alpha_component(root)
    row = await tx.fetch_one(
        """INSERT INTO {{tables.tasks}}
           (team_id, task_number, root_task_seq, task_ref_suffix, title, description,
            assignee_alias, assignee_did, created_by_alias, created_by_did, app_request)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) RETURNING task_id, created_at""",
        credential.team_id, number, root, suffix, task["title"], task["description"] or "",
        target.alias, task["assignee_did"], info["alias"], principal, json.dumps(metadata),
    )
    receipt = {
        "task_id": str(row["task_id"]), "task_ref": format_task_ref(_get_team_slug(credential.team_id), suffix),
        "task_rev": 1, "external_request_id": metadata["external_request_id"], "task_body_sha256": digest,
        "originator": {"principal_did": principal, "certificate_id": info["certificate_id"]},
        "transport_app": {"app_id": credential.app_id, "installation_id": credential.installation_id,
                          "installation_generation": credential.installation_generation, "kid": credential.kid},
        "created_at": _time(row["created_at"]), "cancellation": None,
    }
    await tx.execute(
        """INSERT INTO {{tables.task_app_requests}}
           (task_id, team_id, app_id, installation_id, installation_generation, originator_did,
            external_request_id, task_body_sha256, task_authorization, receipt)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)""",
        row["task_id"], credential.team_id, credential.app_id, credential.installation_id,
        credential.installation_generation, principal, metadata["external_request_id"], digest,
        json.dumps(body["task_authorization"]), json.dumps(receipt),
    )
    return receipt, True


async def read_app_request_on(tx, *, credential: AppCredential, installation: dict, external_request_id: str, originator: str,
                              required_scope: str = "requests.read"):
    if required_scope not in _scopes(installation):
        raise ForbiddenError("scope_denied")
    row = await tx.fetch_one(
        """SELECT t.*, r.receipt FROM {{tables.task_app_requests}} r
           JOIN {{tables.tasks}} t ON t.task_id = r.task_id
           WHERE r.team_id = $1 AND r.app_id = $2 AND r.installation_id = $3
             AND r.originator_did = $4 AND r.external_request_id = $5
             AND t.deleted_at IS NULL FOR SHARE OF t""",
        credential.team_id, credential.app_id, credential.installation_id, originator, external_request_id,
    )
    if not row:
        raise NotFoundError("resource_not_found")
    answer = await tx.fetch_one(
        "SELECT * FROM {{tables.task_answers}} WHERE task_id = $1 AND question_rev = $2",
        row["task_id"], row["question_rev"],
    )
    cancellation = _json(row["cancellation"])
    return {"receipt": {**_json(row["receipt"]), "cancellation": cancellation}, "task": {
        "status": row["status"], "rev": row["rev"], "question_rev": row["question_rev"],
        "assignee_did": row["assignee_did"], "picked_up": row["picked_up"], "cancellation": cancellation,
        "answer": _answer_receipt(answer, current_question_rev=row["question_rev"], cancelled=cancellation is not None) if answer else None,
    }}


async def cancel_app_task_on(tx, *, team_id, task_id, external_request_id, reason):
    row = await tx.fetch_one(
        "SELECT cancellation FROM {{tables.tasks}} WHERE task_id = $1 AND team_id = $2 FOR UPDATE", task_id, team_id,
    )
    if not row:
        raise NotFoundError("resource_not_found")
    if row["cancellation"] is not None:
        return _json(row["cancellation"])
    cancellation = {"reason": reason, "at": _time(datetime.now(timezone.utc))}
    await tx.execute(
        "INSERT INTO {{tables.task_comments}} (task_id, team_id, author_alias, body) VALUES ($1,$2,'app',$3)",
        task_id, team_id, f"Request cancelled · {external_request_id}",
    )
    await tx.execute(
        """UPDATE {{tables.tasks}} SET cancellation = $2::jsonb, status = 'closed',
           closed_at = COALESCE(closed_at, NOW()), updated_at = NOW() WHERE task_id = $1""",
        task_id, json.dumps(cancellation),
    )
    return cancellation


async def cancel_installation_requests_on(tx, *, team_id: str, app_id: str, installation_id: str):
    """F6 calls this while holding its installation row lock, before uninstall."""
    rows = await tx.fetch_all(
        """SELECT t.task_id, r.external_request_id FROM {{tables.task_app_requests}} r
           JOIN {{tables.tasks}} t ON t.task_id = r.task_id
           WHERE r.team_id = $1 AND r.app_id = $2 AND r.installation_id = $3
             AND t.status <> 'closed' AND t.deleted_at IS NULL
           ORDER BY t.task_id FOR UPDATE OF t""",
        team_id, app_id, installation_id,
    )
    for row in rows:
        await cancel_app_task_on(tx, team_id=team_id, task_id=row["task_id"],
            external_request_id=row["external_request_id"], reason="installation_retired")
    return len(rows)
