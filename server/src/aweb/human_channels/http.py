"""Native HTTP stable-ID ingress adapter; no cross-database atomicity claim."""

from __future__ import annotations

import json
from uuid import UUID

from awid.signing import canonical_json_bytes
from fastapi import HTTPException

from aweb.identity_auth_deps import auth_dids

from .contract import ContractError
from .native import _dto, _hash, _principal

_HEADERS = (
    "X-AWEB-Ingress-Namespace",
    "X-AWEB-Ingress-Key",
    "X-AWEB-Ingress-Input-Hash",
)


def ingress_requested(request):
    supplied = [bool(request.headers.get(name)) for name in _HEADERS]
    if any(supplied) and not all(supplied):
        raise HTTPException(422, detail={"code": "invalid", "effects": "none"})
    return all(supplied)


async def accept_native_http(request, payload, *, auth, db, kind, session_id=None):
    """Called before native route effects when all three ingress headers exist.

    Current local alias/participant discovery and crypto run before UoW locks.
    Recovery compares exact protected ID/kind/envelope before returning the
    original result, without making an old route live again.
    """
    from aweb.routes.messaging import _refusal, _service

    try:
        service = _service(request)
        key = _dto(
            "IngressKey",
            {
                "issuer": _principal(auth),
                "namespace": request.headers[_HEADERS[0]],
                "key": request.headers[_HEADERS[1]],
                "input_hash": request.headers[_HEADERS[2]],
            },
        )
        mid = payload.message_id
        cid = (
            session_id
            or getattr(payload, "conversation_id", None)
            or getattr(payload, "session_id", None)
        )
        if not mid or not cid:
            raise ContractError("invalid", "stable message/conversation IDs required")
        if getattr(payload, "attachments", None):
            raise ContractError(
                "unsupported", "native ingress uses immutable attachment refs"
            )
        if getattr(payload, "from_did", None) and payload.from_did != auth.did_key:
            raise ContractError("invalid", "authenticated signer binding")
        encrypted = getattr(payload, "content_mode", None) == "encrypted_v2"
        if encrypted:
            if (
                getattr(payload, "priority", "normal") != "normal"
                or getattr(payload, "wait_seconds", None) is not None
                or getattr(payload, "leaving", False)
                or getattr(payload, "hang_on", False)
            ):
                raise ContractError("unsupported", "encrypted ingress control metadata")
            if getattr(
                payload, "timestamp", None
            ) is not None and payload.timestamp != payload.encrypted_envelope.get(
                "created_at"
            ):
                raise ContractError("invalid", "encrypted timestamp binding")
            if getattr(
                payload, "reply_to", None
            ) is not None and payload.reply_to != payload.encrypted_envelope.get(
                "reply_to_message_id"
            ):
                raise ContractError("invalid", "encrypted reply binding")
            if (
                getattr(payload, "body", "")
                or getattr(payload, "message", "")
                or getattr(payload, "signature", None)
                or getattr(payload, "signed_payload", None)
            ):
                raise ContractError("invalid", "encrypted native payload")
            envelope = canonical_json_bytes(payload.encrypted_envelope).decode()
            fmt = "native_encrypted_v2"
        else:
            if not payload.signature or not payload.signed_payload:
                raise ContractError("invalid", "signed native envelope required")
            signed = _dto("NativePlaintext", json.loads(payload.signed_payload)).value
            if (
                signed["body"]
                != getattr(payload, "body", getattr(payload, "message", ""))
                or (kind == "mail" and signed["subject"] != payload.subject)
                or signed.get("conversation_id") != cid
                or signed.get("message_id") != mid
                or signed["type"] != kind
                or (
                    getattr(payload, "timestamp", None) is not None
                    and payload.timestamp != signed["timestamp"]
                )
                or (
                    kind == "mail"
                    and payload.priority != signed.get("priority", "normal")
                )
                or (
                    kind == "chat"
                    and any(
                        getattr(payload, outer, default) != signed.get(inner, default)
                        for outer, inner, default in (
                            ("wait_seconds", "wait_seconds", None),
                            ("reply_to", "reply_to", None),
                            ("leaving", "sender_leaving", False),
                            ("hang_on", "hang_on", False),
                        )
                    )
                )
                or (
                    getattr(payload, "from_did", None)
                    and payload.from_did != auth.did_key
                )
            ):
                raise ContractError("invalid", "outer/signed payload binding")
            envelope = canonical_json_bytes(
                {
                    "signature": payload.signature,
                    "signed_payload": payload.signed_payload,
                }
            ).decode()
            fmt = "native_plaintext"
        digest = _hash(envelope.encode())
        try:
            previous = await service.ingress_result(auth, key)
        except ContractError as error:
            if error.code != "not_found":
                raise
        else:
            _exact(previous, mid, cid, kind, digest)
            return previous.value["accepted"]
        recipient = await _target(request, payload, auth, db, kind, session_id)
        target = await service._facts(
            auth, recipient
        )  # OSS-owned route adapter, not an embedding/private-SQL hook.
        prepared = await service.prepare(
            auth,
            _dto(
                "PrepareRequest",
                dict(
                    version="aweb-human-prepare-v1",
                    kind=kind,
                    message_id=mid,
                    author={"kind": "native", "did": _principal(auth)},
                    envelope=envelope,
                    format=fmt,
                    target=target.value,
                    conversation_id=cid,
                    **(
                        {"attachment_refs": payload.attachment_refs}
                        if getattr(payload, "attachment_refs", None)
                        else {}
                    ),
                ),
            ),
        )
        async with service.unit_of_work(auth) as uow:
            previous = await uow.claim_ingress(key)
            if previous is not None:
                _exact(previous, mid, cid, kind, digest)
                return previous.value["accepted"]
            accepted = await uow.accept(prepared)
            await uow.finish_ingress(
                _dto(
                    "IngressResult",
                    {
                        "version": "aweb-ingress-result-v1",
                        "key": key.value,
                        "accepted": accepted.value,
                        "result": {},
                    },
                )
            )
        return accepted.value
    except ContractError as error:
        raise _refusal(error, "accept") from error


def _exact(result, message_id, conversation_id, kind, envelope_hash):
    accepted = result.value["accepted"]
    if any(
        accepted[name] != value
        for name, value in (
            ("message_id", message_id),
            ("conversation_id", conversation_id),
            ("kind", kind),
            ("envelope_hash", envelope_hash),
        )
    ):
        raise ContractError("replay_conflict", "exact original native send")


async def _target(request, payload, auth, db, kind, session_id):
    from aweb.messaging.messages import get_agent_by_id, resolve_agent_by_did
    from aweb.messaging.address_auth import identity_recipient
    from aweb.routes.messages import _resolve_message_alias

    aliases = (
        [getattr(payload, "to_alias", None)]
        if kind == "mail"
        else getattr(payload, "to_aliases", [])
    )
    dids = (
        [getattr(payload, "to_did", None) or getattr(payload, "to_stable_id", None)]
        if kind == "mail"
        else getattr(payload, "to_dids", [])
    )
    aliases = [x for x in aliases if x]
    dids = [x for x in dids if x]
    # P2's frozen target is a native pair, not a managed/group session.
    if len(aliases) + len(dids) > 1:
        raise ContractError("unsupported", "native pair ingress")
    recipient = None
    if aliases:
        recipient = await _resolve_message_alias(db, auth, aliases[0], request=request)
    elif dids:
        recipient = await resolve_agent_by_did(db, dids[0])
    elif kind == "mail" and getattr(payload, "to_agent_id", None):
        recipient = await get_agent_by_id(
            db, team_id=auth.team_id, agent_id=payload.to_agent_id
        )
    elif kind == "mail" and not any(
        getattr(payload, k, None)
        for k in ("to_address", "to_alias", "to_did", "to_stable_id", "to_agent_id")
    ):
        from aweb.messaging.mail_routing import mail_continuation_context

        route = await mail_continuation_context(
            db,
            conversation_id=payload.conversation_id,
            sender_did=_principal(auth),
            equivalent_dids=auth_dids(auth),
        )
        participant = route.recipient_participant
        recipient = await resolve_agent_by_did(db, participant["did"])
        if recipient is not None:
            recipient = identity_recipient(recipient, str(participant.get("address") or ""))
            recipient["alias"] = participant.get("alias") or participant["did"]
    elif kind == "chat" and session_id:
        rows = await db.get_manager("aweb").fetch_all(
            """SELECT p.did, p.alias, p.address FROM {{tables.chat_participants}} p
               WHERE p.session_id=$1 AND p.left_at IS NULL AND NOT (p.did=ANY($2::text[]))
                 AND EXISTS (SELECT 1 FROM {{tables.chat_participants}} a
                   WHERE a.session_id=p.session_id AND a.left_at IS NULL AND a.did=ANY($2::text[]))""",
            UUID(session_id),
            auth_dids(auth),
        )
        if len(rows) == 1:
            participant = rows[0]
            recipient = await resolve_agent_by_did(db, participant["did"])
            if recipient is not None:
                recipient = identity_recipient(recipient, str(participant.get("address") or ""))
                recipient["alias"] = participant.get("alias") or participant["did"]
    if recipient is None:
        raise ContractError(
            "unsupported" if getattr(payload, "to_address", None) else "not_found",
            "same-service recipient",
        )
    return identity_recipient(recipient)
