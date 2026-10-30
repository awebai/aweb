"""P2 native prepared sends with supported PostgreSQL embedding/idempotency.

Authority is supplied by the host through the public authority port. No signing
custody is inferred from a roster, controller, token, domain or encryption key.
Managed membership/export/federation remain separately negotiated capabilities.
"""

from __future__ import annotations

import hashlib
import json
import logging
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

from awid.signing import canonical_json_bytes
from fastapi import HTTPException

from aweb.attachment_service import prepare_attachment_send
from aweb.identity_auth_deps import auth_dids
from aweb.identity_binding import verified_projection
from aweb.inbound_modes import effective_inbound_mode
from aweb.messaging.chat import ensure_session, send_in_session
from aweb.messaging.conversations import create_conversation, get_conversation
from aweb.messaging.messages import authorize_message_delivery, deliver_message

from .authority import NativeMessagingAuthority, NativeMessagingSubject
from .contract import ContractError, ContractRecord, canonical_record, decode_record

logger = logging.getLogger(__name__)


def _grant(auth, kind):
    if auth.grant is not None:
        if kind + ".send" not in auth.grant.scopes:
            raise ContractError("forbidden", "grant send scope")
        if not auth.grant.never_expires and auth.grant.expires_at <= datetime.now(UTC):
            raise ContractError("stale", "expired grant")


def _dto(schema, value):
    return decode_record(schema, canonical_json_bytes(value))


def _snapshot(record, schema):
    if not isinstance(record, ContractRecord) or record.schema != schema:
        raise ContractError("invalid", schema)
    return decode_record(schema, canonical_record(record))


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _principal(auth):
    return auth.did_aw or auth.did_key


def _auth_binding(auth):
    # Grants remain bound even when their root principal is the same.
    return (
        auth.did_key,
        auth.did_aw,
        auth.team_id,
        auth.agent_id,
        auth.verified_team_id,
        auth.alias,
        auth.address,
        auth.certificate_id,
        getattr(auth.grant, "grant_id", None) if auth.grant else None,
    )


class _TransactionInfra:
    def __init__(self, original, manager):
        self.original, self.manager = original, manager

    def get_manager(self, name="aweb"):
        return self.manager if name == "aweb" else self.original.get_manager(name)


@dataclass(frozen=True)
class _Preparation:
    caller: tuple
    prepared_bytes: bytes
    author: dict
    recipient: dict
    payload: object
    request_bytes: bytes


class NativeMessagingService:
    """Public embedding entry point. Provider context must be immutable/scoped.

    A stateless provider may serve concurrent requests. Operation-specific host
    context must belong to one service instance, or be keyed by exact caller +
    preparation/ingress identity. Never mutate a global "current route" slot.
    `service` is the host's independently configured ServiceBinding, not a route
    discovered from a submitted envelope. `publisher` acknowledges durable
    intents by UUID; sinks must deduplicate UUID/message ID for usage/wakes.
    """

    def __init__(
        self,
        db,
        *,
        authority: NativeMessagingAuthority,
        service: ContractRecord,
        publisher=None,
        attachment_backend=None,
        max_preparations=1024,
    ):
        self.db = db
        self.authority = authority
        self.service = _snapshot(service, "ServiceBinding")
        self.publisher = publisher
        self.attachment_backend = attachment_backend
        self.max_preparations = max_preparations
        self._preparations = {}

    async def capabilities(self, auth):
        implemented = ["human-alias-v1", "human-send-uow-v1"]
        return _dto(
            "Capabilities",
            {
                "version": "aweb-human-channels-capabilities-v1",
                "implemented": implemented,
                "enabled": implemented,
                "refused": [],
            },
        )

    async def _row(self, *, principal=None, actor_id=None, team_id=None):
        rows = await self.db.get_manager("aweb").fetch_all(
            """SELECT agent_id, team_id, alias, did_key, did_aw, address,
                      did_aw_verified_key, identity_scope,
                      (NULLIF(did_aw,'') IS NOT NULL) AS has_global_claim,
                      did_aw AS policy_did_aw,
                      status, deleted_at, certificate_id, agent_type, inbound_mode
               FROM {{tables.agents}}
               WHERE deleted_at IS NULL
                 AND ($1::uuid IS NULL OR agent_id=$1)
                 AND ($2::text IS NULL OR (did_aw=$2 AND did_aw_verified_key=did_key) OR did_key=$2)
                 AND ($3::text IS NULL OR team_id=$3)""",
            UUID(actor_id) if actor_id else None,
            principal,
            team_id,
        )
        if len(rows) != 1:
            raise ContractError(
                "not_found" if not rows else "forbidden", "exact local actor"
            )
        row = verified_projection(rows[0])
        if row["status"] != "active":
            raise ContractError("forbidden", "inactive actor")
        return row

    async def _authority_call(self, method, *args):
        try:
            return await method(*args)
        except ContractError:
            raise
        except Exception as error:
            logger.exception(
                "Native messaging authority unavailable: %s",
                getattr(method, "__name__", "provider"),
            )
            raise ContractError(
                "authority_unavailable", "current messaging authority"
            ) from error

    async def _authority_check(self, method, *args):
        if await self._authority_call(method, *args) is not None:
            raise ContractError("authority_unavailable", "authority hook result")

    async def _facts(self, auth, row):
        subject = NativeMessagingSubject(
            row["did_aw"] or row["did_key"],
            row["did_key"],
            str(row["agent_id"]),
            row["team_id"],
        )
        facts = _snapshot(
            await self._authority_call(self.authority.current, deepcopy(auth), subject),
            "AuthorityFacts",
        )
        value = facts.value
        if (
            value["principal"] != {"kind": "native", "did": subject.principal}
            or value["signing_key_id"] != subject.signing_key_id
            or value.get("actor_id") != subject.actor_id
            or value.get("team_id") != subject.team_id
            or value["route"] != self.service.value
        ):
            raise ContractError(
                "authority_unavailable", "exact current actor authority"
            )
        if (
            not value["active"]
            or value["access"] != "allowed"
            or value["inbound"] != "allowed"
        ):
            raise ContractError("forbidden", "current access/inbound policy")
        return facts

    async def resolve(self, auth, request):
        request = _snapshot(request, "ResolveRequest")
        value = request.value
        if "session_id" in value:
            raise ContractError(
                "unsupported", "typed session resolution requires P4/P5"
            )
        if not auth.team_id or value["team_id"] != auth.team_id:
            raise ContractError("forbidden", "selected team")
        rows = await self.db.get_manager("aweb").fetch_all(
            "SELECT agent_id FROM {{tables.agents}} WHERE team_id=$1 AND alias=$2 AND deleted_at IS NULL",
            auth.team_id,
            value["selector"],
        )
        if len(rows) != 1:
            raise ContractError(
                "not_found" if not rows else "forbidden", "selected-team actor"
            )
        row = await self._row(actor_id=str(rows[0]["agent_id"]), team_id=auth.team_id)
        return await self._facts(auth, row)

    async def prepare(self, auth, request):
        request = _snapshot(request, "PrepareRequest")
        auth = deepcopy(auth)
        value = request.value
        _grant(auth, value["kind"])
        if value["format"] == "managed_chat_plaintext" or "group_context" in value:
            raise ContractError("unsupported", "managed session requires P4/P5")
        if value["author"] != {"kind": "native", "did": _principal(auth)}:
            raise ContractError("forbidden", "authenticated author")
        author = await self._row(
            principal=_principal(auth), actor_id=auth.agent_id, team_id=auth.team_id
        )
        if author["did_key"] != auth.did_key:
            raise ContractError("stale", "current author key")
        author_facts = await self._facts(auth, author)
        requested_target = _dto("AuthorityFacts", value["target"])
        target_ref = requested_target.value["principal"]
        if target_ref["kind"] != "native":
            raise ContractError("unsupported", "native recipient")
        recipient = await self._row(
            principal=target_ref["did"], actor_id=requested_target.value.get("actor_id")
        )
        if (
            recipient.get("agent_type") == "human"
            and recipient["team_id"] != auth.team_id
        ):
            raise ContractError("forbidden", "human selected team")
        facts = await self._facts(auth, recipient)
        if canonical_record(facts) != canonical_record(requested_target):
            raise ContractError("stale", "recipient authority")
        await self._policy(self.db, auth, recipient)
        payload = self._validate_envelope(auth, value, recipient)
        now = datetime.now(UTC)
        for pid, retained in list(self._preparations.items()):
            if json.loads(retained.prepared_bytes)["expires_at"] <= now.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ):
                del self._preparations[pid]
        if len(self._preparations) >= self.max_preparations:
            raise ContractError("limit_exceeded", "preparations")
        confidentiality = "server_readable"
        if value["format"] == "native_encrypted_v2":
            from awid.e2ee_keys import validate_encryption_key_assertion

            assertion = facts.value.get("key_assertion")
            if not assertion:
                raise ContractError(
                    "authority_unavailable", "recipient encryption assertion"
                )
            try:
                validate_encryption_key_assertion(
                    assertion,
                    current_did_key=recipient["did_key"],
                    stable_id=recipient.get("did_aw") or None,
                    now=now,
                )
            except ValueError as error:
                raise ContractError(
                    "invalid", "recipient encryption assertion"
                ) from error
            wraps = payload.encrypted_envelope.get("key_wraps", [])
            if not any(
                w.get("recipient_did") == recipient["did_key"]
                and w.get("wrap_purpose") == "delivery"
                and w.get("recipient_encryption_key_id")
                == assertion["encryption_key_id"]
                for w in wraps
            ):
                raise ContractError("stale", "recipient encryption key binding")
            sender_assertion = (
                payload.encrypted_envelope.get("sender_encryption_key") or {}
            )
            # Signing custody and decryption custody are independent. Never
            # promote an explicit hosted/bridge-readable authority fact to E2EE.
            confidentiality = (
                "end_to_end"
                if (
                    all(
                        f.value["custody"] == "self_custodial"
                        and f.value["confidentiality"] == "end_to_end"
                        for f in (author_facts, facts)
                    )
                    and all(
                        a.get("custody") == "self"
                        for a in (assertion, sender_assertion)
                    )
                )
                else "hosted_readable"
            )
            if any(
                f.value["confidentiality"] == "bridge_readable"
                for f in (author_facts, facts)
            ):
                confidentiality = "bridge_readable"
            elif any(
                f.value["confidentiality"] == "server_readable"
                for f in (author_facts, facts)
            ):
                confidentiality = "server_readable"
        projection = {
            "author": value["author"],
            "author_assurance": "native",
            "verified": True,
            "signer_verified": True,
            "trust_status": "verified_custodial"
            if author_facts.value["custody"] != "self_custodial"
            else "verified",
            "confidentiality": confidentiality,
        }
        if value["format"] == "native_plaintext":
            via = json.loads(payload.signed_payload).get("via")
            if via is not None:
                projection["via"] = via
        prepared = _dto(
            "PreparedSend",
            dict(
                version="aweb-prepared-send-v1",
                prepared_id=str(uuid4()),
                message_id=value["message_id"],
                kind=value["kind"],
                envelope=value["envelope"],
                envelope_hash=_hash(value["envelope"].encode()),
                author=projection,
                authority_revision=author_facts.value["authorization_revision"],
                recipients=[facts.value],
                expires_at=(now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                conversation_id=payload.conversation_id,
                **(
                    {"attachment_refs": value["attachment_refs"]}
                    if value.get("attachment_refs")
                    else {}
                ),
            ),
        )
        self._preparations[prepared.value["prepared_id"]] = _Preparation(
            _auth_binding(auth),
            canonical_record(prepared),
            author,
            recipient,
            payload,
            canonical_record(request),
        )
        return prepared

    async def _policy(self, db, auth, recipient):
        from aweb.service_errors import ServiceError

        try:
            await authorize_message_delivery(
                db,
                recipient_agent=recipient,
                sender_did=_principal(auth),
                sender_address=auth.address,
                sender_team_id=auth.team_id,
                sender_verified_team_id=auth.verified_team_id,
                sender_verified_dids=auth_dids(auth),
            )
        except ServiceError as error:
            raise ContractError("forbidden", error.detail) from error

    def _validate_envelope(self, auth, value, recipient):
        # Reuse native validators: this facade neither re-signs nor rewrites the
        # signed content, signature, IDs, native v2 header or ciphertext.
        from aweb.routes.chat import (
            CreateSessionRequest,
            _validate_encrypted_chat_payload,
            _validate_signed_chat_payload,
        )
        from aweb.routes.messages import (
            SendMessageRequest,
            _validate_encrypted_payload,
            _validate_signed_mail_payload,
        )

        try:
            if value["format"] == "native_plaintext":
                artifact = decode_record(
                    "SignedArtifact", value["envelope"].encode()
                ).value
                signed = decode_record(
                    "NativePlaintext", artifact["signed_payload"].encode()
                ).value
                if (
                    signed.get("message_id") != value["message_id"]
                    or signed["type"] != value["kind"]
                ):
                    raise ContractError("invalid", "signed message binding")
                cid = signed.get("conversation_id")
                if not cid or cid != value.get("conversation_id"):
                    raise ContractError("invalid", "signed conversation binding")
                common = {
                    "signature": artifact["signature"],
                    "signed_payload": artifact["signed_payload"],
                    "from_alias": auth.alias,
                    "from_address": auth.address,
                    "from_stable_id": auth.did_aw,
                    "body": signed["body"],
                    "from_did": auth.did_key,
                    "message_id": value["message_id"],
                    "timestamp": signed["timestamp"],
                    "conversation_id": cid,
                }
                if value["kind"] == "mail":
                    _validate_signed_mail_payload(
                        **common,
                        recipient=recipient,
                        to_agent_id=str(recipient["agent_id"]),
                        to_alias=recipient["alias"],
                        requested_to_alias=recipient["alias"],
                        priority=signed.get("priority", "normal"),
                        subject=signed["subject"],
                    )
                else:
                    _validate_signed_chat_payload(
                        **common,
                        recipient_rows=[recipient],
                        requested_to_aliases=[recipient["alias"]],
                        wait_seconds=signed.get("wait_seconds"),
                        reply_to=signed.get("reply_to"),
                        sender_leaving=signed.get("sender_leaving", False),
                        hang_on=signed.get("hang_on", False),
                    )
                payload = SimpleNamespace(
                    conversation_id=cid,
                    body=signed["body"],
                    subject=signed.get("subject", ""),
                    priority=signed.get("priority", "normal"),
                    signature=artifact["signature"],
                    signed_payload=artifact["signed_payload"],
                    content_mode="legacy_plaintext_v1",
                    message_version=1,
                    encrypted_envelope=None,
                    encrypted_metadata=None,
                    wait_seconds=signed.get("wait_seconds"),
                    reply_to=signed.get("reply_to"),
                    leaving=signed.get("sender_leaving", False),
                    hang_on=signed.get("hang_on", False),
                )
            else:
                # Duplicate keys and unsafe/non-JSON values must not yield two
                # interpretations of the same preserved envelope.
                from .contract import require_canonical_signed_payload

                raw = value["envelope"].encode()
                require_canonical_signed_payload(raw)
                envelope = json.loads(raw)
                cid = value.get("conversation_id")
                if not cid:
                    raise ContractError("invalid", "conversation required")
                fields = {
                    "message_id": value["message_id"],
                    "timestamp": envelope.get("created_at"),
                    "content_mode": "encrypted_v2",
                    "message_version": 2,
                    "encrypted_envelope": envelope,
                }
                if value["kind"] == "mail":
                    model = SendMessageRequest(
                        **fields, to_alias=recipient["alias"], conversation_id=cid
                    )
                    metadata = _validate_encrypted_payload(
                        model,
                        auth=auth,
                        sender_did=_principal(auth),
                        recipient=recipient,
                        recipient_did=recipient["did_aw"] or recipient["did_key"],
                    )
                else:
                    model = CreateSessionRequest(
                        **fields,
                        to_aliases=[recipient["alias"]],
                        session_id=cid,
                        message="",
                    )
                    metadata = _validate_encrypted_chat_payload(
                        model,
                        auth=auth,
                        actor_did=_principal(auth),
                        session_id=cid,
                        recipient_rows=[recipient],
                    )
                payload = SimpleNamespace(
                    conversation_id=cid,
                    body="",
                    subject="",
                    priority="normal",
                    signature=None,
                    signed_payload=None,
                    content_mode="encrypted_v2",
                    message_version=2,
                    encrypted_envelope=envelope,
                    encrypted_metadata=metadata,
                    wait_seconds=None,
                    reply_to=envelope.get("reply_to_message_id"),
                    leaving=False,
                    hang_on=False,
                )
            payload.attachment_refs = value.get("attachment_refs") or []
            payload.attachments = None
            payload.model_dump = lambda: {
                "message_id": value["message_id"],
                "conversation_id": cid,
                "session_id": cid if value["kind"] == "chat" else None,
                "content_mode": payload.content_mode,
                "message_version": payload.message_version,
                "encrypted_envelope": payload.encrypted_envelope,
                "attachment_refs": payload.attachment_refs,
                "from_did": auth.did_key,
            }
            if payload.attachment_refs and (
                payload.content_mode != "encrypted_v2"
                or self.attachment_backend is None
            ):
                raise ContractError("unsupported", "attachment provider")
            if payload.attachment_refs:
                from aweb.attachments import AttachmentError, refs

                try:
                    refs(payload.attachment_refs)
                except AttachmentError as error:
                    raise ContractError("invalid", "attachment references") from error
            return payload
        except HTTPException as error:
            raise ContractError("invalid", str(error.detail)) from error
        except (ValueError, TypeError, KeyError) as error:
            if isinstance(error, ContractError):
                raise
            raise ContractError("invalid", "native envelope") from error

    @asynccontextmanager
    async def unit_of_work(self, auth):
        async with self.db.get_manager("aweb").transaction() as tx:
            uow = NativeMessagingUnitOfWork(self, deepcopy(auth), tx)
            try:
                yield uow
                if uow.claim is not None and not uow.finished:
                    raise ContractError("invalid", "unfinished ingress")
            finally:
                uow.open = False
        # Publish only after a successful commit. A crash here leaves durable
        # pending intents for publish_pending(), not an ambiguous second send.
        if self.publisher is not None:
            try:
                await self.publish_pending()
            except Exception:
                # Acceptance already committed. Keep its successful durable
                # result and pending intent; never report a no-effects refusal.
                logger.exception(
                    "Native messaging publication pending after committed acceptance"
                )

    async def ingress_result(self, auth, key):
        async with self.unit_of_work(auth) as uow:
            result = await uow.claim_ingress(key)
            if result is None:
                # No new claim is committed by a read.
                raise ContractError("not_found", "ingress result")
            return result

    async def publish_pending(self, *, limit=100):
        if self.publisher is None:
            raise ContractError("authority_unavailable", "durable publisher")
        if not 1 <= limit <= 200:
            raise ContractError("invalid", "publication limit")
        rows = await self.db.get_manager("aweb").fetch_all(
            "SELECT mutation_id, event_type, context FROM {{tables.human_channel_mutations}} WHERE published_at IS NULL ORDER BY created_at,mutation_id LIMIT $1",
            limit,
        )
        for row in rows:
            # The sink acknowledges stable intent IDs. At-least-once event
            # delivery is deliberate; exactly-once model/tool work is not promised.
            context = (
                json.loads(row["context"])
                if isinstance(row["context"], str)
                else row["context"]
            )
            await self.publisher(str(row["mutation_id"]), row["event_type"], context)
            await self.db.get_manager("aweb").execute(
                "UPDATE {{tables.human_channel_mutations}} SET published_at=NOW() WHERE mutation_id=$1",
                row["mutation_id"],
            )


class NativeMessagingUnitOfWork:
    def __init__(self, service, auth, manager):
        self.service, self.auth, self.manager = service, auth, manager
        self.open, self.finished, self.claim, self.accepted = True, False, None, None

    def _guard(self):
        if not self.open:
            raise ContractError("invalid", "closed unit of work")

    @property
    def transaction(self):
        self._guard()
        return self.manager.connection

    async def claim_ingress(self, key):
        self._guard()
        if self.claim is not None:
            raise ContractError("invalid", "one ingress claim")
        key = _snapshot(key, "IngressKey")
        if key.value["issuer"] != _principal(self.auth):
            raise ContractError("forbidden", "authenticated ingress issuer")
        # Never return an original/caller result before current authorization.
        await self.service._authority_check(
            self.service.authority.authorize_recovery,
            deepcopy(self.auth),
            _snapshot(key, "IngressKey"),
            self.transaction,
        )
        await self.manager.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            canonical_json_bytes(
                {k: key.value[k] for k in ("issuer", "namespace", "key")}
            ).decode(),
        )
        row = await self.manager.fetch_one(
            "SELECT input_hash,result FROM {{tables.human_channel_ingress}} WHERE issuer=$1 AND namespace=$2 AND ingress_key=$3",
            key.value["issuer"],
            key.value["namespace"],
            key.value["key"],
        )
        if row:
            if row["input_hash"] != key.value["input_hash"]:
                raise ContractError("replay_conflict", "ingress input")
            result = _dto(
                "IngressResult",
                json.loads(row["result"])
                if isinstance(row["result"], str)
                else row["result"],
            )
            _grant(self.auth, result.value["accepted"]["kind"])
            self.finished = True
            self.claim = key
            return result
        self.claim = key
        return None

    async def accept(self, prepared):
        self._guard()
        if self.claim is None or self.finished or self.accepted is not None:
            raise ContractError("invalid", "new ingress claim required")
        prepared = _snapshot(prepared, "PreparedSend")
        value = prepared.value
        _grant(self.auth, value["kind"])
        retained = self.service._preparations.get(value["prepared_id"])
        if (
            retained is None
            or retained.caller != _auth_binding(self.auth)
            or retained.prepared_bytes != canonical_record(prepared)
        ):
            raise ContractError("forbidden", "retained preparation")
        if value["expires_at"] <= datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"):
            raise ContractError("stale", "preparation expired")
        # Hooks see fresh snapshots of retained, checked DTOs, never unchecked
        # caller fields. Host locks persist through finish/outer commit.
        await self.service._authority_check(
            self.service.authority.lock_authority,
            deepcopy(self.auth),
            decode_record("PreparedSend", retained.prepared_bytes),
            _snapshot(self.claim, "IngressKey"),
            self.transaction,
        )
        rows = await self.manager.fetch_all(
            "SELECT * FROM {{tables.agents}} WHERE agent_id=ANY($1::uuid[]) ORDER BY agent_id FOR UPDATE",
            sorted(
                {retained.author["agent_id"], retained.recipient["agent_id"]}, key=str
            ),
        )
        by_id = {str(row["agent_id"]): verified_projection(row) for row in rows}
        for old in (retained.author, retained.recipient):
            row = by_id.get(str(old["agent_id"]))
            if (
                row is None
                or row["status"] != "active"
                or row.get("deleted_at") is not None
            ):
                raise ContractError("forbidden", "inactive actor")
            if any(
                row.get(k) != old.get(k)
                for k in (
                    "did_key",
                    "did_aw",
                    "team_id",
                    "certificate_id",
                    "agent_type",
                    "alias",
                    "address",
                    "did_aw_verified_key",
                )
            ):
                raise ContractError("stale", "current actor binding")
        if value["expires_at"] <= datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"):
            raise ContractError("stale", "preparation expired while locking")
        _grant(self.auth, value["kind"])
        # Identity-wide policy can be narrowed through another membership.
        # Hold its complete current cohort until this acceptance commits.
        policy_did = retained.recipient.get("policy_did_aw")
        if policy_did:
            await effective_inbound_mode(self.manager, policy_did, for_share=True)
        # Freeze any existing contact proof against concurrent removal/narrowing.
        # Missing contacts cannot permit a send; a later insert only widens.
        await self.manager.fetch_all(
            "SELECT contact_id FROM {{tables.contacts}} WHERE owner_did=ANY($1::text[]) ORDER BY contact_id FOR SHARE",
            [
                d
                for d in (retained.recipient["did_aw"], retained.recipient["did_key"])
                if d
            ],
        )
        db = _TransactionInfra(self.service.db, self.manager)
        await self.service._policy(
            db, self.auth, by_id[str(retained.recipient["agent_id"])]
        )
        await self.manager.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "native-message:" + value["message_id"],
        )
        old = await self.manager.fetch_one(
            "SELECT issuer,request_hash,accepted FROM {{tables.human_channel_sends}} WHERE message_id=$1",
            UUID(value["message_id"]),
        )
        original = json.loads(retained.request_bytes)
        original["target"] = original["target"]["principal"]
        request_hash = _hash(canonical_json_bytes(original))
        if old:
            if (
                old["issuer"] != _principal(self.auth)
                or old["request_hash"] != request_hash
            ):
                raise ContractError("replay_conflict", "message ID/envelope binding")
            accepted = (
                json.loads(old["accepted"])
                if isinstance(old["accepted"], str)
                else old["accepted"]
            )
            accepted["replayed"] = True
            self.accepted = _dto("AcceptedSend", accepted)
            return _snapshot(self.accepted, "AcceptedSend")
        await self.manager.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "native-conversation:" + value["conversation_id"],
        )
        await self.manager.fetch_one(
            "SELECT conversation_id FROM {{tables.conversations}} WHERE conversation_id=$1 FOR UPDATE",
            UUID(value["conversation_id"]),
        )
        await self.manager.fetch_one(
            "SELECT session_id FROM {{tables.chat_sessions}} WHERE session_id=$1 FOR UPDATE",
            UUID(value["conversation_id"]),
        )
        await self._persist(db, retained, value)
        mutation_id = str(uuid4())
        self.accepted = _dto(
            "AcceptedSend",
            {
                "version": "aweb-accepted-send-v1",
                "message_id": value["message_id"],
                "kind": value["kind"],
                "envelope_hash": value["envelope_hash"],
                "replayed": False,
                "publication": "durable_outbox",
                "mutation_ids": [mutation_id],
                "conversation_id": value["conversation_id"],
            },
        )
        await self.manager.execute(
            "INSERT INTO {{tables.human_channel_sends}} (message_id,issuer,request_hash,accepted) VALUES ($1,$2,$3,$4::jsonb)",
            UUID(value["message_id"]),
            _principal(self.auth),
            request_hash,
            canonical_record(self.accepted).decode(),
        )
        context = {
            "message_id": value["message_id"],
            "conversation_id": value["conversation_id"],
            "session_id": value["conversation_id"],
            "team_id": self.auth.team_id,
            "from_agent_id": self.auth.agent_id,
            "from_did": _principal(self.auth),
            "from_alias": self.auth.alias,
            "from_did_aw": self.auth.did_aw,
            "subject": retained.payload.subject,
            "priority": retained.payload.priority,
            "to_agent_id": str(retained.recipient["agent_id"]),
            "to_alias": retained.recipient["alias"],
            "content_mode": retained.payload.content_mode,
        }
        await self.manager.execute(
            "INSERT INTO {{tables.human_channel_mutations}} (mutation_id,message_id,event_type,context) VALUES ($1,$2,$3,$4::jsonb)",
            UUID(mutation_id),
            UUID(value["message_id"]),
            "message.sent" if value["kind"] == "mail" else "chat.message_sent",
            json.dumps(context),
        )
        return _snapshot(self.accepted, "AcceptedSend")

    async def _persist(self, db, retained, value):
        payload = retained.payload
        actor = dict(retained.author, did=_principal(self.auth), transport_hint="local")
        recipient = dict(
            retained.recipient,
            did=retained.recipient["did_aw"] or retained.recipient["did_key"],
            transport_hint="local",
        )
        common = {
            "signature": payload.signature,
            "signed_payload": payload.signed_payload,
            "content_mode": payload.content_mode,
            "message_version": payload.message_version,
            "encrypted_envelope": payload.encrypted_envelope,
            "encrypted_metadata": payload.encrypted_metadata,
            "id_chain": self.auth.id_chain,
            "message_id": UUID(value["message_id"]),
        }
        request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    attachment_backend=self.service.attachment_backend
                )
            )
        )
        attachment_context = prepare_attachment_send(request, payload, self.auth)

        async def persist():
            if value["kind"] == "mail":
                cid = value["conversation_id"]
                existing = await get_conversation(db, conversation_id=cid)
                if existing is None:
                    await create_conversation(
                        db,
                        conversation_type="mail",
                        created_by_did=_principal(self.auth),
                        initiator=actor,
                        recipients=[recipient],
                        conversation_id=cid,
                        team_id=self.auth.team_id,
                    )
                else:
                    from aweb.messaging.mail_routing import mail_continuation_context

                    route = await mail_continuation_context(
                        db,
                        conversation_id=cid,
                        sender_did=_principal(self.auth),
                        equivalent_dids=auth_dids(self.auth),
                    )
                    if route.recipient_participant["did"] != recipient["did"]:
                        raise ContractError(
                            "forbidden", "exact conversation participant"
                        )
                await deliver_message(
                    db,
                    **common,
                    from_did=_principal(self.auth),
                    to_did=recipient["did"],
                    from_alias=self.auth.alias,
                    to_alias=recipient["alias"],
                    subject=payload.subject,
                    body=payload.body,
                    priority=payload.priority,
                    sender_address=self.auth.address,
                    team_id=self.auth.team_id,
                    from_agent_id=self.auth.agent_id,
                    to_agent_id=str(recipient["agent_id"]),
                    conversation_id=cid,
                    skip_policy_check=True,
                )
            else:
                cid = await ensure_session(
                    db,
                    team_id=self.auth.team_id,
                    participant_rows=[actor, recipient],
                    created_by=_principal(self.auth),
                    session_id=UUID(value["conversation_id"]),
                )
                # A native pair preparation may not silently expand to an old
                # group's recipients. Managed/group preparation belongs to P4/P5.
                participants = await self.manager.fetch_all(
                    "SELECT did FROM {{tables.chat_participants}} WHERE session_id=$1 AND left_at IS NULL",
                    cid,
                )
                if {r["did"] for r in participants} != {actor["did"], recipient["did"]}:
                    raise ContractError("forbidden", "exact session audience")
                sent = await send_in_session(
                    db,
                    **common,
                    session_id=cid,
                    sender_did=_principal(self.auth),
                    sender_agent_id=self.auth.agent_id,
                    sender_address=self.auth.address,
                    body=payload.body,
                    reply_to=UUID(payload.reply_to) if payload.reply_to else None,
                    leaving=payload.leaving,
                    hang_on=payload.hang_on,
                )
                if sent is None:
                    raise ContractError("forbidden", "session participant")
                if payload.wait_seconds is not None:
                    await self.manager.execute(
                        "UPDATE {{tables.chat_sessions}} SET wait_seconds=$2,wait_started_at=$3,wait_started_by=$4 WHERE session_id=$1",
                        cid,
                        payload.wait_seconds,
                        sent["created_at"],
                        UUID(self.auth.agent_id) if self.auth.agent_id else None,
                    )

        if attachment_context is None:
            await persist()
        else:
            with attachment_context:
                await persist()

    async def finish_ingress(self, result):
        self._guard()
        result = _snapshot(result, "IngressResult")
        if self.claim is None or self.accepted is None or self.finished:
            raise ContractError("invalid", "unfinished new send required")
        if (
            result.value["key"] != self.claim.value
            or result.value["accepted"] != self.accepted.value
        ):
            raise ContractError("invalid", "exact ingress result")
        await self.manager.execute(
            "INSERT INTO {{tables.human_channel_ingress}} (issuer,namespace,ingress_key,input_hash,result) VALUES ($1,$2,$3,$4,$5::jsonb)",
            self.claim.value["issuer"],
            self.claim.value["namespace"],
            self.claim.value["key"],
            self.claim.value["input_hash"],
            canonical_record(result).decode(),
        )
        self.finished = True
