"""Capability links (docs/page-links.md §1-§3, §6): mint, exchange and signed requests.

A member mints a link for a bounded projection of one page and an explicit
list of allowed actions, never more than they can read and do themselves. The
link's secret is returned once and stored only as its verifier. The holder
exchanges the secret for a short-lived session bound to a browser key, and
every later request is an ``aweb.link-request/1`` signed by that key, whose
nonce is recorded in its own committed write before anything else runs.

The app supplies a :class:`LinkAuthority`: what a creator can read and do on
a page now, which it consults at mint and at every use, so a link narrows as
its creator's access does. Rate limits use :mod:`aweb_naapp.ratelimit`, whose
migrations the app applies too.

The link's lifecycle under its row lock, receipts, reads, actions, asset
grants and streams build on this module.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from awid.signing import canonical_json_bytes
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pgdbm.core import TransactionManager

from aweb_naapp.ratelimit import Charge, Decision, take
from aweb_naapp.runtime.link_requests import (
    LinkRequestRefused,
    check_session_did_key,
    secret_verifier,
    verify_link_request_bytes,
)

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_capability_links"

RATE_POLICY = "link-default-v1"
MAX_LINK_LIFETIME = timedelta(days=30)
SESSION_LIFETIME = timedelta(minutes=15)
CLOCK_WINDOW = timedelta(seconds=60)
# link-default-v1 (§6): (capacity, window_s) per bucket.
EXCHANGES_PER_LINK = (10, 60)
EXCHANGES_PER_CLIENT = (30, 60)

MAX_COLLECTIONS = 16
MAX_RECORDS = 200
MAX_FIELDS = 64
MAX_ASSETS = 64
MAX_ACTIONS = 16
MAX_FIELD_NAME = 256

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_REQUEST_FIELDS = frozenset(
    {"mode", "page_rev", "projection", "actions", "intent_sponsor_did", "one_use", "expires_at"}
)
_LINK_KINDS = frozenset({"edit", "intent"})
_SAFE_METHODS = frozenset({"GET", "HEAD"})
# Compared against when no link matches, so an unknown link costs the same.
_ABSENT_VERIFIER = "0" * 64


class LinkRefused(Exception):
    """A link operation failed with the contract's ``code`` and HTTP ``status``.

    ``reason`` is for the app's log only, never for the response.
    """

    def __init__(
        self, code: str, status: int, *, reason: str = "", retry_after_s: int | None = None
    ) -> None:
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.status = status
        self.reason = reason
        self.retry_after_s = retry_after_s


def _schema(reason: str) -> LinkRefused:
    return LinkRefused("schema_invalid", 422, reason=reason)


def _denied() -> LinkRefused:
    return LinkRefused("action_denied", 403)


def _unavailable() -> LinkRefused:
    return LinkRefused("link_unavailable", 404)


def _limited(decision: Decision) -> LinkRefused:
    return LinkRefused("safety_rate_limited", 429, retry_after_s=decision.retry_after_s)


@dataclass(frozen=True)
class LinkScope:
    """The team, installation and page a link belongs to."""

    team_id: str
    installation_id: str
    page_id: str


@dataclass(frozen=True)
class Readable:
    """The records and fields of one collection a creator can read now."""

    records: tuple[str, ...]
    fields: frozenset[str]


class LinkAuthority(Protocol):
    """A creator's current authority on a page, as the serving app knows it."""

    async def readable(
        self, tx: TransactionManager, *, creator: str, page_id: str, collection: str
    ) -> Readable | None: ...

    async def can_read_asset(
        self, tx: TransactionManager, *, creator: str, page_id: str, asset_id: str
    ) -> bool: ...

    async def action_kind(
        self, tx: TransactionManager, *, page_id: str, action_id: str
    ) -> str | None: ...

    async def can_act(
        self,
        tx: TransactionManager,
        *,
        creator: str,
        page_id: str,
        action_id: str,
        constraints: Mapping[str, Any],
    ) -> bool: ...

    async def is_team_agent(self, tx: TransactionManager, *, did: str) -> bool: ...


@dataclass(frozen=True)
class MintedLink:
    """A new link. ``secret`` is given only here; it is never stored or returned again."""

    link_id: str
    secret: str
    expires_at: datetime


@dataclass(frozen=True)
class LinkSession:
    """A holder's session; ``csrf_token`` is given only here, and stored as its digest."""

    session_id: str
    csrf_token: str
    expires_at: datetime
    link: Mapping[str, Any]


@dataclass(frozen=True)
class LinkCaller:
    """An authenticated link request: anonymous, via this link and session."""

    link_id: str
    session_id: str


async def apply_capability_link_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def _timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise _schema("timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _schema("timestamp") from exc


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _distinct(values: Sequence[object]) -> bool:
    return len(set(values)) == len(values)


def _identifiers(value: object, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise _schema("list bounds")
    if not all(_identifier(item) for item in value) or not _distinct(value):
        raise _schema("identifiers")
    return list(value)


def _field_names(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FIELDS:
        raise _schema("fields")
    if not all(isinstance(f, str) and 1 <= len(f) <= MAX_FIELD_NAME for f in value):
        raise _schema("fields")
    if not _distinct(value):
        raise _schema("fields")
    return list(value)


def _check_request(request: object, now: datetime) -> dict[str, Any]:
    """The request's shape (§1 "The record"); authority is checked separately."""
    if not isinstance(request, Mapping) or set(request) != _REQUEST_FIELDS:
        raise _schema("request fields")
    mode, page_rev = request["mode"], request["page_rev"]
    if mode == "pinned":
        if not (isinstance(page_rev, int) and not isinstance(page_rev, bool) and page_rev >= 0):
            raise _schema("page_rev")
    elif mode != "live" or page_rev is not None:
        raise _schema("mode")
    projection = request["projection"]
    if not isinstance(projection, Mapping) or set(projection) != {"collections", "assets"}:
        raise _schema("projection")
    collections = projection["collections"]
    if not isinstance(collections, list) or not 1 <= len(collections) <= MAX_COLLECTIONS:
        raise _schema("collections")
    checked = []
    for entry in collections:
        if not isinstance(entry, Mapping) or set(entry) != {"collection", "record_ids", "fields"}:
            raise _schema("collection")
        if not _identifier(entry["collection"]):
            raise _schema("collection")
        records = entry["record_ids"]
        if records != "*":
            records = _identifiers(records, 1, MAX_RECORDS)
        checked.append(
            {
                "collection": entry["collection"],
                "record_ids": records,
                "fields": _field_names(entry["fields"]),
            }
        )
    if not _distinct([entry["collection"] for entry in checked]):
        raise _schema("collections")
    assets = _identifiers(projection["assets"], 0, MAX_ASSETS)
    actions = request["actions"]
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        raise _schema("actions")
    for action in actions:
        if not isinstance(action, Mapping) or set(action) != {"action_id", "constraints"}:
            raise _schema("action")
        if not _identifier(action["action_id"]) or not isinstance(action["constraints"], Mapping):
            raise _schema("action")
        try:
            canonical_json_bytes(dict(action["constraints"]))
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            raise _schema("constraints") from exc
    if not _distinct([action["action_id"] for action in actions]):
        raise _schema("actions")
    sponsor = request["intent_sponsor_did"]
    if sponsor is not None and not (isinstance(sponsor, str) and sponsor.startswith("did:")):
        raise _schema("intent_sponsor_did")
    if not isinstance(request["one_use"], bool):
        raise _schema("one_use")
    expires_at = _parse_timestamp(request["expires_at"])
    if not now < expires_at <= now + MAX_LINK_LIFETIME:
        raise _schema("expires_at")
    return {
        "mode": mode,
        "page_rev": page_rev,
        "projection": {"collections": checked, "assets": assets},
        "actions": [
            {"action_id": action["action_id"], "constraints": dict(action["constraints"])}
            for action in actions
        ],
        "intent_sponsor_did": sponsor,
        "one_use": request["one_use"],
        "expires_at": expires_at,
    }


async def _freeze_projection(
    tx: TransactionManager,
    authority: LinkAuthority,
    *,
    creator: str,
    page_id: str,
    projection: Mapping[str, Any],
) -> dict[str, Any] | None:
    """The projection with "*" frozen to the creator's records, or None when the
    creator cannot read all of it now."""
    frozen = []
    for entry in projection["collections"]:
        readable = await authority.readable(
            tx, creator=creator, page_id=page_id, collection=entry["collection"]
        )
        if readable is None or not set(entry["fields"]) <= readable.fields:
            return None
        records = entry["record_ids"]
        if records == "*":
            records = sorted(readable.records)
            if not 1 <= len(records) <= MAX_RECORDS:
                return None
        elif not set(records) <= set(readable.records):
            return None
        frozen.append({**entry, "record_ids": list(records)})
    for asset_id in projection["assets"]:
        if not await authority.can_read_asset(
            tx, creator=creator, page_id=page_id, asset_id=asset_id
        ):
            return None
    return {"collections": frozen, "assets": list(projection["assets"])}


async def mint(
    tx: TransactionManager,
    authority: LinkAuthority,
    *,
    scope: LinkScope,
    creator: str,
    creator_certificate_id: str,
    request: object,
    now: datetime,
) -> MintedLink:
    """Mint a capability link for ``creator`` (§1 "Minting").

    The request is the record's grantable fields; everything else comes from
    the caller's verified context. Writes on the caller's transaction, where
    the app also records its audit row. Raises :class:`LinkRefused`:
    ``schema_invalid`` for the request's shape, ``action_denied`` for anything
    beyond the creator's current authority.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    checked = _check_request(request, now)
    kinds = [
        await authority.action_kind(tx, page_id=scope.page_id, action_id=action["action_id"])
        for action in checked["actions"]
    ]
    has_intent = "intent" in kinds
    if has_intent != (checked["intent_sponsor_did"] is not None):
        raise _schema("intent_sponsor_did")
    projection = await _freeze_projection(
        tx, authority, creator=creator, page_id=scope.page_id, projection=checked["projection"]
    )
    if projection is None:
        raise _denied()
    for action, kind in zip(checked["actions"], kinds, strict=True):
        if kind not in _LINK_KINDS or not await authority.can_act(
            tx,
            creator=creator,
            page_id=scope.page_id,
            action_id=action["action_id"],
            constraints=action["constraints"],
        ):
            raise _denied()
    if has_intent and not await authority.is_team_agent(tx, did=checked["intent_sponsor_did"]):
        raise _denied()

    link_id = "lnk_" + secrets.token_hex(16)
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    record = {
        "link_id": link_id,
        "team_id": scope.team_id,
        "installation_id": scope.installation_id,
        "page_id": scope.page_id,
        "mode": checked["mode"],
        "page_rev": checked["page_rev"],
        "projection": projection,
        "actions": checked["actions"],
        "intent_sponsor_did": checked["intent_sponsor_did"],
        "one_use": checked["one_use"],
        "created_by": {"principal_did": creator, "certificate_id": creator_certificate_id},
        "created_at": _timestamp(now),
        "expires_at": _timestamp(checked["expires_at"]),
        "rate_policy": RATE_POLICY,
    }
    await tx.execute(
        """
        INSERT INTO {{tables.capability_links}}
            (link_id, verifier_sha256, team_id, installation_id, page_id, record,
             created_by, created_at, expires_at, one_use)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
        """,
        link_id,
        secret_verifier(secret),
        scope.team_id,
        scope.installation_id,
        scope.page_id,
        json.dumps(record),
        creator,
        now,
        checked["expires_at"],
        checked["one_use"],
    )
    return MintedLink(link_id=link_id, secret=secret, expires_at=checked["expires_at"])


def _strict_object(body: bytes) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _schema("body") from exc


def _record(value: Any) -> Mapping[str, Any]:
    return json.loads(value) if isinstance(value, str) else value


async def _creator_still_reads(
    tx: TransactionManager, authority: LinkAuthority, record: Mapping[str, Any]
) -> bool:
    creator = record["created_by"]["principal_did"]
    frozen = await _freeze_projection(
        tx, authority, creator=creator, page_id=record["page_id"], projection=record["projection"]
    )
    return frozen is not None


async def exchange(
    db: AsyncDatabaseManager,
    authority: LinkAuthority,
    *,
    link_id: str,
    body: bytes,
    client: str,
    now: datetime,
) -> LinkSession:
    """Exchange a link's secret for a session bound to a browser key (§2).

    ``client`` is the caller's address as the app keys it. Every exchange
    spends from the client's bucket, which commits even when the exchange then
    fails; only a successful one spends from the link's, so a stranger who
    knows the link ID cannot lock its holder out. A wrong secret, an unknown
    link and an unusable one are all ``link_unavailable``. The app never logs
    this route's request body.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    request = _strict_object(body)
    if not isinstance(request, dict) or set(request) != {"secret", "session_did_key"}:
        raise _schema("exchange fields")
    if not isinstance(request["secret"], str):
        raise _schema("secret")
    try:
        check_session_did_key(request["session_did_key"])
    except LinkRequestRefused as exc:
        raise _schema("session_did_key") from exc

    async with db.transaction() as tx:
        per_client = await take(
            tx, [Charge("link.exchange.client", client, *EXCHANGES_PER_CLIENT)], now=now
        )
    if not per_client.allowed:
        raise _limited(per_client)

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT verifier_sha256, record, expires_at, one_use, revoked_at, used_at
            FROM {{tables.capability_links}} WHERE link_id = $1 FOR SHARE
            """,
            link_id,
        )
        stored = row["verifier_sha256"] if row is not None else _ABSENT_VERIFIER
        matches = hmac.compare_digest(secret_verifier(request["secret"]), stored)
        if row is None or not matches:
            raise _unavailable()
        record = _record(row["record"])
        usable = (
            row["revoked_at"] is None
            and now < row["expires_at"]
            and not (row["one_use"] and row["used_at"] is not None)
        )
        if not usable or not await _creator_still_reads(tx, authority, record):
            raise _unavailable()
        per_link = await take(tx, [Charge("link.exchange", link_id, *EXCHANGES_PER_LINK)], now=now)
        if not per_link.allowed:
            raise _limited(per_link)
        session_id = "lks_" + secrets.token_hex(16)
        csrf_token = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")
        expires_at = min(now + SESSION_LIFETIME, row["expires_at"])
        await tx.execute(
            """
            INSERT INTO {{tables.link_sessions}}
                (session_id, link_id, session_did_key, csrf_sha256, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            session_id,
            link_id,
            request["session_did_key"],
            hashlib.sha256(csrf_token.encode("ascii")).digest(),
            now,
            expires_at,
        )
    return LinkSession(
        session_id=session_id,
        csrf_token=csrf_token,
        expires_at=expires_at,
        link={
            "page_id": record["page_id"],
            "mode": record["mode"],
            "actions": [action["action_id"] for action in record["actions"]],
        },
    )


def _signature_invalid() -> LinkRefused:
    return LinkRefused("signature_invalid", 401)


async def authenticate(
    db: AsyncDatabaseManager,
    *,
    authorization: str | None,
    signed_payload: str | None,
    method: str,
    target: str,
    body: bytes,
    origin: str | None,
    csrf: str | None,
    app_origin: str,
    now: datetime,
) -> LinkCaller:
    """Verify a link holder's signed request, §3 steps 1-5.

    ``target`` is the raw request path with its query. The nonce is recorded
    in its own committed write as soon as the signature, binding and time
    hold, before the Origin and CSRF checks and before any action, so a signed
    request is never accepted twice. The link's lifecycle (step 6) is checked
    under its row lock by the operation that follows.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not isinstance(authorization, str) or not isinstance(signed_payload, str):
        raise _signature_invalid()
    parts = authorization.split(" ")
    if len(parts) != 3 or parts[0] != "AWEB-Link-Request":
        raise _signature_invalid()
    _, session_id, signature = parts
    session = await db.fetch_one(
        """
        SELECT link_id, session_did_key, csrf_sha256, expires_at
        FROM {{tables.link_sessions}} WHERE session_id = $1
        """,
        session_id,
    )
    if session is None or now >= session["expires_at"]:
        raise _signature_invalid()
    try:
        payload = verify_link_request_bytes(
            signed_payload,
            signature,
            session_did_key=session["session_did_key"],
            expected={
                "link_id": session["link_id"],
                "session_id": session_id,
                "method": method,
                "path": target,
                "body_sha256": hashlib.sha256(body).hexdigest(),
            },
            now=now,
        )
    except LinkRequestRefused as exc:
        raise LinkRefused(exc.code, 401) from exc
    issued_at = _parse_timestamp(payload["issued_at"])
    async with db.transaction() as tx:
        recorded = await tx.fetch_value(
            """
            INSERT INTO {{tables.link_nonces}} (session_id, nonce, keep_until)
            VALUES ($1, $2, $3)
            ON CONFLICT (session_id, nonce) DO NOTHING
            RETURNING 1
            """,
            session_id,
            payload["nonce"],
            max(session["expires_at"], issued_at + CLOCK_WINDOW),
        )
    if recorded is None:
        raise LinkRefused("idempotency_conflict", 409)
    if method not in _SAFE_METHODS:
        if origin != app_origin or not isinstance(csrf, str):
            raise _denied()
        digest = hashlib.sha256(csrf.encode("utf-8")).digest()
        if not hmac.compare_digest(digest, bytes(session["csrf_sha256"])):
            raise _denied()
    return LinkCaller(link_id=session["link_id"], session_id=session_id)


async def expire_sessions(db: AsyncDatabaseManager, *, now: datetime) -> int:
    """Delete expired sessions and the nonces past their keeping time, in their own
    transaction. Returns how many rows were deleted."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    async with db.transaction() as tx:
        sessions = await tx.fetch_value(
            """
            WITH gone AS (
                DELETE FROM {{tables.link_sessions}} WHERE expires_at <= $1 RETURNING 1
            ) SELECT count(*) FROM gone
            """,
            now,
        )
        nonces = await tx.fetch_value(
            """
            WITH gone AS (
                DELETE FROM {{tables.link_nonces}} WHERE keep_until <= $1 RETURNING 1
            ) SELECT count(*) FROM gone
            """,
            now,
        )
    return int(sessions) + int(nonces)
