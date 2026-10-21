"""Capability links (docs/page-links.md §1-§6).

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

Reads and submissions take the link's row lock in the caller's transaction.
The app loads a checked read projection before releasing that transaction;
its action port looks up receipts and applies actions on the same transaction.
Asset grants and streams build on this lifecycle.
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

from aweb_naapp.idempotency import IdempotencyConflict, IdempotencyExpired
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
READS_PER_SESSION = (120, 60)
WRITES_PER_LINK = (20, 60)
WRITES_PER_CLIENT = (60, 60)

MAX_COLLECTIONS = 16
MAX_RECORDS = 200
MAX_FIELDS = 64
MAX_ASSETS = 64
MAX_ACTIONS = 16
MAX_FIELD_NAME = 256
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024

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


@dataclass(frozen=True)
class LinkRead:
    """A checked projection; load it before releasing the caller's transaction.

    ``mode`` and ``page_rev`` select the pinned or live page version. The app
    applies its row/field ACLs as ``creator`` as well as this projection and
    ``allowed_action_ids``. A pinned ``source_snapshot`` is internal app input,
    never a response before that narrowing. ``asset_versions`` stays outside
    the page; the asset adapter supplies only available captured-version URLs.
    """

    scope: LinkScope
    creator: str
    mode: str
    page_rev: int | None
    projection: Mapping[str, Any]
    source_snapshot: Mapping[str, Any] | None = None
    asset_versions: Mapping[str, str] | None = None
    allowed_action_ids: tuple[str, ...] = ()


class SnapshotSource(Protocol):
    """The app's shared redactor captures one complete authorized aweb.page/1.

    Creator identity is translated to its verified ACL identity by the app.
    The source captures layout, state, schemas, values and only allowed action
    definitions at expected_page_rev, in this transaction. It applies C1's
    limits and C4's projection, 16-action and 64-asset bounds; excluded widgets
    become inert placeholders. No asset URL or grant is stored in the page.
    The same redactor narrows the stored source at use under current ACLs and
    action authority, never substituting current layout, state or values.
    """

    async def capture_link_snapshot_on(
        self,
        tx: TransactionManager,
        *,
        scope: LinkScope,
        creator_id: str,
        projection: Mapping[str, Any],
        allowed_action_ids: Sequence[str],
        expected_page_rev: int,
    ) -> Mapping[str, Any]: ...


class AssetVersions(Protocol):
    """Resolve captured asset IDs to immutable content versions on the mint tx.

    The app holds its asset lifecycle lock while resolving versions and N5
    records retention references on that same transaction. Ordinary GC takes
    that lock and consults retained_asset_versions_on. Explicit owner deletion
    overrides retention; phase-3 grants check each version's availability.
    """

    async def versions_on(
        self, tx: TransactionManager, *, scope: LinkScope, asset_ids: Sequence[str]
    ) -> Mapping[str, str]: ...


@dataclass(frozen=True)
class LinkAction:
    """Context built after link verification, for the app's action port.

    The creator supplies delegated authority; ``caller`` is anonymous link
    provenance, never a member Principal. The app validates the action schema,
    expected revisions and field policy within ``projection``, and writes its
    effect, audit, outbox and receipt on the supplied transaction. It must not
    open another transaction, commit this transaction, or dispatch external effects.
    """

    scope: LinkScope
    caller: LinkCaller
    creator: str
    mode: str
    page_rev: int | None
    projection: Mapping[str, Any]
    constraints: Mapping[str, Any]
    kind: str
    intent_sponsor_did: str | None
    request: Mapping[str, Any]
    key: tuple[str, ...]
    request_hash: bytes


@dataclass(frozen=True)
class ActionReceipt:
    """The app's stored operation and its bounded response, with no link secrets."""

    operation_id: str
    result: Mapping[str, Any]


class ActionPort(Protocol):
    """N3's receipt and action seam. Both methods use the supplied transaction.

    ``lookup`` is read-only; ``apply`` claims the same key/hash in the shared
    idempotency store and writes the receipt with the effect. A matching retry
    returns only the prior bounded receipt, not a fresh page read. N5 owns the
    link lock; the app neither takes a second link lock nor fabricates a member.
    """

    async def lookup(
        self, tx: TransactionManager, *, key: tuple[str, ...], request_hash: bytes
    ) -> ActionReceipt | None: ...

    async def apply(self, tx: TransactionManager, *, action: LinkAction) -> ActionReceipt: ...


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
    snapshot_source: SnapshotSource | None = None,
    asset_source: AssetVersions | None = None,
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

    snapshot_bytes = None
    asset_versions: Mapping[str, str] = {}
    if checked["mode"] == "pinned":
        if snapshot_source is None:
            raise RuntimeError("pinned mint requires the app's shared snapshot source")
        snapshot = await snapshot_source.capture_link_snapshot_on(
            tx,
            scope=scope,
            creator_id=creator,
            projection=projection,
            allowed_action_ids=[a["action_id"] for a in checked["actions"]],
            expected_page_rev=checked["page_rev"],
        )
        if snapshot.get("rev") != checked["page_rev"]:
            raise LinkRefused("revision_conflict", 409, reason="snapshot source revision differs")
        if snapshot.get("page_id") != scope.page_id:
            raise ValueError("snapshot source returned another page")
        snapshot_bytes = _snapshot_bytes(snapshot)
        if projection["assets"]:
            if asset_source is None:
                raise RuntimeError("pinned assets require an immutable-version source")
            asset_versions = await asset_source.versions_on(
                tx, scope=scope, asset_ids=projection["assets"]
            )
            if set(asset_versions) != set(projection["assets"]) or any(
                not isinstance(v, str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", v) is None
                for v in asset_versions.values()
            ):
                raise ValueError("asset source must resolve every captured immutable version")

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
    if snapshot_bytes is not None:
        await tx.execute(
            """
            INSERT INTO {{tables.capability_link_snapshots}}
                (link_id, page_rev, snapshot, snapshot_sha256)
            VALUES ($1, $2, $3::jsonb, $4)
            """,
            link_id,
            checked["page_rev"],
            snapshot_bytes.decode("utf-8"),
            hashlib.sha256(snapshot_bytes).digest(),
        )
        for asset_id, version in asset_versions.items():
            await tx.execute(
                "INSERT INTO {{tables.capability_link_asset_refs}} "
                "(link_id, asset_id, content_version) VALUES ($1, $2, $3)",
                link_id,
                asset_id,
                version,
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


def _snapshot_bytes(snapshot: Mapping[str, Any]) -> bytes:
    """Bound the trusted projection result; ACL/redaction stay in the app source."""
    if (
        not isinstance(snapshot, Mapping)
        or snapshot.get("page_format") != "aweb.page/1"
        or type(snapshot.get("rev")) is not int
        or snapshot["rev"] < 0
        or not isinstance(snapshot["collections"], list)
    ):
        raise ValueError("invalid pinned snapshot shape")
    raw = canonical_json_bytes(dict(snapshot))
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("pinned snapshot exceeds the page snapshot byte bound")
    return raw


async def _pinned_source(
    tx: TransactionManager, record: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    if record["mode"] != "pinned":
        return None
    stored = await tx.fetch_one(
        "SELECT page_rev, snapshot, snapshot_sha256 FROM {{tables.capability_link_snapshots}} "
        "WHERE link_id = $1",
        record["link_id"],
    )
    try:
        if stored is None or stored["page_rev"] != record["page_rev"]:
            raise ValueError("missing pinned source or revision mismatch")
        snapshot = _record(stored["snapshot"])
        raw = _snapshot_bytes(snapshot)
        if (
            snapshot["rev"] != record["page_rev"]
            or snapshot.get("page_id") != record["page_id"]
            or not hmac.compare_digest(
                hashlib.sha256(raw).digest(), bytes(stored["snapshot_sha256"])
            )
        ):
            raise ValueError("pinned source revision or digest mismatch")
    except (ValueError, TypeError, KeyError, UnicodeEncodeError, RecursionError) as exc:
        raise LinkRefused(
            "link_unavailable", 410, reason="missing or corrupt pinned snapshot"
        ) from exc
    return snapshot


async def _creator_still_reads(
    tx: TransactionManager, authority: LinkAuthority, record: Mapping[str, Any]
) -> bool:
    creator = record["created_by"]["principal_did"]
    frozen = await _freeze_projection(
        tx,
        authority,
        creator=creator,
        page_id=record["page_id"],
        projection={"collections": record["projection"]["collections"], "assets": []},
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
    if session is None:
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
    if now >= session["expires_at"]:
        raise LinkRefused("link_unavailable", 410)
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


def _scope(record: Mapping[str, Any]) -> LinkScope:
    return LinkScope(record["team_id"], record["installation_id"], record["page_id"])


async def _locked_link(
    tx: TransactionManager, *, caller: LinkCaller, write: bool, now: datetime
) -> Mapping[str, Any]:
    """Serialize against revocation, and recheck the session before any receipt."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    lock = "FOR UPDATE" if write else "FOR SHARE"
    row = await tx.fetch_one(
        "SELECT record, revoked_at, expires_at, one_use, used_at "
        "FROM {{tables.capability_links}} WHERE link_id = $1 " + lock,
        caller.link_id,
    )
    if row is None:
        raise LinkRefused("link_unavailable", 410)
    session = await tx.fetch_one(
        "SELECT link_id, expires_at FROM {{tables.link_sessions}} WHERE session_id = $1",
        caller.session_id,
    )
    if session is None or session["link_id"] != caller.link_id or now >= session["expires_at"]:
        raise LinkRefused("link_unavailable", 410)
    return row


def _check_lifecycle(row: Mapping[str, Any], now: datetime) -> None:
    if (
        row["revoked_at"] is not None
        or now >= row["expires_at"]
        or (row["one_use"] and row["used_at"] is not None)
    ):
        raise LinkRefused("link_unavailable", 410)


def _select_projection(
    requested: Mapping[str, Any] | None, granted: Mapping[str, Any]
) -> dict[str, Any]:
    if requested is None:
        return dict(granted)
    if not isinstance(requested, Mapping) or set(requested) != {"collections", "assets"}:
        raise _schema("projection")
    collections = requested["collections"]
    if not isinstance(collections, list) or len(collections) > MAX_COLLECTIONS:
        raise _schema("collections")
    allowed = {entry["collection"]: entry for entry in granted["collections"]}
    checked = []
    for entry in collections:
        if not isinstance(entry, Mapping) or set(entry) != {"collection", "record_ids", "fields"}:
            raise _schema("collection")
        if not _identifier(entry["collection"]):
            raise _schema("collection")
        records = _identifiers(entry["record_ids"], 1, MAX_RECORDS)
        fields = _field_names(entry["fields"])
        grant = allowed.get(entry["collection"])
        if (
            grant is None
            or not set(records) <= set(grant["record_ids"])
            or not set(fields) <= set(grant["fields"])
        ):
            raise _denied()
        checked.append({"collection": entry["collection"], "record_ids": records, "fields": fields})
    if not _distinct([entry["collection"] for entry in checked]):
        raise _schema("collections")
    assets = _identifiers(requested["assets"], 0, MAX_ASSETS)
    if not set(assets) <= set(granted["assets"]):
        raise _denied()
    return {"collections": checked, "assets": assets}


async def read(
    tx: TransactionManager,
    authority: LinkAuthority,
    *,
    caller: LinkCaller,
    page_id: str,
    projection: Mapping[str, Any] | None = None,
    now: datetime,
) -> LinkRead:
    """Admit a projection read under FOR SHARE (§4–§6).

    ``caller`` comes from :func:`authenticate`. The app must load the returned
    projection within this same transaction, never after its lock is released.
    A subset remains readable when the creator loses an unrelated field. For
    pinned mode ``source_snapshot`` is always present and verified. The app
    projects that source through the same ACL/redaction path as live data,
    within this transaction; it must not expose the unprojected source itself.
    """
    row = await _locked_link(tx, caller=caller, write=False, now=now)
    _check_lifecycle(row, now)
    record = _record(row["record"])
    if record["page_id"] != page_id:
        raise _denied()
    selected = _select_projection(projection, record["projection"])
    creator = record["created_by"]["principal_did"]
    if (
        await _freeze_projection(
            tx,
            authority,
            creator=creator,
            page_id=page_id,
            projection={"collections": selected["collections"], "assets": []},
        )
        is None
    ):
        raise _denied()
    selected["assets"] = [
        asset_id
        for asset_id in selected["assets"]
        if await authority.can_read_asset(tx, creator=creator, page_id=page_id, asset_id=asset_id)
    ]
    allowed_actions = []
    for action in record["actions"]:
        if await authority.action_kind(
            tx, page_id=page_id, action_id=action["action_id"]
        ) in _LINK_KINDS and await authority.can_act(
            tx,
            creator=creator,
            page_id=page_id,
            action_id=action["action_id"],
            constraints=action["constraints"],
        ):
            allowed_actions.append(action["action_id"])
    source = await _pinned_source(tx, record)
    versions = None
    if source is not None:
        versions = {
            row["asset_id"]: row["content_version"]
            for row in await tx.fetch_all(
                "SELECT asset_id, content_version FROM {{tables.capability_link_asset_refs}} "
                "WHERE link_id = $1",
                caller.link_id,
            )
            if row["asset_id"] in selected["assets"]
        }
    limit = await take(tx, [Charge("link.read", caller.session_id, *READS_PER_SESSION)], now=now)
    if not limit.allowed:
        raise _limited(limit)
    return LinkRead(
        _scope(record),
        creator,
        record["mode"],
        record["page_rev"],
        selected,
        source,
        versions,
        tuple(allowed_actions),
    )


def _action_request(body: bytes) -> dict[str, Any]:
    """Parse only what is needed for receipt identity before admission checks."""
    request = _strict_object(body)
    if (
        not isinstance(request, dict)
        or not isinstance(request.get("idempotency_key"), str)
        or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", request["idempotency_key"]) is None
    ):
        raise _schema("action request")
    try:
        canonical_json_bytes(request)
    except (UnicodeEncodeError, ValueError, TypeError, RecursionError) as exc:
        raise _schema("action request") from exc
    return request


def _check_action_request(request: Mapping[str, Any]) -> None:
    required = {"action_id", "input", "idempotency_key"}
    if (
        not required <= set(request)
        or set(request) - required - {"expected_page_rev", "expected_record_revs"}
        or not _identifier(request["action_id"])
        or not isinstance(request["input"], dict)
    ):
        raise _schema("action request")


async def admit(
    tx: TransactionManager,
    authority: LinkAuthority,
    actions: ActionPort,
    *,
    caller: LinkCaller,
    page_id: str,
    body: bytes,
    client: str,
    now: datetime,
) -> ActionReceipt:
    """Admit an edit or anonymous intent (§4–§6), in the caller's transaction.

    The body is the same bytes :func:`authenticate` bound to the request.
    Receipt lookup precedes lifecycle/authority under FOR UPDATE. An admitted
    one-use operation and its receipt commit together; a failure rolls both
    back. Fresh nonces allow retries, whose result survives use or revocation
    only while the session lives. ``client`` follows the trusted proxy rule.
    """
    request = _action_request(body)
    request_hash = hashlib.sha256(
        canonical_json_bytes({"operation": "link.action", "page_id": page_id, "request": request})
    ).digest()
    row = await _locked_link(tx, caller=caller, write=True, now=now)
    record = _record(row["record"])
    key = (
        record["installation_id"],
        record["team_id"],
        "link:" + caller.link_id,
        request["idempotency_key"],
    )
    try:
        stored = await actions.lookup(tx, key=key, request_hash=request_hash)
        if stored is not None:
            return stored
        _check_lifecycle(row, now)
        _check_action_request(request)
        if record["page_id"] != page_id:
            raise _denied()
        allowed = next(
            (a for a in record["actions"] if a["action_id"] == request["action_id"]), None
        )
        if allowed is None:
            raise _denied()
        constraints = allowed["constraints"]
        for field, value in constraints.items():
            if field not in request["input"] or canonical_json_bytes(
                request["input"][field]
            ) != canonical_json_bytes(value):
                raise _denied()
        creator = record["created_by"]["principal_did"]
        kind = await authority.action_kind(tx, page_id=page_id, action_id=request["action_id"])
        if kind not in _LINK_KINDS or not await authority.can_act(
            tx,
            creator=creator,
            page_id=page_id,
            action_id=request["action_id"],
            constraints=constraints,
        ):
            raise _denied()
        sponsor = record["intent_sponsor_did"]
        if kind == "intent" and (
            sponsor is None or not await authority.is_team_agent(tx, did=sponsor)
        ):
            raise _denied()
        limit = await take(
            tx,
            [
                Charge("link.write", caller.link_id, *WRITES_PER_LINK),
                Charge("link.write.client", client, *WRITES_PER_CLIENT),
            ],
            now=now,
        )
        if not limit.allowed:
            raise _limited(limit)
        receipt = await actions.apply(
            tx,
            action=LinkAction(
                scope=_scope(record),
                caller=caller,
                creator=creator,
                mode=record["mode"],
                page_rev=record["page_rev"],
                projection=record["projection"],
                constraints=constraints,
                kind=kind,
                intent_sponsor_did=sponsor,
                request=request,
                key=key,
                request_hash=request_hash,
            ),
        )
    except (IdempotencyConflict, IdempotencyExpired) as exc:
        raise LinkRefused(exc.code, exc.status) from exc
    if row["one_use"]:
        await tx.execute(
            "UPDATE {{tables.capability_links}} SET used_at = $2, used_by_operation = $3 "
            "WHERE link_id = $1",
            caller.link_id,
            now,
            receipt.operation_id,
        )
    return receipt


async def revoke(
    tx: TransactionManager,
    *,
    scope: LinkScope,
    link_id: str,
    actor: str,
    is_owner: bool,
    now: datetime,
) -> None:
    """Revoke as the creator or a verified owner, under the admission lock (§4).

    The app supplies ``scope``, ``actor`` and ``is_owner`` from its verified
    team-auth context and writes the audit on this transaction.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    row = await tx.fetch_one(
        "SELECT created_by FROM {{tables.capability_links}} WHERE link_id = $1 "
        "AND team_id = $2 AND installation_id = $3 AND page_id = $4 FOR UPDATE",
        link_id,
        scope.team_id,
        scope.installation_id,
        scope.page_id,
    )
    if row is None:
        raise _unavailable()
    if row["created_by"] != actor and not is_owner:
        raise _denied()
    await tx.execute(
        "UPDATE {{tables.capability_links}} SET revoked_at = COALESCE(revoked_at, $2) "
        "WHERE link_id = $1",
        link_id,
        now,
    )
    await tx.execute(
        "DELETE FROM {{tables.capability_link_asset_refs}} WHERE link_id = $1", link_id
    )


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


async def purge_page_links_on(tx: TransactionManager, *, scope: LinkScope) -> int:
    """Purge a page's links and cascade pinned content/sessions on caller's tx.

    The app invokes this from its authorized content-purge/installation-delete
    path under its declared retention policy. It records export/deletion
    coverage and backup retention there; deleting these rows does not claim
    that backups or app-owned action receipts have been erased.
    """
    count = await tx.fetch_value(
        """
        WITH gone AS (
            DELETE FROM {{tables.capability_links}}
            WHERE installation_id = $1 AND team_id = $2 AND page_id = $3 RETURNING 1
        ) SELECT count(*) FROM gone
        """,
        scope.installation_id,
        scope.team_id,
        scope.page_id,
    )
    return int(count)


async def expire_snapshots(db: AsyncDatabaseManager, *, now: datetime) -> int:
    """Remove pinned content once its link has expired and no session can read it.

    The app runs this cleanup alongside expire_sessions. Earlier page/content
    deletion uses purge_page_links_on; this supplies no new retention default.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    async with db.transaction() as tx:
        await tx.execute(
            "DELETE FROM {{tables.capability_link_asset_refs}} AS ref "
            "USING {{tables.capability_links}} AS link WHERE ref.link_id=link.link_id "
            "AND (link.revoked_at IS NOT NULL OR link.expires_at <= $1)",
            now,
        )
        count = await tx.fetch_value(
            """
        WITH gone AS (
            DELETE FROM {{tables.capability_link_snapshots}} AS snapshot
            USING {{tables.capability_links}} AS link
            WHERE snapshot.link_id = link.link_id AND link.expires_at <= $1 RETURNING 1
        ) SELECT count(*) FROM gone
        """,
            now,
        )
    return int(count)


async def retained_asset_versions_on(
    tx: TransactionManager, *, scope: LinkScope, asset_id: str, now: datetime
) -> frozenset[str]:
    """Versions ordinary asset GC must retain for all pages in this installation.

    The app calls this under its own asset lifecycle lock, on the same tx as
    deleting unreferenced versions. Owner-directed deletion wins regardless.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    rows = await tx.fetch_all(
        "SELECT ref.content_version FROM {{tables.capability_link_asset_refs}} AS ref "
        "JOIN {{tables.capability_links}} AS link ON link.link_id=ref.link_id "
        "WHERE link.installation_id=$1 AND link.team_id=$2 "
        "AND ref.asset_id=$3 AND link.revoked_at IS NULL AND link.expires_at>$4",
        scope.installation_id,
        scope.team_id,
        asset_id,
        now,
    )
    return frozenset(row["content_version"] for row in rows)
