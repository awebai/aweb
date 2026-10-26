"""A team's chain as its readers see it: events projected from their retained
envelopes, filtered, paged and tailed (audit-substrate.md §B4, §B5, §B8).

Every value a reader sees comes from the event's signed envelope or its chain
skeleton; nothing is added. ``mediation`` is derived from the producer, never
claimed: a client's event stays ``client``. A purged event shows only its
skeleton and its purging act, and no content filter matches it.

The projection rows in ``read_events`` exist only to filter. Before each read,
the team's events that have none are projected from ``chain_events``, so
ingest needs no knowledge of readers.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any

from aweb_naapp.hooks import envelope as hook_envelope
from pgdbm import AsyncDatabaseManager

MAX_LIMIT = 200
DEFAULT_LIMIT = 50
_PROJECTION_BATCH = 500
_TIME_LAYOUT = "%Y-%m-%dT%H:%M:%S.%fZ"

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_TRACE_ID = re.compile(r"[0-9a-f]{32}")
_DID = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}|did:aw:[1-9A-HJ-NP-Za-km-z]{20,32}")
_APP_ID = re.compile(r"[a-z][a-z0-9-]{0,62}")
_CURSOR = re.compile(r"([1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,15})")

MEDIATIONS = ("server", "registry_observed", "client")
RESULT_STATUSES = ("success", "denied", "failed", "outcome_unknown")

# The payload field that names an event's type, per hook.
_EVENT_TYPE_FIELD = {
    "post-secret-use-hook": "action",
    "post-governance-hook": "act",
    "post-mutation-hook": "mutation_type",
    "post-manifest-command-hook": "tool",
    "post-command-hook": "command_class",
}
# Payload references a reader can filter on, each a column of read_events.
REFERENCES = ("operation_id", "job_id", "dispatch_id", "approval_id", "grant_id", "secret_id")
_ACTOR_FIELDS = ("authority_mode", "did_key", "did_aw", "alias", "certificate_id", "grant_id")


class InvalidRead(ValueError):
    """A filter, cursor or limit a reader may not ask for."""

    code = "invalid_filter"


@dataclass(frozen=True, order=True)
class Cursor:
    """A position in a team's chain, opaque to readers."""

    chain_epoch: int
    team_seq: int

    def encode(self) -> str:
        text = f"{self.chain_epoch}.{self.team_seq}".encode("ascii")
        return base64.urlsafe_b64encode(text).rstrip(b"=").decode("ascii")

    @classmethod
    def decode(cls, text: str) -> Cursor:
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise InvalidRead("cursor") from None
        match = _CURSOR.fullmatch(raw)
        if match is None:
            raise InvalidRead("cursor")
        cursor = cls(int(match.group(1)), int(match.group(2)))
        if cursor.encode() != text:
            raise InvalidRead("cursor")
        return cursor


@dataclass(frozen=True)
class EventFilter:
    """Exact-match conditions, all of which an event must meet."""

    hook: str | None = None
    mediation: str | None = None
    event_type: str | None = None
    result_status: str | None = None
    actor: str | None = None
    app_id: str | None = None
    trace_id: str | None = None
    event_id: str | None = None
    operation_id: str | None = None
    job_id: str | None = None
    dispatch_id: str | None = None
    approval_id: str | None = None
    grant_id: str | None = None
    secret_id: str | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None

    @classmethod
    def from_query(cls, values: Mapping[str, str]) -> EventFilter:
        """The filter a reader's query parameters name, or :class:`InvalidRead`."""
        known = {field.name for field in fields(cls)}
        parsed: dict[str, Any] = {}
        for name, value in values.items():
            if name not in known:
                raise InvalidRead(name)
            parsed[name] = _parse(name, value)
        return cls(**parsed)

    def needs_content(self) -> bool:
        return any(
            getattr(self, field.name) is not None for field in fields(self) if field.name != "hook"
        )


@dataclass(frozen=True)
class Page:
    events: list[dict[str, Any]]
    next_cursor: str | None


def _parse(name: str, value: str) -> Any:
    if name == "hook":
        return _one_of(name, value, tuple(hook_envelope.HOOKS))
    if name == "mediation":
        return _one_of(name, value, MEDIATIONS)
    if name == "result_status":
        return _one_of(name, value, RESULT_STATUSES)
    if name in ("occurred_from", "occurred_to"):
        return _time(name, value)
    pattern = {
        "event_type": _TOKEN,
        "actor": _DID,
        "app_id": _APP_ID,
        "trace_id": _TRACE_ID,
        "event_id": hook_envelope.UUID_PATTERN,
    }.get(name, _REF)
    if not pattern.fullmatch(value) or (name == "trace_id" and value == "0" * 32):
        raise InvalidRead(name)
    return value


def _one_of(name: str, value: str, options: Sequence[str]) -> str:
    if value not in options:
        raise InvalidRead(name)
    return value


def _time(name: str, value: str) -> datetime:
    try:
        moment = datetime.strptime(value, _TIME_LAYOUT).replace(tzinfo=UTC)
    except ValueError:
        raise InvalidRead(name) from None
    if moment.strftime(_TIME_LAYOUT)[:-4] + "Z" != value:
        raise InvalidRead(name)
    return moment


def _limit(limit: int) -> int:
    if not 1 <= limit <= MAX_LIMIT:
        raise InvalidRead("limit")
    return limit


async def query(
    db: AsyncDatabaseManager,
    team_id: str,
    where: EventFilter,
    *,
    limit: int = DEFAULT_LIMIT,
    before: str | None = None,
) -> Page:
    """The team's events matching ``where``, newest first, after the position
    ``before`` names when it is given."""
    limit = _limit(limit)
    start = Cursor.decode(before) if before is not None else None
    await project(db, team_id)
    conditions, arguments = _conditions(team_id, where)
    if start is not None:
        arguments += [start.chain_epoch, start.team_seq]
        conditions.append(
            f"(r.chain_epoch, r.team_seq) < (${len(arguments) - 1}, ${len(arguments)})"
        )
    rows = await _rows(db, conditions, arguments, "DESC", limit + 1)
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = _position(rows[-1]).encode() if more else None
    return Page([_event(row) for row in rows], next_cursor)


async def tail(
    db: AsyncDatabaseManager,
    team_id: str,
    where: EventFilter,
    *,
    after: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> Page:
    """The team's events matching ``where`` after the position ``after`` names,
    oldest first. Without ``after`` it returns no events and the team's head,
    from which to follow."""
    limit = _limit(limit)
    if after is None:
        head = await db.fetch_one(
            "SELECT chain_epoch, team_seq FROM {{tables.chain_heads}} WHERE team_id = $1", team_id
        )
        position = Cursor(head["chain_epoch"], head["team_seq"]) if head else Cursor(1, 0)
        return Page([], position.encode())
    start = Cursor.decode(after)
    await project(db, team_id)
    conditions, arguments = _conditions(team_id, where)
    arguments += [start.chain_epoch, start.team_seq]
    conditions.append(f"(r.chain_epoch, r.team_seq) > (${len(arguments) - 1}, ${len(arguments)})")
    rows = await _rows(db, conditions, arguments, "ASC", limit)
    position = _position(rows[-1]) if rows else start
    return Page([_event(row) for row in rows], position.encode())


async def project(db: AsyncDatabaseManager, team_id: str) -> None:
    """Project the team's chain events that have no projection yet."""
    while True:
        rows = await db.fetch_all(
            "SELECT e.chain_epoch, e.team_seq, e.hook, e.signing_bytes"
            " FROM {{tables.chain_events}} e"
            " WHERE e.team_id = $1 AND NOT EXISTS ("
            "   SELECT 1 FROM {{tables.read_events}} r WHERE r.team_id = e.team_id"
            "   AND r.chain_epoch = e.chain_epoch AND r.team_seq = e.team_seq)"
            " ORDER BY e.chain_epoch, e.team_seq LIMIT $2",
            team_id,
            _PROJECTION_BATCH,
        )
        if not rows:
            return
        await db.executemany(
            "INSERT INTO {{tables.read_events}} (team_id, chain_epoch, team_seq, purged, hook,"
            " event_id, event_type, mediation, occurred_at, result_status, trace_id,"
            " actor_did_key, actor_did_aw, app_id, operation_id, job_id, dispatch_id,"
            " approval_id, grant_id, secret_id)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,"
            " $17, $18, $19, $20)"
            " ON CONFLICT (team_id, chain_epoch, team_seq) DO NOTHING",
            [_projection(team_id, row) for row in rows],
        )


def _projection(team_id: str, row: Mapping[str, Any]) -> tuple[Any, ...]:
    position = (team_id, row["chain_epoch"], row["team_seq"])
    if row["signing_bytes"] is None:
        return (*position, True, row["hook"], *([None] * 15))
    envelope = hook_envelope.open_envelope(bytes(row["signing_bytes"]))
    f = envelope.fields
    payload, actor, producer = f["payload"], f["actor"], f["producer"]
    return (
        *position,
        False,
        envelope.hook,
        envelope.event_id,
        payload.get(_EVENT_TYPE_FIELD[envelope.hook]),
        _mediation(envelope),
        datetime.strptime(f["occurred_at"], _TIME_LAYOUT).replace(tzinfo=UTC),
        f["result_status"],
        f["trace"]["id"],
        actor.get("did_key"),
        actor.get("did_aw"),
        producer.get("app_id"),
        *(payload.get(name) for name in REFERENCES),
    )


def _mediation(envelope: hook_envelope.Envelope) -> str:
    if envelope.producer_kind == "client":
        return "client"
    if envelope.producer_kind == "core" and envelope.fields["payload"].get("observed") is True:
        return "registry_observed"
    return "server"


def _conditions(team_id: str, where: EventFilter) -> tuple[list[str], list[Any]]:
    conditions = ["r.team_id = $1"]
    arguments: list[Any] = [team_id]

    def add(sql: str, value: Any) -> None:
        arguments.append(value)
        conditions.append(sql.replace("?", f"${len(arguments)}"))

    if where.needs_content():
        conditions.append("NOT r.purged AND e.signing_bytes IS NOT NULL")
    if where.actor is not None:
        add("(r.actor_did_key = ? OR r.actor_did_aw = ?)", where.actor)
    if where.event_id is not None:
        add("r.event_id = ?::uuid", where.event_id)
    if where.occurred_from is not None:
        add("r.occurred_at >= ?", where.occurred_from)
    if where.occurred_to is not None:
        add("r.occurred_at <= ?", where.occurred_to)
    for name in (
        "hook",
        "mediation",
        "event_type",
        "result_status",
        "app_id",
        "trace_id",
        *REFERENCES,
    ):
        value = getattr(where, name)
        if value is not None:
            add(f"r.{name} = ?", value)
    return conditions, arguments


async def _rows(
    db: AsyncDatabaseManager, conditions: list[str], arguments: list[Any], order: str, limit: int
) -> list[dict[str, Any]]:
    arguments = [*arguments, limit]
    return await db.fetch_all(
        "SELECT e.chain_epoch, e.team_seq, e.event_hash, e.received_at, e.hook,"
        " e.producer_origin, e.signing_bytes, e.purge_act"
        " FROM {{tables.read_events}} r JOIN {{tables.chain_events}} e"
        " ON e.team_id = r.team_id AND e.chain_epoch = r.chain_epoch AND e.team_seq = r.team_seq"
        f" WHERE {' AND '.join(conditions)}"
        f" ORDER BY r.chain_epoch {order}, r.team_seq {order} LIMIT ${len(arguments)}",
        *arguments,
    )


def _position(row: Mapping[str, Any]) -> Cursor:
    return Cursor(row["chain_epoch"], row["team_seq"])


def _event(row: Mapping[str, Any]) -> dict[str, Any]:
    skeleton = {
        "chain_epoch": row["chain_epoch"],
        "team_seq": row["team_seq"],
        "event_hash": row["event_hash"],
        "received_at": row["received_at"],
        "hook": row["hook"],
    }
    if row["signing_bytes"] is None:
        return skeleton | {
            "producer_origin": row["producer_origin"],
            "purged": True,
            "purge_act": row["purge_act"],
        }
    envelope = hook_envelope.open_envelope(bytes(row["signing_bytes"]))
    f = envelope.fields
    producer = {"kind": envelope.producer_kind}
    for name in ("origin", "app_id", "certificate_id"):
        if name in f["producer"]:
            producer[name] = f["producer"][name]
    return {
        "event_id": envelope.event_id,
        **skeleton,
        "event_type": f["payload"].get(_EVENT_TYPE_FIELD[envelope.hook]),
        "mediation": _mediation(envelope),
        "occurred_at": f["occurred_at"],
        "result_status": f["result_status"],
        "trace_id": f["trace"]["id"],
        "producer": producer,
        "actor": {name: f["actor"][name] for name in _ACTOR_FIELDS if name in f["actor"]},
        "payload": f["payload"],
        "purged": False,
    }
