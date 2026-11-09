"""Reading a team's chain as its readers see it: projected events, filters,
pages and tail, on real PostgreSQL with real signed envelopes."""

from __future__ import annotations

import copy
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from awid.did import stable_id_from_public_key
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_logs import MIGRATIONS_MODULE, MIGRATIONS_PATH, read_store
from aweb_logs.ledger import LogsSigner, append, append_on, open_next_epoch
from aweb_logs.read_store import REFERENCES, Cursor, EventFilter, InvalidRead, query, tail

from .fixtures import (
    CORE_ORIGIN,
    CORE_SEED,
    LOGS_KID,
    LOGS_ORIGIN,
    LOGS_SEED,
    MEMBER_SEED,
    SECRETS_ORIGIN,
    SECRETS_SEED,
    TEAM_ID,
    did_key,
    signed_event,
)

SIGNER = LogsSigner(logs_origin=LOGS_ORIGIN, kid=LOGS_KID, signing_key=SigningKey(LOGS_SEED))
OTHER_TEAM = "other:example.com"
START = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
AGENT = did_key(MEMBER_SEED)
OTHER_AGENT = did_key(SigningKey(bytes(range(200, 232))).encode())
AGENT_AW = stable_id_from_public_key(bytes(SigningKey(MEMBER_SEED).verify_key))

_SECRET_USE: dict[str, Any] = {
    "v": 1,
    "type": "aweb.hook-event",
    "catalog": {"id": "aweb.hooks", "version": 1},
    "hook": "post-secret-use-hook",
    "trace": {"id": "0af7651916cd43dd8448eb211c80319c", "origin": "producer"},
    "producer": {
        "kind": "app",
        "origin": SECRETS_ORIGIN,
        "app_id": "secrets",
        "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
        "generation": 2,
        "kid": "hook-2026-10",
        "did_key": did_key(SECRETS_SEED),
    },
    "fired_at": "2026-10-20T12:00:01.002Z",
}


def secret_use(
    *,
    action: str = "completed",
    seq: int = 1,
    actor: str = AGENT,
    alias: str = "bond",
    team_id: str = TEAM_ID,
    trace_id: str = "0af7651916cd43dd8448eb211c80319c",
    occurred_at: str = "2026-10-20T12:00:01.000Z",
    result_status: str = "success",
    actor_aw: str | None = None,
    **payload: Any,
) -> tuple[bytes, str]:
    event = copy.deepcopy(_SECRET_USE)
    event["event_id"] = str(uuid.uuid4())
    event["team_id"] = team_id
    event["producer"]["seq"] = seq
    event["trace"]["id"] = trace_id
    event["occurred_at"] = occurred_at
    event["fired_at"] = occurred_at
    event["result_status"] = result_status
    event["actor"] = {
        "alias": alias,
        "attestations": [],
        "authority_mode": "team_cert",
        "certificate_id": "c_41",
        "did_key": actor,
    }
    if actor_aw is not None:
        event["actor"]["did_aw"] = actor_aw
    body: dict[str, Any] = {"action": action, "op_kind": "run_job"}
    if action == "completed":
        body |= {"disposition": "withheld", "undeclared_credential": False}
    event["payload"] = body | payload
    return hook_envelope.sign(SECRETS_SEED, event)


def certificate_observed(seq: int = 1) -> tuple[bytes, str]:
    event = {
        "v": 1,
        "type": "aweb.hook-event",
        "catalog": {"id": "aweb.hooks", "version": 1},
        "hook": "post-mutation-hook",
        "event_id": str(uuid.uuid4()),
        "trace": {"id": "5bf92f3577b34da6a3ce929d0e0e4736", "origin": "producer"},
        "team_id": TEAM_ID,
        "producer": {
            "kind": "core",
            "origin": CORE_ORIGIN,
            "kid": "hook-2026-10",
            "did_key": did_key(CORE_SEED),
            "seq": seq,
        },
        "actor": {"attestations": [], "authority_mode": "system"},
        "occurred_at": "2026-10-20T12:00:03.000Z",
        "fired_at": "2026-10-20T12:00:03.000Z",
        "result_status": "success",
        "payload": {
            "mutation_type": "membership.certificate_issued",
            "target_ref": "certificate:c_42",
            "certificate_id": "c_42",
            "certificate_sha256": "ab" * 32,
            "member_did_key": AGENT,
            "member_alias": "bond",
            "registry_origin": "https://api.awid.ai",
            "registry_recorded_at": "2026-10-20T12:00:02Z",
            "observed": True,
        },
    }
    return hook_envelope.sign(CORE_SEED, event)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="logs_read_store")
    await AsyncMigrationManager(
        database, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()
    yield database


async def _append(
    db: AsyncDatabaseManager, signed: tuple[bytes, str], *, team_id: str = TEAM_ID, minute: int = 0
) -> str:
    signing, signature = signed
    event = hook_envelope.verify(signing, signature, team_id=team_id)
    await append(
        db,
        SIGNER,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
        received_at=START + timedelta(minutes=minute),
    )
    return event.event_id


async def _chain_rows_read_by_catch_up(db: AsyncDatabaseManager) -> int:
    """The chain_events rows the read path's catch-up statement reads, from its
    executed plan. Index scans are forced so the count does not depend on the
    planner preferring a sequential scan of a small test table."""
    async with db.transaction() as tx:
        await tx.execute("SET LOCAL enable_seqscan = off")
        plan = await tx.fetch_value(
            "EXPLAIN (ANALYZE, FORMAT JSON) " + read_store._UNPROJECTED,
            TEAM_ID,
            read_store._PROJECTION_BATCH,
        )

    def read(node: dict[str, Any]) -> int:
        rows = 0
        if node.get("Relation Name", "").endswith("chain_events"):
            loops = node["Actual Loops"]
            rows += (node["Actual Rows"] + node.get("Rows Removed by Filter", 0)) * loops
        return rows + sum(read(child) for child in node.get("Plans", []))

    document = json.loads(plan) if isinstance(plan, str) else plan
    return read(document[0]["Plan"])


async def _unproject(db: AsyncDatabaseManager, *, after_seq: int) -> None:
    """Leave the team's events after ``after_seq`` unprojected, as events
    appended before the write path projected them are."""
    await db.execute(
        "DELETE FROM {{tables.read_events}} WHERE team_id = $1 AND team_seq > $2",
        TEAM_ID,
        after_seq,
    )


def _filter(**values: str) -> EventFilter:
    return EventFilter.from_query(values)


async def test_query_returns_each_event_newest_first_with_what_its_envelope_signed(
    db: AsyncDatabaseManager,
) -> None:
    core_id = await _append(db, signed_event("core"), minute=0)
    use_id = await _append(
        db,
        secret_use(job_id="job-7", dispatch_id="d-9", secret_id="sec-1", seq=1),
        minute=1,
    )

    page = await query(db, TEAM_ID, _filter())

    assert [event["event_id"] for event in page.events] == [use_id, core_id]
    use = page.events[0]
    assert use == {
        "event_id": use_id,
        "chain_epoch": 1,
        "team_seq": 2,
        "event_hash": use["event_hash"],
        "received_at": "2026-10-20T12:01:00.000Z",
        "hook": "post-secret-use-hook",
        "event_type": "completed",
        "mediation": "server",
        "occurred_at": "2026-10-20T12:00:01.000Z",
        "result_status": "success",
        "trace_id": "0af7651916cd43dd8448eb211c80319c",
        "producer": {
            "kind": "app",
            "origin": SECRETS_ORIGIN,
            "app_id": "secrets",
            "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
            "generation": 2,
        },
        "actor": {
            "authority_mode": "team_cert",
            "did_key": AGENT,
            "alias": "bond",
            "certificate_id": "c_41",
        },
        "payload": {
            "action": "completed",
            "op_kind": "run_job",
            "disposition": "withheld",
            "undeclared_credential": False,
            "job_id": "job-7",
            "dispatch_id": "d-9",
            "secret_id": "sec-1",
        },
        "purged": False,
    }
    assert page.events[1]["event_type"] == "task.updated"
    assert page.next_cursor is None


async def test_mediation_is_derived_from_the_producer_and_never_upgrades_a_client(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db, signed_event("core"))
    await _append(db, signed_event("client"))
    await _append(db, certificate_observed(seq=2))

    page = await query(db, TEAM_ID, _filter())
    assert [(e["hook"], e["mediation"]) for e in page.events] == [
        ("post-mutation-hook", "registry_observed"),
        ("post-command-hook", "client"),
        ("post-mutation-hook", "server"),
    ]
    client_only = await query(db, TEAM_ID, _filter(mediation="client"))
    assert [e["hook"] for e in client_only.events] == ["post-command-hook"]


@pytest.mark.parametrize(
    ("name", "match", "miss"),
    [
        ("job_id", {"job_id": "job-7"}, {"job_id": "job-8"}),
        ("dispatch_id", {"dispatch_id": "d-1"}, {"dispatch_id": "d-2"}),
        ("operation_id", {"operation_id": "op-1"}, {"operation_id": "op-2"}),
        ("approval_id", {"approval_id": "ap-1"}, {"approval_id": "ap-2"}),
        ("grant_id", {"grant_id": "g-1"}, {"grant_id": "g-2"}),
        ("secret_id", {"secret_id": "sec-1"}, {"secret_id": "sec-2"}),
    ],
)
async def test_each_correlation_reference_filters_by_exact_match(
    db: AsyncDatabaseManager, name: str, match: dict[str, str], miss: dict[str, str]
) -> None:
    wanted = await _append(db, secret_use(seq=1, **match))
    await _append(db, secret_use(seq=2, **miss))
    await _append(db, secret_use(seq=3))

    page = await query(db, TEAM_ID, _filter(**{name: match[name]}))
    assert [event["event_id"] for event in page.events] == [wanted]


async def test_actor_trace_type_status_and_hook_filters(db: AsyncDatabaseManager) -> None:
    refused = await _append(
        db,
        secret_use(
            action="refused",
            refusal_code="grant_revoked",
            result_status="denied",
            trace_id="1" * 32,
            seq=1,
        ),
    )
    other = await _append(db, secret_use(actor=OTHER_AGENT, alias="moneypenny", seq=2))
    await _append(db, signed_event("core"))

    assert [
        e["event_id"] for e in (await query(db, TEAM_ID, _filter(actor=OTHER_AGENT))).events
    ] == [other]
    assert [
        e["event_id"] for e in (await query(db, TEAM_ID, _filter(trace_id="1" * 32))).events
    ] == [refused]
    assert [
        e["event_id"] for e in (await query(db, TEAM_ID, _filter(event_type="refused"))).events
    ] == [refused]
    assert [
        e["event_id"] for e in (await query(db, TEAM_ID, _filter(result_status="denied"))).events
    ] == [refused]
    by_hook = await query(db, TEAM_ID, _filter(hook="post-secret-use-hook"))
    assert {e["event_id"] for e in by_hook.events} == {refused, other}


async def test_occurred_bounds_are_inclusive(db: AsyncDatabaseManager) -> None:
    early = await _append(db, secret_use(occurred_at="2026-10-20T12:00:01.000Z", seq=1))
    middle = await _append(db, secret_use(occurred_at="2026-10-20T12:00:02.000Z", seq=2))
    await _append(db, secret_use(occurred_at="2026-10-20T12:00:03.000Z", seq=3))

    page = await query(
        db,
        TEAM_ID,
        _filter(occurred_from="2026-10-20T12:00:01.000Z", occurred_to="2026-10-20T12:00:02.000Z"),
    )
    assert [e["event_id"] for e in page.events] == [middle, early]


async def test_pages_continue_from_their_cursor_without_repeating(db: AsyncDatabaseManager) -> None:
    ids = [await _append(db, secret_use(seq=i + 1)) for i in range(5)]

    first = await query(db, TEAM_ID, _filter(), limit=2)
    second = await query(db, TEAM_ID, _filter(), limit=2, before=first.next_cursor)
    third = await query(db, TEAM_ID, _filter(), limit=2, before=second.next_cursor)

    seen = [e["event_id"] for page in (first, second, third) for e in page.events]
    assert seen == list(reversed(ids))
    assert third.next_cursor is None


async def test_a_team_never_reads_another_teams_events(db: AsyncDatabaseManager) -> None:
    await _append(db, secret_use(job_id="job-7", team_id=OTHER_TEAM), team_id=OTHER_TEAM)

    assert (await query(db, TEAM_ID, _filter())).events == []
    assert (await query(db, TEAM_ID, _filter(job_id="job-7"))).events == []


async def test_a_purged_event_shows_only_its_skeleton_and_matches_no_content_filter(
    db: AsyncDatabaseManager,
) -> None:
    purged_id = await _append(db, secret_use(job_id="job-7", seq=1))
    # L5's purge, as the chain's schema defines it: content gone, the act named.
    await db.execute(
        "UPDATE {{tables.chain_events}} SET salt = NULL, signing_bytes = NULL, signature = NULL,"
        " purge_act = 'erase:1' WHERE team_id = $1 AND event_id = $2",
        TEAM_ID,
        uuid.UUID(purged_id),
    )

    page = await query(db, TEAM_ID, _filter())
    assert page.events == [
        {
            "chain_epoch": 1,
            "team_seq": 1,
            "event_hash": page.events[0]["event_hash"],
            "received_at": "2026-10-20T12:00:00.000Z",
            "hook": "post-secret-use-hook",
            "producer_origin": SECRETS_ORIGIN,
            "purged": True,
            "purge_act": "erase:1",
        }
    ]
    assert (await query(db, TEAM_ID, _filter(job_id="job-7"))).events == []


async def test_tail_starts_at_the_head_and_returns_only_later_events_oldest_first(
    db: AsyncDatabaseManager,
) -> None:
    await _append(db, secret_use(seq=1))
    start = await tail(db, TEAM_ID, _filter())
    assert start.events == [] and start.next_cursor is not None

    second = await _append(db, secret_use(seq=2), minute=1)
    third = await _append(db, secret_use(seq=3), minute=2)
    page = await tail(db, TEAM_ID, _filter(), after=start.next_cursor)
    assert [e["event_id"] for e in page.events] == [second, third]

    again = await tail(db, TEAM_ID, _filter(), after=page.next_cursor)
    assert again.events == [] and again.next_cursor == page.next_cursor


async def test_tail_of_an_empty_chain_waits_at_its_start(db: AsyncDatabaseManager) -> None:
    start = await tail(db, TEAM_ID, _filter())
    assert start.events == []
    first = await _append(db, secret_use(seq=1))
    assert [
        e["event_id"] for e in (await tail(db, TEAM_ID, _filter(), after=start.next_cursor)).events
    ] == [first]


@pytest.mark.parametrize(
    "values",
    [
        {"unknown": "x"},
        {"mediation": "human"},
        {"actor": "bond"},
        {"trace_id": "XYZ"},
        {"occurred_from": "2026-10-20T12:00:01Z"},
        {"job_id": "has space"},
        {"job_id": ""},
    ],
)
def test_a_malformed_filter_is_refused(values: dict[str, str]) -> None:
    with pytest.raises(InvalidRead):
        EventFilter.from_query(values)


@pytest.mark.parametrize("text", ["", "abc", "MDEuMg", "1.2", "LTEuMg"])
def test_a_malformed_cursor_is_refused(text: str) -> None:
    with pytest.raises(InvalidRead):
        Cursor.decode(text)


async def test_limit_is_bounded(db: AsyncDatabaseManager) -> None:
    for limit in (0, 201):
        with pytest.raises(InvalidRead):
            await query(db, TEAM_ID, _filter(), limit=limit)


async def test_catching_up_reads_only_the_events_not_yet_projected(
    db: AsyncDatabaseManager,
) -> None:
    for seq in range(1, 43):
        await _append(db, secret_use(seq=seq))
    await _unproject(db, after_seq=40)
    assert await _chain_rows_read_by_catch_up(db) == 2
    assert len((await query(db, TEAM_ID, _filter(), limit=50)).events) == 42
    assert await _chain_rows_read_by_catch_up(db) == 0


async def test_events_of_a_later_epoch_are_read_after_the_earlier_one(
    db: AsyncDatabaseManager,
) -> None:
    first = await _append(db, secret_use(seq=1))
    start = await tail(db, TEAM_ID, _filter())
    await query(db, TEAM_ID, _filter())
    await open_next_epoch(db, SIGNER, TEAM_ID, at=START + timedelta(minutes=1))
    second = await _append(db, secret_use(seq=2), minute=2)

    page = await tail(db, TEAM_ID, _filter(), after=start.next_cursor)
    assert [(e["event_id"], e["chain_epoch"]) for e in page.events] == [(second, 2)]
    newest = await query(db, TEAM_ID, _filter())
    assert [e["event_id"] for e in newest.events] == [second, first]


async def test_an_appended_event_is_readable_with_no_catch_up(
    db: AsyncDatabaseManager,
) -> None:
    appended = await _append(db, secret_use(seq=1))

    assert await _chain_rows_read_by_catch_up(db) == 0
    rows = await db.fetch_all(
        "SELECT event_id FROM {{tables.read_events}} WHERE team_id = $1", TEAM_ID
    )
    assert [str(row["event_id"]) for row in rows] == [appended]


async def test_projecting_in_the_appending_transaction_leaves_nothing_to_catch_up(
    db: AsyncDatabaseManager,
) -> None:
    earlier = await _append(db, secret_use(seq=1))
    await _unproject(db, after_seq=0)
    signing, signature = secret_use(seq=2)
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    async with db.transaction() as tx:
        await append_on(
            tx,
            SIGNER,
            event=event,
            signing_bytes=signing,
            signature=signature,
            key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
            received_at=START + timedelta(minutes=1),
        )

    # The earlier event, appended before projection ran in the write path, is
    # projected too: catch-up never skips a position below the highest one.
    assert await _chain_rows_read_by_catch_up(db) == 0
    rows = await db.fetch_all(
        "SELECT event_id FROM {{tables.read_events}} WHERE team_id = $1"
        " ORDER BY chain_epoch, team_seq",
        TEAM_ID,
    )
    assert [str(row["event_id"]) for row in rows] == [earlier, event.event_id]


async def test_a_projection_rolls_back_with_its_append(db: AsyncDatabaseManager) -> None:
    signing, signature = secret_use(seq=1)
    event = hook_envelope.verify(signing, signature, team_id=TEAM_ID)
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await append_on(
                tx,
                SIGNER,
                event=event,
                signing_bytes=signing,
                signature=signature,
                key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
                received_at=START,
            )
            raise RuntimeError("the effect failed")
    assert (await query(db, TEAM_ID, _filter())).events == []


# For each exact-identifier filter: the event fields that match it, the fields
# that miss it, and the filter value.
_POLLED = {
    "trace_id": ({"trace_id": "1" * 32}, {"trace_id": "2" * 32}, "1" * 32),
    **{name: ({name: "wanted"}, {name: "other"}, "wanted") for name in REFERENCES},
    "actor did:key": ({"actor": AGENT}, {"actor": OTHER_AGENT}, AGENT),
    "actor did:aw": ({"actor_aw": AGENT_AW}, {}, AGENT_AW),
}


async def _read_events_rows_read(db: AsyncDatabaseManager, statement: tuple[Any, ...]) -> int:
    """The read_events rows a read page's statement reads, from its executed
    plan, with index scans forced as in the catch-up measure."""
    sql, *arguments = statement
    await db.execute("ANALYZE {{tables.read_events}}")
    await db.execute("ANALYZE {{tables.chain_events}}")
    async with db.transaction() as tx:
        await tx.execute("SET LOCAL enable_seqscan = off")
        plan = await tx.fetch_value("EXPLAIN (ANALYZE, FORMAT JSON) " + sql, *arguments)

    def read(node: dict[str, Any]) -> int:
        rows = 0
        if node.get("Relation Name", "").endswith("read_events"):
            removed = node.get("Rows Removed by Filter", 0) + node.get(
                "Rows Removed by Index Recheck", 0
            )
            rows += (node["Actual Rows"] + removed) * node["Actual Loops"]
        return rows + sum(read(child) for child in node.get("Plans", []))

    document = json.loads(plan) if isinstance(plan, str) else plan
    return read(document[0]["Plan"])


@pytest.mark.parametrize("name", list(_POLLED))
async def test_a_filtered_read_reads_only_its_matching_events_past_its_cursor(
    db: AsyncDatabaseManager, name: str
) -> None:
    match, miss, value = _POLLED[name]
    where = _filter(**{name.split(" ")[0]: value})
    seq = iter(range(1, 1000))
    for _ in range(40):
        await _append(db, secret_use(seq=next(seq), **match))
    start = await tail(db, TEAM_ID, where)
    for _ in range(160):
        await _append(db, secret_use(seq=next(seq), **miss))
    for _ in range(2):
        await _append(db, secret_use(seq=next(seq), **match))
    await query(db, TEAM_ID, where)
    cursor = Cursor.decode(start.next_cursor or "")

    following = read_store._page(TEAM_ID, where, cursor, "ASC", 50)
    assert await _read_events_rows_read(db, following) == 2
    newest = read_store._page(TEAM_ID, where, None, "DESC", 2)
    assert await _read_events_rows_read(db, newest) == 2


async def test_one_projection_batch_projects_the_earliest_unprojected_events_only(
    db: AsyncDatabaseManager,
) -> None:
    ids = [await _append(db, secret_use(seq=seq)) for seq in range(1, 6)]
    await _unproject(db, after_seq=0)

    async with db.transaction() as tx:
        assert await read_store.project_batch(tx, TEAM_ID, limit=2) == 2

    rows = await db.fetch_all(
        "SELECT event_id FROM {{tables.read_events}} WHERE team_id = $1"
        " ORDER BY chain_epoch, team_seq",
        TEAM_ID,
    )
    assert [str(row["event_id"]) for row in rows] == ids[:2]
    assert await _chain_rows_read_by_catch_up(db) == 3
    assert [e["event_id"] for e in (await query(db, TEAM_ID, _filter())).events] == ids[::-1]
