"""The reader's viewer on logs' console origin (audit-substrate.md §B5, §B8), on
real PostgreSQL with a real AWID registry, real owner acts and a software
passkey, served by the console router logs composes.

A reader signed in with its passkey browses its team's events, narrows them
by exact filters, follows new ones as they arrive and reads the integrity
report. Every event shows how it was recorded: an agent's own client events
are marked agent-reported, never shown as mediated fact. The integrity report
keeps what the signed chain proves apart from what this logs server observed
of delivery.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
)
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import TEAM_ID
from fastapi import FastAPI

from aweb_logs.ledger import append
from aweb_logs.reader_service import ReaderService

from .fixtures import signed_event
from .reader_world import (
    CONSOLE,
    LOGS,
    World,
    console_headed,
    enrolled_reader,
    world_fixture,  # noqa: F401
)
from .test_read_routes import login, other_team_event

VIEWER_PAGES = ("/events", "/follow", "/integrity")
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source"}


class Html(HTMLParser):
    """Each element of a page: its tag, its attributes, its text and the
    attributes of the elements around it."""

    def __init__(self, html: str) -> None:
        super().__init__()
        self.elements: list[dict[str, Any]] = []
        self._open: list[dict[str, Any]] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        element = {
            "tag": tag,
            "attrs": dict(attrs),
            "text": "",
            "within": [dict(e["attrs"]) for e in self._open],
        }
        self.elements.append(element)
        if tag not in _VOID:
            self._open.append(element)

    def handle_endtag(self, tag):
        for index in range(len(self._open) - 1, -1, -1):
            if self._open[index]["tag"] == tag:
                del self._open[index:]
                return

    def handle_data(self, data):
        for element in self._open:
            element["text"] += data

    def all(self, tag: str | None = None, **attrs: str) -> list[dict[str, str]]:
        """The attributes of each matching element; a bare attribute is ``""``."""
        return [
            {name: value or "" for name, value in e["attrs"].items()}
            for e in self._matching(tag, attrs)
        ]

    def first(self, tag: str | None = None, **attrs: str) -> dict[str, str]:
        return self.all(tag, **attrs)[0]

    def with_attribute(self, name: str) -> list[dict[str, Any]]:
        return [e for e in self.elements if name in e["attrs"]]

    def _matching(self, tag: str | None, attrs: dict[str, str]) -> list[dict[str, Any]]:
        return [
            e
            for e in self.elements
            if (tag is None or e["tag"] == tag)
            and all(e["attrs"].get(k.replace("_", "-")) == v for k, v in attrs.items())
        ]


def events_of(page: Html) -> list[dict[str, str]]:
    return [attrs for attrs in page.all("article") if "data-team-seq" in attrs]


def within_event(element: dict[str, Any], event_id: str) -> bool:
    return any(attrs.get("data-event-id") == event_id for attrs in element["within"])


@asynccontextmanager
async def console(world: World) -> AsyncIterator[httpx.AsyncClient]:
    """logs' console origin as :class:`ReaderService` composes it."""
    await apply_console_migrations(world.db)
    service = ReaderService(
        db=world.db,
        directory=world.directory,
        fence=world.fence,
        designations=world.designations,
        governance=world.governance,
        passkeys=world.passkeys,
        recorder=world.recorder,
        sessions=ConsoleSessions(
            world.db, passkeys=world.passkeys, scopes=world.directory.is_current_reader
        ),
        limiter=LoginLimiter(
            world.db, client_identity=ClientIdentity(), limit=12, window=timedelta(minutes=1)
        ),
        chain_keys=frozenset({world.signer.did_key}),
    )
    human = FastAPI()
    human.include_router(service.console_router)
    app = split_origins(FastAPI(), human, agent_origin=LOGS, human_origin=CONSOLE)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=CONSOLE
    ) as client:
        yield client


_SEQ = iter(range(1, 1_000_000))


async def recorded(world: World, kind: str, **fields: Any) -> str:
    """A ``core``, ``app`` or ``client`` event appended to the team's chain: its id."""
    event_id = str(uuid.uuid4())
    signing, signature = signed_event(kind, event_id=event_id, seq=next(_SEQ), **fields)
    event = verify(signing, signature, team_id=TEAM_ID)
    await append(
        world.db,
        world.signer,
        event=event,
        signing_bytes=signing,
        signature=signature,
        key_evidence={"did_key": event.producer_did_key, "kid": event.producer_kid},
        received_at=datetime.now(UTC),
    )
    return event_id


async def purged(world: World, event_id: str) -> int:
    """L5's purge, as the chain's schema defines it: content gone, the act
    named. Returns the event's position in the chain."""
    return await world.db.fetch_value(
        "UPDATE {{tables.chain_events}} SET salt = NULL, signing_bytes = NULL, signature = NULL,"
        " purge_act = 'erase:1' WHERE team_id = $1 AND event_id = $2 RETURNING team_seq",
        TEAM_ID,
        uuid.UUID(event_id),
    )


async def signed_in(world: World, human: httpx.AsyncClient) -> None:
    scope, _ = await enrolled_reader(world)
    assert (await login(world, human, scope)).status_code == 200


async def test_without_a_session_each_viewer_page_sends_the_browser_to_sign_in(world: World):
    await enrolled_reader(world)
    async with console(world) as human:
        for path in VIEWER_PAGES:
            response = await human.get(path)
            assert (response.status_code, response.headers["location"]) == (303, "/login"), path
            assert console_headed(response), path
        feed = await human.get("/follow/events", params={"after": "MS4w"})
    assert (feed.status_code, feed.json()) == (401, {"detail": "console_session_required"})


async def test_a_reader_sees_its_teams_events_newest_first_each_marked_by_its_mediation(
    world: World,
):
    async with console(world) as human:
        await signed_in(world, human)
        client = await recorded(world, "client")
        core = await recorded(world, "core")
        await other_team_event(world)
        response = await human.get("/events")
    assert response.status_code == 200
    assert console_headed(response)
    page = Html(response.text)
    shown = events_of(page)
    assert [event["data-event-id"] for event in shown[:2]] == [core, client]
    assert len(shown) == 4  # and the reader's own designation and enrolment
    mediation = {event["data-event-id"]: event["data-mediation"] for event in shown}
    assert mediation[client] == "client"
    assert set(mediation.values()) == {"client", "server"}
    marked = page.with_attribute("data-agent-reported")
    assert marked and all(within_event(element, client) for element in marked)
    window = page.first(id="revocation-window")
    assert window["data-seconds"] == "60"
    # Every fact shown has a value; one an event lacks is left out.
    assert all(element["text"].strip() for element in page.elements if element["tag"] == "dd")


async def test_a_reader_narrows_the_events_by_an_exact_filter_and_follows_a_trace(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        client = await recorded(world, "client")
        app = await recorded(world, "app")
        await other_team_event(world)
        narrowed = Html((await human.get("/events", params={"mediation": "client"})).text)
        # A submitted filter form sends its empty fields too.
        submitted = Html(
            (await human.get("/events", params={"mediation": "client", "actor": ""})).text
        )
        everything = Html((await human.get("/events")).text)
        trace = next(
            element
            for element in everything.with_attribute("data-filter")
            if element["attrs"]["data-filter"] == "trace_id" and within_event(element, app)
        )
        followed = await human.get(trace["attrs"]["href"])
    assert [event["data-event-id"] for event in events_of(narrowed)] == [client]
    assert "selected" in narrowed.first("option", value="client")
    assert [event["data-event-id"] for event in events_of(submitted)] == [client]
    assert urlsplit(trace["attrs"]["href"]).path == "/events"
    assert [event["data-event-id"] for event in events_of(Html(followed.text))] == [app]


async def test_a_reader_pages_back_through_older_events_keeping_its_filter(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        oldest, middle, newest = [await recorded(world, "client") for _ in range(3)]
        first = Html((await human.get("/events?mediation=client&limit=2")).text)
        older = first.first("a", id="older")["href"]
        second = Html((await human.get(older)).text)
    assert [event["data-event-id"] for event in events_of(first)] == [newest, middle]
    assert dict(parse_qsl(urlsplit(older).query))["mediation"] == "client"
    assert [event["data-event-id"] for event in events_of(second)] == [oldest]
    assert second.all("a", id="older") == []


async def test_a_filter_the_reader_may_not_ask_for_shows_no_events(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(world, "client")
        for query in ({"mediation": "everything"}, {"unknown": "1"}, {"cursor": "nonsense"}):
            response = await human.get("/events", params=query)
            assert response.status_code == 400, query
            assert console_headed(response), query
            assert events_of(Html(response.text)) == [], query


async def test_a_purged_event_shows_its_skeleton_and_purging_act_without_content(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        team_seq = await purged(world, await recorded(world, "client"))
        page = Html((await human.get("/events")).text)
    event = page.first("article", data_team_seq=str(team_seq))
    assert "data-purged" in event
    assert "data-event-id" not in event
    inside = [
        element
        for element in page.elements
        if any(attrs.get("data-team-seq") == str(team_seq) for attrs in element["within"])
    ]
    assert [e["attrs"]["data-purge-act"] for e in inside if "data-purge-act" in e["attrs"]] == [
        "erase:1"
    ]
    assert not any("data-payload" in e["attrs"] for e in inside)


async def test_follow_shows_only_the_matching_events_appended_after_the_page_loaded(
    world: World,
):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(world, "client")
        page = Html((await human.get("/follow", params={"mediation": "client"})).text)
        follow = page.first(id="follow")
        client = await recorded(world, "client")
        await recorded(world, "core")

        async def feed(after: str) -> Html:
            source = urlsplit(follow["data-source"])
            query = dict(parse_qsl(source.query)) | {"after": after}
            response = await human.get(source.path + "?" + urlencode(query))
            assert response.status_code == 200
            assert console_headed(response)
            return Html(response.text)

        arrived = await feed(follow["data-after"])
        position = arrived.first("ol")["data-after"]
        quiet = await feed(position)
    assert events_of(page) == []
    assert [event["data-event-id"] for event in events_of(arrived)] == [client]
    assert position != follow["data-after"]
    assert events_of(quiet) == []
    assert quiet.first("ol")["data-after"] == position


async def test_integrity_separates_the_verified_chain_from_what_this_server_observed(
    world: World,
):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(world, "core")
        team_seq = await purged(world, await recorded(world, "client"))
        await recorded(world, "app")
        response = await human.get("/integrity")
        unknown = await human.get("/integrity", params={"chain_epoch": "99"})
    assert response.status_code == 200
    assert console_headed(response)
    page = Html(response.text)
    chain = page.first("section", id="chain")
    assert chain["data-intact"] == "true"
    [purged_range] = [element["attrs"] for element in page.with_attribute("data-purged-range")]
    assert (purged_range["data-from"], purged_range["data-to"], purged_range["data-act"]) == (
        str(team_seq),
        str(team_seq),
        "erase:1",
    )
    observed = page.first("section", id="observed")
    assert observed["data-scope"] == "observed_internal_only"
    sections = {element["attrs"].get("id"): element for element in page.elements}
    assert not any(attrs.get("id") == "chain" for attrs in sections["observed"]["within"])
    assert not any(attrs.get("id") == "observed" for attrs in sections["chain"]["within"])
    assert unknown.status_code == 404
    assert console_headed(unknown)


async def test_integrity_refuses_an_epoch_that_is_not_a_chain_epoch(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        for epoch in ("0", "01", "-1", "\u00b2", "1" * 5000, str(2**31), str(2**63)):
            response = await human.get("/integrity", params={"chain_epoch": epoch})
            assert response.status_code == 400, epoch[:20]
            assert console_headed(response), epoch[:20]


HOSTILE = '<img src=x onerror="alert(1)">'


async def test_a_value_recorded_in_an_event_is_shown_as_text(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(
            world,
            "client",
            payload={"command": HOSTILE, "command_class": HOSTILE, HOSTILE: HOSTILE},
        )
        response = await human.get("/events")
    page = Html(response.text)
    assert page.all("img") == []
    assert sum(HOSTILE in element["text"] for element in page.elements) >= 3


async def test_a_reader_filters_by_a_utc_day_or_moment_written_as_people_write_it(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        core = await recorded(world, "core")  # 2026-10-20T12:00:00.412Z
        app = await recorded(world, "app")  # 2026-10-20T12:00:01.000Z
        client = await recorded(world, "client")  # 2026-10-20T12:00:02.000Z
        day = Html(
            (
                await human.get(
                    "/events", params={"occurred_from": "2026-10-20", "occurred_to": "2026-10-20"}
                )
            ).text
        )
        moment = Html(
            (
                await human.get(
                    "/events",
                    params={
                        "occurred_from": "2026-10-20T12:00:01Z",
                        "occurred_to": "2026-10-20 12:00:01",
                    },
                )
            ).text
        )
        before = Html((await human.get("/events", params={"occurred_to": "2026-10-19"})).text)
    assert [event["data-event-id"] for event in events_of(day)] == [client, app, core]
    assert [event["data-event-id"] for event in events_of(moment)] == [app]
    assert events_of(before) == []
    for name in ("occurred_from", "occurred_to"):
        field = day.first("input", id=f"filter-{name}")
        described = field["aria-describedby"].split()
        assert described and all(day.all(id=ident) for ident in described)


async def test_a_value_that_cannot_be_used_is_marked_on_the_form_with_the_rest_kept(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(world, "client")
        responses = {
            path: await human.get(
                path,
                params={
                    "event_type": "task.updated",
                    "occurred_from": "yesterday",
                    "mediation": "client",
                },
            )
            for path in ("/events", "/follow")
        }
    for path, response in responses.items():
        assert response.status_code == 400, path
        assert console_headed(response), path
        page = Html(response.text)
        assert events_of(page) == [], path
        assert page.all(id="follow") == [], path
        refused = page.first("input", id="filter-occurred_from")
        assert refused["value"] == "yesterday", path
        assert refused["aria-invalid"] == "true", path
        assert all(page.all(id=ident) for ident in refused["aria-describedby"].split()), path
        kept = page.first("input", id="filter-event_type")
        assert kept["value"] == "task.updated", path
        assert "aria-invalid" not in kept, path
        assert "selected" in page.first("option", value="client"), path


async def test_a_moment_finer_than_events_are_recorded_is_refused_not_rounded(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        core = await recorded(world, "core")  # 2026-10-20T12:00:00.412Z
        at = Html(
            (await human.get("/events", params={"occurred_from": "2026-10-20T12:00:00.412Z"})).text
        )
        after = Html(
            (await human.get("/events", params={"occurred_from": "2026-10-20T12:00:00.413Z"})).text
        )
        finer = await human.get("/events", params={"occurred_from": "2026-10-20T12:00:00.412001Z"})
    assert core in [event["data-event-id"] for event in events_of(at)]
    assert core not in [event["data-event-id"] for event in events_of(after)]
    assert finer.status_code == 400
    page = Html(finer.text)
    assert events_of(page) == []
    assert page.first("input", id="filter-occurred_from")["aria-invalid"] == "true"


async def test_integrity_offers_the_whole_log_to_take_away(world: World):
    async with console(world) as human:
        await signed_in(world, human)
        await recorded(world, "client")
        page = Html((await human.get("/integrity")).text)
        link = page.first("a", id="export")
        bundle = await human.get(link["href"])
    assert "download" in link
    assert bundle.status_code == 200
    assert bundle.headers["content-type"].split(";")[0] == "application/jsonl"
    assert b'"type":"aweb.logs-export"' in bundle.content.splitlines()[0]
