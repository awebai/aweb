"""Capability links on real PostgreSQL, with an authority built from the
creator's grants that the conformance vectors state."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.capability_links import (
    LinkScope,
    Readable,
    apply_capability_link_migrations,
    mint,
)

AWEB_ROOT = Path(__file__).resolve().parents[4]
CAPABILITY = json.loads((AWEB_ROOT / "docs" / "vectors" / "link-capability-v1.json").read_text())
REQUESTS = json.loads((AWEB_ROOT / "docs" / "vectors" / "link-request-v1.json").read_text())

T0 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
CREATOR = "did:aw:2DHRM4x8em88KQdL3UCJtwoDBY5V"
SPONSOR = "did:aw:2bvkNehXHxb9NusXh7MbiUwn2vva"
SCOPE = LinkScope(team_id="backend:acme.com", installation_id="inst_01JB7Q", page_id="pg_4hd2")
KINDS = {
    "mark-cleaned": "edit",
    "request-cleaner": "intent",
    "refund": "edit",
    "approve-price": "answer",
}


@dataclass
class GrantedAuthority:
    """What each creator may read and do on the page, as a vector states it."""

    reads: dict[str, dict[str, Readable]] = field(default_factory=dict)
    actions: dict[str, set[str]] = field(default_factory=dict)
    assets: dict[str, set[str]] = field(default_factory=dict)
    agents: set[str] = field(default_factory=lambda: {SPONSOR})

    async def readable(self, tx, *, creator: str, page_id: str, collection: str) -> Readable | None:
        return self.reads.get(creator, {}).get(collection)

    async def can_read_asset(self, tx, *, creator: str, page_id: str, asset_id: str) -> bool:
        return asset_id in self.assets.get(creator, set())

    async def action_kind(self, tx, *, page_id: str, action_id: str) -> str | None:
        return KINDS.get(action_id)

    async def can_act(
        self, tx, *, creator: str, page_id: str, action_id: str, constraints: Mapping[str, Any]
    ) -> bool:
        return action_id in self.actions.get(creator, set())

    async def is_team_agent(self, tx, *, did: str) -> bool:
        return did in self.agents


def authority_from(creator: Mapping[str, Any]) -> GrantedAuthority:
    reads = {
        name: Readable(records=tuple(grant["records"]), fields=frozenset(grant["fields"]))
        for name, grant in creator["reads"].items()
    }
    return GrantedAuthority(reads={CREATOR: reads}, actions={CREATOR: set(creator["actions"])})


def request_from(link: Mapping[str, Any], *, now: datetime = T0) -> dict[str, Any]:
    """A mint request in the record's shape, from a vector's abstract link."""
    return {
        "mode": "live",
        "page_rev": None,
        "projection": {
            "collections": [
                {"collection": name, "record_ids": grant["records"], "fields": grant["fields"]}
                for name, grant in link["projection"].items()
            ],
            "assets": [],
        },
        "actions": [
            {"action_id": action["action_id"], "constraints": action["constraints"]}
            for action in link["actions"]
        ],
        "intent_sponsor_did": link.get("intent_sponsor", SPONSOR if _has_intent(link) else None),
        "one_use": False,
        "expires_at": _stamp(now + timedelta(seconds=link.get("expires_in_seconds", 7 * 86400))),
    }


def _has_intent(link: Mapping[str, Any]) -> bool:
    return any(KINDS.get(action["action_id"]) == "intent" for action in link["actions"])


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


DEFAULT_CREATOR = CAPABILITY["delegation"][0]["creator"]
DEFAULT_LINK = CAPABILITY["delegation"][0]["link"]


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="naapp_capability_links")
    await apply_ratelimit_migrations(database)
    await apply_capability_link_migrations(database)
    yield database


@pytest.fixture
def authority() -> GrantedAuthority:
    return authority_from(DEFAULT_CREATOR)


async def mint_link(
    db: AsyncDatabaseManager,
    authority: GrantedAuthority,
    request: Mapping[str, Any] | None = None,
    *,
    now: datetime = T0,
):
    async with db.transaction() as tx:
        return await mint(
            tx,
            authority,
            scope=SCOPE,
            creator=CREATOR,
            creator_certificate_id="0b4c2c1e-7f4e-4a53-9d43-2f1f0d2c6a11",
            request=request if request is not None else request_from(DEFAULT_LINK, now=now),
            now=now,
        )
