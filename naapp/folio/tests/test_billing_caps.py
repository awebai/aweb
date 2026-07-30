from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from fastapi import HTTPException

from folio.auth import Principal
from folio.config import Settings
from folio.repository import (
    append_version,
    create_document,
    get_billing_status,
    get_document,
    list_documents,
    list_versions,
)


class FakeTransaction:
    def __init__(self, db: FakeDB) -> None:
        self.db = db

    async def __aenter__(self) -> FakeTransaction:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    async def execute(self, sql: str, *args: Any) -> None:
        await self.db.execute(sql, *args)

    async def fetch_one(self, sql: str, *args: Any) -> dict[str, Any] | None:
        return await self.db.fetch_one(sql, *args)


class FakeDB:
    def __init__(
        self,
        *,
        tier: str = "free",
        document_count: int = 0,
        version_count: int = 1,
        max_versions_per_doc: int | None = None,
        document_exists: bool = True,
    ) -> None:
        self.tier = tier
        self.document_count = document_count
        self.version_count = version_count
        self.max_versions_per_doc = max_versions_per_doc if max_versions_per_doc is not None else version_count
        self.document_exists = document_exists
        self.document_id = uuid4()
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append((sql, args))

    async def fetch_one(self, sql: str, *args: Any) -> dict[str, Any] | None:
        compact = " ".join(sql.split())
        if "SELECT tier FROM" in compact:
            return {"tier": self.tier}
        if "SELECT COUNT(*) AS n FROM {{tables.documents}} WHERE team_id" in compact:
            return {"n": self.document_count}
        if "COALESCE(MAX(version_count), 0)" in compact:
            return {"n": self.max_versions_per_doc}
        if "SELECT document_id FROM {{tables.documents}}" in compact:
            return {"document_id": self.document_id} if self.document_exists else None
        if "SELECT COUNT(*) AS n FROM {{tables.document_versions}}" in compact:
            return {"n": self.version_count}
        if "COALESCE(MAX(version_number), 0)" in compact:
            return {"n": self.version_count}
        if "JOIN {{tables.document_versions}}" in compact and "ORDER BY v.version_number DESC" in compact:
            return self._document_row()
        raise AssertionError(f"unexpected fetch_one SQL: {compact}")

    async def fetch_all(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        compact = " ".join(sql.split())
        if "FROM {{tables.documents}} d" in compact and "LEFT JOIN" in compact:
            return [
                {
                    "document_id": self.document_id,
                    "slug": "note",
                    "title": "Note",
                    "current_version": self.version_count,
                    "created_at": datetime.now(UTC),
                    "updated_at": datetime.now(UTC),
                }
            ]
        if "FROM {{tables.document_versions}}" in compact:
            return [
                {
                    "version_id": uuid4(),
                    "version_number": self.version_count,
                    "body": None,
                    "created_by_did_key": "did:key:zMember",
                    "created_by_did_aw": None,
                    "created_by_address": None,
                    "created_by_alias": "alice",
                    "certificate_id": "cert-1",
                    "created_by_editor_name": None,
                    "created_at": datetime.now(UTC),
                }
            ]
        raise AssertionError(f"unexpected fetch_all SQL: {compact}")

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self)

    def _document_row(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "document_id": self.document_id,
            "slug": "note",
            "title": "Note",
            "created_at": now,
            "updated_at": now,
            "version_id": uuid4(),
            "version_number": self.version_count,
            "body": "hello",
            "created_by_did_key": "did:key:zMember",
            "created_by_did_aw": None,
            "created_by_address": None,
            "created_by_alias": "alice",
            "certificate_id": "cert-1",
            "created_by_editor_name": None,
            "version_created_at": now,
        }


@pytest.fixture
def principal() -> Principal:
    return Principal(
        team_id="backend:example.com",
        did_key="did:key:zMember",
        did_aw=None,
        address="example.com/alice",
        alias="alice",
        certificate_id="cert-1",
        team_did_key="did:key:zTeam",
    )


def settings() -> Settings:
    return Settings(free_max_documents=3, free_max_versions_per_doc=50)


@pytest.mark.asyncio
async def test_get_billing_returns_tier_caps_and_usage(principal: Principal) -> None:
    db = FakeDB(tier="free", document_count=2, max_versions_per_doc=7)

    response = await get_billing_status(cast(Any, db), principal=principal, settings=settings())

    assert response == {
        "team_id": "backend:example.com",
        "tier": "free",
        "caps": {"max_documents": 3, "max_versions_per_doc": 50},
        "usage": {"documents": 2, "max_versions_per_doc": 7},
    }


@pytest.mark.asyncio
async def test_create_document_below_free_cap_is_allowed(principal: Principal) -> None:
    db = FakeDB(tier="free", document_count=2)

    response = await create_document(
        cast(Any, db),
        principal=principal,
        settings=settings(),
        slug="note",
        title="Note",
        body="hello",
    )

    assert response["slug"] == "note"
    assert any("INSERT INTO {{tables.documents}}" in sql for sql, _args in db.executed)


@pytest.mark.asyncio
async def test_create_document_at_free_cap_returns_structured_402(principal: Principal) -> None:
    db = FakeDB(tier="free", document_count=3)

    with pytest.raises(HTTPException) as raised:
        await create_document(
            cast(Any, db),
            principal=principal,
            settings=settings(),
            slug="note",
            title="Note",
            body="hello",
        )

    assert raised.value.status_code == 402
    assert raised.value.detail == {
        "code": "free_tier_limit_exceeded",
        "limit": "documents",
        "current": 3,
        "max": 3,
        "subscriptions_available": False,
        "message": "Free tier limit reached; subscriptions are not yet available.",
    }
    assert not any("INSERT INTO {{tables.documents}}" in sql for sql, _args in db.executed)


@pytest.mark.asyncio
async def test_active_tier_bypasses_document_cap(principal: Principal) -> None:
    db = FakeDB(tier="active", document_count=100)

    response = await create_document(
        cast(Any, db),
        principal=principal,
        settings=settings(),
        slug="note",
        title="Note",
        body="hello",
    )

    assert response["slug"] == "note"


@pytest.mark.asyncio
async def test_append_version_at_free_cap_returns_structured_402(principal: Principal) -> None:
    db = FakeDB(tier="free", version_count=50)

    with pytest.raises(HTTPException) as raised:
        await append_version(
            cast(Any, db),
            principal=principal,
            settings=settings(),
            slug="note",
            body="new body",
        )

    detail = cast(dict[str, Any], raised.value.detail)
    assert raised.value.status_code == 402
    assert detail["limit"] == "versions_per_doc"
    assert detail["current"] == 50
    assert detail["max"] == 50
    assert detail["subscriptions_available"] is False
    assert "not yet available" in detail["message"]


@pytest.mark.asyncio
async def test_active_tier_bypasses_version_cap(principal: Principal) -> None:
    db = FakeDB(tier="active", version_count=500)

    response = await append_version(
        cast(Any, db),
        principal=principal,
        settings=settings(),
        slug="note",
        body="new body",
    )

    assert response["current_version"] == 500
    assert any("INSERT INTO {{tables.document_versions}}" in sql for sql, _args in db.executed)


@pytest.mark.asyncio
async def test_reads_are_not_blocked_when_team_is_over_cap(principal: Principal) -> None:
    db = FakeDB(tier="free", document_count=100, version_count=500)

    assert (await get_document(cast(Any, db), principal=principal, slug="note"))["slug"] == "note"
    assert len(await list_documents(cast(Any, db), principal=principal)) == 1
    assert len(await list_versions(cast(Any, db), principal=principal, slug="note")) == 1
    assert not any("{{tables.subscriptions}}" in sql for sql, _args in db.executed)


def test_initial_migration_contains_subscription_projection_shape() -> None:
    migration = (Path(__file__).resolve().parents[1] / "src" / "folio" / "migrations" / "001_initial.sql").read_text()

    assert "CREATE TABLE IF NOT EXISTS {{tables.subscriptions}}" in migration
    assert "tier TEXT NOT NULL DEFAULT 'free'" in migration
    assert "stripe_customer_id TEXT" in migration
    assert "stripe_subscription_id TEXT" in migration
    assert "current_period_end TIMESTAMPTZ" in migration
    assert "last_event_id TEXT" in migration
