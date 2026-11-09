"""Internal handoff storage grants nothing, on owned PostgreSQL."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key

from aweb_naapp.console import apply_console_migrations
from aweb_naapp.console.handoff_store import HandoffStore, parse_start
from aweb_naapp.console.handoff_wire import HandoffWireRefused

ORIGIN = "https://console.example"


def start_body(**changes):
    _, public = generate_keypair()
    key = did_from_public_key(public)
    return {
        "v": 1,
        "purpose": "session",
        "client_key": key,
        "return": "loopback",
        "redirect_uri": "http://127.0.0.1:54321/callback",
        "verifier_sha256": hashlib.sha256(b"ephemeral verifier text").hexdigest(),
        "scope": {
            "installation_id": "00000000-0000-4000-8000-000000000001",
            "role": "example.owner",
            "principal": stable_id_from_did_key(key),
        },
        **changes,
    }


@pytest.fixture
async def handoff_db(test_db_factory):
    db = await test_db_factory.create_db(suffix="handoffs", schema="app")
    await apply_console_migrations(db)
    return db


async def test_create_returns_only_a_bounded_handoff_reference(handoff_db):
    before = datetime.now(UTC)
    body = start_body()
    result = await HandoffStore(handoff_db).create(parse_start(body))
    assert set(result) == {"handoff_id", "expires_at"}
    expires = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
    assert before < expires <= datetime.now(UTC) + timedelta(minutes=10)
    row = await handoff_db.fetch_one(
        "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid", result["handoff_id"]
    )
    assert bytes(row["verifier_sha256"]).hex() == body["verifier_sha256"]
    assert row["redirect_uri"] == body["redirect_uri"]
    assert row["completed_at"] is None and row["released_at"] is None
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0


@pytest.mark.parametrize(
    "change,detail",
    [
        ({"redirect_uri": "https://attacker.example/callback"}, "redirect_uri_refused"),
        ({"return": "user_code"}, "handoff_invalid"),
        ({"extra": "unknown"}, "handoff_invalid"),
        ({"verifier_sha256": "not-a-digest"}, "handoff_invalid"),
    ],
)
async def test_refused_creation_never_leaves_a_handoff(handoff_db, change, detail):
    with pytest.raises(HandoffWireRefused) as refused:
        parse_start(start_body(**change))
    assert str(refused.value) == detail
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_handoffs}}") == 0
