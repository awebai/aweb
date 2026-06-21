"""Real-Postgres flow for proposal minting (.14.6).

A profile proposal carries the base it evolves from and the new version's content;
approve verifies the base is still current (reject-if-stale) and mints a new shelf
version, returning the minted triple so aw can update ref.json + re-materialize.
Skips when no Postgres is configured.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.blueprint import parse_profile_payload
from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, PROFILE_PAYLOAD_SCHEMA, collect_files
from library.models import ProposalCreateRequest
from library.repository import (
    approve_proposal,
    create_proposal,
    import_to_shelf,
    list_shelf,
    publish_blueprint,
)

_SOURCE = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"
_BASE_DIGEST = "sha256:b84396c46b66559e0a881f9cd1e85acb8e531296e45dcc6398c695841ecfcbe0"


def _bumped_coordinator_payload(new_version: str) -> list[dict[str, str]]:
    """The coordinator profile-payload with profile.yaml's version bumped (the
    deliberate version bump a minting proposal carries)."""
    files = collect_files(_SOURCE / "profiles" / "coordinator")
    out: list[dict[str, str]] = []
    for entry in files:
        if entry["path"] == "profile.yaml":
            content = entry["content_utf8"].replace("version: 0.1.0", f"version: {new_version}")
            out.append(
                {
                    "content_utf8": content,
                    "path": "profile.yaml",
                    "sha256": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
                }
            )
        else:
            out.append(entry)
    return out


async def _publish_and_import(db) -> None:
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        _TEAM,
        "did:key:zMintTest",
    )
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    await publish_blueprint(
        db, principal=principal, payload={"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA}
    )
    await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=None,
    )


async def test_approve_mints_new_shelf_version(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")

    bumped = _bumped_coordinator_payload("0.2.0")
    expected_digest = parse_profile_payload(bumped).digest
    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            base_profile_version="0.1.0",
            base_profile_digest=_BASE_DIGEST,
            content={"schema": PROFILE_PAYLOAD_SCHEMA, "files": bumped},
            summary="Sharpen the mission",
        ),
    )
    assert proposal["status"] == "open"

    approved = await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert approved["status"] == "approved"
    minted = approved["minted"]
    assert minted["profile_ref"] == "coordinator"
    assert minted["version"] == "0.2.0"
    assert minted["digest"] == expected_digest
    assert minted["supersedes_profile_version"] == "0.1.0"
    assert minted["supersedes_profile_digest"] == _BASE_DIGEST

    # The shelf's latest coordinator version is now the minted one; provenance and
    # the source pin are unchanged (local evolution, not a source sync).
    shelf = await list_shelf(db, principal=principal)
    coordinator = next(p for p in shelf["profiles"] if p["profile_ref"] == "coordinator")
    assert coordinator["version"] == "0.2.0"
    assert coordinator["digest"] == expected_digest
    assert coordinator["source_blueprint_ref"] == "aweb.engineering"


async def test_approve_rejects_stale_base(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")

    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            base_profile_version="0.1.0",
            base_profile_digest="sha256:staleimaginarybase",
            content={"schema": PROFILE_PAYLOAD_SCHEMA, "files": _bumped_coordinator_payload("0.2.0")},
        ),
    )
    with pytest.raises(HTTPException) as excinfo:
        await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert excinfo.value.status_code == 409


async def test_approve_rejects_minting_an_existing_version(migrated_db) -> None:
    # Mint 0.2.0, then a fresh proposal whose content version is 0.1.0 (already a
    # shelf version) must 409 — a version's digest is immutable, never overwritten.
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")

    first = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            base_profile_version="0.1.0",
            base_profile_digest=_BASE_DIGEST,
            content={"schema": PROFILE_PAYLOAD_SCHEMA, "files": _bumped_coordinator_payload("0.2.0")},
        ),
    )
    minted = (await approve_proposal(db, principal=principal, proposal_id=first["proposal_id"]))["minted"]

    # Base is now the current 0.2.0; propose content under the already-existing 0.1.0.
    colliding = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            base_profile_version=minted["version"],
            base_profile_digest=minted["digest"],
            content={"schema": PROFILE_PAYLOAD_SCHEMA, "files": _bumped_coordinator_payload("0.1.0")},
        ),
    )
    with pytest.raises(HTTPException) as excinfo:
        await approve_proposal(db, principal=principal, proposal_id=colliding["proposal_id"])
    assert excinfo.value.status_code == 409
