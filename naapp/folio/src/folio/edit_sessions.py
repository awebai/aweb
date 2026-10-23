"""Single-use editor openers and revocable, durable page sessions."""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_naapp.runtime.team_auth import MembershipProof
from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from folio.installation_access import capability_permit, require_binding
from folio.installation_access import refusal as installation_refusal

SESSION_HEADER = "X-Folio-Edit-Session"


def unavailable() -> HTTPException:
    return HTTPException(status_code=404, detail="Presentation not found")


def secret_hash(value: str | None) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise unavailable()
    return hashlib.sha256(value.encode("ascii")).digest()


async def member_proof(runtime: NaappRuntime, row: dict[str, Any]) -> MembershipProof:
    key = row.get("creator_team_did_key")
    if not key:
        raise unavailable()
    return await runtime.check_current_member(
        row["team_id"],
        certificate_id=row["certificate_id"],
        team_did_key=key,
    )


def require_proof(row: dict[str, Any], proof: MembershipProof) -> None:
    now = time.monotonic()  # Re-read after the lock, not before waiting for it.
    if (
        proof.team_id != row["team_id"]
        or proof.certificate_id != row["certificate_id"]
        or proof.team_did_key != row["creator_team_did_key"]
        or not all(math.isfinite(t) for t in (proof.checked_at, proof.fresh_until, now))
        or not 0 <= proof.fresh_until - proof.checked_at <= 60
        or not proof.checked_at <= now <= proof.fresh_until
    ):
        raise unavailable()


async def exchange(
    db: AsyncDatabaseManager,
    runtime: NaappRuntime,
    *,
    link_id: str,
    opener: str | None,
) -> tuple[str, dict[str, Any]]:
    digest = secret_hash(opener)
    evidence = await db.fetch_one(
        """SELECT p.*, d.team_id FROM {{tables.presentation_links}} p
        JOIN {{tables.documents}} d ON d.document_id=p.document_id
        WHERE p.token=$1 AND p.opener_sha256=$2 AND p.editable IS TRUE
          AND p.consumed_at IS NULL AND p.revoked_at IS NULL
          AND p.expires_at>NOW() AND p.expires_at<=p.created_at+interval '300 seconds'""",
        link_id,
        digest,
    )
    if evidence is None:
        raise unavailable()
    permit = await capability_permit(db, runtime, link_id=link_id)
    try:
        proof = await member_proof(runtime, dict(evidence))
    except HTTPException as error:
        if error.status_code == 403:
            raise unavailable() from None
        raise
    credential = secrets.token_urlsafe(32)
    async with installation_transaction(db) as tx:
        await permit.check(tx)
        # UPDATE's predicate is rechecked after any concurrent updater commits.
        consumed = await tx.fetch_one(
            """UPDATE {{tables.presentation_links}} SET consumed_at=NOW()
            WHERE token=$1 AND opener_sha256=$2 AND editable IS TRUE
              AND consumed_at IS NULL AND revoked_at IS NULL
              AND expires_at>clock_timestamp() AND expires_at<=created_at+interval '300 seconds'
            RETURNING *""",
            link_id,
            digest,
        )
        if consumed is None:
            raise unavailable()
        row = dict(consumed)
        row["team_id"] = evidence["team_id"]
        require_proof(row, proof)
        require_binding(permit, row)
        await tx.execute(
            """INSERT INTO {{tables.edit_sessions}} (credential_hash,link_id,document_id,installation_id)
            VALUES ($1,$2,$3,$4)""",
            secret_hash(credential),
            link_id,
            row["document_id"],
            permit.admitted.installation_id,
        )
        current = await tx.fetch_one(
            """SELECT body,version_number FROM {{tables.document_versions}}
            WHERE document_id=$1 ORDER BY version_number DESC LIMIT 1""",
            row["document_id"],
        )
        if current is None:
            raise unavailable()
        row.update(dict(current))
    return credential, row


_SESSION = """SELECT p.*, d.team_id, d.slug, s.installation_id AS session_installation_id,
    s.installation_refused AS session_installation_refused, s.created_at AS session_created_at
    FROM {{tables.edit_sessions}} s
    JOIN {{tables.presentation_links}} p ON p.token=s.link_id AND p.document_id=s.document_id
    JOIN {{tables.documents}} d ON d.document_id=s.document_id
    WHERE s.credential_hash=$1 AND p.token=$2 AND p.editable IS TRUE
      AND s.revoked_at IS NULL AND p.revoked_at IS NULL"""


@asynccontextmanager
async def access(
    db: AsyncDatabaseManager,
    runtime: NaappRuntime,
    *,
    link_id: str,
    credential: str | None,
    write: bool = False,
) -> AsyncIterator[tuple[TransactionManager, dict[str, Any]]]:
    digest = secret_hash(credential)
    evidence = await db.fetch_one(_SESSION, digest, link_id)
    if evidence is None:
        raise unavailable()
    permit = await capability_permit(db, runtime, link_id=link_id, session_hash=digest)
    try:
        proof = await member_proof(runtime, dict(evidence))
    except HTTPException as error:
        if error.status_code == 403:
            # A departed/replaced certificate cannot resume this session later.
            await db.execute(
                "UPDATE {{tables.edit_sessions}} SET revoked_at=NOW() WHERE credential_hash=$1",
                digest,
            )
            raise unavailable() from None
        raise
    async with installation_transaction(db) as tx:
        await permit.check(tx)
        lock = "FOR UPDATE OF p,d,s" if write else "FOR SHARE OF p,d,s"
        selected = await tx.fetch_one(_SESSION + " " + lock, digest, link_id)
        if selected is None:
            raise unavailable()
        row = dict(selected)
        require_proof(row, proof)
        require_binding(permit, row)
        require_binding(permit, row, session=True)
        yield tx, row


@asynccontextmanager
async def installation_transaction(db: AsyncDatabaseManager):
    try:
        async with db.transaction() as tx:
            yield tx
    except InstallationRefused as error:
        raise installation_refusal(error) from None
