"""Folio's capability rows consume the shared installation permit/fence."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from uuid import UUID

from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.installation import InstallationPermit, InstallationRefused
from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from folio.link_secrets import read_only_link_key

if TYPE_CHECKING:
    from folio.repository import TeamImage


def refusal(error: InstallationRefused) -> HTTPException:
    return HTTPException(
        status_code=503 if error.status == 503 else 404, detail={"code": error.code}
    )


def require_binding(permit: InstallationPermit, row: dict, *, session: bool = False) -> str:
    prefix = "session_" if session else ""
    return permit.bind(
        installation_id=row[prefix + "installation_id"],
        created_at=row[prefix + "created_at"],
        refused=row[prefix + "installation_refused"],
    )


async def capability_permit(
    db: AsyncDatabaseManager,
    runtime: NaappRuntime,
    *,
    link_id: str,
    session_hash: bytes | None = None,
) -> InstallationPermit:
    """Persist legacy adoption/refusal before an access transaction can raise.

    The shared fence always locks first. Every caller checks the returned
    permit again in its own content/session transaction, before resource locks.
    No network occurs while those resource locks are held.
    """
    query = """SELECT p.*, d.team_id FROM {{tables.presentation_links}} p
        JOIN {{tables.documents}} d ON d.document_id=p.document_id
        WHERE p.token=$1 AND p.revoked_at IS NULL"""
    parameters: list[str | bytes] = [link_id]
    lock = " FOR UPDATE OF p"
    if session_hash is not None:
        query = """SELECT p.*, d.team_id, s.installation_id AS session_installation_id,
            s.installation_refused AS session_installation_refused, s.created_at AS session_created_at
            FROM {{tables.presentation_links}} p
            JOIN {{tables.documents}} d ON d.document_id=p.document_id
            JOIN {{tables.edit_sessions}} s ON s.link_id=p.token AND s.document_id=p.document_id
            WHERE p.token=$1 AND s.credential_hash=$2 AND p.editable IS TRUE
              AND p.revoked_at IS NULL AND s.revoked_at IS NULL"""
        parameters.append(session_hash)
        lock = " FOR UPDATE OF p,s"
    evidence = await db.fetch_one(query, *parameters)
    if evidence is None:
        raise HTTPException(404, detail="Presentation not found")
    if evidence["installation_refused"] or (
        session_hash is not None and evidence["session_installation_refused"]
    ):
        raise HTTPException(404, detail={"code": "installation_binding_refused"})
    try:
        permit = await runtime.installation_fence().permit(evidence["team_id"])
        denied = None
        async with permit.transaction() as tx:
            selected = await tx.fetch_one(query + lock, *parameters)
            if selected is None:
                raise HTTPException(404, detail="Presentation not found")
            row = dict(selected)
            for is_session in [False, True] if session_hash is not None else [False]:
                try:
                    bound = require_binding(permit, row, session=is_session)
                except InstallationRefused as error:
                    if error.status == 503:
                        raise
                    # Commit the refusal; raising inside this tx would roll it back.
                    if is_session:
                        await tx.execute(
                            "UPDATE {{tables.edit_sessions}} SET installation_refused=TRUE WHERE credential_hash=$1",
                            session_hash,
                        )
                    else:
                        await tx.execute(
                            "UPDATE {{tables.presentation_links}} SET installation_refused=TRUE WHERE token=$1",
                            link_id,
                        )
                    denied = error
                    break
                if row[("session_" if is_session else "") + "installation_id"] is None:
                    if is_session:
                        await tx.execute(
                            "UPDATE {{tables.edit_sessions}} SET installation_id=$2 WHERE credential_hash=$1",
                            session_hash,
                            bound,
                        )
                    else:
                        await tx.execute(
                            "UPDATE {{tables.presentation_links}} SET installation_id=$2 WHERE token=$1",
                            link_id,
                            bound,
                        )
        if denied is not None:
            raise denied
        return permit
    except InstallationRefused as error:
        raise refusal(error) from None


@asynccontextmanager
async def live_presentation(
    db: AsyncDatabaseManager, *, runtime: NaappRuntime, token: str
) -> AsyncIterator[tuple[TransactionManager, str]]:
    """A transaction in which the read-only link opened by ``token`` is bound to
    the current installation; yields it with the link's stored key.

    Everything served under the link, its page and the images that page shows,
    passes this check (docs/sot.md §1, Images), and the link must still be live
    when the content has been read.
    """
    link_key = read_only_link_key(token)
    permit = await capability_permit(db, runtime, link_id=link_key)
    try:
        async with permit.transaction() as tx:
            selected = await tx.fetch_one(
                "SELECT * FROM {{tables.presentation_links}} WHERE token=$1 FOR SHARE", link_key
            )
            if selected is None:
                raise HTTPException(404, detail="Presentation not found")
            require_binding(permit, dict(selected))
            yield tx, link_key
            await require_unexpired(tx, link_key=link_key)
    except InstallationRefused as error:
        raise refusal(error) from None


async def require_unexpired(tx: TransactionManager, *, link_key: str) -> None:
    """Refuse unless the link is unrevoked and before its deadline on live time.

    NOW() is fixed when the transaction starts, and a read can then wait on
    installation and link locks; clock_timestamp() is read after every wait, so
    nothing is served past the link's expiry (docs/sot.md §7, Lifetime).
    """
    live = await tx.fetch_one(
        """SELECT 1 FROM {{tables.presentation_links}}
        WHERE token=$1 AND revoked_at IS NULL AND expires_at > clock_timestamp()""",
        link_key,
    )
    if live is None:
        raise HTTPException(404, detail="Presentation not found")


async def presented_document(
    db: AsyncDatabaseManager, *, runtime: NaappRuntime, token: str
) -> dict:
    from folio.repository import get_presented_document

    async with live_presentation(db, runtime=runtime, token=token) as (tx, link_key):
        return await get_presented_document(tx, link_key=link_key)


async def presented_image(
    db: AsyncDatabaseManager, *, runtime: NaappRuntime, token: str, asset_id: UUID
) -> TeamImage:
    """An image the live read-only link shows: one its pinned version embeds, or the team logo."""
    from folio.repository import get_presented_document, get_team_image

    async with live_presentation(db, runtime=runtime, token=token) as (tx, link_key):
        presented = await get_presented_document(tx, link_key=link_key)
        if asset_id not in shown_image_ids(presented):
            raise HTTPException(404, detail="Asset not found")
        return await get_team_image(tx, team_id=presented["team_id"], asset_id=asset_id)


def shown_image_ids(presented: dict) -> set[UUID]:
    """The images a presented page shows: its body's image assets and the team logo."""
    shown = {
        asset_id
        for asset_id, asset in presented["allowed_assets"].items()
        if asset["kind"] == "image"
    }
    logo = (presented.get("theme") or {}).get("logo_asset_id")
    if logo is not None:
        shown.add(logo)
    return shown
