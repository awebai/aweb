"""Current creator evidence for read-only document table access."""

from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from folio import edit_sessions
from folio.installation_access import capability_permit, require_binding

_VIEW = """SELECT p.*, d.team_id, d.slug FROM {{tables.presentation_links}} p
    JOIN {{tables.documents}} d ON d.document_id=p.document_id
    WHERE p.token=$1 AND p.editable IS FALSE AND p.revoked_at IS NULL
      AND p.expires_at>clock_timestamp()"""


@dataclass(frozen=True)
class CheckedView:
    tx: object = field(repr=False)
    row: dict = field(repr=False)
    permit: object = field(repr=False)
    proof: object = field(repr=False)

    async def revalidate(self, tx):
        await self.permit.check(tx)
        selected = await tx.fetch_one(_VIEW, self.row["token"])
        if selected is None:
            raise edit_sessions.unavailable()
        row = dict(selected)
        for name in (
            "document_id",
            "team_id",
            "certificate_id",
            "creator_team_did_key",
            "records_creator_id",
            "version_number",
        ):
            if row[name] != self.row[name]:
                raise edit_sessions.unavailable()
        require_binding(self.permit, row)
        if row["records_creator_id"]:
            if self.proof is None:
                raise edit_sessions.unavailable()
            edit_sessions.require_proof(row, self.proof)


@asynccontextmanager
async def checked_view(db, runtime, token):
    selected = await db.fetch_one(_VIEW, token)
    if selected is None:
        raise edit_sessions.unavailable()
    evidence = dict(selected)
    permit = await capability_permit(db, runtime, link_id=token)
    # Legacy prose-only links get no row data and need no identity bridge.
    proof = (
        await edit_sessions.member_proof(runtime, evidence)
        if evidence["records_creator_id"]
        else None
    )
    async with edit_sessions.installation_transaction(permit) as tx:
        selected = await tx.fetch_one(_VIEW + " FOR SHARE OF p,d", token)
        if selected is None:
            raise edit_sessions.unavailable()
        context = CheckedView(tx, dict(selected), permit, proof)
        await context.revalidate(tx)
        yield context
