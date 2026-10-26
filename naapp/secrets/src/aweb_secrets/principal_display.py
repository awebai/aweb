"""How owner views name a principal: display only, never authority or a join key.

The name comes from the runtime's own record of authenticated members, read in
the caller's owner-scoped transaction. Grants, roles and correlation always key
on the canonical principal DID, which stays visible beside any name.
"""

from __future__ import annotations

from html import escape

from pgdbm.core import TransactionManager


async def observed_principal_alias(
    tx: TransactionManager, *, team_id: str, principal_did: str
) -> str | None:
    """The alias the team's member was observed under, or None when unknown or ambiguous.

    A did:aw principal matches observations carrying that did_aw. A did:key is
    canonical only for a member without a did_aw, so it matches observations of
    that key with no did_aw. Exactly one distinct non-empty alias names it.
    """
    if principal_did.startswith("did:aw:"):
        match = "did_aw = $2"
    elif principal_did.startswith("did:key:"):
        match = "did_key = $2 AND did_aw IS NULL"
    else:
        return None
    rows = await tx.fetch_all(
        "SELECT DISTINCT alias FROM {{tables.agents}}"
        f" WHERE team_id = $1 AND {match} AND btrim(alias) <> ''",
        team_id,
        principal_did,
    )
    return rows[0]["alias"] if len(rows) == 1 else None


def principal_html(*, principal_did: str, alias: str | None, team_id: str) -> str:
    """The escaped label for a principal: its name in its team when known, and always its DID."""
    did = f'<code class="principal-did">{escape(principal_did)}</code>'
    name = (
        ""
        if alias is None
        else f'<span class="principal-name">{escape(alias)}</span>'
        f' <span class="principal-team">{escape(team_id)}</span> '
    )
    return f'<span class="principal" data-principal-did="{escape(principal_did, quote=True)}">{name}{did}</span>'
