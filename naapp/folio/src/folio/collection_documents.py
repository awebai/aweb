"""Metadata joining collection pages to Folio's existing Documents discovery.

These functions do not authorize access. The caller admits the installation and
checks the shared PageStore ACL before returning an entry or minting its link.
"""

import json
from uuid import NAMESPACE_URL, UUID, uuid5

from aweb_naapp.page_store import Scope, StoreError
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.team_auth import Principal
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

_SELECT = """
    SELECT c.installation_id, c.team_id, c.app_id, c.collection_id, c.page_id,
           d.document_id, d.slug, d.title, d.created_at, d.updated_at, 'table'::TEXT AS kind
    FROM {{tables.collection_documents}} c
    JOIN {{tables.documents}} d ON d.document_id=c.document_id AND d.team_id=c.team_id
    WHERE c.installation_id=$1 AND c.team_id=$2 AND c.app_id=$3
"""


def collection_scope(installation: AdmittedInstallation, collection_id: str) -> Scope:
    """Stable page/resource ID; installation authority always comes from admission."""
    resource = json.dumps([installation.installation_id, installation.team_id,
                           installation.app_id, collection_id], separators=(",", ":"))
    page_id = str(uuid5(NAMESPACE_URL, "folio.collection:" + resource))
    return Scope(installation.installation_id, installation.team_id, installation.app_id, page_id)


async def put_collection_document_on(
    tx: TransactionManager, scope: Scope, principal: Principal, *, collection_id: str, title: str,
) -> dict:
    """Join create_on's caller transaction; replay leaves the same discovery entry."""
    if principal.team_id != scope.team_id:
        raise StoreError("resource_not_found", 404)
    document_id = UUID(scope.page_id)
    slug = "table-" + scope.page_id
    await tx.execute(
        """INSERT INTO {{tables.documents}}
           (document_id, team_id, slug, title, created_by_did_key, created_by_did_aw, created_by_alias)
           VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (document_id) DO NOTHING""",
        document_id, scope.team_id, slug, title, principal.did_key, principal.did_aw, principal.alias,
    )
    await tx.execute(
        """INSERT INTO {{tables.collection_documents}}
           (installation_id, team_id, app_id, collection_id, page_id, document_id)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (installation_id,team_id,app_id,collection_id) DO NOTHING""",
        scope.installation_id, scope.team_id, scope.app_id, collection_id, scope.page_id, document_id,
    )
    row = await tx.fetch_one(
        _SELECT + " AND c.collection_id=$4 AND c.page_id=$5",
        scope.installation_id, scope.team_id, scope.app_id, collection_id, scope.page_id,
    )
    if row is None:
        raise StoreError("revision_conflict", 409)
    return dict(row)


async def find_collection_document(
    db: AsyncDatabaseManager | TransactionManager, installation: AdmittedInstallation, *, slug: str,
) -> dict | None:
    row = await db.fetch_one(
        _SELECT + " AND d.slug=$4",
        installation.installation_id, installation.team_id, installation.app_id, slug,
    )
    return dict(row) if row is not None else None


async def list_collection_documents(
    db: AsyncDatabaseManager | TransactionManager, installation: AdmittedInstallation,
) -> list[dict]:
    rows = await db.fetch_all(
        _SELECT + " ORDER BY d.updated_at DESC,d.slug ASC",
        installation.installation_id, installation.team_id, installation.app_id,
    )
    return [dict(row) for row in rows]
