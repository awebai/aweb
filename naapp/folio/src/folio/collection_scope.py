"""Canonical installed collection resource identity, independent of documents."""

import json
from uuid import NAMESPACE_URL, uuid5

from aweb_naapp.page_store import Scope
from aweb_naapp.runtime.installation import AdmittedInstallation


def collection_scope(installation: AdmittedInstallation, collection_id: str) -> Scope:
    """Stable page/resource ID; installation authority always comes from admission."""
    resource = json.dumps([installation.installation_id, installation.team_id,
                           installation.app_id, collection_id], separators=(",", ":"))
    page_id = str(uuid5(NAMESPACE_URL, "folio.collection:" + resource))
    return Scope(installation.installation_id, installation.team_id, installation.app_id, page_id)

