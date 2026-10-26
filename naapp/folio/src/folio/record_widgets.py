"""Saved document widgets resolve through the admitted collection authority."""

from aweb_naapp.page_store import StoreError, principal_id
from aweb_naapp.pages import validate_page

from folio.collection_documents import collection_scope
from folio.document_widgets import WidgetDocumentError, table_widgets
from folio.record_collections import build_collection_page


async def validate_saved_widgets_on(tx, installation, principal, body, storage):
    """Hold current collection ACL locks through the member's document write.

    The parser establishes structure only. Every column, predicate and sort key
    must be readable by the actual saving member, independently of any later
    link minter's broader rights. Collection authority is never posted by a client.
    """
    try:
        definitions = table_widgets(body)
    except WidgetDocumentError as error:
        raise StoreError(error.code, 422) from None
    if not definitions:
        return
    for widget in sorted(definitions.values(), key=lambda w: (w["bind"]["collection"], w["id"])):
        scope = collection_scope(installation, widget["bind"]["collection"])
        await resolve_widget_on(tx, installation, principal_id(principal, scope), widget, storage)


async def resolve_widget_on(tx, installation, creator_id, widget, storage, *, write=False):
    """Resolve a structurally checked saved widget through shared store policy."""
    collection = widget["bind"]["collection"]
    scope = collection_scope(installation, collection)
    metadata = await storage.require_store().collection_access_on(
        tx,
        scope,
        creator_id=creator_id,
        collection=collection,
        link_mode="live",
        write=write,
        exclusive=write,
    )
    if metadata is None:
        raise StoreError("resource_not_found", 404)
    referenced = {column["field"] for column in widget["props"]["columns"]}
    referenced.update(field["field"] for field in widget["bind"].get("all", []))
    referenced.update(field["field"] for field in widget["bind"].get("sort", []))
    if referenced - set(metadata["fields"]):
        raise StoreError("resource_not_found", 404)
    probe = build_collection_page(
        page_id=scope.page_id,
        collection_id=collection,
        title="Records",
        schema=metadata["schema"],
        owner=metadata["owner"],
    )
    probe["layout"] = [widget]
    if not validate_page(probe).valid:
        raise StoreError("invalid_widget", 422)
    return scope, metadata, probe
