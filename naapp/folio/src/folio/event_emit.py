"""Emit folio/doc.changed app events so an owning agent WAKES when its document
is updated, instead of polling.

The event is enqueued in the same transaction as the document write, so a
committed write always has its event and a rolled-back one never does; the
runtime's outbox delivers it to aweb and retries until it is accepted. The event
carries metadata only (slug, version, edit source), never the document body.
Nothing is enqueued when no app-event key is configured.
"""

from __future__ import annotations

from aweb_naapp.runtime.event_emit import AppEvents
from pgdbm.core import TransactionManager

DOC_CHANGED_EVENT_TYPE = "folio/doc.changed"


async def emit_doc_changed(
    events: AppEvents,
    tx: TransactionManager,
    *,
    team_id: str,
    slug: str,
    version: int,
    source: str,
) -> None:
    await events.emit(
        tx,
        team_id=team_id,
        event_type=DOC_CHANGED_EVENT_TYPE,
        resource_ref=slug,
        delivery_intent="wake",
        payload={"version": str(version), "source": source},
    )
