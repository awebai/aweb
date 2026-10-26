"""Trusted host context for a checked document edit session, never wire input."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aweb_naapp.page_store.models import Scope, StoreError

if TYPE_CHECKING:
    from pgdbm.core import TransactionManager


@dataclass(frozen=True)
class LinkRecordContext:
    """Separate the creator's ACL identity from the session authorizing a write.

    The host constructs this only after checking the session/document binding,
    installation, current creator evidence and saved widget's frozen write grant.
    ``revalidate`` performs local checks on that evidence after the store obtains
    its page lock; it must not make remote calls while resource locks are held.
    Session IDs are public opaque identifiers, never credentials or their hashes.
    """

    scope: Scope
    creator_id: str
    creator_did_key: str
    creator_did_aw: str | None
    creator_alias: str | None
    certificate_id: str
    editor_name: str | None
    link_id: str
    session_id: str
    document_id: str
    widget_id: str
    collection: str
    operations: frozenset[str]
    fields: frozenset[str]
    revalidate: Callable[[TransactionManager], Awaitable[None]]

    def __post_init__(self):
        if (
            not isinstance(self.scope, Scope)
            or any(
                not isinstance(value, str) or not value
                for value in (
                    self.creator_id,
                    self.creator_did_key,
                    self.certificate_id,
                    self.link_id,
                    self.session_id,
                    self.document_id,
                    self.widget_id,
                    self.collection,
                )
            )
            or not isinstance(self.operations, frozenset)
            or self.operations - {"add", "patch", "delete"}
            or not isinstance(self.fields, frozenset)
            or any(not isinstance(field, str) or not field for field in self.fields)
            or not callable(self.revalidate)
        ):
            raise ValueError("a checked link record context is required")

    def require(self, scope, *, operation, collection, values):
        if scope != self.scope:
            raise StoreError("resource_not_found", 404)
        if collection != self.collection or operation not in self.operations:
            raise StoreError("action_denied", 403)
        if isinstance(values, dict) and set(values) - self.fields:
            raise StoreError("action_denied", 403)

    def request_actor(self, operation):
        encoded = json.dumps(
            [
                self.creator_id,
                self.link_id,
                self.session_id,
                self.document_id,
                self.widget_id,
                operation,
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return "link:" + hashlib.sha256(encoded).hexdigest()

    def evidence(self):
        return {
            "origin_kind": "link",
            "creator_id": self.creator_id,
            "creator_did_key": self.creator_did_key,
            "creator_did_aw": self.creator_did_aw,
            "creator_alias": self.creator_alias,
            "certificate_id": self.certificate_id,
            "editor_name": self.editor_name,
            "link_id": self.link_id,
            "session_id": self.session_id,
            "document_id": self.document_id,
            "widget_id": self.widget_id,
        }
