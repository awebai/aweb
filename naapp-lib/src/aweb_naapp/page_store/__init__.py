"""Authorized persistent pages, using shared outbox and idempotency primitives.

Hosts supply an authenticated runtime Principal, current installation/scope
admission, and app authorization before calling this module. This store adds
page/row/field ACLs; possession of a Scope is never permission.
"""

from aweb_naapp.page_store.models import Access, RetentionPolicy, Scope, StoreError
from aweb_naapp.page_store.store import PageStore, apply_page_store_migrations
from aweb_naapp.page_store.support import identity as principal_id

__all__ = [
    "Access",
    "PageStore",
    "RetentionPolicy",
    "Scope",
    "StoreError",
    "apply_page_store_migrations",
    "principal_id",
]
