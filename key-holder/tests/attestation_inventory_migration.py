"""Build historical or damaged inventory states for holder recovery tests."""

import sqlite3
from contextlib import closing, contextmanager

from legacy_schema import remove_attestation_inventory


@contextmanager
def upgraded_pre_inventory_store(store):
    """Exercise migration 006 with the pending binding retained from schema 5."""
    with closing(sqlite3.connect(":memory:")) as inventory_present:
        with store._connection() as db:
            db.backup(inventory_present)
        try:
            with store._connection() as db, db:
                db.execute("BEGIN IMMEDIATE")
                remove_attestation_inventory(db)
                db.execute("PRAGMA user_version=5")
            store.migrate()
            yield
        finally:
            with store._connection() as db:
                inventory_present.backup(db)


def lose_passkey_inventory(store, person, credential):
    with store._connection() as db, db:
        # unreachable-state: a mixed binding lost only its passkey inventory row
        removed = db.execute(
            "DELETE FROM attestation_inventory WHERE person=? AND credential=?",
            (person, credential),
        )
        assert removed.rowcount == 1
